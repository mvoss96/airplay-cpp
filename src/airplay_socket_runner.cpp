#include "airplay_socket_runner.h"

#ifdef AIRPLAY_HAS_SOCKETS

#include "airplay_dacp.h"
#include "airplay_log.h"

#include <algorithm>
#include <cerrno>

#if defined(ESP_PLATFORM)
#include <esp_timer.h>
#include <fcntl.h>
#include <lwip/sockets.h>
#include <unistd.h>
#elif defined(__ZEPHYR__)
// Zephyr's own socket API, so that CONFIG_POSIX_API is not needed
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#endif

namespace airplay {

/// The few socket calls the runner needs, mapped to each platform's API
namespace net {
#if defined(__ZEPHYR__)
static constexpr int MSG_NO_SIGNAL = 0;
static constexpr int MSG_DONT_WAIT = ZSOCK_MSG_DONTWAIT;
inline int socket(int domain, int type, int protocol) { return zsock_socket(domain, type, protocol); }
inline int close(int fd) { return zsock_close(fd); }
inline int bind(int fd, const struct sockaddr *address, socklen_t length) { return zsock_bind(fd, address, length); }
inline int listen(int fd, int backlog) { return zsock_listen(fd, backlog); }
inline int accept(int fd, struct sockaddr *address, socklen_t *length) { return zsock_accept(fd, address, length); }
inline int connect(int fd, const struct sockaddr *address, socklen_t length) {
  return zsock_connect(fd, address, length);
}
inline int getsockname(int fd, struct sockaddr *address, socklen_t *length) {
  return zsock_getsockname(fd, address, length);
}
inline int setsockopt(int fd, int level, int name, const void *value, socklen_t length) {
  return zsock_setsockopt(fd, level, name, value, length);
}
inline int getsockopt(int fd, int level, int name, void *value, socklen_t *length) {
  return zsock_getsockopt(fd, level, name, value, length);
}
inline ssize_t send(int fd, const void *data, size_t length, int flags) { return zsock_send(fd, data, length, flags); }
inline ssize_t recv(int fd, void *data, size_t length, int flags) { return zsock_recv(fd, data, length, flags); }
inline ssize_t sendto(int fd, const void *data, size_t length, int flags, const struct sockaddr *to,
                      socklen_t to_length) {
  return zsock_sendto(fd, data, length, flags, to, to_length);
}
inline ssize_t recvfrom(int fd, void *data, size_t length, int flags, struct sockaddr *from, socklen_t *from_length) {
  return zsock_recvfrom(fd, data, length, flags, from, from_length);
}
inline void set_timeouts(int fd, uint32_t timeout_ms) {
  struct zsock_timeval timeout {};
  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
  zsock_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  zsock_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}
/// Waits until one of the sockets is readable (or writable) and marks them in `ready`. False on timeout.
inline bool wait(const int *fds, size_t count, uint32_t timeout_ms, bool *ready, bool for_writing = false) {
  struct zsock_pollfd poll_fds[8];
  count = std::min(count, sizeof(poll_fds) / sizeof(poll_fds[0]));
  for (size_t i = 0; i < count; i++) {
    poll_fds[i].fd = fds[i];
    poll_fds[i].events = for_writing ? ZSOCK_POLLOUT : ZSOCK_POLLIN;
    poll_fds[i].revents = 0;
  }
  if (zsock_poll(poll_fds, count, static_cast<int>(timeout_ms)) <= 0)
    return false;
  for (size_t i = 0; i < count; i++)
    ready[i] = fds[i] >= 0 && poll_fds[i].revents != 0;
  return true;
}
inline bool set_nonblocking(int fd, bool enable) {
  const int flags = zsock_fcntl(fd, ZVFS_F_GETFL, 0);
  return zsock_fcntl(fd, ZVFS_F_SETFL, enable ? (flags | ZVFS_O_NONBLOCK) : (flags & ~ZVFS_O_NONBLOCK)) == 0;
}
#else
#ifdef MSG_NOSIGNAL
static constexpr int MSG_NO_SIGNAL = MSG_NOSIGNAL;
#else
static constexpr int MSG_NO_SIGNAL = 0;
#endif
static constexpr int MSG_DONT_WAIT = MSG_DONTWAIT;
using ::accept;
using ::bind;
using ::close;
using ::connect;
using ::getsockname;
using ::getsockopt;
using ::listen;
using ::recv;
using ::recvfrom;
using ::send;
using ::sendto;
using ::setsockopt;
using ::socket;
inline void set_timeouts(int fd, uint32_t timeout_ms) {
  struct timeval timeout {};
  timeout.tv_sec = static_cast<decltype(timeout.tv_sec)>(timeout_ms / 1000);
  timeout.tv_usec = static_cast<decltype(timeout.tv_usec)>((timeout_ms % 1000) * 1000);
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}
/// Waits until one of the sockets is readable (or writable) and marks them in `ready`. False on timeout.
inline bool wait(const int *fds, size_t count, uint32_t timeout_ms, bool *ready, bool for_writing = false) {
  fd_set set;
  FD_ZERO(&set);
  int max_fd = -1;
  for (size_t i = 0; i < count; i++) {
    if (fds[i] >= 0) {
      FD_SET(fds[i], &set);
      max_fd = std::max(max_fd, fds[i]);
    }
  }
  struct timeval timeout {};
  timeout.tv_sec = static_cast<decltype(timeout.tv_sec)>(timeout_ms / 1000);
  timeout.tv_usec = static_cast<decltype(timeout.tv_usec)>((timeout_ms % 1000) * 1000);
  if (::select(max_fd + 1, for_writing ? nullptr : &set, for_writing ? &set : nullptr, nullptr, &timeout) <= 0)
    return false;
  for (size_t i = 0; i < count; i++)
    ready[i] = fds[i] >= 0 && FD_ISSET(fds[i], &set);
  return true;
}
inline bool set_nonblocking(int fd, bool enable) {
  const int flags = ::fcntl(fd, F_GETFL, 0);
  return ::fcntl(fd, F_SETFL, enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK)) == 0;
}
#endif
}  // namespace net

static constexpr uint32_t FAST_POLL_MS = 5;
static constexpr size_t MAX_PACKETS_PER_READ = 16;
static constexpr size_t TCP_READ_SIZE = 1024;
static constexpr int LISTEN_BACKLOG = 2;
// Detect senders that disappear without closing the connection
static constexpr int KEEPALIVE_IDLE_S = 30;
static constexpr int KEEPALIVE_INTERVAL_S = 5;
static constexpr int KEEPALIVE_COUNT = 3;

int64_t SocketRunner::now_us() {
#if defined(ESP_PLATFORM)
  return esp_timer_get_time();
#elif defined(__ZEPHYR__)
  return static_cast<int64_t>(k_ticks_to_us_floor64(k_uptime_ticks()));
#else
  return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch())
      .count();
#endif
}

static void close_fd(int *fd) {
  if (*fd >= 0) {
    net::close(*fd);
    *fd = -1;
  }
}

static int open_udp_socket(uint16_t *port) {
  const int fd = net::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0)
    return -1;
  struct sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_ANY);
  address.sin_port = 0;
  socklen_t length = sizeof(address);
  if (net::bind(fd, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) != 0 ||
      net::getsockname(fd, reinterpret_cast<struct sockaddr *>(&address), &length) != 0) {
    net::close(fd);
    return -1;
  }
  *port = ntohs(address.sin_port);
  return fd;
}

SocketRunner::~SocketRunner() { this->end(); }

bool SocketRunner::begin(Receiver &receiver, uint16_t port) {
  this->receiver_ = &receiver;
  if (this->listen_fd_ >= 0)
    return true;
  const int fd = net::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    AIRPLAY_LOGW("Failed to create socket: %d", errno);
    return false;
  }
  int enable = 1;
  net::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

  struct sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_ANY);
  address.sin_port = htons(port);
  if (net::bind(fd, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) != 0 ||
      net::listen(fd, LISTEN_BACKLOG) != 0) {
    AIRPLAY_LOGW("Failed to listen on port %u: %d", port, errno);
    net::close(fd);
    return false;
  }
  this->listen_fd_ = fd;
  AIRPLAY_LOGI("Listening on port %u", port);
  return true;
}

void SocketRunner::end() {
  for (uint8_t i = 0; i < Receiver::MAX_CONNECTIONS; i++) {
    if (this->connection_fds_[i] >= 0) {
      close_fd(&this->connection_fds_[i]);
      if (this->receiver_ != nullptr)
        this->receiver_->connection_closed(i);
    }
  }
  this->close_udp();
  close_fd(&this->listen_fd_);
}

void SocketRunner::run_once(uint32_t max_wait_ms) {
  if (this->receiver_ == nullptr)
    return;
  const uint32_t wait_ms = this->receiver_->needs_fast_polling() ? std::min(max_wait_ms, FAST_POLL_MS) : max_wait_ms;

  // Sockets in the order they are handled: UDP first, as the audio is the most urgent. Existing connections are
  // read before accepting, so a new connection cannot reuse a descriptor number that is still marked as ready.
  int fds[NUM_UDP_CHANNELS + Receiver::MAX_CONNECTIONS + 1];
  bool ready[NUM_UDP_CHANNELS + Receiver::MAX_CONNECTIONS + 1] = {};
  size_t count = 0;
  for (int fd : this->udp_fds_)
    fds[count++] = fd;
  for (int fd : this->connection_fds_)
    fds[count++] = fd;
  fds[count++] = this->listen_fd_;
  if (net::wait(fds, count, wait_ms, ready)) {
    for (size_t i = 0; i < NUM_UDP_CHANNELS; i++) {
      if (ready[i] && this->udp_fds_[i] == fds[i])
        this->receive_udp_(static_cast<UdpChannel>(i));
    }
    for (uint8_t i = 0; i < Receiver::MAX_CONNECTIONS; i++) {
      if (ready[NUM_UDP_CHANNELS + i] && this->connection_fds_[i] == fds[NUM_UDP_CHANNELS + i] &&
          fds[NUM_UDP_CHANNELS + i] >= 0)
        this->receive_tcp_(i);
    }
    if (ready[count - 1] && this->listen_fd_ >= 0)
      this->accept_connection_();
  }
  this->receiver_->poll(SocketRunner::now_us());
}

void SocketRunner::accept_connection_() {
  struct sockaddr_in peer {};
  socklen_t peer_length = sizeof(peer);
  const int fd = net::accept(this->listen_fd_, reinterpret_cast<struct sockaddr *>(&peer), &peer_length);
  if (fd < 0)
    return;

  int slot = -1;
  for (uint8_t i = 0; i < Receiver::MAX_CONNECTIONS; i++) {
    if (this->connection_fds_[i] < 0) {
      slot = i;
      break;
    }
  }
  if (slot < 0) {
    // All slots are taken: drop the connection that is not playing
    for (uint8_t i = 0; i < Receiver::MAX_CONNECTIONS; i++) {
      if (!this->receiver_->is_session_owner(i)) {
        close_fd(&this->connection_fds_[i]);
        this->receiver_->connection_closed(i);
        slot = i;
        break;
      }
    }
  }
  if (slot < 0) {
    net::close(fd);
    return;
  }

  int enable = 1;
  net::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
  net::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
#ifdef TCP_KEEPIDLE
  int keepalive = KEEPALIVE_IDLE_S;
  net::setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive, sizeof(keepalive));
#endif
#ifdef TCP_KEEPINTVL
  int interval = KEEPALIVE_INTERVAL_S;
  net::setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
#endif
#ifdef TCP_KEEPCNT
  int count = KEEPALIVE_COUNT;
  net::setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
#endif

  struct sockaddr_in local {};
  socklen_t local_length = sizeof(local);
  net::getsockname(fd, reinterpret_cast<struct sockaddr *>(&local), &local_length);

  this->connection_fds_[slot] = fd;
  this->receiver_->connection_opened(static_cast<uint8_t>(slot), Endpoint{peer.sin_addr.s_addr, ntohs(peer.sin_port)},
                                     Endpoint{local.sin_addr.s_addr, ntohs(local.sin_port)});
}

void SocketRunner::receive_tcp_(uint8_t connection) {
  uint8_t buffer[TCP_READ_SIZE];
  const auto received = net::recv(this->connection_fds_[connection], buffer, sizeof(buffer), 0);
  if (received <= 0) {
    close_fd(&this->connection_fds_[connection]);
    this->receiver_->connection_closed(connection);
    return;
  }
  this->receiver_->connection_data(connection, buffer, static_cast<size_t>(received), SocketRunner::now_us());
}

void SocketRunner::receive_udp_(UdpChannel channel) {
  for (size_t i = 0; i < MAX_PACKETS_PER_READ; i++) {
    const int fd = this->udp_fds_[static_cast<size_t>(channel)];
    if (fd < 0)
      return;  // Closed by the receiver while handling a packet
    struct sockaddr_in source {};
    socklen_t source_length = sizeof(source);
    const auto received = net::recvfrom(fd, this->udp_buffer_, sizeof(this->udp_buffer_), net::MSG_DONT_WAIT,
                                        reinterpret_cast<struct sockaddr *>(&source), &source_length);
    if (received <= 0)
      return;
    this->receiver_->udp_packet(channel, this->udp_buffer_, static_cast<size_t>(received),
                                Endpoint{source.sin_addr.s_addr, ntohs(source.sin_port)}, SocketRunner::now_us());
  }
}

bool SocketRunner::send(uint8_t connection, const uint8_t *data, size_t length) {
  if (connection >= Receiver::MAX_CONNECTIONS || this->connection_fds_[connection] < 0)
    return false;
  while (length > 0) {
    const auto sent = net::send(this->connection_fds_[connection], data, length, net::MSG_NO_SIGNAL);
    if (sent <= 0)
      return false;
    data += sent;
    length -= static_cast<size_t>(sent);
  }
  return true;
}

void SocketRunner::close(uint8_t connection) {
  if (connection < Receiver::MAX_CONNECTIONS)
    close_fd(&this->connection_fds_[connection]);
}

bool SocketRunner::open_udp(uint16_t *ports) {
  this->close_udp();
  for (size_t i = 0; i < NUM_UDP_CHANNELS; i++) {
    this->udp_fds_[i] = open_udp_socket(&ports[i]);
    if (this->udp_fds_[i] < 0) {
      this->close_udp();
      return false;
    }
  }
  return true;
}

void SocketRunner::close_udp() {
  for (int &fd : this->udp_fds_)
    close_fd(&fd);
}

void SocketRunner::send_udp(UdpChannel channel, const Endpoint &to, const uint8_t *data, size_t length) {
  const int fd = this->udp_fds_[static_cast<size_t>(channel)];
  if (fd < 0)
    return;
  struct sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_port = htons(to.port);
  address.sin_addr.s_addr = to.address;
  net::sendto(fd, data, length, 0, reinterpret_cast<struct sockaddr *>(&address), sizeof(address));
}

int send_dacp_command(const RemoteTarget &target, uint16_t port, const char *command, uint32_t timeout_ms) {
  char request[256];
  const size_t request_length = dacp_format_request(target, port, command, request, sizeof(request));
  if (request_length == 0 || port == 0)
    return 0;

  const int fd = net::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0)
    return 0;
  net::set_timeouts(fd, timeout_ms);

  // Connect without blocking for longer than the timeout
  net::set_nonblocking(fd, true);
  struct sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = target.address;
  bool connected = net::connect(fd, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) == 0;
  if (!connected && errno == EINPROGRESS) {
    bool writable = false;
    int error = 0;
    socklen_t error_length = sizeof(error);
    connected = net::wait(&fd, 1, timeout_ms, &writable, true) && writable &&
                net::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) == 0 && error == 0;
  }
  net::set_nonblocking(fd, false);

  int status = 0;
  if (connected && net::send(fd, request, request_length, net::MSG_NO_SIGNAL) == static_cast<ssize_t>(request_length)) {
    char reply[32];
    const auto received = net::recv(fd, reply, sizeof(reply), 0);
    if (received > 0)
      status = dacp_parse_status(reply, static_cast<size_t>(received));
  }
  net::close(fd);
  if (status >= 200 && status < 300) {
    AIRPLAY_LOGD("Sent '%s'", command);
  } else {
    AIRPLAY_LOGW("Remote command '%s' failed (%d)", command, status);
  }
  return status;
}

}  // namespace airplay

#endif  // AIRPLAY_HAS_SOCKETS
