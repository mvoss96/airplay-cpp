#include "airplay_socket_runner.h"

#ifdef AIRPLAY_HAS_SOCKETS

#include "airplay_dacp.h"
#include "airplay_ptp.h"
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
// The runner polls up to 6 sockets at once (3 UDP, 2 RTSP connections and the listening socket)
#if defined(CONFIG_ZVFS_POLL_MAX) && CONFIG_ZVFS_POLL_MAX < 6
#error "airplay-cpp needs CONFIG_ZVFS_POLL_MAX=6 or more"
#endif
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
  // Only open sockets: each entry counts against CONFIG_ZVFS_POLL_MAX
  static constexpr size_t MAX_POLL = 16;
  struct zsock_pollfd poll_fds[MAX_POLL];
  size_t index[MAX_POLL];
  size_t used = 0;
  for (size_t i = 0; i < count && used < MAX_POLL; i++) {
    ready[i] = false;
    if (fds[i] < 0)
      continue;
    poll_fds[used].fd = fds[i];
    poll_fds[used].events = for_writing ? ZSOCK_POLLOUT : ZSOCK_POLLIN;
    poll_fds[used].revents = 0;
    index[used++] = i;
  }
  if (used == 0) {
    k_sleep(K_MSEC(timeout_ms));
    return false;
  }
  if (zsock_poll(poll_fds, used, static_cast<int>(timeout_ms)) <= 0)
    return false;
  for (size_t i = 0; i < used; i++)
    ready[index[i]] = poll_fds[i].revents != 0;
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

/// Receiver::poll() interval while a session plays. Each call costs about the same however little there is to do
/// (on the ESP32 mostly cache misses), so it does not follow every packet.
static constexpr int64_t FAST_POLL_US = 10000;
static constexpr size_t MAX_PACKETS_PER_READ = 16;
static constexpr size_t TCP_READ_SIZE = 1024;
/// Steps that take this long can starve the output and other tasks, so they are logged
static constexpr int64_t SLOW_STEP_MS = 50;
static constexpr int64_t SLOW_SEND_MS = 10;
static constexpr int LISTEN_BACKLOG = 2;
static constexpr uint32_t UDP_PORT_ATTEMPTS = 100;
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

static int bind_udp_socket(uint16_t port) {
  const int fd = net::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0)
    return -1;
  struct sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_ANY);
  address.sin_port = htons(port);
  if (net::bind(fd, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) != 0) {
    net::close(fd);
    return -1;
  }
  return fd;
}

/// Opens a UDP socket on a port the system picks. Network stacks without getsockname() (e.g. Zephyr's
/// native_sim sockets) get the next free port from `*next_port` on instead.
static int open_udp_socket(uint16_t *port, uint16_t *next_port) {
  int fd = bind_udp_socket(0);
  if (fd >= 0) {
    struct sockaddr_in address {};
    socklen_t length = sizeof(address);
    if (net::getsockname(fd, reinterpret_cast<struct sockaddr *>(&address), &length) == 0 && address.sin_port != 0) {
      *port = ntohs(address.sin_port);
      return fd;
    }
    net::close(fd);
  }
  for (uint32_t attempt = 0; attempt < UDP_PORT_ATTEMPTS && *next_port != 0; attempt++) {
    const uint16_t candidate = (*next_port)++;
    fd = bind_udp_socket(candidate);
    if (fd >= 0) {
      *port = candidate;
      return fd;
    }
  }
  return -1;
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
  this->port_ = port;
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
  for (int &fd : this->ptp_fds_)
    close_fd(&fd);
  close_fd(&this->listen_fd_);
}

void SocketRunner::run_once(uint32_t max_wait_ms) {
  if (this->receiver_ == nullptr)
    return;
  const bool fast = this->receiver_->needs_fast_polling();
  uint32_t wait_ms = max_wait_ms;
  if (fast) {
    const int64_t due_in_us = this->last_poll_us_ + FAST_POLL_US - SocketRunner::now_us();
    wait_ms = due_in_us > 0 ? std::min(max_wait_ms, static_cast<uint32_t>((due_in_us + 999) / 1000)) : 0;
  }

  // Sockets in the order they are handled: UDP first, as the audio is the most urgent. Existing connections are
  // read before accepting, so a new connection cannot reuse a descriptor number that is still marked as ready.
  int fds[NUM_UDP_CHANNELS + 2 + Receiver::MAX_CONNECTIONS + 1];
  bool ready[NUM_UDP_CHANNELS + 2 + Receiver::MAX_CONNECTIONS + 1] = {};
  size_t count = 0;
  for (int fd : this->udp_fds_)
    fds[count++] = fd;
  for (int fd : this->ptp_fds_)
    fds[count++] = fd;
  for (uint8_t i = 0; i < Receiver::MAX_CONNECTIONS; i++)
    fds[count++] = this->receive_paused_[i] ? -1 : this->connection_fds_[i];
  fds[count++] = this->listen_fd_;
  // Where the time goes when the thread falls behind: waiting longer than asked means it did not get to run
  const int64_t wait_start = SocketRunner::now_us();
  const bool any_ready = net::wait(fds, count, wait_ms, ready);
  const int64_t wait_end = SocketRunner::now_us();
  this->loops_.fetch_add(1, std::memory_order_relaxed);
  this->wait_us_.fetch_add(static_cast<uint32_t>(wait_end - wait_start), std::memory_order_relaxed);
  const int64_t waited_ms = (wait_end - wait_start) / 1000;
  if (waited_ms >= wait_ms + SLOW_STEP_MS)
    AIRPLAY_LOGW("Waiting for the network took %u ms (up to %u ms asked)", static_cast<unsigned>(waited_ms),
                 static_cast<unsigned>(wait_ms));
  if (any_ready) {
    const int64_t udp_start = SocketRunner::now_us();
    size_t packets = 0;
    for (size_t i = 0; i < NUM_UDP_CHANNELS; i++) {
      if (ready[i] && this->udp_fds_[i] == fds[i])
        packets += this->receive_udp_(static_cast<UdpChannel>(i));
    }
    for (size_t i = 0; i < 2; i++) {
      if (ready[NUM_UDP_CHANNELS + i] && this->ptp_fds_[i] == fds[NUM_UDP_CHANNELS + i])
        this->receive_ptp_(i);
    }
    // Many packets: catching up after the thread was held up; few: held up while handling them
    const int64_t udp_end = SocketRunner::now_us();
    this->udp_us_.fetch_add(static_cast<uint32_t>(udp_end - udp_start), std::memory_order_relaxed);
    const int64_t udp_ms = (udp_end - udp_start) / 1000;
    if (udp_ms >= SLOW_STEP_MS)
      AIRPLAY_LOGW("Receiving %u UDP packets took %u ms", static_cast<unsigned>(packets),
                   static_cast<unsigned>(udp_ms));
    for (uint8_t i = 0; i < Receiver::MAX_CONNECTIONS; i++) {
      const size_t at = NUM_UDP_CHANNELS + 2 + i;
      if (ready[at] && this->connection_fds_[i] == fds[at] && fds[at] >= 0) {
        const int64_t start = SocketRunner::now_us();
        this->receive_tcp_(i);
        const int64_t end = SocketRunner::now_us();
        this->tcp_us_.fetch_add(static_cast<uint32_t>(end - start), std::memory_order_relaxed);
        const int64_t took_ms = (end - start) / 1000;
        if (took_ms >= SLOW_STEP_MS)
          AIRPLAY_LOGW("Handling data of connection %u took %u ms", i, static_cast<unsigned>(took_ms));
      }
    }
    if (ready[count - 1] && this->listen_fd_ >= 0)
      this->accept_connection_();
  }
  const int64_t start = SocketRunner::now_us();
  if (fast && start - this->last_poll_us_ < FAST_POLL_US)
    return;
  this->last_poll_us_ = start;
  this->polls_.fetch_add(1, std::memory_order_relaxed);
  this->receiver_->poll(start);
  const int64_t end = SocketRunner::now_us();
  this->poll_us_.fetch_add(static_cast<uint32_t>(end - start), std::memory_order_relaxed);
  const int64_t took_ms = (end - start) / 1000;
  if (took_ms >= SLOW_STEP_MS)
    AIRPLAY_LOGW("Playback step took %u ms", static_cast<unsigned>(took_ms));
}

SocketRunner::Timing SocketRunner::take_timing() {
  return Timing{this->loops_.exchange(0, std::memory_order_relaxed),
                this->wait_us_.exchange(0, std::memory_order_relaxed) / 1000,
                this->udp_us_.exchange(0, std::memory_order_relaxed) / 1000,
                this->recv_us_.exchange(0, std::memory_order_relaxed) / 1000,
                this->tcp_us_.exchange(0, std::memory_order_relaxed) / 1000,
                this->poll_us_.exchange(0, std::memory_order_relaxed) / 1000,
                this->polls_.exchange(0, std::memory_order_relaxed)};
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
      if (!this->receiver_->is_session_connection(i)) {
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
  this->receive_paused_[slot] = false;
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

size_t SocketRunner::receive_udp_(UdpChannel channel) {
  for (size_t i = 0; i < MAX_PACKETS_PER_READ; i++) {
    const int fd = this->udp_fds_[static_cast<size_t>(channel)];
    if (fd < 0)
      return i;  // Closed by the receiver while handling a packet
    struct sockaddr_in source {};
    socklen_t source_length = sizeof(source);
    const int64_t start = SocketRunner::now_us();
    const auto received = net::recvfrom(fd, this->udp_buffer_, sizeof(this->udp_buffer_), net::MSG_DONT_WAIT,
                                        reinterpret_cast<struct sockaddr *>(&source), &source_length);
    this->recv_us_.fetch_add(static_cast<uint32_t>(SocketRunner::now_us() - start), std::memory_order_relaxed);
    if (received <= 0)
      return i;
    this->receiver_->udp_packet(channel, this->udp_buffer_, static_cast<size_t>(received),
                                Endpoint{source.sin_addr.s_addr, ntohs(source.sin_port)}, SocketRunner::now_us());
  }
  return MAX_PACKETS_PER_READ;
}

void SocketRunner::receive_ptp_(size_t index) {
  for (size_t i = 0; i < MAX_PACKETS_PER_READ; i++) {
    struct sockaddr_in source {};
    socklen_t source_length = sizeof(source);
    const auto received =
        net::recvfrom(this->ptp_fds_[index], this->udp_buffer_, sizeof(this->udp_buffer_), net::MSG_DONT_WAIT,
                      reinterpret_cast<struct sockaddr *>(&source), &source_length);
    if (received <= 0)
      return;
    this->receiver_->ptp_packet(index == 1, this->udp_buffer_, static_cast<size_t>(received), source.sin_addr.s_addr,
                                SocketRunner::now_us());
  }
}

bool SocketRunner::send(uint8_t connection, const uint8_t *data, size_t length) {
  if (connection >= Receiver::MAX_CONNECTIONS || this->connection_fds_[connection] < 0)
    return false;
  // A peer that does not read makes the send wait for room, which holds up playback
  const int64_t start = SocketRunner::now_us();
  const size_t total = length;
  while (length > 0) {
    const auto sent = net::send(this->connection_fds_[connection], data, length, net::MSG_NO_SIGNAL);
    if (sent <= 0)
      return false;
    data += sent;
    length -= static_cast<size_t>(sent);
  }
  const int64_t took_ms = (SocketRunner::now_us() - start) / 1000;
  if (took_ms >= SLOW_SEND_MS)
    AIRPLAY_LOGW("Sending %u bytes on connection %u took %u ms", static_cast<unsigned>(total), connection,
                 static_cast<unsigned>(took_ms));
  return true;
}

void SocketRunner::close(uint8_t connection) {
  if (connection < Receiver::MAX_CONNECTIONS)
    close_fd(&this->connection_fds_[connection]);
}

void SocketRunner::pause_receiving(uint8_t connection, bool paused) {
  if (connection < Receiver::MAX_CONNECTIONS)
    this->receive_paused_[connection] = paused;
}

bool SocketRunner::open_udp(uint16_t *ports) {
  this->close_udp();
  uint16_t next_port = static_cast<uint16_t>(this->port_ + 1);
  for (size_t i = 0; i < NUM_UDP_CHANNELS; i++) {
    if (this->udp_base_port_ != 0) {
      ports[i] = static_cast<uint16_t>(this->udp_base_port_ + i);
      this->udp_fds_[i] = bind_udp_socket(ports[i]);
    } else {
      this->udp_fds_[i] = open_udp_socket(&ports[i], &next_port);
    }
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

bool SocketRunner::open_ptp() {
#if defined(__ZEPHYR__)
  return false;  // Two more sockets than CONFIG_ZVFS_POLL_MAX allows for
#else
  if (this->ptp_fds_[0] >= 0)
    return true;
  const uint16_t ports[2] = {PTP_EVENT_PORT, PTP_GENERAL_PORT};
  for (size_t i = 0; i < 2; i++) {
    const int fd = net::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int enable = 1;
    if (fd >= 0)
      net::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    struct sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(ports[i]);
    if (fd < 0 || net::bind(fd, reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) != 0) {
      AIRPLAY_LOGW("Failed to open PTP port %u: %d", ports[i], errno);
      if (fd >= 0)
        net::close(fd);
      for (int &open_fd : this->ptp_fds_)
        close_fd(&open_fd);
      return false;
    }
    // Senders may send to the PTP multicast group as well as to the receiver
    struct ip_mreq group {};
    group.imr_multiaddr.s_addr = htonl(0xe0000181);  // 224.0.1.129
    group.imr_interface.s_addr = htonl(INADDR_ANY);
    if (net::setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group, sizeof(group)) != 0)
      AIRPLAY_LOGD("Failed to join the PTP multicast group on port %u: %d", ports[i], errno);
    this->ptp_fds_[i] = fd;
  }
  AIRPLAY_LOGI("Listening for PTP on ports %u and %u", PTP_EVENT_PORT, PTP_GENERAL_PORT);
  return true;
#endif
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
