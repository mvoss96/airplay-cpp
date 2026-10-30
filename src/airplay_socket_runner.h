#pragma once

// Drives a Receiver with BSD sockets: ESP-IDF and Arduino-ESP32 (lwIP), Zephyr (CONFIG_NET_SOCKETS), Linux and
// macOS. Define AIRPLAY_NO_SOCKETS to leave it out, e.g. on platforms with another network API.

#if !defined(AIRPLAY_NO_SOCKETS) && \
    (defined(ESP_PLATFORM) || defined(__ZEPHYR__) || defined(__unix__) || defined(__APPLE__))
#define AIRPLAY_HAS_SOCKETS 1
#endif

#ifdef AIRPLAY_HAS_SOCKETS

#include "airplay_receiver.h"

#include <cstddef>
#include <cstdint>

namespace airplay {

/// Owns the listening socket, the RTSP connections and the UDP sockets of a Receiver.
///
/// Usage: construct the runner, construct the Receiver with it as Transport, call begin(), then call run_once()
/// in a loop on one thread (e.g. a FreeRTOS task with a priority above the network stack's lowest).
class SocketRunner final : public Transport {
 public:
  SocketRunner() = default;
  ~SocketRunner() override;
  SocketRunner(const SocketRunner &) = delete;
  SocketRunner &operator=(const SocketRunner &) = delete;

  /// @brief Starts listening for senders.
  /// @return false if the port could not be opened; call again later.
  bool begin(Receiver &receiver, uint16_t port = Receiver::DEFAULT_PORT);
  /// @brief Closes all sockets. The receiver ends its session.
  void end();

  /// @brief Waits up to max_wait_ms for network traffic, hands it to the receiver and calls Receiver::poll().
  /// The wait is shortened to 5 ms while a session plays.
  void run_once(uint32_t max_wait_ms = 100);

  /// @brief Monotonic time in microseconds, the clock the runner passes to the receiver. Use it for the
  /// timestamps of Receiver::notify_played().
  static int64_t now_us();

  // Transport
  bool send(uint8_t connection, const uint8_t *data, size_t length) override;
  void close(uint8_t connection) override;
  bool open_udp(uint16_t *ports) override;
  void close_udp() override;
  void send_udp(UdpChannel channel, const Endpoint &to, const uint8_t *data, size_t length) override;

 protected:
  void accept_connection_();
  void receive_tcp_(uint8_t connection);
  void receive_udp_(UdpChannel channel);

  Receiver *receiver_{nullptr};
  int listen_fd_{-1};
  int connection_fds_[Receiver::MAX_CONNECTIONS]{-1, -1};
  int udp_fds_[NUM_UDP_CHANNELS]{-1, -1, -1};
  uint8_t udp_buffer_[1600];
};

/// @brief Sends a remote control command to the sender and waits for the answer (blocking, up to timeout_ms
/// for connecting and again for the answer). Run it outside the thread that drives the receiver.
/// @param port Port of the sender's "_dacp._tcp" service (see airplay_dacp.h).
/// @param command E.g. DACP_PAUSE, or the output of dacp_volume_command().
/// @return The HTTP status code, or 0 if the sender could not be reached. 2xx means success.
int send_dacp_command(const RemoteTarget &target, uint16_t port, const char *command, uint32_t timeout_ms = 1500);

}  // namespace airplay

#endif  // AIRPLAY_HAS_SOCKETS
