#pragma once

#include "airplay_alac.h"
#include "airplay_crypto.h"
#include "airplay_types.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace airplay {

/// Network access for the receiver. SocketRunner implements it with BSD sockets; implement it yourself for
/// other network stacks.
class Transport {
 public:
  virtual ~Transport() = default;
  /// Sends RTSP data on a connection. Returns false if the connection failed.
  virtual bool send(uint8_t connection, const uint8_t *data, size_t length) = 0;
  /// Closes a connection on behalf of the receiver. Do not call Receiver::connection_closed() for it.
  virtual void close(uint8_t connection) = 0;
  /// Opens the three UDP sockets of a session on free ports. Fills `ports`, indexed by UdpChannel.
  virtual bool open_udp(uint16_t *ports) = 0;
  virtual void close_udp() = 0;
  virtual void send_udp(UdpChannel channel, const Endpoint &to, const uint8_t *data, size_t length) = 0;
};

/// Audio output. Must not block.
class AudioSink {
 public:
  virtual ~AudioSink() = default;
  /// Takes interleaved 16-bit stereo frames at 44.1 kHz. Returns how many frames were accepted; the rest is
  /// offered again later.
  virtual size_t write(const int16_t *samples, size_t frames) = 0;
};

/// Events of the receiver. Called on the thread that drives the receiver.
class Listener {
 public:
  virtual ~Listener() = default;
  virtual void on_session_state(SessionState /*state*/) {}
  /// Volume from the sender's slider, 0 to 1
  virtual void on_volume(float /*volume*/) {}
  virtual void on_mute(bool /*muted*/) {}
  virtual void on_metadata(const Metadata & /*metadata*/) {}
  /// The sender's remote control details, see dacp.h
  virtual void on_remote_target(const RemoteTarget & /*target*/) {}
};

struct ReceiverConfig {
  /// Name shown on the sender
  const char *name{"AirPlay"};
  /// MAC address of the network interface; part of the mDNS name and of the Apple-Challenge answer
  uint8_t mac[6]{};
  /// Jitter buffer. Synchronized playback needs the sender's latency plus a margin, about 2250 ms;
  /// smaller buffers play unsynchronized with three quarters of the buffer (at most 500 ms) of delay.
  uint32_t buffer_ms{500};
  /// Advertise and accept track details (Listener::on_metadata)
  bool metadata{false};
  /// Allocator for the jitter buffer (e.g. external RAM); malloc/free when not set
  void *(*allocate)(size_t size){nullptr};
  void (*deallocate)(void *pointer){nullptr};
};

struct ReceiverStats {
  uint32_t lost_packets;  // Replaced by silence
  uint32_t late_packets;  // Arrived or were due too late
  uint32_t decode_errors;
  uint32_t resend_requests;
  uint32_t trimmed_frames;  // Single frames dropped or repeated to follow the sender's clock or the buffer level
  uint32_t silence_frames;  // Written instead of audio: for lost packets and to line playback up
  uint32_t underruns;       // Times the output ran out of audio during playback
  bool synchronized;        // Playing on the sender's timeline
};

/// AirPlay 1 (RAOP) audio receiver without any I/O of its own: feed it RTSP connections, UDP packets and the
/// time, and it writes PCM to an AudioSink.
///
/// Threading: everything except the methods marked thread-safe must be called from one thread.
class Receiver {
 public:
  static constexpr uint8_t MAX_CONNECTIONS = 2;
  static constexpr uint16_t DEFAULT_PORT = 5000;

  Receiver(const ReceiverConfig &config, Crypto &crypto, Transport &transport, AudioSink &sink,
           Listener *listener = nullptr);
  ~Receiver();
  Receiver(const Receiver &) = delete;
  Receiver &operator=(const Receiver &) = delete;

  /// @brief Allocates the buffers. Call once before anything else.
  bool begin();

  // ===== Events from the transport =====
  void connection_opened(uint8_t connection, const Endpoint &peer, const Endpoint &local);
  void connection_closed(uint8_t connection);
  void connection_data(uint8_t connection, const uint8_t *data, size_t length, int64_t now_us);
  void udp_packet(UdpChannel channel, const uint8_t *data, size_t length, const Endpoint &from, int64_t now_us);
  /// Drives timing, retransmission and playback. Call at least every 5 ms during a session
  /// (needs_fast_polling()), otherwise every 100 ms or so.
  void poll(int64_t now_us);

  bool is_session_owner(uint8_t connection) const { return this->session_owner_ == connection; }
  bool needs_fast_polling() const { return this->audio_active_; }
  SessionState session_state() const { return this->session_state_; }
  const ReceiverStats &stats() const { return this->stats_; }

  // ===== Thread-safe =====
  /// @brief Reports audio that the output has played, e.g. from its DMA callback.
  /// @param timestamp_us When the last of these frames was played, on the clock passed to poll().
  void notify_played(uint32_t frames, int64_t timestamp_us);
  /// @brief Tells the receiver that the output pipeline was restarted and holds none of its audio any more.
  void request_output_restart() { this->output_restart_requested_.store(true, std::memory_order_release); }
  /// @brief Ends the session at the next poll(), e.g. because another source takes over the speaker.
  void request_disconnect() { this->disconnect_requested_.store(true, std::memory_order_release); }

  // ===== mDNS =====
  /// @brief Instance name of the _raop._tcp service: "<MAC>@<name>".
  size_t service_instance_name(char *buffer, size_t size) const;
  /// @brief TXT records of the _raop._tcp service.
  const TxtRecord *txt_records(size_t *count) const;

 protected:
  enum class Codec : uint8_t {
    NONE,
    ALAC,
    PCM,
  };

  struct Connection {
    bool open{false};
    size_t rx_length{0};
    size_t discard_remaining{0};
    Endpoint peer{};
    Endpoint local{};
    char *buffer{nullptr};
  };

  struct PacketSlot {
    uint32_t rtp;
    uint32_t missing_since_ms;  // Non-zero while the packet is missing and may be asked for again
    uint32_t last_request_ms;
    uint16_t seq;
    uint16_t frames;
    bool valid;
    int16_t samples[FRAMES_PER_PACKET * NUM_CHANNELS];
  };

  struct TimingSample {
    int64_t offset_ns;
    int64_t round_trip_ns;
  };

  static constexpr size_t RTSP_BUFFER_SIZE = 2048;
  static constexpr size_t PACKET_BUFFER_SIZE = 1600;
  static constexpr uint32_t TIMING_SAMPLE_COUNT = 8;
  static constexpr uint8_t NO_CONNECTION = 0xff;

  void *allocate_(size_t size) const;
  void free_(void *pointer) const;

  // RTSP
  void process_requests_(uint8_t connection, int64_t now_us);
  /// @return false if the connection must be closed
  bool handle_request_(uint8_t connection, char *request, size_t header_length, char *body, size_t body_length,
                       int64_t now_us);
  bool handle_announce_(const char *body, size_t body_length);
  bool handle_setup_(uint8_t connection, const char *transport, char *response_headers, size_t size);
  void handle_set_parameter_(const char *content_type, const char *body, size_t body_length);
  bool add_apple_response_(uint8_t connection, const char *challenge, char *output, size_t size);
  void update_remote_target_(const char *dacp_id, const char *active_remote, uint32_t address);
  void close_connection_(uint8_t connection);
  void end_session_();
  void set_session_state_(SessionState state);
  void close_udp_();

  // Audio
  bool start_audio_(int64_t now_us);
  void stop_audio_();
  void flush_(bool have_seq, uint16_t seq);
  void reset_playback_();
  void handle_audio_packet_(uint16_t seq, uint32_t rtp, const uint8_t *payload, size_t length, uint32_t now_ms);
  void handle_sync_packet_(const uint8_t *packet, size_t length);
  void handle_timing_reply_(const uint8_t *packet, size_t length, int64_t now_us);
  void handle_timing_request_(UdpChannel channel, const uint8_t *packet, size_t length, const Endpoint &from,
                              int64_t now_us);
  void send_timing_request_(int64_t now_us);
  void retry_resends_(uint32_t now_ms);
  void request_resend_(uint16_t first, uint16_t count);
  void advance_head_();
  /// Converts an RTP timestamp to the local time at which it should be heard
  bool rtp_to_local_us_(uint32_t rtp, int64_t *local_us) const;
  bool write_pending_output_(uint32_t now_ms);
  /// @param trim 0, or +1/-1 to repeat/drop one frame for clock correction
  void queue_packet_output_(const PacketSlot &slot, int32_t trim);
  void queue_silence_output_();
  void playback_step_(int64_t now_us);
  bool start_playback_();
  bool synced_step_(int64_t now_us);
  bool unsynced_step_();
  /// Frames waiting in the output: written minus reported as played
  uint32_t speaker_queued_frames_() const;
  uint32_t buffered_packets_() const;

  ReceiverConfig config_;
  Crypto &crypto_;
  Transport &transport_;
  AudioSink &sink_;
  Listener *listener_;
  ALACDecoder decoder_;

  // Cross-thread requests and reports
  std::atomic<uint32_t> frames_played_{0};
  std::atomic<uint32_t> played_timestamp_{0};  // Low 32 bits of the time in microseconds; 0 = none
  std::atomic<bool> output_restart_requested_{false};
  std::atomic<bool> disconnect_requested_{false};

  // Buffers
  char *rtsp_buffers_{nullptr};
  PacketSlot *slots_{nullptr};
  uint8_t *packet_buffer_{nullptr};
  int16_t *output_buffer_{nullptr};
  uint32_t slot_count_{0};
  uint32_t fill_target_frames_{0};

  // RTSP and session
  Connection connections_[MAX_CONNECTIONS];
  uint8_t session_owner_{NO_CONNECTION};
  SessionState session_state_{SessionState::NONE};
  RemoteTarget remote_target_{};
  bool airplay_muted_{false};
  float airplay_volume_{-15.0f};
  Codec codec_{Codec::NONE};
  bool encrypted_{false};
  uint8_t aes_iv_[AES_BLOCK_SIZE]{};
  bool udp_open_{false};
  Endpoint client_control_{};
  Endpoint client_timing_{};
  uint16_t initial_seq_{0};
  bool have_initial_seq_{false};
  uint16_t sender_version_{0};  // From "User-Agent: AirPlay/<version>"

  // Audio session
  bool audio_active_{false};
  uint32_t head_slot_{0};
  uint16_t next_seq_{0};
  uint16_t highest_seq_{0};
  uint16_t accept_from_seq_{0};
  uint16_t resend_seq_{0};
  bool have_seq_{false};
  bool accept_any_seq_{false};
  uint32_t last_packet_ms_{0};
  uint32_t last_resend_scan_ms_{0};
  uint32_t output_restart_ms_{0};
  bool output_restart_pending_{false};
  bool playback_started_{false};
  bool synced_{false};
  bool sync_logged_{false};
  bool played_reports_missing_{false};
  size_t output_offset_{0};  // Frames of output_buffer_ already written
  size_t output_length_{0};  // Frames in output_buffer_
  uint32_t silence_pending_frames_{0};
  uint64_t frames_written_{0};
  uint32_t first_write_ms_{0};
  int32_t drift_error_{0};
  int32_t servo_error_us_{0};
  bool servo_engaged_{false};
  uint32_t trim_counter_{0};
  uint32_t last_stats_log_ms_{0};
  bool output_dry_{false};
  ReceiverStats stats_{};

  // Clock of the sender
  TimingSample timing_samples_[TIMING_SAMPLE_COUNT]{};
  uint32_t timing_sample_count_{0};
  uint32_t timing_sample_index_{0};
  uint32_t timing_requests_sent_{0};
  uint32_t last_timing_request_ms_{0};
  int64_t clock_offset_ns_{0};
  bool clock_locked_{false};
  bool anchor_valid_{false};
  uint32_t anchor_rtp_{0};
  int64_t anchor_remote_ns_{0};
  uint32_t sender_latency_frames_{0};
  uint32_t next_rtp_{0};
  bool have_next_rtp_{false};
};

}  // namespace airplay
