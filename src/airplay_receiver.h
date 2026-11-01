#pragma once

#include "airplay_aac.h"
#include "airplay_alac.h"
#include "airplay_crypto.h"
#include "airplay_hap_crypto.h"
#include "airplay_packet_queue.h"
#include "airplay_types.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace airplay {

class SrpServer;

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
  /// Stops or resumes reading a connection, so that a sender that sends audio ahead waits while the receiver's
  /// buffer is full. Without it the receiver drops what does not fit.
  virtual void pause_receiving(uint8_t /*connection*/, bool /*paused*/) {}
};

/// Audio output. Must not block.
class AudioSink {
 public:
  virtual ~AudioSink() = default;
  /// Takes interleaved 16-bit stereo frames at 44.1 kHz. Returns how many frames were accepted; the rest is
  /// offered again later.
  virtual size_t write(const int16_t *samples, size_t frames) = 0;
};

/// Playback commands for an AirPlay 2 sender (Receiver::request_sender_command)
enum class SenderCommand : uint8_t {
  SENDER_COMMAND_PLAY = 0,
  SENDER_COMMAND_PAUSE,
  SENDER_COMMAND_PLAY_PAUSE,
  SENDER_COMMAND_NEXT,
  SENDER_COMMAND_PREVIOUS,
};

/// Cover art data that may still arrive after Listener::artwork_room() fell below it: the receiver's request
/// buffer and one read of the transport (at most 2 KB)
inline constexpr size_t ARTWORK_RESERVE = 6 * 1024;

/// Events of the receiver. Called on the thread that drives the receiver.
class Listener {
 public:
  virtual ~Listener() = default;
  virtual void on_session_state(SessionState /*state*/) {}
  /// Volume from the sender's slider, 0 to 1
  virtual void on_volume(float /*volume*/) {}
  virtual void on_mute(bool /*muted*/) {}
  virtual void on_metadata(const Metadata & /*metadata*/) {}
  /// Cover art of the current track (config.artwork). It arrives in pieces: on_artwork_begin(), then
  /// on_artwork_data() until `size` bytes have been passed, then on_artwork_end(). Return false from
  /// on_artwork_begin() to skip the image, e.g. when it is too large.
  virtual bool on_artwork_begin(ArtworkFormat /*format*/, size_t /*size*/) { return false; }
  virtual void on_artwork_data(const uint8_t * /*data*/, size_t /*length*/) {}
  /// @brief Free space for cover art data, so that an image can be decoded while it arrives through a small buffer.
  ///
  /// While this is below ARTWORK_RESERVE, the receiver stops reading the sender's connection; up to ARTWORK_RESERVE
  /// bytes may still be passed after that. Reading resumes once there is room again, which poll() checks. Other
  /// requests of the sender wait meanwhile. The default takes any amount.
  virtual size_t artwork_room() { return SIZE_MAX; }
  /// @param complete false if the session ended before the whole image arrived
  virtual void on_artwork_end(bool /*complete*/) {}
  /// The current track has no cover art, or the session ended
  virtual void on_artwork_clear() {}
  /// Position and length of the current track (config.progress), sent at the start of a track and after seeking.
  /// The position then advances in real time while the session plays.
  virtual void on_progress(const Progress & /*progress*/) {}
  /// The sender's remote control details, see dacp.h
  virtual void on_remote_target(const RemoteTarget & /*target*/) {}
};

struct ReceiverConfig {
  /// Name shown on the sender
  const char *name{"AirPlay"};
  /// Device model announced in mDNS ("am"); must stay valid while the receiver exists
  const char *model{"airplay-cpp"};
  /// MAC address of the network interface; part of the mDNS name and of the Apple-Challenge answer
  uint8_t mac[6]{};
  /// Jitter buffer. Synchronized playback needs the sender's latency plus a margin, about 2250 ms;
  /// smaller buffers play unsynchronized with three quarters of the buffer (at most 500 ms) of delay.
  uint32_t buffer_ms{500};
  /// Advertise and accept track details (Listener::on_metadata)
  bool metadata{false};
  /// Advertise and accept cover art (Listener::on_artwork_begin)
  bool artwork{false};
  /// Advertise and accept the track position (Listener::on_progress)
  bool progress{false};
  /// Password senders must enter (RTSP Digest authentication); none when null. Must stay valid.
  const char *password{nullptr};
  /// Also offer AirPlay 2 (transient pairing, realtime audio with NTP timing). Needs `random`. Not offered when a
  /// password is set.
  bool airplay2{false};
  /// Fills a buffer with cryptographically secure random bytes; for AirPlay 2 pairing
  void (*random)(uint8_t *buffer, size_t length){nullptr};
  /// Feature bits announced for AirPlay 2, to try what senders do with other combinations; 0 for the default
  uint64_t airplay2_features{0};
  /// Decoder for AirPlay 2 buffered audio (AAC), which iOS uses for most apps; not offered without one. Must stay
  /// valid while the receiver exists.
  AacDecoder *aac_decoder{nullptr};
  /// Buffer for the compressed audio that buffered streams send ahead (at 256 kbit/s, 32 KB per second). The audio
  /// is decoded into the jitter buffer (buffer_ms) as that has room.
  uint32_t buffered_audio_bytes{128 * 1024};
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
  uint32_t longest_gap_ms;  // Longest time between two poll() calls in a session, e.g. while the thread was blocked
  bool synchronized;        // Playing on the sender's timeline
};

/// AirPlay 1 (RAOP) and, optionally, AirPlay 2 audio receiver without any I/O of its own: feed it RTSP
/// connections, UDP packets and the time, and it writes PCM to an AudioSink.
///
/// Threading: everything except the methods marked thread-safe must be called from one thread.
class Receiver {
 public:
  /// An AirPlay 2 sender's session (RTSP, event and buffered audio connections) and its second session (RTSP and
  /// event), or a second sender taking over, plus one for short requests such as GET /info
  static constexpr uint8_t MAX_CONNECTIONS = 6;
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
  /// @brief Whether a connection belongs to the playing sender: its RTSP, event or buffered audio connection.
  bool is_session_connection(uint8_t connection) const;
  bool needs_fast_polling() const { return this->audio_active_ || this->artwork_paused_ != NO_CONNECTION; }
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
  /// @brief Moves the AirPlay 2 sender's volume slider, e.g. after the volume was changed on the device.
  /// @param volume 0 to 1, as Listener::on_volume() reports it.
  /// @return false if the sender cannot take it this way; AirPlay 1 senders take DACP commands instead (dacp.h).
  bool request_sender_volume(float volume);
  /// @brief Sends a playback command to the AirPlay 2 sender, as a HomePod does for its buttons.
  /// @return false if the sender cannot take it this way; AirPlay 1 senders take DACP commands instead (dacp.h).
  bool request_sender_command(SenderCommand command);

  // ===== mDNS =====
  /// @brief Instance name of the _raop._tcp service: "<MAC>@<name>".
  size_t service_instance_name(char *buffer, size_t size) const;
  /// @brief TXT records of the _raop._tcp service.
  const TxtRecord *txt_records(size_t *count) const;
  /// @brief Whether AirPlay 2 is offered: config.airplay2, with a random source and without a password.
  bool airplay2_enabled() const { return this->airplay2_; }
  /// @brief TXT records of the _airplay._tcp service, which AirPlay 2 senders look for; none if AirPlay 2 is not
  /// offered. Its instance name is config.name and its port the RTSP port.
  const TxtRecord *airplay_txt_records(size_t *count) const;

 protected:
  enum class Codec : uint8_t {
    NONE,
    ALAC,
    PCM,
    AAC,  // AirPlay 2 buffered audio
  };

  struct Connection {
    bool open{false};
    size_t rx_length{0};
    size_t discard_remaining{0};
    Endpoint peer{};
    Endpoint local{};
    char *buffer{nullptr};
    bool authenticated{false};
    char nonce[17]{};  // Of the password challenge
    // AirPlay 2: after pair-setup all data is encrypted in frames
    bool encrypted{false};
    bool encrypt_after_response{false};
    bool event_channel{false};  // A sender's event connection; nothing to read on it
    bool audio_data{false};     // A sender's buffered audio connection
    // Another AirPlay 2 session of the sender that is playing: it takes over once it sets up a stream
    bool session_pending{false};
    bool pending_recording{false};
    uint16_t pending_timing_port{0};
    uint8_t read_key[CHACHA_KEY_SIZE];
    uint8_t write_key[CHACHA_KEY_SIZE];
    uint8_t event_key[CHACHA_KEY_SIZE];  // From pair-setup, for writing on the event connection that follows
    uint8_t pair_secret[SHA512_SIZE];    // Pair-setup's shared secret, from which stream keys may be derived
    uint64_t read_counter{0};
    uint64_t write_counter{0};
    uint8_t *frame{nullptr};  // An incoming encrypted frame, until it is complete
    size_t frame_length{0};
  };

  /// A response to an AirPlay 2 request
  struct Response {
    int status{200};
    const char *status_text{"OK"};
    char *headers{nullptr};  // Extra headers
    size_t headers_size{0};
    const char *content_type{nullptr};
    const uint8_t *body{nullptr};
    size_t body_length{0};
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
  static constexpr size_t MAX_TXT_RECORDS = 20;
  static constexpr size_t MAX_AIRPLAY_TXT_RECORDS = 15;
  /// An encrypted frame: length, up to 1024 bytes and the tag
  static constexpr size_t HAP_FRAME_DATA_SIZE = 1024;
  static constexpr size_t HAP_FRAME_SIZE = 2 + HAP_FRAME_DATA_SIZE + POLY1305_TAG_SIZE;
  static constexpr size_t AIRPLAY2_BODY_SIZE = 1024;
  /// Version announced to AirPlay 2 senders
  static constexpr char AIRPLAY2_SOURCE_VERSION[] = "366.0";

  void *allocate_(size_t size) const;
  void free_(void *pointer) const;

  // RTSP
  void process_requests_(uint8_t connection, int64_t now_us);
  /// @return false if the connection must be closed
  bool handle_request_(uint8_t connection, char *request, size_t header_length, char *body, size_t body_length,
                       int64_t now_us);
  bool handle_announce_(const char *body, size_t body_length);
  bool handle_setup_(uint8_t connection, const char *transport, char *response_headers, size_t size);
  void handle_set_parameter_(const char *content_type, const char *body, size_t body_length, uint32_t now_ms);
  /// Starts receiving cover art. `body` is null if the image is too large to buffer and arrives in pieces.
  void begin_artwork_(const char *content_type, const char *body, size_t body_length);
  void end_artwork_(bool complete);
  void resume_artwork_();
  bool add_apple_response_(uint8_t connection, const char *challenge, char *output, size_t size);
  /// @return true if the request carries the right password for the connection's challenge
  bool check_authorization_(Connection &c, const char *method, const char *request, size_t header_length);
  void handle_progress_(const char *value, uint32_t now_ms);
  void update_remote_target_(const char *dacp_id, const char *active_remote, uint32_t address);
  void close_connection_(uint8_t connection);
  /// Sends on a connection, encrypted once it is
  bool send_(uint8_t connection, const uint8_t *data, size_t length);
  /// Takes over the session for a sender
  void take_session_(uint8_t connection, const char *request, size_t header_length);
  /// Hands the session to the sender's other session on `connection`, keeping the UDP sockets
  void adopt_session_(uint8_t connection, const char *request, size_t header_length);
  /// When the session owner goes: hands the session to a waiting session of the same sender
  /// @return false if there is none
  bool promote_pending_session_(uint8_t leaving);
  void read_sender_version_(const char *request, size_t header_length);
  /// Opens the UDP sockets for a session
  bool open_udp_(uint8_t connection, uint32_t control_port, uint32_t timing_port, uint16_t *ports);

  // AirPlay 2 (airplay_receiver_ap2.cpp)
  void init_airplay2_();
  /// @return true if the request is an AirPlay 2 request and `response` is filled in
  bool handle_airplay2_request_(uint8_t connection, const char *method, const char *request, size_t header_length,
                                const char *body, size_t body_length, Response &response, int64_t now_us);
  void handle_pair_setup_(uint8_t connection, const uint8_t *body, size_t length, Response &response);
  void handle_airplay2_setup_(uint8_t connection, const char *request, size_t header_length, const uint8_t *body,
                              size_t length, Response &response, int64_t now_us);
  void build_info_(Response &response);
  /// Decrypts an encrypted connection's frames and passes the RTSP data on
  void receive_encrypted_(uint8_t connection, const uint8_t *data, size_t length, int64_t now_us);
  void pass_plain_(uint8_t connection, const uint8_t *data, size_t length, int64_t now_us);
  /// @return the length of the audio in `output`, or 0 if the packet is not authentic
  size_t decrypt_airplay2_audio_(const uint8_t *header, const uint8_t *payload, size_t length, uint8_t *output);
  // Buffered audio (airplay_receiver_ap2.cpp)
  void receive_buffered_audio_(uint8_t connection, const uint8_t *data, size_t length, uint32_t now_ms);
  /// Decodes queued audio into the jitter buffer while it has room
  void decode_buffered_audio_(uint32_t now_ms);
  void handle_rate_anchor_(const uint8_t *body, size_t length);
  void handle_flush_buffered_(const uint8_t *body, size_t length);
  void stop_buffered_audio_();
  void update_event_channel_ready_();
  void send_sender_requests_();
  void add_key_candidate_(const uint8_t *key, const char *name);
  void prepare_key_candidates_(const Connection &c);
  /// Sends a media remote command on the playing sender's event connection; the volume only if not below 0
  void send_media_remote_command_(const char *value, float volume);
  /// A new stream has a timeline of its own: the previous stream's anchor and latency do not apply to it
  void forget_timeline_() {
    this->anchor_valid_ = false;
    this->sender_latency_frames_ = 0;
  }
  void update_receive_pause_();
  /// Takes a packet that did not decrypt with the zero key as unencrypted audio from now on
  size_t detect_plain_audio_(const uint8_t *header, const uint8_t *payload, size_t length, uint8_t *output);

  /// How the audio of an AirPlay 2 stream is encrypted
  enum class AudioEncryption : uint8_t {
    KEY,      // With audio_key_
    UNKNOWN,  // No key given: one of key_candidates_ or none, told by the first packets
    NONE,
    FAILED,  // No key fits: the audio cannot be decrypted
  };
  /// Keys tried for a realtime stream that came without one
  static constexpr size_t MAX_KEY_CANDIDATES = 8;
  struct KeyCandidate {
    uint8_t key[CHACHA_KEY_SIZE];
    const char *name;
  };
  void end_session_();
  void set_session_state_(SessionState state);
  void close_udp_();

  // Audio
  bool start_audio_(int64_t now_us);
  void stop_audio_();
  void flush_(bool have_seq, uint16_t seq);
  void reset_playback_();
  /// @param header The packet's RTP header
  void handle_audio_packet_(const uint8_t *header, const uint8_t *payload, size_t length, uint32_t now_ms);
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
  TxtRecord txt_records_[MAX_TXT_RECORDS];
  size_t txt_record_count_{0};
  char md_[8]{};  // Value of the "md" TXT record
  uint32_t nonce_counter_{0};
  uint32_t metadata_hash_{0};  // Of the last track details passed on
  // Kept across sessions: iOS starts a new session on a track change
  uint32_t track_hash_{0};             // Of the details of the current track
  uint32_t last_progress_frames_{0};   // Length of the track of the last progress
  uint32_t stale_progress_frames_{0};  // Length of the previous track until the new track's progress arrives
  uint32_t last_progress_ms_{0};       // When the last progress arrived

  // AirPlay 2
  bool airplay2_{false};
  TxtRecord airplay_txt_records_[MAX_AIRPLAY_TXT_RECORDS];
  size_t airplay_txt_record_count_{0};
  char device_id_[18]{};  // MAC as "AA:BB:CC:DD:EE:FF"
  char features_[24]{};
  uint64_t airplay2_features_{0};
  char public_key_hex_[2 * CHACHA_KEY_SIZE + 1]{};
  char pairing_id_[37]{};
  char public_session_id_[37]{};  // "psi"
  char features_base64_[16]{};    // "fex": the feature bits as little endian bytes
  uint8_t public_key_[CHACHA_KEY_SIZE]{};
  SrpServer *srp_{nullptr};
  uint8_t pairing_connection_{0xff};   // Connection between pair-setup M1 and M3
  uint8_t *frames_{nullptr};           // Per connection: an incoming encrypted frame
  uint8_t *send_buffer_{nullptr};      // An outgoing encrypted frame
  uint8_t *body_buffer_{nullptr};      // Body of an AirPlay 2 response
  bool airplay2_audio_{false};         // The session's audio is encrypted with audio_key_
  bool event_channel_pending_{false};  // A sender is about to open its event connection, from this address:
  uint32_t event_channel_address_{0};
  uint8_t event_channel_source_{NO_CONNECTION};  // The connection that set up the session, with the event key
  uint32_t event_cseq_{0};
  bool airplay2_recording_{false};  // RECORD came; streams set up afterwards start playing at once  // The session
                                    // owner is about to open its event connection
  uint8_t audio_key_[CHACHA_KEY_SIZE]{};
  AudioEncryption audio_encryption_{AudioEncryption::KEY};
  // Buffered audio
  PacketQueue buffered_queue_;
  uint8_t *buffered_storage_{nullptr};
  int16_t *aac_samples_{nullptr};  // One decoded AAC frame
  bool buffered_stream_{false};    // The session's audio stream is buffered (AAC over TCP)
  bool buffered_playing_{false};   // Rate 1 from SETRATEANCHORTIME
  bool data_channel_pending_{false};
  bool receive_paused_{false};
  uint8_t data_connection_{0xff};
  uint16_t buffered_next_seq_{0};  // Sequence number of the next piece of decoded audio in the jitter buffer
  uint32_t flush_until_seq_{0};    // Packets before this one are dropped (24-bit sequence numbers)
  bool flush_active_{false};
  uint32_t buffered_dropped_{0};
  uint8_t session_stream_key_[CHACHA_KEY_SIZE]{};  // The last key a stream setup of the session carried
  // The last key any stream setup carried, and the sender's address; kept across sessions
  uint8_t remembered_stream_key_[CHACHA_KEY_SIZE]{};
  uint32_t remembered_key_address_{0};
  KeyCandidate key_candidates_[MAX_KEY_CANDIDATES]{};
  uint8_t key_candidate_count_{0};
  uint8_t undecryptable_packets_{0};
  uint8_t plain_packets_{0};
  bool have_session_stream_key_{false};

  // Cross-thread requests and reports
  std::atomic<uint32_t> frames_played_{0};
  std::atomic<uint32_t> played_timestamp_{0};  // Low 32 bits of the time in microseconds; 0 = none
  std::atomic<bool> output_restart_requested_{false};
  std::atomic<bool> disconnect_requested_{false};
  std::atomic<bool> event_channel_ready_{false};     // The playing sender has an event connection
  std::atomic<float> sender_volume_request_{-1.0f};  // For the sender's slider; below 0 when none
  std::atomic<uint8_t> sender_command_requests_{0};  // Bit per SenderCommand

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
  uint16_t udp_ports_[NUM_UDP_CHANNELS]{};
  Endpoint client_control_{};
  Endpoint client_timing_{};
  uint16_t initial_seq_{0};
  bool have_initial_seq_{false};
  uint16_t sender_version_{0};             // From "User-Agent: AirPlay/<version>"
  bool artwork_streaming_{false};          // Passing the skipped body of the session owner's request to the listener
  uint8_t artwork_paused_{NO_CONNECTION};  // Connection not read while the listener has no room for cover art

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
  uint32_t last_poll_ms_{0};
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
