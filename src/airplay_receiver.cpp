#include "airplay_receiver.h"

#include "airplay_log.h"
#include "airplay_srp.h"
#include "airplay_util.h"

#if defined(ESP_PLATFORM)
#include <esp_memory_utils.h>
#endif

#include <algorithm>
#include <iterator>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <utility>

namespace airplay {

// ===== RTSP =====
static constexpr size_t RTSP_MAX_BODY_SIZE = 1024 * 1024;
static constexpr size_t RESPONSE_SIZE = 1024;
static constexpr size_t EXTRA_HEADERS_SIZE = 512;
static constexpr size_t RESPONSE_BODY_SIZE = 64;
/// A progress this recent when the details of a new track arrive belongs to that track
static constexpr uint32_t FRESH_PROGRESS_MS = 2000;

/// AirPlay volume is -30 (quiet) to 0 (full) dB, with -144 meaning mute
static constexpr float AIRPLAY_VOLUME_MIN = -30.0f;
static constexpr float AIRPLAY_VOLUME_MUTE_LIMIT = -100.0f;

static constexpr char AIRPLAY2_PUBLIC_METHODS[] =
    "Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER, POST, GET\r\n";
static constexpr char PUBLIC_METHODS[] =
    "Public: ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER\r\n";

// ===== RTP =====
static constexpr size_t RTP_HEADER_SIZE = 12;
static constexpr size_t RETRANSMIT_HEADER_SIZE = 4;
static constexpr size_t TIMING_PACKET_SIZE = 32;
static constexpr size_t SYNC_PACKET_SIZE = 20;
static constexpr uint32_t MAX_CHUNKS_PER_STEP = 8;
/// Packets handled per poll at most, also those that are only dropped
static constexpr uint32_t MAX_STEPS_PER_POLL = 256;

// RTP payload types (second header byte without the marker bit)
static constexpr uint8_t PAYLOAD_TIMING_REQUEST = 0x52;
static constexpr uint8_t PAYLOAD_TIMING_REPLY = 0x53;
static constexpr uint8_t PAYLOAD_SYNC = 0x54;
/// Sync packet of a sender that times its audio with PTP: a frame, its PTP time and the clock
static constexpr uint8_t PAYLOAD_PTP_SYNC = 0x57;
static constexpr size_t PTP_SYNC_PACKET_SIZE = 28;
static constexpr uint8_t PAYLOAD_RESEND_REQUEST = 0x55;
static constexpr uint8_t PAYLOAD_RETRANSMIT = 0x56;
static constexpr uint8_t PAYLOAD_AUDIO = 0x60;

// Clock exchange with the sender: a quick burst until the clock locks, then a slow refresh
static constexpr uint32_t TIMING_BURST_COUNT = 3;
static constexpr uint32_t TIMING_BURST_INTERVAL_MS = 100;
static constexpr uint32_t TIMING_INTERVAL_MS = 3000;
static constexpr uint32_t TIMING_LOCK_SAMPLES = 2;
static constexpr int64_t TIMING_MAX_ROUND_TRIP_NS = 500000000;
/// Added to the latency of the sync packets by current senders (see shairport-sync rtp.c)
static constexpr uint32_t FIXED_LATENCY_OFFSET_FRAMES = 11025;
static constexpr uint32_t MAX_SENDER_LATENCY_FRAMES = 5 * SAMPLE_RATE;

// Retransmission: wait briefly for reordered packets, then ask again every 150 ms until the packet is due
static constexpr uint32_t RESEND_FIRST_DELAY_MS = 20;
static constexpr uint32_t RESEND_RETRY_INTERVAL_MS = 150;
static constexpr uint32_t RESEND_SCAN_INTERVAL_MS = 50;
static constexpr uint32_t MAX_RESEND_RANGES = 4;

// Synchronized playback
/// Audio is handed to the sink at most this far ahead, so that a pause or seek takes effect quickly. Enough to ride
/// out the driving thread being held up for a while, e.g. 200 ms on an ESP32 while its display redraws.
/// A packet this far off its due time means that the sender's timeline does not fit its clock at all
static constexpr int64_t MAX_TIMELINE_ERROR_US = 10000000;
/// Silence to line up the first packet is only written once it is due within this window
static constexpr int64_t START_WINDOW_US = 100000;
/// An output that has not played anything yet may take a while to start (an ESPHome speaker starts its task first,
/// and its main loop may be busy). It is started with a little silence this long before the first packet is due,
/// and the audio is lined up once it reports what it played.
static constexpr int64_t OUTPUT_START_LEAD_US = 500000;
/// An output whose last report is this much older than its queued audio lasts has run dry
static constexpr int64_t DRY_MARGIN_US = 20000;
/// More than an output plays before it reports (its DMA buffers), and well within the lead
static constexpr uint32_t OUTPUT_START_FRAMES = SAMPLE_RATE / 10;
/// Packets later than this are dropped; packets earlier than this are lined up with silence
static constexpr int64_t EARLY_LATE_THRESHOLD_US = 50000;
/// A missing packet is replaced by silence once it is due within this time
static constexpr int64_t CONCEAL_MARGIN_US = 10000;
/// Extra buffer needed on top of the sender's latency for synchronized playback (250 ms)
static constexpr uint32_t SYNC_MARGIN_FRAMES = SAMPLE_RATE / 4;
/// Timestamps of playback reports older than this are not used
static constexpr int64_t REPORT_MAX_AGE_US = 200000;
/// The output must report played audio within this time, or playback cannot be synchronized
static constexpr uint32_t PLAYED_REPORT_TIMEOUT_MS = 1000;

// Position servo for synchronized playback (after airplay-esp32 audio_timing.c): trims single samples
// at the quietest point of a packet when the filtered timing error leaves a dead band
static constexpr int32_t SERVO_FILTER_DIV = 16;
static constexpr int32_t SERVO_INNOVATION_CLAMP_US = 1500;
static constexpr int32_t SERVO_ENGAGE_US = 2000;
static constexpr int32_t SERVO_DISENGAGE_US = 500;
static constexpr uint32_t SERVO_TRIM_INTERVAL = 4;
static constexpr int32_t SERVO_FAST_US = 5000;
/// Above SERVO_LARGE_US, one frame per SERVO_FAST_FRAME_US of error is dropped or repeated in each packet, up to
/// MAX_TRIM_FRAMES: an error of 20 ms, e.g. from the output's latency when playback starts, is gone in a few
/// seconds instead of half a minute
static constexpr int32_t SERVO_LARGE_US = 10000;
static constexpr int32_t SERVO_FAST_FRAME_US = 2500;
static constexpr int32_t MAX_TRIM_FRAMES = 8;

// Unsynchronized playback: the buffer level is kept on target instead
/// Buffer level for unsynchronized playback, at most 500 ms
static constexpr uint32_t MAX_FILL_TARGET_FRAMES = SAMPLE_RATE / 2;
/// Spare slots for packets that arrive early or out of order
static constexpr uint32_t SPARE_SLOTS = 8;
/// A missing packet is replaced by silence once the sink has less than this queued (60 ms). The sink is fed
/// the whole buffer ahead, so that there is time for retransmissions.
static constexpr uint32_t CONCEAL_THRESHOLD_FRAMES = SAMPLE_RATE * 60 / 1000;
/// Audio beyond this much above the target buffer level is dropped in whole packets (100 ms)
static constexpr uint32_t OVERFILL_FRAMES = SAMPLE_RATE / 10;
/// Dead band of the buffer level control (20 ms) and its smoothing, as a right shift (about 2 s)
static constexpr int32_t FILL_DEADBAND_FRAMES = SAMPLE_RATE / 50;
static constexpr int32_t FILL_SMOOTHING_SHIFT = 8;

/// Time for the output to finish its reset after request_output_restart()
static constexpr uint32_t OUTPUT_RESTART_SETTLE_MS = 20;
/// The session shows as paused when a playing sender sends no audio for this long
static constexpr uint32_t SENDER_IDLE_MS = 3000;
/// Payload of an audio packet that holds only silence: compressed ALAC silence of a packet is 32 bytes, and even
/// the quietest audio takes a few hundred
static constexpr size_t SILENT_PACKET_MAX_BYTES = 64;
/// The buffer for buffered audio holds at least this much, so that pausing the connection leaves room
static constexpr size_t MIN_BUFFERED_AUDIO_BYTES = 32 * 1024;
/// Statistics are logged at debug level this often during playback
static constexpr uint32_t STATS_LOG_INTERVAL_MS = 10000;

/// Seconds between 1900 (NTP epoch) and 1970
static constexpr int64_t NTP_UNIX_OFFSET_NS = 2208988800LL * 1000000000LL;

// ===== Helpers =====

static inline uint16_t read_be16(const uint8_t *data) { return static_cast<uint16_t>((data[0] << 8) | data[1]); }

static inline uint32_t read_be32(const uint8_t *data) {
  return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) | data[3];
}

static inline uint32_t to_ms(int64_t now_us) { return static_cast<uint32_t>(now_us / 1000); }

/// Some timestamps use 0 for "not set"
static inline uint32_t nonzero_ms(uint32_t ms) { return ms == 0 ? 1 : ms; }
/// Adds a measured duration; nothing is measured without ReceiverConfig::clock_us, then both ends are 0
static inline void add_us(std::atomic<uint32_t> &total, int64_t took_us) {
  total.fetch_add(static_cast<uint32_t>(took_us), std::memory_order_relaxed);
}

/// Local time on the NTP time scale, in nanoseconds. Only offsets matter, so the caller's clock is used.
static inline int64_t local_ntp_ns(int64_t now_us) { return now_us * 1000LL + NTP_UNIX_OFFSET_NS; }

static int64_t read_ntp_ns(const uint8_t *data) {
  const uint64_t seconds = read_be32(data);
  const uint64_t fraction = read_be32(data + 4);
  return static_cast<int64_t>(seconds * 1000000000ULL + ((fraction * 1000000000ULL) >> 32));
}

static void write_ntp_ns(uint8_t *out, int64_t ns) {
  const auto value = static_cast<uint64_t>(ns);
  const auto seconds = static_cast<uint32_t>(value / 1000000000ULL);
  const auto fraction = static_cast<uint32_t>(((value % 1000000000ULL) << 32) / 1000000000ULL);
  for (int i = 0; i < 4; i++) {
    out[i] = static_cast<uint8_t>(seconds >> (24 - 8 * i));
    out[4 + i] = static_cast<uint8_t>(fraction >> (24 - 8 * i));
  }
}

static inline int64_t frames_to_us(int64_t frames) { return frames * 1000000 / SAMPLE_RATE; }

static uint32_t fnv1a(const void *data, size_t length, uint32_t hash = 2166136261u) {
  const auto *bytes = static_cast<const uint8_t *>(data);
  for (size_t i = 0; i < length; i++)
    hash = (hash ^ bytes[i]) * 16777619u;
  return hash;
}

/// Finds "key=" in a parameter list such as "control_port=6001;timing_port=6002" and parses its number.
static bool get_numeric_parameter(const char *text, const char *key, uint32_t *value) {
  const size_t key_length = std::strlen(key);
  for (const char *p = text; (p = std::strstr(p, key)) != nullptr; p += key_length) {
    if ((p == text || p[-1] == ';' || p[-1] == ' ') && p[key_length] == '=') {
      *value = static_cast<uint32_t>(std::strtoul(p + key_length + 1, nullptr, 10));
      return true;
    }
  }
  return false;
}

/// Finds `needle` within [begin, end)
static bool contains(const char *begin, const char *end, const char *needle) {
  const size_t needle_length = std::strlen(needle);
  for (const char *p = begin; p + needle_length <= end; p++) {
    if (std::memcmp(p, needle, needle_length) == 0)
      return true;
  }
  return false;
}

// ===== Receiver =====

Receiver::Receiver(const ReceiverConfig &config, Crypto &crypto, Transport &transport, AudioSink &sink,
                   Listener *listener)
    : config_(config), crypto_(crypto), transport_(transport), sink_(sink), listener_(listener) {
  // The set shairport-sync advertises, which current Apple senders accept. cn: codecs (0 = PCM, 1 = ALAC),
  // et: encryption (0 = none, 1 = RSA), vn: protocol version (65537 = 1.1), sf: status flags
  static const TxtRecord RECORDS[] = {
      {"txtvers", "1"}, {"ch", "2"},     {"cn", "0,1"},   {"et", "0,1"},      {"ek", "1"},
      {"sv", "false"},  {"da", "true"},  {"sr", "44100"}, {"ss", "16"},       {"tp", "UDP"},
      {"vn", "65537"},  {"vs", "366.0"}, {"sf", "0x4"},   {"fv", "76400.10"},
  };
  static_assert(sizeof(RECORDS) / sizeof(RECORDS[0]) + 3 <= MAX_TXT_RECORDS, "No room for pw, am and md");
  for (const TxtRecord &record : RECORDS) {
    // The status flags change with HomeKit access control
    this->txt_records_[this->txt_record_count_++] =
        std::strcmp(record.key, "sf") == 0 ? TxtRecord{record.key, this->status_flags_} : record;
  }
  this->txt_records_[this->txt_record_count_++] = TxtRecord{"pw", config.password != nullptr ? "true" : "false"};
  this->txt_records_[this->txt_record_count_++] = TxtRecord{"am", config.model};
  // md: which details the receiver takes (0 = text, 1 = cover art, 2 = progress)
  size_t md_length = 0;
  for (const auto &[enabled, digit] :
       {std::pair{config.metadata, '0'}, std::pair{config.artwork, '1'}, std::pair{config.progress, '2'}}) {
    if (!enabled)
      continue;
    if (md_length > 0)
      this->md_[md_length++] = ',';
    this->md_[md_length++] = digit;
  }
  if (md_length > 0)
    this->txt_records_[this->txt_record_count_++] = TxtRecord{"md", this->md_};

  this->airplay2_ = config.airplay2 && config.random != nullptr && config.password == nullptr;
  if (this->airplay2_) {
    this->init_airplay2_();
    // AirPlay 2 senders also look at the features of the RAOP service
    this->txt_records_[this->txt_record_count_++] = TxtRecord{"ft", this->features_};
    this->txt_records_[this->txt_record_count_++] = TxtRecord{"pk", this->public_key_hex_};
    this->txt_records_[this->txt_record_count_++] = TxtRecord{"vv", "2"};
  }
}

Receiver::~Receiver() {
  if (this->srp_ != nullptr) {
    this->srp_->~SrpServer();
    this->free_(this->srp_);
  }
  this->free_(this->frames_);
  this->free_(this->send_buffer_);
  this->free_(this->buffered_storage_);
  this->free_(this->aac_samples_);
  this->free_(this->body_buffer_);
  this->free_(this->slots_);
  std::free(this->benchmark_input_);
  std::free(this->benchmark_output_);
  std::free(this->packet_buffer_);
  std::free(this->output_buffer_);
  this->free_(this->rtsp_buffers_);
}

void *Receiver::allocate_(size_t size) const {
  return this->config_.allocate != nullptr ? this->config_.allocate(size) : std::malloc(size);
}

void Receiver::free_(void *pointer) const {
  if (pointer == nullptr)
    return;
  if (this->config_.deallocate != nullptr) {
    this->config_.deallocate(pointer);
  } else {
    std::free(pointer);
  }
}

bool Receiver::begin() {
  if (this->slots_ != nullptr)
    return true;
  if (!this->decoder_.init(FRAMES_PER_PACKET)) {
    AIRPLAY_LOGE("Failed to allocate the decoder");
    return false;
  }
  if (this->config_.clock_us != nullptr) {
    this->benchmark_input_ = static_cast<uint8_t *>(std::malloc(PACKET_BUFFER_SIZE));
    this->benchmark_output_ = static_cast<int16_t *>(std::malloc(FRAMES_PER_PACKET * BYTES_PER_FRAME));
  }

  // Synchronized playback holds the sender's whole latency (about 2.25 s) in this buffer. Unsynchronized
  // playback fills three quarters of it, up to 500 ms, before it starts.
  const uint32_t buffer_frames = this->config_.buffer_ms * SAMPLE_RATE / 1000;
  this->slot_count_ = (buffer_frames + FRAMES_PER_PACKET - 1) / FRAMES_PER_PACKET + SPARE_SLOTS;
  this->fill_target_frames_ = std::min(MAX_FILL_TARGET_FRAMES, buffer_frames * 3 / 4);

  this->slots_ = static_cast<PacketSlot *>(this->allocate_(this->slot_count_ * sizeof(PacketSlot)));
  // Small and touched for every packet, so with malloc, which keeps them in internal RAM on the ESP32: under load,
  // decrypting and copying took about twice as long in external RAM
  this->packet_buffer_ = static_cast<uint8_t *>(std::malloc(PACKET_BUFFER_SIZE));
  // Room to repeat frames that correct clock drift
  this->output_buffer_ =
      static_cast<int16_t *>(std::malloc((FRAMES_PER_PACKET + MAX_TRIM_FRAMES) * NUM_CHANNELS * sizeof(int16_t)));
  // One extra byte per connection so that headers and body can be null terminated in place. The extra headers of a
  // response follow; kept off the stack, because pairing needs much of it.
  this->rtsp_buffers_ =
      static_cast<char *>(this->allocate_(MAX_CONNECTIONS * (RTSP_BUFFER_SIZE + 1) + EXTRA_HEADERS_SIZE));
  if (this->slots_ == nullptr || this->packet_buffer_ == nullptr || this->output_buffer_ == nullptr ||
      this->rtsp_buffers_ == nullptr) {
    AIRPLAY_LOGE("Failed to allocate buffers");
    this->free_(this->slots_);
    std::free(this->packet_buffer_);
    std::free(this->output_buffer_);
    this->free_(this->rtsp_buffers_);
    this->slots_ = nullptr;
    this->packet_buffer_ = nullptr;
    this->output_buffer_ = nullptr;
    this->rtsp_buffers_ = nullptr;
    return false;
  }
  this->extra_headers_ = this->rtsp_buffers_ + MAX_CONNECTIONS * (RTSP_BUFFER_SIZE + 1);
  for (uint32_t i = 0; i < this->slot_count_; i++) {
    this->slots_[i].valid = false;
    this->slots_[i].missing_since_ms = 0;
  }
  for (size_t i = 0; i < MAX_CONNECTIONS; i++)
    this->connections_[i].buffer = &this->rtsp_buffers_[i * (RTSP_BUFFER_SIZE + 1)];

  if (this->airplay2_) {
    this->frames_ = static_cast<uint8_t *>(this->allocate_(MAX_CONNECTIONS * HAP_FRAME_SIZE));
    this->send_buffer_ = static_cast<uint8_t *>(this->allocate_(HAP_FRAME_SIZE));
    this->body_buffer_ = static_cast<uint8_t *>(this->allocate_(AIRPLAY2_BODY_SIZE));
    void *srp = this->allocate_(sizeof(SrpServer));
    if (srp != nullptr) {
      this->srp_ = new (srp) SrpServer();
      this->srp_->set_crypto(&this->crypto_);
    }
    if (this->frames_ == nullptr || this->send_buffer_ == nullptr || this->body_buffer_ == nullptr ||
        this->srp_ == nullptr) {
      AIRPLAY_LOGW("Failed to allocate the AirPlay 2 buffers; only AirPlay 1 is offered");
      this->airplay2_ = false;
    } else {
      for (size_t i = 0; i < MAX_CONNECTIONS; i++)
        this->connections_[i].frame = &this->frames_[i * HAP_FRAME_SIZE];
    }
  }
  // Buffered audio: AAC from iOS (with an AAC decoder), ALAC from Music Assistant when PTP is offered
  if (this->airplay2_) {
    const size_t bytes = std::max<size_t>(this->config_.buffered_audio_bytes, MIN_BUFFERED_AUDIO_BYTES);
    this->buffered_storage_ = static_cast<uint8_t *>(this->allocate_(bytes));
    this->aac_samples_ =
        static_cast<int16_t *>(this->allocate_(AAC_FRAMES_PER_PACKET * NUM_CHANNELS * sizeof(int16_t)));
    if (this->buffered_storage_ == nullptr || this->aac_samples_ == nullptr) {
      AIRPLAY_LOGW("Failed to allocate the buffer for buffered audio; it is not offered");
      this->free_(this->buffered_storage_);
      this->free_(this->aac_samples_);
      this->buffered_storage_ = nullptr;
      this->aac_samples_ = nullptr;
    } else {
      this->buffered_queue_.init(this->buffered_storage_, bytes);
    }
  }
  if (this->airplay2_ && this->config_.ptp) {
    this->ptp_open_ = this->transport_.open_ptp();
    this->ptp_clocks_.set_identity(this->config_.mac);
    if (!this->ptp_open_)
      AIRPLAY_LOGW("PTP is not available; senders that need it (macOS) are turned down");
  }
  AIRPLAY_LOGD("Buffer of %" PRIu32 " packets", this->slot_count_);
  return true;
}

void Receiver::ptp_packet(bool general, const uint8_t *data, size_t length, uint32_t from_address, int64_t now_us) {
  if (this->ptp_open_)
    this->ptp_clocks_.handle(general, data, length, from_address, now_us);
}

size_t Receiver::service_instance_name(char *buffer, size_t size) const {
  const uint8_t *mac = this->config_.mac;
  const int length = std::snprintf(buffer, size, "%02X%02X%02X%02X%02X%02X@%s", mac[0], mac[1], mac[2], mac[3], mac[4],
                                   mac[5], this->config_.name);
  return length > 0 && static_cast<size_t>(length) < size ? static_cast<size_t>(length) : 0;
}

const TxtRecord *Receiver::txt_records(size_t *count) const {
  *count = this->txt_record_count_;
  return this->txt_records_;
}

void Receiver::notify_played(uint32_t frames, int64_t timestamp_us) {
  // 32 bits avoid 64-bit atomics, which some 32-bit targets lack; the lowest bit marks the value as set
  this->played_timestamp_.store(static_cast<uint32_t>(timestamp_us) | 1u, std::memory_order_relaxed);
  this->frames_played_.fetch_add(frames, std::memory_order_relaxed);
}

// ===== Connections =====

void Receiver::connection_opened(uint8_t connection, const Endpoint &peer, const Endpoint &local) {
  if (connection >= MAX_CONNECTIONS || this->rtsp_buffers_ == nullptr)
    return;
  Connection &c = this->connections_[connection];
  if (c.open)
    this->connection_closed(connection);
  c.open = true;
  c.rx_length = 0;
  c.discard_remaining = 0;
  c.peer = peer;
  c.local = local;
  c.authenticated = false;
  c.encrypted = false;
  c.encrypt_after_response = false;
  c.event_channel = false;
  c.event_requests = 0;
  c.event_answers = 0;
  c.event_first_request_ms = 0;
  c.event_silent = false;
  c.audio_data = false;
  c.remote_control = false;
  c.homekit_controller = false;
  c.verify_pending = false;
  std::fill(std::begin(c.relay_streams), std::end(c.relay_streams), 0);
  c.relay_latest = 0;
  c.relayed_to_sender = 0;
  c.relayed_to_controller = 0;
  c.relay_not_sent = 0;
  c.relay_target = NO_CONNECTION;
  c.session_pending = false;
  c.pending_recording = false;
  c.sender_name[0] = '\0';
  c.group_id[0] = '\0';
  c.group_leader = false;
  c.frame_length = 0;
  // An AirPlay 2 sender connects its event connection right after setting up its session
  if (this->event_channel_pending_ && this->event_channel_address_ == peer.address) {
    this->event_channel_pending_ = false;
    c.event_channel = true;
    // Nothing is read on it, but the receiver may send requests to the sender, encrypted with pair-setup's key
    const uint8_t source = this->event_channel_source_;
    if (source < MAX_CONNECTIONS && this->connections_[source].encrypted) {
      std::memcpy(c.write_key, this->connections_[source].event_key, sizeof(c.write_key));
      std::memcpy(c.read_key, this->connections_[source].event_read_key, sizeof(c.read_key));
      c.write_counter = 0;
      c.read_counter = 0;
      c.encrypted = true;
    }
    AIRPLAY_LOGD("Event connection");
  } else if (this->data_channel_pending_ && this->session_owner_ != NO_CONNECTION &&
             this->connections_[this->session_owner_].peer.address == peer.address) {
    // The same for the buffered audio connection after the stream setup
    this->data_channel_pending_ = false;
    c.audio_data = true;
    this->data_connection_ = connection;
    this->receive_paused_ = false;
    AIRPLAY_LOGD("Buffered audio connection");
  }
  if (this->config_.password != nullptr) {
    // A new nonce for every connection, so that an answer cannot be replayed on another one
    char seed[64];
    const int length = std::snprintf(seed, sizeof(seed), "%" PRIu32 ":%" PRIu32 ":%u:%p", this->nonce_counter_++,
                                     peer.address, peer.port, static_cast<void *>(this));
    char hex[MD5_SIZE * 2 + 1];
    md5_hex(seed, length > 0 ? static_cast<size_t>(length) : 0, hex);
    std::memcpy(c.nonce, hex, sizeof(c.nonce) - 1);
    c.nonce[sizeof(c.nonce) - 1] = '\0';
  }
  const auto *ip = reinterpret_cast<const uint8_t *>(&peer.address);
  AIRPLAY_LOGD("Connection from %u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

void Receiver::connection_closed(uint8_t connection) {
  if (connection >= MAX_CONNECTIONS || !this->connections_[connection].open)
    return;
  const Connection &c = this->connections_[connection];
  const auto *ip = reinterpret_cast<const uint8_t *>(&c.peer.address);
  const char *kind = c.event_channel                      ? "event"
                     : c.audio_data                       ? "audio"
                     : c.session_pending                  ? "paused sender"
                     : connection == this->session_owner_ ? "playing sender"
                                                          : "other";
  AIRPLAY_LOGD("Connection closed (%u.%u.%u.%u, %s)", ip[0], ip[1], ip[2], ip[3], kind);
  if (c.event_channel && c.event_requests > 0)
    AIRPLAY_LOGD("Event connection: %u requests sent, %u answers", c.event_requests, c.event_answers);
  this->end_relay_(connection);
  if (connection == this->pairing_connection_)
    this->pairing_connection_ = NO_CONNECTION;
  if (connection == this->data_connection_)
    this->data_connection_ = NO_CONNECTION;
  if (connection == this->session_owner_ && !this->promote_pending_session_(connection))
    this->end_session_();
  this->connections_[connection].open = false;
}

void Receiver::close_connection_(uint8_t connection) {
  if (connection >= MAX_CONNECTIONS || !this->connections_[connection].open)
    return;
  this->end_relay_(connection);
  if (connection == this->session_owner_ && !this->promote_pending_session_(connection))
    this->end_session_();
  if (connection == this->pairing_connection_)
    this->pairing_connection_ = NO_CONNECTION;
  if (connection == this->data_connection_)
    this->data_connection_ = NO_CONNECTION;
  this->connections_[connection].open = false;
  this->transport_.close(connection);
}

bool Receiver::is_session_connection(uint8_t connection) const {
  if (connection >= MAX_CONNECTIONS || this->session_owner_ == NO_CONNECTION)
    return false;
  const Connection &c = this->connections_[connection];
  return connection == this->session_owner_ ||
         (c.open && (c.event_channel || c.audio_data || c.session_pending) &&
          c.peer.address == this->connections_[this->session_owner_].peer.address);
}

void Receiver::connection_data(uint8_t connection, const uint8_t *data, size_t length, int64_t now_us) {
  if (connection >= MAX_CONNECTIONS)
    return;
  Connection &c = this->connections_[connection];
  if (!c.open)
    return;
  if (c.event_channel) {
    // Answers to the receiver's requests; their content is only logged
    if (c.event_answers++ == 0) {
      // macOS answers its first requests only after many seconds
      if (c.event_silent)
        AIRPLAY_LOGI("The sender answers on its event connection after all");
      else
        AIRPLAY_LOGD("The sender answers on its event connection");
      c.event_silent = false;
    }
    if (detail::g_log_level >= LogLevel::LOG_LEVEL_VERBOSE)
      this->receive_event_answer_(connection, data, length);
    return;
  }
  if (c.audio_data) {
    this->receive_buffered_audio_(connection, data, length, to_ms(now_us));
    return;
  }
  if (c.encrypted) {
    this->receive_encrypted_(connection, data, length, now_us);
  } else {
    this->pass_plain_(connection, data, length, now_us);
  }
}

void Receiver::pass_plain_(uint8_t connection, const uint8_t *data, size_t length, int64_t now_us) {
  Connection &c = this->connections_[connection];
  while (length > 0 && c.open) {
    const size_t chunk = std::min(length, RTSP_BUFFER_SIZE - c.rx_length);
    std::memcpy(c.buffer + c.rx_length, data, chunk);
    c.rx_length += chunk;
    data += chunk;
    length -= chunk;
    this->process_requests_(connection, now_us);
  }
}

void Receiver::process_requests_(uint8_t connection, int64_t now_us) {
  Connection &c = this->connections_[connection];
  while (c.open && c.rx_length > 0) {
    char *buffer = c.buffer;

    if (c.discard_remaining > 0) {
      // Skipping the body of a request that did not fit in the buffer; cover art goes to the listener
      const size_t drop = std::min(c.discard_remaining, c.rx_length);
      if (c.relay_target != NO_CONNECTION) {
        // The body of a relayed message, passed on as it comes
        if (this->connections_[c.relay_target].open)
          this->send_(c.relay_target, reinterpret_cast<const uint8_t *>(buffer), drop);
        std::memmove(buffer, buffer + drop, c.rx_length - drop);
        c.rx_length -= drop;
        c.discard_remaining -= drop;
        if (c.discard_remaining == 0)
          c.relay_target = NO_CONNECTION;
        continue;
      }
      const bool artwork = this->artwork_streaming_ && connection == this->session_owner_;
      if (artwork)
        this->listener_->on_artwork_data(reinterpret_cast<const uint8_t *>(buffer), drop);
      std::memmove(buffer, buffer + drop, c.rx_length - drop);
      c.rx_length -= drop;
      c.discard_remaining -= drop;
      if (artwork && c.discard_remaining == 0) {
        this->end_artwork_(true);
      } else if (artwork && this->artwork_paused_ == NO_CONNECTION &&
                 this->listener_->artwork_room() < ARTWORK_RESERVE) {
        // The listener works through the image; the rest waits in the sender's socket meanwhile
        this->artwork_paused_ = connection;
        this->transport_.pause_receiving(connection, true);
      }
      continue;
    }

    buffer[c.rx_length] = '\0';
    const char *header_end = std::strstr(buffer, "\r\n\r\n");
    if (header_end == nullptr) {
      if (c.rx_length == RTSP_BUFFER_SIZE) {
        AIRPLAY_LOGW("Request headers too large");
        this->close_connection_(connection);
      }
      return;
    }
    const size_t header_length = static_cast<size_t>(header_end - buffer) + 4;

    char value[16];
    size_t content_length = 0;
    if (get_header(buffer, header_length, "Content-Length", value, sizeof(value)))
      content_length = std::strtoul(value, nullptr, 10);
    if (content_length > RTSP_MAX_BODY_SIZE) {
      AIRPLAY_LOGW("Request body too large");
      this->close_connection_(connection);
      return;
    }

    size_t consumed;
    bool keep_open;
    if (header_length + content_length > RTSP_BUFFER_SIZE) {
      // Too large to buffer (e.g. cover art): answer without the body and skip it
      keep_open = this->handle_request_(connection, buffer, header_length, nullptr, content_length, now_us);
      consumed = header_length;
      c.discard_remaining = content_length;
    } else {
      if (c.rx_length < header_length + content_length)
        return;  // Wait for the rest of the body
      consumed = header_length + content_length;
      // Null terminate the body in place, restoring the byte that follows it afterwards
      char *body = buffer + header_length;
      const char saved = body[content_length];
      body[content_length] = '\0';
      keep_open = this->handle_request_(connection, buffer, header_length, body, content_length, now_us);
      body[content_length] = saved;
    }

    if (!keep_open) {
      this->close_connection_(connection);
      return;
    }
    if (!c.open)
      return;
    std::memmove(buffer, buffer + consumed, c.rx_length - consumed);
    c.rx_length -= consumed;
  }
}

/// AirPlay 1 senders name their device in every request; AirPlay 2 senders in the session SETUP. Not inlined, so that
/// its buffer is not on the stack of the deep pairing path.
__attribute__((noinline)) static void read_sender_name(const char *request, size_t header_length, char *name,
                                                       size_t size) {
  char value[SENDER_NAME_SIZE * 2];
  if (get_header(request, header_length, "X-Apple-Client-Name", value, sizeof(value)))
    copy_utf8(name, size, reinterpret_cast<const uint8_t *>(value), std::strlen(value));
}

bool Receiver::handle_request_(uint8_t connection, char *request, size_t header_length, char *body, size_t body_length,
                               int64_t now_us) {
  Connection &c = this->connections_[connection];
  char method[20];
  size_t method_length = 0;
  while (method_length < header_length && method_length < sizeof(method) - 1 && request[method_length] != ' ')
    method_length++;
  std::memcpy(method, request, method_length);
  method[method_length] = '\0';

  char cseq[16] = "0";
  get_header(request, header_length, "CSeq", cseq, sizeof(cseq));
  AIRPLAY_LOGV("%s (CSeq %s)", method, cseq);

  int status = 200;
  const char *status_text = "OK";
  bool keep_open = true;
  char *extra_headers = this->extra_headers_;
  extra_headers[0] = '\0';
  char response_body[RESPONSE_BODY_SIZE];
  response_body[0] = '\0';

  const bool is_owner = connection == this->session_owner_;
  Response airplay2_response;
  airplay2_response.headers = extra_headers;
  airplay2_response.headers_size = EXTRA_HEADERS_SIZE;
  bool airplay2 = false;

  if (this->airplay2_ && this->handle_airplay2_request_(connection, method, request, header_length, body, body_length,
                                                        airplay2_response, now_us)) {
    airplay2 = true;
    status = airplay2_response.status;
    status_text = airplay2_response.status_text;
  } else if (this->config_.password != nullptr && !c.authenticated && std::strcmp(method, "OPTIONS") != 0 &&
             !this->check_authorization_(c, method, request, header_length)) {
    status = 401;
    status_text = "Unauthorized";
    std::snprintf(extra_headers, EXTRA_HEADERS_SIZE, "WWW-Authenticate: Digest realm=\"raop\", nonce=\"%s\"\r\n",
                  c.nonce);
  } else if (std::strcmp(method, "OPTIONS") == 0) {
    std::snprintf(extra_headers, EXTRA_HEADERS_SIZE, "%s", this->airplay2_ ? AIRPLAY2_PUBLIC_METHODS : PUBLIC_METHODS);
  } else if (!c.encrypted &&
             (std::strcmp(method, "ANNOUNCE") == 0 || std::strcmp(method, "SETUP") == 0 ||
              std::strcmp(method, "RECORD") == 0) &&
             this->refuse_(connection, "AirPlay 1")) {
    status = 403;
    status_text = "Forbidden";
  } else if (std::strcmp(method, "ANNOUNCE") == 0) {
    this->take_session_(connection, request, header_length);
    if (!this->handle_announce_(body != nullptr ? body : "", body != nullptr ? body_length : 0)) {
      status = 415;
      status_text = "Unsupported Media Type";
    }
  } else if (std::strcmp(method, "SETUP") == 0) {
    char transport[192] = "";
    get_header(request, header_length, "Transport", transport, sizeof(transport));
    if (!is_owner || !this->handle_setup_(connection, transport, extra_headers, EXTRA_HEADERS_SIZE)) {
      status = 455;
      status_text = "Method Not Valid in This State";
    }
  } else if (std::strcmp(method, "RECORD") == 0) {
    char rtp_info[96] = "";
    uint32_t seq = 0;
    this->have_initial_seq_ = get_header(request, header_length, "RTP-Info", rtp_info, sizeof(rtp_info)) &&
                              get_numeric_parameter(rtp_info, "seq", &seq);
    this->initial_seq_ = static_cast<uint16_t>(seq);
    const bool airplay2_session = is_owner && c.encrypted;
    if (airplay2_session)
      this->airplay2_recording_ = true;
    if (c.remote_control) {
      // The Home app sends it in the session it sets up to add the receiver; nothing plays
    } else if (!is_owner && c.session_pending) {
      // The sender's other session plays on until this one sets up its stream
      c.pending_recording = true;
      std::snprintf(extra_headers, EXTRA_HEADERS_SIZE, "Audio-Latency: 11025\r\n");
    } else if (is_owner && this->start_audio_(now_us)) {
      AIRPLAY_LOGI("Playback started");
      this->set_session_state_(SessionState::PLAYING);
      // The same value as shairport-sync and the AirPort Express
      std::snprintf(extra_headers, EXTRA_HEADERS_SIZE, "Audio-Latency: 11025\r\n");
    } else if (airplay2_session && this->codec_ == Codec::NONE && this->udp_open_) {
      // AirPlay 2 senders may send RECORD before they set up the audio stream
      AIRPLAY_LOGD("Waiting for the audio stream");
      std::snprintf(extra_headers, EXTRA_HEADERS_SIZE, "Audio-Latency: 11025\r\n");
    } else {
      status = 455;
      status_text = "Method Not Valid in This State";
    }
  } else if (std::strcmp(method, "FLUSH") == 0) {
    if (is_owner) {
      char rtp_info[96] = "";
      uint32_t seq = 0;
      const bool have_seq = get_header(request, header_length, "RTP-Info", rtp_info, sizeof(rtp_info)) &&
                            get_numeric_parameter(rtp_info, "seq", &seq);
      this->flush_(have_seq, static_cast<uint16_t>(seq));
    }
  } else if (std::strcmp(method, "TEARDOWN") == 0) {
    if (is_owner) {
      AIRPLAY_LOGI("Playback stopped");
      this->end_session_();
    }
    std::snprintf(extra_headers, EXTRA_HEADERS_SIZE, "Connection: close\r\n");
    keep_open = false;
  } else if (std::strcmp(method, "SET_PARAMETER") == 0) {
    char content_type[48] = "";
    get_header(request, header_length, "Content-Type", content_type, sizeof(content_type));
    if (is_owner && equals_ignore_case(content_type, "image/", 6)) {
      this->begin_artwork_(content_type, body, body_length);
    } else if (is_owner && body != nullptr) {
      this->handle_set_parameter_(content_type, body, body_length, to_ms(now_us));
    }
  } else if (std::strcmp(method, "GET_PARAMETER") == 0) {
    if (body != nullptr && std::strstr(body, "volume") != nullptr)
      std::snprintf(response_body, sizeof(response_body), "volume: %.6f\r\n",
                    static_cast<double>(this->airplay_volume_));
  } else {
    // E.g. GET /info or POST /pair-setup from AirPlay 2 senders
    const char *line_end = std::strstr(request, "\r\n");
    const int line_length = line_end != nullptr ? static_cast<int>(std::min<ptrdiff_t>(line_end - request, 96)) : 0;
    AIRPLAY_LOGD("Unsupported request: %.*s", line_length, request);
    status = 501;
    status_text = "Not Implemented";
  }

  read_sender_name(request, header_length, c.sender_name, sizeof(c.sender_name));

  // Remote control details of the sender that owns the session
  if (connection == this->session_owner_) {
    char dacp_id[RemoteTarget::DACP_ID_SIZE];
    char active_remote[RemoteTarget::ACTIVE_REMOTE_SIZE] = "";
    if (get_header(request, header_length, "DACP-ID", dacp_id, sizeof(dacp_id))) {
      get_header(request, header_length, "Active-Remote", active_remote, sizeof(active_remote));
      this->update_remote_target_(dacp_id, active_remote, c.peer.address);
    }
  }

  char challenge[64];
  const size_t extra_length = std::strlen(extra_headers);
  if (get_header(request, header_length, "Apple-Challenge", challenge, sizeof(challenge))) {
    if (!this->add_apple_response_(connection, challenge, extra_headers + extra_length,
                                   EXTRA_HEADERS_SIZE - extra_length)) {
      AIRPLAY_LOGW("Failed to answer the Apple-Challenge");
    }
  }

  // Text parameters, or the binary body of an AirPlay 2 response
  const char *content_type = "text/parameters";
  const auto *body_data = reinterpret_cast<const uint8_t *>(response_body);
  size_t body_size = std::strlen(response_body);
  if (airplay2 && airplay2_response.body != nullptr) {
    content_type = airplay2_response.content_type;
    body_data = airplay2_response.body;
    body_size = airplay2_response.body_length;
  }

  char response[RESPONSE_SIZE];
  int length =
      std::snprintf(response, sizeof(response),
                    "RTSP/1.0 %d %s\r\n"
                    "CSeq: %s\r\n"
                    "Server: AirTunes/%s\r\n"
                    "Audio-Jack-Status: connected; type=analog\r\n"
                    "%s",
                    status, status_text, cseq, this->airplay2_ ? AIRPLAY2_SOURCE_VERSION : "105.1", extra_headers);
  if (body_size > 0 && length > 0 && static_cast<size_t>(length) < sizeof(response)) {
    length += std::snprintf(response + length, sizeof(response) - length, "Content-Type: %s\r\nContent-Length: %u\r\n",
                            content_type, static_cast<unsigned>(body_size));
  }
  if (length > 0 && static_cast<size_t>(length) < sizeof(response))
    length += std::snprintf(response + length, sizeof(response) - length, "\r\n");
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(response)) {
    AIRPLAY_LOGW("Response too large");
    return false;
  }
  if (!c.open || !this->send_(connection, reinterpret_cast<const uint8_t *>(response), static_cast<size_t>(length)) ||
      (body_size > 0 && !this->send_(connection, body_data, body_size))) {
    return false;
  }
  if (this->airplay2_)
    AIRPLAY_LOGV("Response: %d %s (%u bytes)", status, status_text, static_cast<unsigned>(body_size));
  // After pair-setup everything that follows is encrypted, starting with the next request
  if (c.encrypt_after_response) {
    c.encrypt_after_response = false;
    c.encrypted = true;
    c.read_counter = 0;
    c.write_counter = 0;
    c.frame_length = 0;
  }
  return keep_open;
}

void Receiver::take_session_(uint8_t connection, const char *request, size_t header_length) {
  if (connection != this->session_owner_ && this->session_owner_ != NO_CONNECTION) {
    AIRPLAY_LOGI("Another sender took over");
    const uint8_t previous = this->session_owner_;
    const bool keep = this->set_aside_owner_(connection);
    const bool recording = this->airplay2_recording_;
    this->session_owner_ = NO_CONNECTION;  // Ends the session rather than handing it to a waiting one
    this->end_session_(keep ? this->connections_[previous].peer.address : 0);
    if (keep) {
      // It does not send RECORD again when it comes back
      this->connections_[previous].session_pending = true;
      this->connections_[previous].pending_recording = recording;
    } else {
      this->close_connection_(previous);
    }
  }
  this->stop_audio_();
  this->session_owner_ = connection;
  this->read_sender_version_(request, header_length);
}

void Receiver::adopt_session_(uint8_t connection, const char *request, size_t header_length) {
  Connection &c = this->connections_[connection];
  const uint8_t previous = this->session_owner_;
  const bool other_sender = previous != NO_CONNECTION && this->connections_[previous].peer.address != c.peer.address;
  AIRPLAY_LOGI(other_sender ? "A paused sender took over again" : "The sender's other session took over");
  const bool keep = previous != NO_CONNECTION && previous != connection && this->set_aside_owner_(connection);
  const bool recording = this->airplay2_recording_;
  this->stop_audio_();
  this->stop_buffered_audio_();
  // The new owner first, so that closing the previous one keeps the session and its sockets
  this->session_owner_ = connection;
  if (keep) {
    this->connections_[previous].session_pending = true;
    this->connections_[previous].pending_recording = recording;
  } else if (previous != NO_CONNECTION && previous != connection) {
    this->close_connection_(previous);
  }
  if (other_sender)
    this->restart_clock_();
  c.session_pending = false;
  this->airplay2_recording_ = c.pending_recording;
  this->have_session_stream_key_ = false;
  this->codec_ = Codec::NONE;
  this->airplay2_audio_ = false;
  this->encrypted_ = false;
  this->client_timing_ = Endpoint{c.peer.address, c.pending_timing_port};
  this->set_ptp_timing_(c.pending_ptp);
  this->read_sender_version_(request, header_length);
}

bool Receiver::promote_pending_session_(uint8_t leaving) {
  for (uint8_t i = 0; i < MAX_CONNECTIONS; i++) {
    Connection &c = this->connections_[i];
    if (i == leaving || !c.open || !c.session_pending)
      continue;
    const bool other_sender = leaving < MAX_CONNECTIONS && this->connections_[leaving].peer.address != c.peer.address;
    AIRPLAY_LOGI(other_sender ? "A paused sender is next, still paused" : "The sender's other session took over");
    this->stop_audio_();
    this->stop_buffered_audio_();
    if (other_sender)
      this->restart_clock_();
    this->session_owner_ = i;
    c.session_pending = false;
    this->airplay2_recording_ = c.pending_recording;
    this->have_session_stream_key_ = false;
    this->codec_ = Codec::NONE;
    this->airplay2_audio_ = false;
    this->client_timing_ = Endpoint{c.peer.address, c.pending_timing_port};
    this->set_ptp_timing_(c.pending_ptp);
    if (this->session_state_ == SessionState::PLAYING)
      this->set_session_state_(SessionState::PAUSED);
    return true;
  }
  return false;
}

bool Receiver::set_aside_owner_(uint8_t connection) {
  const Connection &previous = this->connections_[this->session_owner_];
  // An AirPlay 2 sender of another device stays connected, paused, so that it can take over again with a new
  // stream: iOS keeps its route to a receiver that closes the connection and does not connect again by itself.
  // Another session of the same sender replaces it, and AirPlay 1 senders cannot come back this way.
  const bool keep = previous.encrypted && previous.peer.address != this->connections_[connection].peer.address;
  AIRPLAY_LOGD("Pausing the previous sender%s", keep ? "; it can take over again" : "");
  this->send_media_remote_command_("paus", -1.0f);
  return keep;
}

void Receiver::restart_clock_() {
  this->timing_requests_sent_ = 0;
  this->last_timing_request_ms_ = 0;
  this->timing_sample_count_ = 0;
  this->timing_sample_index_ = 0;
  this->clock_locked_ = false;
  this->forget_timeline_();
}

void Receiver::read_sender_version_(const char *request, size_t header_length) {
  // Senders identify as e.g. "AirPlay/381.13"; the version decides how the latency is computed
  char user_agent[48] = "";
  this->sender_version_ = 0;
  if (get_header(request, header_length, "User-Agent", user_agent, sizeof(user_agent)) &&
      equals_ignore_case(user_agent, "AirPlay/", 8)) {
    this->sender_version_ = static_cast<uint16_t>(std::strtoul(user_agent + 8, nullptr, 10));
  }
}

bool Receiver::handle_announce_(const char *body, size_t body_length) {
  if (this->airplay2_) {
    // While AirPlay 2 is new: show how senders describe the stream (keys are long base64 lines, shown cut off)
    for (const char *line = body; line < body + body_length;) {
      const char *line_end = line;
      while (line_end < body + body_length && *line_end != '\r' && *line_end != '\n')
        line_end++;
      if (line_end > line)
        AIRPLAY_LOGV("  sdp: %.*s", static_cast<int>(std::min<ptrdiff_t>(line_end - line, 100)), line);
      line = line_end + 1;
    }
  }
  this->codec_ = Codec::NONE;
  this->encrypted_ = false;
  this->airplay2_audio_ = false;
  bool have_key = false;
  bool have_iv = false;
  bool key_error = false;
  ALACConfig alac;
  bool have_fmtp = false;

  const char *end = body + body_length;
  const char *line = body;
  while (line < end) {
    const char *line_end = line;
    while (line_end < end && *line_end != '\r' && *line_end != '\n')
      line_end++;
    const size_t length = static_cast<size_t>(line_end - line);

    if (length > 9 && std::strncmp(line, "a=rtpmap:", 9) == 0) {
      if (contains(line, line_end, "AppleLossless")) {
        this->codec_ = Codec::ALAC;
      } else if (contains(line, line_end, "L16/44100/2")) {
        this->codec_ = Codec::PCM;
      }
    } else if (length > 7 && std::strncmp(line, "a=fmtp:", 7) == 0) {
      // payload_type frame_length version bit_depth pb mb kb channels max_run max_frame_bytes bit_rate sample_rate
      unsigned long values[12];
      size_t count = 0;
      const char *p = line + 7;
      while (count < 12) {
        char *next = nullptr;
        const unsigned long value = std::strtoul(p, &next, 10);
        if (next == p || next > line_end)
          break;
        values[count++] = value;
        p = next;
      }
      if (count == 12) {
        alac.frame_length = static_cast<uint32_t>(values[1]);
        alac.bit_depth = static_cast<uint8_t>(values[3]);
        alac.pb = static_cast<uint8_t>(values[4]);
        alac.mb = static_cast<uint8_t>(values[5]);
        alac.kb = static_cast<uint8_t>(values[6]);
        alac.num_channels = static_cast<uint8_t>(values[7]);
        alac.max_run = static_cast<uint16_t>(values[8]);
        alac.sample_rate = static_cast<uint32_t>(values[11]);
        have_fmtp = true;
      }
    } else if (length > 12 && std::strncmp(line, "a=rsaaeskey:", 12) == 0) {
      uint8_t encrypted_key[RSA_SIGNATURE_SIZE];
      uint8_t key[AES_KEY_SIZE];
      const size_t key_length = base64_decode(line + 12, length - 12, encrypted_key, sizeof(encrypted_key));
      have_key = this->crypto_.decrypt_session_key(encrypted_key, key_length, key) && this->crypto_.set_audio_key(key);
      key_error = !have_key;
    } else if (length > 8 && std::strncmp(line, "a=aesiv:", 8) == 0) {
      have_iv = base64_decode(line + 8, length - 8, this->aes_iv_, sizeof(this->aes_iv_)) == sizeof(this->aes_iv_);
    }

    line = line_end;
    while (line < end && (*line == '\r' || *line == '\n'))
      line++;
  }

  if (key_error) {
    AIRPLAY_LOGW("Failed to decrypt the session key");
    this->codec_ = Codec::NONE;
    return false;
  }
  if (have_key != have_iv) {
    AIRPLAY_LOGW("Incomplete encryption parameters");
    this->codec_ = Codec::NONE;
    return false;
  }
  this->encrypted_ = have_key;

  if (this->codec_ == Codec::ALAC) {
    if (!have_fmtp || alac.sample_rate != SAMPLE_RATE || alac.num_channels != NUM_CHANNELS ||
        alac.frame_length > FRAMES_PER_PACKET || !this->decoder_.configure(alac)) {
      AIRPLAY_LOGW("Unsupported ALAC parameters");
      this->codec_ = Codec::NONE;
    }
  }
  if (this->codec_ == Codec::NONE) {
    AIRPLAY_LOGW("Unsupported audio format");
    return false;
  }
  AIRPLAY_LOGD("Stream: %s, %s", this->codec_ == Codec::ALAC ? "ALAC" : "PCM",
               this->encrypted_ ? "encrypted" : "unencrypted");
  return true;
}

bool Receiver::handle_setup_(uint8_t connection, const char *transport, char *response_headers, size_t size) {
  uint32_t control_port = 0;
  uint32_t timing_port = 0;
  get_numeric_parameter(transport, "control_port", &control_port);
  get_numeric_parameter(transport, "timing_port", &timing_port);

  uint16_t ports[NUM_UDP_CHANNELS] = {};
  if (!this->open_udp_(connection, control_port, timing_port, ports))
    return false;

  std::snprintf(response_headers, size,
                "Transport: RTP/AVP/UDP;unicast;mode=record;server_port=%u;control_port=%u;timing_port=%u\r\n"
                "Session: 1\r\n",
                ports[static_cast<size_t>(UdpChannel::AUDIO)], ports[static_cast<size_t>(UdpChannel::CONTROL)],
                ports[static_cast<size_t>(UdpChannel::TIMING)]);
  return true;
}

bool Receiver::open_udp_(uint8_t connection, uint32_t control_port, uint32_t timing_port, uint16_t *ports) {
  this->stop_audio_();
  this->close_udp_();
  if (!this->transport_.open_udp(ports)) {
    AIRPLAY_LOGW("Failed to open UDP sockets");
    this->transport_.close_udp();
    return false;
  }
  this->udp_open_ = true;
  this->timing_requests_sent_ = 0;
  this->last_timing_request_ms_ = 0;
  this->timing_sample_count_ = 0;
  this->timing_sample_index_ = 0;
  this->clock_locked_ = false;
  this->anchor_valid_ = false;

  const uint32_t address = this->connections_[connection].peer.address;
  this->client_control_ = Endpoint{address, static_cast<uint16_t>(control_port)};
  this->client_timing_ = Endpoint{address, static_cast<uint16_t>(timing_port)};
  return true;
}

void Receiver::handle_set_parameter_(const char *content_type, const char *body, size_t body_length, uint32_t now_ms) {
  if (equals_ignore_case(content_type, "application/x-dmap-tagged", 25)) {
    if (!this->config_.metadata)
      return;
    Metadata metadata{};
    parse_dmap_metadata(reinterpret_cast<const uint8_t *>(body), body_length, metadata);
    // Senders repeat the details of a track several times
    const uint32_t hash = fnv1a(&metadata, sizeof(metadata));
    if (hash == this->metadata_hash_)
      return;
    this->metadata_hash_ = hash;
    // A new track: title or artist changed. Some senders send its position just before its details; that position
    // stays. Otherwise the position is unknown until the new track's arrives, and iOS first sends the previous track's
    // again, so a progress with that track's length is not taken for this one.
    const uint32_t track_hash =
        fnv1a(metadata.artist, sizeof(metadata.artist), fnv1a(metadata.title, sizeof(metadata.title)));
    if (track_hash != this->track_hash_) {
      this->track_hash_ = track_hash;
      if (this->last_progress_frames_ != 0 && now_ms - this->last_progress_ms_ > FRESH_PROGRESS_MS) {
        this->stale_progress_frames_ = this->last_progress_frames_;
        if (this->config_.progress && this->listener_ != nullptr)
          this->listener_->on_progress(Progress{});
      }
    }
    AIRPLAY_LOGD("Now playing: %s - %s", metadata.artist, metadata.title);
    if (this->listener_ != nullptr)
      this->listener_->on_metadata(metadata);
    return;
  }
  if (!equals_ignore_case(content_type, "text/parameters", 15))
    return;

  if (const char *progress = std::strstr(body, "progress:")) {
    if (this->config_.progress)
      this->handle_progress_(progress + 9, now_ms);
    return;
  }
  const char *volume = std::strstr(body, "volume:");
  if (volume == nullptr)
    return;
  const float airplay_volume = std::strtof(volume + 7, nullptr);
  this->airplay_volume_ = airplay_volume;
  AIRPLAY_LOGD("Volume: %.2f dB", static_cast<double>(airplay_volume));

  if (airplay_volume <= AIRPLAY_VOLUME_MUTE_LIMIT) {
    if (!this->airplay_muted_) {
      this->airplay_muted_ = true;
      if (this->listener_ != nullptr)
        this->listener_->on_mute(true);
    }
    return;
  }
  const float level = std::clamp((airplay_volume - AIRPLAY_VOLUME_MIN) / -AIRPLAY_VOLUME_MIN, 0.0f, 1.0f);
  if (this->listener_ != nullptr)
    this->listener_->on_volume(level);
  if (this->airplay_muted_) {
    this->airplay_muted_ = false;
    if (this->listener_ != nullptr)
      this->listener_->on_mute(false);
  }
}

void Receiver::resume_artwork_() {
  // After reading stops: what is left in the request buffer, the rest of the current read and the next request buffer
  static_assert(ARTWORK_RESERVE >= 2 * RTSP_BUFFER_SIZE + 2048, "ARTWORK_RESERVE too small");
  if (this->artwork_paused_ == NO_CONNECTION)
    return;
  this->transport_.pause_receiving(this->artwork_paused_, false);
  this->artwork_paused_ = NO_CONNECTION;
}

void Receiver::begin_artwork_(const char *content_type, const char *body, size_t body_length) {
  if (!this->config_.artwork || this->listener_ == nullptr)
    return;
  ArtworkFormat format{ArtworkFormat::JPEG};
  if (equals_ignore_case(content_type + 6, "jpeg", 5)) {
    format = ArtworkFormat::JPEG;
  } else if (equals_ignore_case(content_type + 6, "png", 4)) {
    format = ArtworkFormat::PNG;
  } else {
    body_length = 0;  // "image/none": the track has no cover art
  }
  if (body_length == 0) {
    AIRPLAY_LOGD("No cover art");
    this->listener_->on_artwork_clear();
    return;
  }
  AIRPLAY_LOGD("Cover art: %s, %u bytes", content_type, static_cast<unsigned>(body_length));
  if (!this->listener_->on_artwork_begin(format, body_length))
    return;
  if (body == nullptr) {
    this->artwork_streaming_ = true;  // The rest arrives through process_requests_()
    return;
  }
  this->listener_->on_artwork_data(reinterpret_cast<const uint8_t *>(body), body_length);
  this->listener_->on_artwork_end(true);
}

void Receiver::end_artwork_(bool complete) {
  this->artwork_streaming_ = false;
  this->resume_artwork_();
  this->listener_->on_artwork_end(complete);
}

void Receiver::handle_progress_(const char *value, uint32_t now_ms) {
  // "start/current/end" as RTP timestamps
  char *end = nullptr;
  const auto start = static_cast<uint32_t>(std::strtoul(value, &end, 10));
  if (end == nullptr || *end != '/')
    return;
  const auto current = static_cast<uint32_t>(std::strtoul(end + 1, &end, 10));
  if (end == nullptr || *end != '/')
    return;
  const auto finish = static_cast<uint32_t>(std::strtoul(end + 1, nullptr, 10));
  uint32_t duration = finish - start;
  if (duration == this->stale_progress_frames_) {
    AIRPLAY_LOGD("Ignoring the progress of the previous track");
    return;
  }
  // Some senders (e.g. YouTube) report the length of the same track a fraction of a second differently each time;
  // it is kept, so that a shown remaining time does not jump
  if (this->stale_progress_frames_ == 0 && this->last_progress_frames_ != 0 &&
      static_cast<uint32_t>(std::abs(static_cast<int32_t>(duration - this->last_progress_frames_))) <= SAMPLE_RATE)
    duration = this->last_progress_frames_;
  this->stale_progress_frames_ = 0;
  this->last_progress_frames_ = duration;
  this->last_progress_ms_ = now_ms;
  const uint32_t position = std::min(current - start, duration);
  Progress progress{static_cast<uint32_t>(static_cast<uint64_t>(position) * 1000 / SAMPLE_RATE),
                    static_cast<uint32_t>(static_cast<uint64_t>(duration) * 1000 / SAMPLE_RATE)};
  AIRPLAY_LOGD("Progress: %" PRIu32 ":%02" PRIu32 " of %" PRIu32 ":%02" PRIu32 " (%" PRIu32 "/%" PRIu32 "/%" PRIu32 ")",
               progress.position_ms / 60000, progress.position_ms / 1000 % 60, progress.duration_ms / 60000,
               progress.duration_ms / 1000 % 60, start, current, finish);
  if (this->listener_ != nullptr)
    this->listener_->on_progress(progress);
}

/// Copies the quoted value of a field of a Digest header, e.g. nonce="abc"
static bool get_digest_field(const char *header, const char *name, char *value, size_t size) {
  const size_t name_length = std::strlen(name);
  for (const char *p = header; (p = std::strstr(p, name)) != nullptr; p += name_length) {
    // Only a whole field name, not the end of another one
    if (p != header && p[-1] != ' ' && p[-1] != ',')
      continue;
    if (p[name_length] != '=' || p[name_length + 1] != '"')
      continue;
    const char *start = p + name_length + 2;
    const char *stop = std::strchr(start, '"');
    if (stop == nullptr || static_cast<size_t>(stop - start) >= size)
      return false;
    std::memcpy(value, start, stop - start);
    value[stop - start] = '\0';
    return true;
  }
  return false;
}

bool Receiver::check_authorization_(Connection &c, const char *method, const char *request, size_t header_length) {
  char header[384];
  if (!get_header(request, header_length, "Authorization", header, sizeof(header)))
    return false;
  char username[64];
  char realm[32];
  char nonce[sizeof(c.nonce) + 1];
  char uri[128];
  char response[MD5_SIZE * 2 + 1];
  if (!equals_ignore_case(header, "Digest ", 7) || !get_digest_field(header, "username", username, sizeof(username)) ||
      !get_digest_field(header, "realm", realm, sizeof(realm)) ||
      !get_digest_field(header, "nonce", nonce, sizeof(nonce)) || !get_digest_field(header, "uri", uri, sizeof(uri)) ||
      !get_digest_field(header, "response", response, sizeof(response)) || std::strcmp(nonce, c.nonce) != 0) {
    return false;
  }
  // response = MD5(MD5(username:realm:password):nonce:MD5(method:uri))
  char text[256];
  char ha1[MD5_SIZE * 2 + 1];
  char ha2[MD5_SIZE * 2 + 1];
  char expected[MD5_SIZE * 2 + 1];
  int length = std::snprintf(text, sizeof(text), "%s:%s:%s", username, realm, this->config_.password);
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(text))
    return false;
  md5_hex(text, length, ha1);
  length = std::snprintf(text, sizeof(text), "%s:%s", method, uri);
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(text))
    return false;
  md5_hex(text, length, ha2);
  length = std::snprintf(text, sizeof(text), "%s:%s:%s", ha1, nonce, ha2);
  md5_hex(text, length, expected);
  if (std::strlen(response) != MD5_SIZE * 2 || !equals_ignore_case(response, expected, MD5_SIZE * 2)) {
    AIRPLAY_LOGW("Wrong password");
    return false;
  }
  c.authenticated = true;
  return true;
}

bool Receiver::add_apple_response_(uint8_t connection, const char *challenge, char *output, size_t size) {
  static constexpr size_t CHALLENGE_SIZE = 16;
  static constexpr size_t SIGNED_SIZE = 32;
  // The signed data is the challenge, the receiver's IP address on this connection and its MAC address,
  // padded with zeros to 32 bytes
  uint8_t data[SIGNED_SIZE] = {};
  size_t length = base64_decode(challenge, std::strlen(challenge), data, CHALLENGE_SIZE);
  if (length != CHALLENGE_SIZE)
    return false;
  std::memcpy(data + length, &this->connections_[connection].local.address, 4);
  length += 4;
  std::memcpy(data + length, this->config_.mac, sizeof(this->config_.mac));

  uint8_t signature[RSA_SIGNATURE_SIZE];
  if (!this->crypto_.sign_challenge(data, SIGNED_SIZE, signature))
    return false;

  static constexpr char HEADER[] = "Apple-Response: ";
  static constexpr size_t HEADER_LENGTH = sizeof(HEADER) - 1;
  if (size < HEADER_LENGTH + 3)
    return false;
  std::memcpy(output, HEADER, HEADER_LENGTH);
  const size_t encoded =
      base64_encode_unpadded(signature, sizeof(signature), output + HEADER_LENGTH, size - HEADER_LENGTH - 2);
  if (encoded == 0)
    return false;
  std::memcpy(output + HEADER_LENGTH + encoded, "\r\n", 3);
  return true;
}

void Receiver::update_remote_target_(const char *dacp_id, const char *active_remote, uint32_t address) {
  RemoteTarget &target = this->remote_target_;
  bool changed = false;
  if (std::strcmp(target.dacp_id, dacp_id) != 0 || target.address != address) {
    std::snprintf(target.dacp_id, sizeof(target.dacp_id), "%s", dacp_id);
    target.address = address;
    changed = true;
  }
  if (active_remote[0] != '\0' && std::strcmp(target.active_remote, active_remote) != 0) {
    std::snprintf(target.active_remote, sizeof(target.active_remote), "%s", active_remote);
    changed = true;
  }
  if (changed && this->listener_ != nullptr)
    this->listener_->on_remote_target(target);
}

void Receiver::end_session_(uint32_t keep_address) {
  this->stop_audio_();
  this->close_udp_();
  this->session_owner_ = NO_CONNECTION;
  // Reported again in the next session, also when the same sender opens it with the same details
  this->remote_target_ = RemoteTarget{};
  this->codec_ = Codec::NONE;
  this->airplay2_audio_ = false;
  this->event_channel_pending_ = false;
  this->airplay2_recording_ = false;
  this->have_session_stream_key_ = false;
  this->stop_buffered_audio_();
  // The sender's event connection goes with its session, unless the sender stays connected
  for (uint8_t i = 0; i < MAX_CONNECTIONS; i++) {
    Connection &c = this->connections_[i];
    if (c.open && c.relay_latest != 0) {
      // A controller of the sender that played: nothing left to relay to
      const auto *ip = reinterpret_cast<const uint8_t *>(&c.peer.address);
      AIRPLAY_LOGI("Remote control streams of %u.%u.%u.%u ended with the session", ip[0], ip[1], ip[2], ip[3]);
      std::fill(std::begin(c.relay_streams), std::end(c.relay_streams), 0);
      c.relay_latest = 0;
      c.open = false;
      this->transport_.close(i);
      continue;
    }
    const bool kept = c.event_channel && keep_address != 0 && c.peer.address == keep_address;
    if (c.open && (c.event_channel || c.audio_data) && !kept) {
      c.open = false;
      this->transport_.close(i);
    }
  }
  if (this->artwork_streaming_)
    this->end_artwork_(false);
  this->metadata_hash_ = 0;
  if (this->listener_ != nullptr && this->config_.metadata)
    this->listener_->on_metadata(Metadata{});
  if (this->listener_ != nullptr && this->config_.artwork)
    this->listener_->on_artwork_clear();
  if (this->listener_ != nullptr && this->config_.progress)
    this->listener_->on_progress(Progress{});
  if (this->airplay_muted_) {
    this->airplay_muted_ = false;
    if (this->listener_ != nullptr)
      this->listener_->on_mute(false);
  }
  this->set_session_state_(SessionState::NONE);
}

void Receiver::set_session_state_(SessionState state) {
  if (this->session_state_ == state)
    return;
  this->session_state_ = state;
  this->update_sender_address_();
  this->update_sender_name_();
  if (this->listener_ != nullptr)
    this->listener_->on_session_state(state);
}

void Receiver::update_sender_address_() {
  const uint32_t address =
      this->session_owner_ != NO_CONNECTION ? this->connections_[this->session_owner_].peer.address : 0;
  this->sender_address_.store(address, std::memory_order_relaxed);
}

void Receiver::update_sender_name_() {
  const char *name = this->session_owner_ != NO_CONNECTION && this->session_state_ != SessionState::NONE
                         ? this->connections_[this->session_owner_].sender_name
                         : "";
  if (std::strcmp(name, this->reported_sender_name_) == 0)
    return;
  std::snprintf(this->reported_sender_name_, sizeof(this->reported_sender_name_), "%s", name);
  if (this->listener_ != nullptr)
    this->listener_->on_sender_name(this->reported_sender_name_);
}

void Receiver::close_udp_() {
  if (!this->udp_open_)
    return;
  this->transport_.close_udp();
  this->udp_open_ = false;
}

// ===== Audio session =====

bool Receiver::start_audio_(int64_t now_us) {
  if (this->codec_ == Codec::NONE || !this->udp_open_)
    return false;
  this->stop_audio_();
  this->reset_playback_();
  this->accept_from_seq_ = this->initial_seq_;
  this->accept_any_seq_ = !this->have_initial_seq_;
  this->last_packet_ms_ = to_ms(now_us);
  this->last_resend_scan_ms_ = 0;
  this->stats_ = ReceiverStats{};
  this->last_poll_ms_ = 0;
  // The written and played frame counts are not reset here: the output may still play audio of an earlier
  // session and keep reporting it. They restart with request_output_restart().
  // The sender's clock is kept from SETUP on: some senders send their first sync packet before RECORD
  this->played_reports_missing_ = false;
  this->sync_logged_ = false;
  this->restarts_ = 0;
  this->late_logged_ = false;
  this->alac_logged_ = false;
  this->timeline_mismatch_ = false;
  this->timeline_unusable_ = false;
  this->audio_active_ = true;
  return true;
}

void Receiver::stop_audio_() {
  if (!this->audio_active_)
    return;
  this->audio_active_ = false;
  const ReceiverStats &st = this->stats_;
  AIRPLAY_LOGD("Session ended: %" PRIu32 " packets lost, %" PRIu32 " late, %" PRIu32 " resend requests, %" PRIu32
               " trimmed frames, %" PRIu32 " ms silence, %" PRIu32 " underruns, longest poll gap %" PRIu32 " ms",
               st.lost_packets, st.late_packets, st.resend_requests, st.trimmed_frames,
               static_cast<uint32_t>(frames_to_us(st.silence_frames) / 1000), st.underruns, st.longest_gap_ms);
}

void Receiver::flush_(bool have_seq, uint16_t seq) {
  if (!this->audio_active_)
    return;
  // Paused or seeking: drop the buffered audio and wait for the sender to continue
  if (have_seq) {
    this->accept_from_seq_ = seq;
    this->accept_any_seq_ = false;
  } else if (this->have_seq_) {
    // Without a sequence number accept whatever arrives next
    this->accept_from_seq_ = this->highest_seq_ + 1;
    this->accept_any_seq_ = false;
  }
  // The timeline may jump after a seek, so wait for the next sync packet. A flush before any audio (some
  // senders send one right after RECORD) changes nothing, so the anchor stays.
  if (this->have_seq_ || this->playback_started_)
    this->anchor_valid_ = false;
  this->reset_playback_();
  if (this->session_state_ == SessionState::PLAYING)
    this->set_session_state_(SessionState::PAUSED);
}

void Receiver::reset_playback_() {
  for (uint32_t i = 0; i < this->slot_count_; i++) {
    this->slots_[i].valid = false;
    this->slots_[i].missing_since_ms = 0;
  }
  this->have_seq_ = false;
  this->have_next_rtp_ = false;
  this->playback_started_ = false;
  this->head_slot_ = 0;
  this->output_offset_ = 0;
  this->output_length_ = 0;
  this->silence_pending_frames_ = 0;
  this->drift_error_ = 0;
  this->servo_error_us_ = 0;
  this->servo_engaged_ = false;
  this->trim_counter_ = 0;
}

void Receiver::udp_packet(UdpChannel channel, const uint8_t *packet, size_t length, const Endpoint &from,
                          int64_t now_us) {
  if (!this->udp_open_ || length < RETRANSMIT_HEADER_SIZE)
    return;
  const uint8_t type = packet[1] & 0x7f;
  if (type == PAYLOAD_TIMING_REQUEST) {
    this->handle_timing_request_(channel, packet, length, from, now_us);
    return;
  }
  // Only from the sender that plays, not from one that was set aside and goes on sending (Music Assistant does)
  if (this->session_owner_ == NO_CONNECTION || from.address != this->connections_[this->session_owner_].peer.address) {
    this->stats_.foreign_packets++;
    return;
  }
  // The clock exchange and sync packets start with SETUP, the audio with RECORD
  switch (type) {
    case PAYLOAD_TIMING_REPLY:
      this->handle_timing_reply_(packet, length, now_us);
      return;
    case PAYLOAD_SYNC:
      this->handle_sync_packet_(packet, length, now_us);
      return;
    case PAYLOAD_PTP_SYNC:
      this->handle_ptp_sync_packet_(packet, length);
      return;
    default:
      break;
  }
  if (!this->audio_active_ || this->buffered_stream_)
    return;
  // Held: dropped as it arrives, unless the sender is paused and its audio may show that it plays again
  if (this->audio_held_ && this->session_state_ != SessionState::PAUSED) {
    // iOS keeps sending silence for several seconds after an AirPlay 1 pause: packets that small are not audio
    if (type == PAYLOAD_AUDIO && length > RTP_HEADER_SIZE + SILENT_PACKET_MAX_BYTES) {
      this->last_packet_ms_ = to_ms(now_us);
    } else if (type == PAYLOAD_AUDIO && !this->held_silence_logged_) {
      this->held_silence_logged_ = true;
      AIRPLAY_LOGD("The sender sends silence (packets of %u bytes)", static_cast<unsigned>(length - RTP_HEADER_SIZE));
    }
    return;
  }

  switch (type) {
    case PAYLOAD_AUDIO:
      if (length > RTP_HEADER_SIZE) {
        this->handle_audio_packet_(packet, packet + RTP_HEADER_SIZE, length - RTP_HEADER_SIZE, to_ms(now_us));
      }
      break;
    case PAYLOAD_RETRANSMIT: {
      // A short header followed by the original RTP packet
      const uint8_t *original = packet + RETRANSMIT_HEADER_SIZE;
      if (length > RETRANSMIT_HEADER_SIZE + RTP_HEADER_SIZE) {
        this->handle_audio_packet_(original, original + RTP_HEADER_SIZE,
                                   length - RETRANSMIT_HEADER_SIZE - RTP_HEADER_SIZE, to_ms(now_us));
      }
      break;
    }
    default:
      break;
  }
}

void Receiver::handle_audio_packet_(const uint8_t *header, const uint8_t *payload, size_t length, uint32_t now_ms) {
  if (this->config_.clock_us == nullptr) {
    this->handle_audio_packet_timed_(header, payload, length, now_ms);
    return;
  }
  const int64_t start = this->config_.clock_us();
  this->handle_audio_packet_timed_(header, payload, length, now_ms);
  this->packet_us_.fetch_add(static_cast<uint32_t>(this->config_.clock_us() - start), std::memory_order_relaxed);
  this->timed_packets_.fetch_add(1, std::memory_order_relaxed);
}

void Receiver::benchmark_decoder_(const uint8_t *data, size_t length, int16_t *output) {
  if (this->benchmark_input_ == nullptr || this->benchmark_output_ == nullptr || length > PACKET_BUFFER_SIZE)
    return;
  static constexpr uint32_t RUNS = 50;
  std::memcpy(this->benchmark_input_, data, length);
  struct Result {
    uint32_t average_us;
    uint32_t fastest_us;
  };
  const auto run = [&](const uint8_t *input, int16_t *samples) {
    int64_t total = 0;
    uint32_t fastest = UINT32_MAX;
    for (uint32_t i = 0; i < RUNS; i++) {
      const int64_t start = this->config_.clock_us();
      this->decoder_.decode(input, length, samples);
      const auto took = static_cast<uint32_t>(this->config_.clock_us() - start);
      total += took;
      fastest = std::min(fastest, took);
    }
    return Result{static_cast<uint32_t>(total / RUNS), fastest};
  };
  const Result internal = run(this->benchmark_input_, this->benchmark_output_);
  const Result actual = run(data, output);
  // The same length through ChaCha20-Poly1305, as AirPlay 2 audio is encrypted
  int64_t crypto_total = 0;
  uint32_t crypto_fastest = UINT32_MAX;
  const uint8_t key[CHACHA_KEY_SIZE] = {};
  const uint8_t nonce[CHACHA_NONCE_SIZE] = {};
  uint8_t tag[POLY1305_TAG_SIZE];
  for (uint32_t i = 0; i < RUNS; i++) {
    const int64_t start = this->config_.clock_us();
    chacha20_poly1305_encrypt(key, nonce, data, 8, this->benchmark_input_, length,
                              reinterpret_cast<uint8_t *>(this->benchmark_output_), tag);
    const auto took = static_cast<uint32_t>(this->config_.clock_us() - start);
    crypto_total += took;
    crypto_fastest = std::min(crypto_fastest, took);
  }
  AIRPLAY_LOGD("ALAC benchmark, %" PRIu32 " decodes of %u bytes: separate buffers %" PRIu32 " us (fastest %" PRIu32
               "), the receiver's %" PRIu32 " us (fastest %" PRIu32 ")",
               RUNS, static_cast<unsigned>(length), internal.average_us, internal.fastest_us, actual.average_us,
               actual.fastest_us);
  AIRPLAY_LOGD("ChaCha20-Poly1305 benchmark, %" PRIu32 " runs over %u bytes: %" PRIu32 " us (fastest %" PRIu32 ")",
               RUNS, static_cast<unsigned>(length), static_cast<uint32_t>(crypto_total / RUNS), crypto_fastest);
#if defined(ESP_PLATFORM)
  AIRPLAY_LOGD("In PSRAM: separate input %d, output %d; the receiver's input %d, output %d; decoder %d",
               esp_ptr_external_ram(this->benchmark_input_), esp_ptr_external_ram(this->benchmark_output_),
               esp_ptr_external_ram(data), esp_ptr_external_ram(output),
               esp_ptr_external_ram(this->decoder_.work_buffer()));
#endif
}

Receiver::PlaybackTiming Receiver::take_playback_timing() {
  return PlaybackTiming{
      this->timers_us_.exchange(0, std::memory_order_relaxed), this->resend_us_.exchange(0, std::memory_order_relaxed),
      this->copy_us_.exchange(0, std::memory_order_relaxed), this->write_us_.exchange(0, std::memory_order_relaxed)};
}

Receiver::PacketTiming Receiver::take_packet_timing() {
  return PacketTiming{this->timed_packets_.exchange(0, std::memory_order_relaxed),
                      this->decrypt_us_.exchange(0, std::memory_order_relaxed),
                      this->decode_us_.exchange(0, std::memory_order_relaxed),
                      this->packet_us_.exchange(0, std::memory_order_relaxed)};
}

void Receiver::handle_audio_packet_timed_(const uint8_t *header, const uint8_t *payload, size_t length,
                                          uint32_t now_ms) {
  const uint16_t seq = read_be16(header + 2);
  const uint32_t rtp = read_be32(header + 4);
  this->last_packet_ms_ = now_ms;
  if (length > PACKET_BUFFER_SIZE) {
    this->stats_.decode_errors++;
    return;
  }
  if (!this->have_seq_) {
    if (!this->accept_any_seq_ && static_cast<int16_t>(seq - this->accept_from_seq_) < 0) {
      this->stats_.late_packets++;  // Sent before the last flush
      return;
    }
    this->have_seq_ = true;
    this->next_seq_ = seq;
    this->highest_seq_ = seq - 1;
    this->head_slot_ = 0;
  }

  int32_t ahead = static_cast<int16_t>(seq - this->next_seq_);
  if (ahead < 0) {
    this->stats_.late_packets++;
    return;
  }
  if (static_cast<uint32_t>(ahead) >= this->slot_count_) {
    // Buffer full: give up on the oldest packets to make room
    const uint32_t drop = static_cast<uint32_t>(ahead) - this->slot_count_ + 1;
    for (uint32_t i = 0; i < drop; i++) {
      const PacketSlot &old = this->slots_[this->head_slot_];
      if (!old.valid || old.seq != this->next_seq_)
        this->stats_.lost_packets++;
      this->advance_head_();
    }
    ahead = static_cast<int32_t>(this->slot_count_) - 1;
  }

  PacketSlot &slot = this->slots_[(this->head_slot_ + static_cast<uint32_t>(ahead)) % this->slot_count_];
  if (slot.valid && slot.seq == seq)
    return;  // Duplicate

  const uint8_t *data = payload;
  const int64_t decrypt_start = this->config_.clock_us != nullptr ? this->config_.clock_us() : 0;
  if (this->airplay2_audio_) {
    length = this->decrypt_airplay2_audio_(header, payload, length, this->packet_buffer_);
    if (length == 0) {
      this->stats_.decode_errors++;
      return;
    }
    data = this->packet_buffer_;
  } else if (this->encrypted_) {
    // Only whole AES blocks are encrypted, and the IV restarts with every packet
    uint8_t *plain = this->packet_buffer_;
    const size_t encrypted_length = length & ~(AES_BLOCK_SIZE - 1);
    uint8_t iv[AES_BLOCK_SIZE];
    std::memcpy(iv, this->aes_iv_, sizeof(iv));
    if (encrypted_length > 0 && !this->crypto_.decrypt_audio(iv, payload, plain, encrypted_length)) {
      this->stats_.decode_errors++;
      return;
    }
    std::memcpy(plain + encrypted_length, payload + encrypted_length, length - encrypted_length);
    data = plain;
  }

  int64_t decode_start = 0;
  if (this->config_.clock_us != nullptr) {
    decode_start = this->config_.clock_us();
    this->decrypt_us_.fetch_add(static_cast<uint32_t>(decode_start - decrypt_start), std::memory_order_relaxed);
  }
  int32_t frames;
  if (this->codec_ == Codec::ALAC) {
    frames = this->decoder_.decode(data, length, slot.samples);
    if (!this->alac_logged_ && frames > 0) {
      // Once per stream: some senders store the audio uncompressed in ALAC packets
      this->alac_logged_ = true;
      if (this->config_.clock_us != nullptr)
        this->benchmark_decoder_(data, length, slot.samples);
      if (this->decoder_.last_uncompressed()) {
        AIRPLAY_LOGD("ALAC packets of %u bytes, stored uncompressed", static_cast<unsigned>(length));
      } else {
        AIRPLAY_LOGD("ALAC packets of %u bytes, compressed, predictor order %" PRIu32, static_cast<unsigned>(length),
                     this->decoder_.last_predictor_order());
      }
    }
    if (this->config_.clock_us != nullptr)
      this->decode_us_.fetch_add(static_cast<uint32_t>(this->config_.clock_us() - decode_start),
                                 std::memory_order_relaxed);
  } else {
    // Big endian 16-bit PCM
    frames = static_cast<int32_t>(std::min<size_t>(length / BYTES_PER_FRAME, FRAMES_PER_PACKET));
    for (int32_t i = 0; i < frames * static_cast<int32_t>(NUM_CHANNELS); i++)
      slot.samples[i] = static_cast<int16_t>(read_be16(data + 2 * i));
  }
  if (frames <= 0) {
    if (this->stats_.decode_errors == 0) {
      AIRPLAY_LOGW("Failed to decode audio (packet %u, %u bytes, starting with %02x %02x %02x %02x)", seq,
                   static_cast<unsigned>(length), data[0], length > 1 ? data[1] : 0, length > 2 ? data[2] : 0,
                   length > 3 ? data[3] : 0);
    }
    AIRPLAY_LOGV("Failed to decode packet %u", seq);
    this->stats_.decode_errors++;
    return;  // Treated as lost
  }
  slot.seq = seq;
  slot.rtp = rtp;
  slot.frames = static_cast<uint16_t>(frames);
  slot.valid = true;
  slot.missing_since_ms = 0;

  const int32_t new_ahead = static_cast<int16_t>(seq - this->highest_seq_);
  if (new_ahead > 0) {
    // Mark the packets in between as missing; retry_resends_() asks for them after a short delay
    for (int32_t i = 1; i < std::min(new_ahead, ahead + 1); i++) {
      PacketSlot &gap = this->slots_[(this->head_slot_ + static_cast<uint32_t>(ahead - i)) % this->slot_count_];
      gap.valid = false;
      gap.missing_since_ms = nonzero_ms(now_ms);
      gap.last_request_ms = 0;
      this->packets_missing_ = true;
    }
    this->highest_seq_ = seq;
  }

  // Leave the paused state when real audio arrives. iOS sends silence for a moment after a pause.
  if (this->session_state_ == SessionState::PAUSED) {
    const int16_t *samples = slot.samples;
    const bool audible = std::any_of(samples, samples + frames * NUM_CHANNELS, [](int16_t s) { return s != 0; });
    if (audible)
      this->set_session_state_(SessionState::PLAYING);
  }
}

void Receiver::handle_sync_packet_(const uint8_t *packet, size_t length, int64_t now_us) {
  if (length < SYNC_PACKET_SIZE)
    return;
  // The frame at bytes 4-7 is due at the sender's time in bytes 8-15, plus a fixed offset for current
  // senders. Bytes 16-19 hold the frame being sent now, so their difference is the sender's latency.
  const uint16_t flags = read_be16(packet + 2);
  const uint32_t rtp_less_latency = read_be32(packet + 4);
  const uint32_t rtp_now = read_be32(packet + 16);
  const uint32_t latency = rtp_now - rtp_less_latency;
  if (latency > MAX_SENDER_LATENCY_FRAMES)
    return;

  const uint16_t version = this->sender_version_;
  const bool fixed_offset = flags == 7 || (version > 0 && version <= 353) || version >= 371;
  int64_t remote_ns = read_ntp_ns(packet + 8);
  // The sender's clock as its sync packets show it, for a sender whose clock requests answer on another one: the
  // largest offset has the least network delay
  this->sync_offsets_[this->sync_offset_index_] = remote_ns - local_ntp_ns(now_us);
  this->sync_offset_index_ = (this->sync_offset_index_ + 1) % SYNC_OFFSET_COUNT;
  if (this->sync_offset_count_ < SYNC_OFFSET_COUNT)
    this->sync_offset_count_++;
  this->sync_clock_offset_ns_ = *std::max_element(this->sync_offsets_, this->sync_offsets_ + this->sync_offset_count_);
  if (fixed_offset)
    remote_ns += frames_to_us(FIXED_LATENCY_OFFSET_FRAMES) * 1000;
  if (this->anchor_valid_ && detail::g_log_level >= LogLevel::LOG_LEVEL_DEBUG) {
    // Where the previous anchor puts this frame: a steady difference means the sender's timeline drifts
    const int64_t expected_ns =
        this->anchor_remote_ns_ + static_cast<int64_t>(static_cast<int32_t>(rtp_less_latency - this->anchor_rtp_)) *
                                      1000000000LL / static_cast<int64_t>(SAMPLE_RATE);
    const auto moved_us = static_cast<int32_t>((remote_ns - expected_ns) / 1000);
    if (moved_us > 2000 || moved_us < -2000)
      AIRPLAY_LOGD("Sender timeline moved by %" PRId32 " us", moved_us);
  }
  this->anchor_rtp_ = rtp_less_latency;
  this->anchor_remote_ns_ = remote_ns;
  this->sender_latency_frames_ = latency + (fixed_offset ? FIXED_LATENCY_OFFSET_FRAMES : 0);
  if (!this->anchor_valid_)
    AIRPLAY_LOGV("Timeline of the sender received (latency %" PRIu32 " frames)", this->sender_latency_frames_);
  this->anchor_valid_ = true;
}

void Receiver::handle_ptp_sync_packet_(const uint8_t *packet, size_t length) {
  if (length < PTP_SYNC_PACKET_SIZE)
    return;
  // As shairport-sync reads it: the frame at bytes 4-7 is due at the PTP time in nanoseconds at bytes 8-15 on the
  // clock at bytes 20-27; bytes 16-19 hold the frame being sent now
  const uint32_t rtp = read_be32(packet + 4);
  const auto remote_ns =
      static_cast<int64_t>((static_cast<uint64_t>(read_be32(packet + 8)) << 32) | read_be32(packet + 12));
  const uint32_t rtp_now = read_be32(packet + 16);
  const uint64_t clock = (static_cast<uint64_t>(read_be32(packet + 20)) << 32) | read_be32(packet + 24);
  if (this->ptp_sync_logged_ < 3) {
    this->ptp_sync_logged_++;
    AIRPLAY_LOGV("PTP sync packet: frame %" PRIu32 " at %" PRId64 ".%09" PRId64 " s on clock %016" PRIx64
                 ", frame %" PRIu32 " now (%" PRId32 " frames ahead), flags %02x%02x",
                 rtp, remote_ns / 1000000000, remote_ns % 1000000000, clock, rtp_now,
                 static_cast<int32_t>(rtp_now - rtp), packet[2], packet[3]);
  }
  if (!this->ptp_timing_)
    return;
  const uint32_t latency = rtp_now - rtp;
  if (latency > MAX_SENDER_LATENCY_FRAMES)
    return;
  if (clock != this->ptp_timeline_)
    this->ptp_clock_ = 0;
  this->ptp_timeline_ = clock;
  this->anchor_rtp_ = rtp;
  this->anchor_remote_ns_ = remote_ns;
  this->sender_latency_frames_ = latency;
  this->anchor_valid_ = true;
}

void Receiver::update_ptp_clock_(int64_t now_us) {
  int64_t offset = 0;
  uint64_t clock = this->ptp_clock_ != 0 ? this->ptp_clock_ : this->ptp_timeline_;
  if (clock == 0 && this->session_owner_ != NO_CONNECTION) {
    // Before the sender names its timeline: its own clock, not whichever grandmaster announced itself last (Music
    // Assistant's is on the network all the time)
    clock = this->ptp_clocks_.clock_at(this->connections_[this->session_owner_].peer.address, now_us);
    if (clock == 0)
      return;
  }
  if (!this->ptp_clocks_.offset_ns(clock, now_us, &offset)) {
    // The timeline may be named after a clock that is not the one that sends Sync messages
    clock = 0;
    if (this->ptp_timeline_ == 0 || !this->ptp_clocks_.offset_ns(0, now_us, &offset)) {
      // No recent samples (the sender may have slept, which stops its clock): an old offset would be wrong
      if (this->clock_locked_) {
        this->clock_locked_ = false;
        AIRPLAY_LOGD("Lost the PTP clock, waiting for it");
      }
      return;
    }
  }
  // rtp_to_local_us_() takes offsets to the local time on the NTP time scale
  this->clock_offset_ns_ = offset - NTP_UNIX_OFFSET_NS;
  const uint64_t used = clock != 0 ? clock : this->ptp_clocks_.grandmaster();
  if (this->clock_locked_ && used != this->ptp_clock_used_)
    AIRPLAY_LOGD("Now on PTP clock %016" PRIx64 " (was %016" PRIx64 ")", used, this->ptp_clock_used_);
  int64_t jump_ns = 0;
  const uint32_t jumps = this->ptp_clocks_.jumps(used, &jump_ns);
  if (used == this->ptp_clock_used_ && jumps != this->ptp_jumps_seen_ && this->anchor_valid_ &&
      this->session_state_ == SessionState::PLAYING) {
    // While playing, the sender's clock jumps when the sender joins a group and follows its new grandmaster: it
    // sends that clock's time from then on, but keeps its anchor. As shairport-sync does, the anchor moves with the
    // clock. (A sender that sleeps has paused before.)
    this->anchor_remote_ns_ += jump_ns;
    AIRPLAY_LOGI("PTP clock %016" PRIx64 " jumped by %" PRId64 " ms while playing (a new grandmaster): the anchor "
                 "moves with it",
                 used, jump_ns / 1000000);
  }
  this->ptp_jumps_seen_ = jumps;
  this->ptp_clock_used_ = used;
  if (!this->clock_locked_) {
    this->clock_locked_ = true;
    AIRPLAY_LOGD("Clock locked to PTP clock %016" PRIx64 "%s", clock != 0 ? clock : this->ptp_clocks_.grandmaster(),
                 clock == 0 && this->ptp_timeline_ != 0 ? " (the grandmaster, not the timeline's clock)" : "");
  }
}

bool Receiver::choose_ptp_clock_(int64_t now_us, bool new_anchor) {
  if (!this->ptp_timing_ || !this->anchor_valid_)
    return false;
  uint32_t rtp = this->anchor_rtp_;
  const PacketSlot &slot = this->slots_[this->head_slot_];
  if (!new_anchor && this->have_seq_ && slot.valid && slot.seq == this->next_seq_) {
    rtp = slot.rtp;
  } else if (!new_anchor && this->have_seq_ && this->have_next_rtp_) {
    rtp = this->next_rtp_;
  }
  const int64_t remote_ns =
      this->anchor_remote_ns_ + static_cast<int64_t>(static_cast<int32_t>(rtp - this->anchor_rtp_)) * 1000000000LL /
                                    static_cast<int64_t>(SAMPLE_RATE);
  // The timeline's clock first, then the others
  uint64_t candidates[1 + PtpClocks::MAX_CLOCKS];
  candidates[0] = this->ptp_timeline_;
  const size_t count = 1 + this->ptp_clocks_.active_clocks(candidates + 1, PtpClocks::MAX_CLOCKS, now_us);
  uint64_t chosen = 0;
  for (size_t i = 0; i < count && chosen == 0; i++) {
    int64_t offset = 0;
    if (candidates[i] == 0 || !this->ptp_clocks_.offset_ns(candidates[i], now_us, &offset))
      continue;
    const int64_t ahead_ns = remote_ns - (now_us * 1000 + offset);
    if (ahead_ns > -MAX_TIMELINE_ERROR_US * 1000 && ahead_ns < MAX_TIMELINE_ERROR_US * 1000)
      chosen = candidates[i];
  }
  // None fits (a clock that jumped and has not settled yet): the timeline's, and wait for it
  if (chosen == this->ptp_timeline_)
    chosen = 0;
  if (chosen == this->ptp_clock_)
    return false;
  this->ptp_clock_ = chosen;
  if (chosen != 0)
    AIRPLAY_LOGI("The timeline of PTP clock %016" PRIx64 " is in the time of PTP clock %016" PRIx64
                 " (the sender follows it), following that",
                 this->ptp_timeline_, chosen);
  this->clock_locked_ = false;
  this->update_ptp_clock_(now_us);
  return true;
}

void Receiver::set_ptp_timing_(bool ptp) {
  if (ptp)
    AIRPLAY_LOGD("Timing with PTP");
  this->ptp_timing_ = ptp;
  this->ptp_timeline_ = 0;
  this->ptp_clock_ = 0;
  this->ptp_error_logged_ = false;
  this->anchor_fits_clock_ = false;
  this->ptp_sync_logged_ = 0;
  if (ptp)
    this->clock_locked_ = false;
}

void Receiver::send_timing_request_(int64_t now_us) {
  this->last_timing_request_ms_ = to_ms(now_us);
  this->timing_requests_sent_++;
  if (this->client_timing_.port == 0)
    return;
  uint8_t request[TIMING_PACKET_SIZE] = {0x80, 0x80 | PAYLOAD_TIMING_REQUEST, 0x00, 0x07};
  write_ntp_ns(request + 24, local_ntp_ns(now_us));
  this->transport_.send_udp(UdpChannel::TIMING, this->client_timing_, request, sizeof(request));
}

void Receiver::handle_timing_reply_(const uint8_t *packet, size_t length, int64_t now_us) {
  if (length < TIMING_PACKET_SIZE)
    return;
  const int64_t arrival = local_ntp_ns(now_us);
  const int64_t origin = read_ntp_ns(packet + 8);     // Our transmit time, echoed back
  const int64_t receive = read_ntp_ns(packet + 16);   // Sender's receive time
  const int64_t transmit = read_ntp_ns(packet + 24);  // Sender's transmit time
  const int64_t round_trip = (arrival - origin) - (transmit - receive);
  if (round_trip < 0 || round_trip > TIMING_MAX_ROUND_TRIP_NS)
    return;

  TimingSample &sample = this->timing_samples_[this->timing_sample_index_];
  sample.offset_ns = ((receive - origin) + (transmit - arrival)) / 2;
  sample.round_trip_ns = round_trip;
  this->timing_sample_index_ = (this->timing_sample_index_ + 1) % TIMING_SAMPLE_COUNT;
  if (this->timing_sample_count_ < TIMING_SAMPLE_COUNT)
    this->timing_sample_count_++;

  // The sample with the shortest round trip has the smallest error
  const TimingSample *best = &this->timing_samples_[0];
  for (uint32_t i = 1; i < this->timing_sample_count_; i++) {
    if (this->timing_samples_[i].round_trip_ns < best->round_trip_ns)
      best = &this->timing_samples_[i];
  }
  this->clock_offset_ns_ = best->offset_ns;
  if (!this->clock_locked_ && this->timing_sample_count_ >= TIMING_LOCK_SAMPLES) {
    this->clock_locked_ = true;
    AIRPLAY_LOGD("Clock locked to the sender (round trip %" PRId32 " us)",
                 static_cast<int32_t>(best->round_trip_ns / 1000));
  }
}

void Receiver::handle_timing_request_(UdpChannel channel, const uint8_t *packet, size_t length, const Endpoint &from,
                                      int64_t now_us) {
  if (length < TIMING_PACKET_SIZE)
    return;
  uint8_t reply[TIMING_PACKET_SIZE] = {0x80, 0x80 | PAYLOAD_TIMING_REPLY, 0x00, 0x07};
  // Origin time is the requester's transmit time, then our receive and transmit times
  std::memcpy(reply + 8, packet + 24, 8);
  write_ntp_ns(reply + 16, local_ntp_ns(now_us));
  std::memcpy(reply + 24, reply + 16, 8);
  this->transport_.send_udp(channel, from, reply, sizeof(reply));
}

void Receiver::retry_resends_(uint32_t now_ms) {
  // Most of the time nothing is missing, and the scan reads a slot header in external RAM per buffered packet
  if (!this->have_seq_ || !this->packets_missing_)
    return;
  const uint32_t buffered = this->buffered_packets_();
  const auto due = [now_ms](const PacketSlot &s) {
    if (s.valid || s.missing_since_ms == 0)
      return false;
    return s.last_request_ms == 0 ? now_ms - s.missing_since_ms >= RESEND_FIRST_DELAY_MS
                                  : now_ms - s.last_request_ms >= RESEND_RETRY_INTERVAL_MS;
  };
  uint32_t ranges = 0;
  uint32_t i = 0;
  bool missing = false;
  while (i < buffered && ranges < MAX_RESEND_RANGES) {
    const PacketSlot &next = this->slots_[(this->head_slot_ + i) % this->slot_count_];
    if (!due(next)) {
      missing = missing || (!next.valid && next.missing_since_ms != 0);
      i++;
      continue;
    }
    missing = true;
    // Ask for a run of consecutive missing packets at once
    const auto first = static_cast<uint16_t>(this->next_seq_ + i);
    uint16_t count = 0;
    while (i < buffered) {
      PacketSlot &slot = this->slots_[(this->head_slot_ + i) % this->slot_count_];
      if (!due(slot))
        break;
      slot.last_request_ms = nonzero_ms(now_ms);
      count++;
      i++;
    }
    this->request_resend_(first, count);
    ranges++;
  }
  this->packets_missing_ = missing;
}

void Receiver::request_resend_(uint16_t first, uint16_t count) {
  this->stats_.resend_requests++;
  if (this->client_control_.port == 0)
    return;
  const uint8_t request[8] = {
      0x80,
      0x80 | PAYLOAD_RESEND_REQUEST,
      static_cast<uint8_t>(this->resend_seq_ >> 8),
      static_cast<uint8_t>(this->resend_seq_),
      static_cast<uint8_t>(first >> 8),
      static_cast<uint8_t>(first),
      static_cast<uint8_t>(count >> 8),
      static_cast<uint8_t>(count),
  };
  this->resend_seq_++;
  this->transport_.send_udp(UdpChannel::CONTROL, this->client_control_, request, sizeof(request));
  AIRPLAY_LOGV("Requested %u packets from %u again", count, first);
}

uint32_t Receiver::speaker_queued_frames_() const {
  const auto written = static_cast<uint32_t>(this->frames_written_);
  const uint32_t queued = written - this->frames_played_.load(std::memory_order_relaxed);
  // Reports from audio of an earlier session can exceed what this session wrote
  return queued > INT32_MAX ? 0 : queued;
}

uint32_t Receiver::buffered_packets_() const {
  if (!this->have_seq_)
    return 0;
  const int32_t span = static_cast<int16_t>(this->highest_seq_ - this->next_seq_) + 1;
  return span > 0 ? static_cast<uint32_t>(span) : 0;
}

void Receiver::advance_head_() {
  PacketSlot &slot = this->slots_[this->head_slot_];
  // Track the timestamp of the next packet, so that a missing one can still be timed
  if (slot.valid && slot.seq == this->next_seq_) {
    this->next_rtp_ = slot.rtp + slot.frames;
    this->have_next_rtp_ = true;
  } else if (this->have_next_rtp_) {
    this->next_rtp_ += FRAMES_PER_PACKET;
  }
  slot.valid = false;
  slot.missing_since_ms = 0;
  this->head_slot_ = (this->head_slot_ + 1) % this->slot_count_;
  this->next_seq_++;
}

bool Receiver::rtp_to_local_us_(uint32_t rtp, int64_t *local_us) const {
  if (!this->anchor_valid_ || !this->clock_locked_)
    return false;
  const int64_t remote_ns =
      this->anchor_remote_ns_ + static_cast<int64_t>(static_cast<int32_t>(rtp - this->anchor_rtp_)) * 1000000000LL /
                                    static_cast<int64_t>(SAMPLE_RATE);
  const int64_t offset_ns =
      this->timeline_mismatch_ && this->sync_offset_count_ > 0 ? this->sync_clock_offset_ns_ : this->clock_offset_ns_;
  *local_us = (remote_ns - offset_ns - NTP_UNIX_OFFSET_NS) / 1000;
  return true;
}

bool Receiver::write_pending_output_(uint32_t now_ms) {
  if (this->output_offset_ >= this->output_length_)
    return true;
  const int64_t write_start = this->clock_now_();
  const size_t written = this->sink_.write(this->output_buffer_ + this->output_offset_ * NUM_CHANNELS,
                                           this->output_length_ - this->output_offset_);
  add_us(this->write_us_, this->clock_now_() - write_start);
  if (written > 0 && this->first_write_ms_ == 0)
    this->first_write_ms_ = nonzero_ms(now_ms);
  this->output_offset_ += written;
  this->frames_written_ += written;
  // Not done if the sink is full
  return this->output_offset_ >= this->output_length_;
}

void Receiver::queue_packet_output_(const PacketSlot &slot, int32_t trim, uint32_t skip) {
  const int64_t copy_start = this->clock_now_();
  int16_t *samples = this->output_buffer_;
  uint32_t frames = slot.frames - skip;
  std::memcpy(samples, slot.samples + skip * NUM_CHANNELS, frames * BYTES_PER_FRAME);

  const auto count = static_cast<uint32_t>(std::min(std::abs(trim), MAX_TRIM_FRAMES));
  if (count > 0 && frames > count + 2) {
    this->stats_.trimmed_frames += count;
    // Drop or repeat frames where the audio is quietest, which makes the seam inaudible
    uint32_t quietest = 1;
    int32_t quietest_level = INT32_MAX;
    for (uint32_t i = 1; i + count + 1 < frames; i++) {
      const int32_t level = std::abs(samples[i * NUM_CHANNELS]) + std::abs(samples[i * NUM_CHANNELS + 1]);
      if (level < quietest_level) {
        quietest_level = level;
        quietest = i;
      }
    }
    int16_t *at = samples + quietest * NUM_CHANNELS;
    if (trim < 0) {
      std::memmove(at, at + count * NUM_CHANNELS, (frames - quietest - count) * BYTES_PER_FRAME);
      frames -= count;
    } else {
      std::memmove(at + (count + 1) * NUM_CHANNELS, at + NUM_CHANNELS, (frames - quietest - 1) * BYTES_PER_FRAME);
      for (uint32_t i = 1; i <= count; i++)
        std::memcpy(at + i * NUM_CHANNELS, at, BYTES_PER_FRAME);
      frames += count;
    }
  }
  this->output_offset_ = 0;
  this->output_length_ = frames;
  add_us(this->copy_us_, this->clock_now_() - copy_start);
}

void Receiver::queue_silence_output_() {
  const uint32_t frames = std::min(this->silence_pending_frames_, FRAMES_PER_PACKET + 1);
  std::memset(this->output_buffer_, 0, frames * BYTES_PER_FRAME);
  this->stats_.silence_frames += frames;
  this->silence_pending_frames_ -= frames;
  this->output_offset_ = 0;
  this->output_length_ = frames;
}

void Receiver::poll(int64_t now_us) {
  if (this->slots_ == nullptr)
    return;
  if (this->airplay2_)
    this->update_group_();
  const int64_t poll_start = this->clock_now_();
  const uint32_t now_ms = to_ms(now_us);
  if (this->audio_active_) {
    if (this->last_poll_ms_ != 0)
      this->stats_.longest_gap_ms = std::max(this->stats_.longest_gap_ms, now_ms - this->last_poll_ms_);
    this->last_poll_ms_ = now_ms;
  }

  this->poll_ms_ = now_ms;
  this->update_event_channel_ready_(now_ms);
  this->update_sender_address_();
  this->update_sender_name_();
  this->send_sender_requests_(now_ms);

  // Room again for cover art: at least what may arrive at once, so that reading does not stop right away again
  if (this->artwork_paused_ != NO_CONNECTION && this->listener_->artwork_room() >= ARTWORK_RESERVE + RTSP_BUFFER_SIZE)
    this->resume_artwork_();

  if (this->disconnect_requested_.exchange(false, std::memory_order_acq_rel)) {
    if (this->session_owner_ != NO_CONNECTION) {
      AIRPLAY_LOGI("Disconnecting the sender");
      this->close_connection_(this->session_owner_);
    }
  }

  const bool hold = this->hold_requested_.load(std::memory_order_acquire);
  if (hold != this->audio_held_) {
    this->audio_held_ = hold;
    this->held_silence_logged_ = false;
    if (hold) {
      AIRPLAY_LOGD("Holding the sender's audio");
    } else {
      AIRPLAY_LOGD("Playing the sender's audio again");
    }
    // Audio was dropped meanwhile, so start over with what arrives next
    if (this->audio_active_) {
      this->reset_playback_();
      this->accept_any_seq_ = true;
    }
  }

  if (this->output_restart_requested_.exchange(false, std::memory_order_acq_rel)) {
    this->output_restart_pending_ = true;
    this->output_restart_ms_ = now_ms;
  }
  if (this->output_restart_pending_) {
    // Nothing is written while the output finishes its reset, as it would not be counted
    if (now_ms - this->output_restart_ms_ < OUTPUT_RESTART_SETTLE_MS)
      return;
    this->output_restart_pending_ = false;
    this->frames_written_ = 0;
    this->first_write_ms_ = 0;
    this->output_offset_ = this->output_length_;  // Drop a half written packet
    this->frames_played_.store(0, std::memory_order_relaxed);
    this->played_timestamp_.store(0, std::memory_order_relaxed);
  }

  if (this->ptp_open_)
    this->ptp_clocks_.log_status(now_us);
  if (!this->udp_open_)
    return;
  if (this->ptp_timing_) {
    uint8_t message[PtpClocks::MAX_MESSAGE_SIZE];
    uint32_t to = 0;
    bool general = false;
    const uint64_t followed = this->ptp_clock_ != 0 ? this->ptp_clock_ : this->ptp_timeline_;
    if (const size_t length = this->ptp_clocks_.next_message(followed, message, now_us, &to, &general)) {
      this->transport_.send_ptp(general, Endpoint{to, general ? PTP_GENERAL_PORT : PTP_EVENT_PORT}, message, length);
    }
    this->update_ptp_clock_(now_us);
  }
  // Keep asking quickly until the clock locks, so that a lost packet does not delay synchronized playback
  const uint32_t timing_interval = this->timing_requests_sent_ < TIMING_BURST_COUNT || !this->clock_locked_
                                       ? TIMING_BURST_INTERVAL_MS
                                       : TIMING_INTERVAL_MS;
  if (this->timing_requests_sent_ == 0 || now_ms - this->last_timing_request_ms_ >= timing_interval)
    this->send_timing_request_(now_us);

  if (!this->audio_active_)
    return;

  if (this->audio_held_) {
    // Buffered audio stays with the sender, which waits while the connection is not read. It pauses and plays by
    // SETRATEANCHORTIME, so it is not shown as paused for sending nothing.
    if (!this->buffered_stream_ && this->session_state_ == SessionState::PLAYING &&
        now_ms - this->last_packet_ms_ > SENDER_IDLE_MS)
      this->set_session_state_(SessionState::PAUSED);
    return;
  }

  const int64_t timers_end = this->clock_now_();
  add_us(this->timers_us_, timers_end - poll_start);
  if (this->buffered_stream_) {
    this->decode_buffered_audio_(now_us);
  } else if (now_ms - this->last_resend_scan_ms_ >= RESEND_SCAN_INTERVAL_MS) {
    this->last_resend_scan_ms_ = now_ms;
    this->retry_resends_(now_ms);
    add_us(this->resend_us_, this->clock_now_() - timers_end);
  }

  // A sender that stops sending without a FLUSH (e.g. iOS after a long pause) is shown as paused.
  // Dead senders are detected by TCP keepalive on the RTSP connection.
  if (this->session_state_ == SessionState::PLAYING && now_ms - this->last_packet_ms_ > SENDER_IDLE_MS) {
    AIRPLAY_LOGD("No audio from the sender for %" PRIu32 " ms (%" PRIu32 " packets buffered%s)",
                 now_ms - this->last_packet_ms_, this->buffered_packets_(),
                 this->receive_paused_ ? ", not reading its connection" : "");
    this->set_session_state_(SessionState::PAUSED);
  }

  this->playback_step_(now_us);
}

void Receiver::playback_step_(int64_t now_us) {
  const uint32_t now_ms = to_ms(now_us);
  // How evenly the output reports played audio: a long gap makes the queued audio look larger than it is
  const uint32_t reported_at = this->played_timestamp_.load(std::memory_order_relaxed);
  if (reported_at != this->last_report_us_) {
    if (this->last_report_us_ != 0 && this->playback_started_) {
      const uint32_t gap_ms = (reported_at - this->last_report_us_) / 1000;
      this->stats_.longest_report_gap_ms = std::max(this->stats_.longest_report_gap_ms, gap_ms);
    }
    this->last_report_us_ = reported_at;
  }
  if (!this->played_reports_missing_ && this->first_write_ms_ != 0 &&
      this->frames_played_.load(std::memory_order_relaxed) == 0 &&
      now_ms - this->first_write_ms_ > PLAYED_REPORT_TIMEOUT_MS) {
    this->played_reports_missing_ = true;
    AIRPLAY_LOGW("The output does not report played audio; playback cannot be synchronized");
    this->synced_ = false;
  }
  this->stats_.synchronized = this->playback_started_ && this->synced_;

  // The output ran dry while playing: an underrun, unless the sender stopped sending
  // Also when the last report is older than the audio still queued lasts: outputs that report in chunks leave the
  // end of the audio unreported until more arrives
  const int64_t queued_us = frames_to_us(this->speaker_queued_frames_());
  const auto report_age_us = static_cast<int32_t>(static_cast<uint32_t>(now_us) - reported_at);
  const bool dry = this->playback_started_ && this->frames_written_ > 0 &&
                   this->frames_played_.load(std::memory_order_relaxed) != 0 &&
                   (queued_us == 0 || (reported_at != 0 && report_age_us > queued_us + DRY_MARGIN_US));
  // Before the first packet of a playback is lined up, the output is empty on purpose and the start handles it
  if (dry && !this->output_dry_ && this->start_aligned_) {
    if (this->buffered_packets_() > 0)
      this->stats_.underruns++;
    // The output may fill the gap with silence of its own that is not counted: what follows is lined up anew
    this->kick_output_ = true;
    this->waiting_for_output_ = false;
    this->start_aligned_ = false;
  }
  this->output_dry_ = dry;

  if (!this->playback_started_ && this->session_state_ == SessionState::PLAYING &&
      now_ms - this->last_stats_log_ms_ >= STATS_LOG_INTERVAL_MS) {
    // Why a session that plays gives no audio
    this->last_stats_log_ms_ = now_ms;
    AIRPLAY_LOGD("Not playing: %" PRIu32 " packets buffered, last audio %" PRIu32 " ms ago, clock %s, anchor %s%s",
                 this->buffered_packets_(), now_ms - this->last_packet_ms_,
                 this->clock_locked_ ? "locked" : "not locked", this->anchor_valid_ ? "valid" : "missing",
                 this->buffered_stream_ && !this->buffered_playing_ ? ", rate 0" : "");
  }
  if (this->playback_started_ && now_ms - this->last_stats_log_ms_ >= STATS_LOG_INTERVAL_MS) {
    this->last_stats_log_ms_ = now_ms;
    const ReceiverStats &st = this->stats_;
    AIRPLAY_LOGD("%s: buffered %" PRIu32 " ms, output %" PRIu32 " ms, servo %" PRId32 " us; lost %" PRIu32
                 ", late %" PRIu32 ", resend requests %" PRIu32 ", trimmed frames %" PRIu32 ", silence %" PRIu32
                 " ms, underruns %" PRIu32,
                 this->synced_ ? "Synchronized" : "Unsynchronized",
                 static_cast<uint32_t>(frames_to_us(this->buffered_packets_() * FRAMES_PER_PACKET) / 1000),
                 static_cast<uint32_t>(frames_to_us(this->speaker_queued_frames_()) / 1000), this->servo_error_us_,
                 st.lost_packets, st.late_packets, st.resend_requests, st.trimmed_frames,
                 static_cast<uint32_t>(frames_to_us(st.silence_frames) / 1000), st.underruns);
    AIRPLAY_LOGD("Timing: longest poll gap %" PRIu32 " ms, longest output report gap %" PRIu32
                 " ms, foreign packets %" PRIu32,
                 st.longest_gap_ms, st.longest_report_gap_ms, st.foreign_packets);
    this->late_detail_logged_ = false;
  }

  if (!this->have_seq_)
    return;
  // Buffered audio plays only between SETRATEANCHORTIME with rate 1 and the next with rate 0
  if (this->buffered_stream_ && !this->buffered_playing_)
    return;
  if (!this->playback_started_ && !this->start_playback_())
    return;

  // Only steps that give the output audio count: packets that are dropped as late go quickly, which matters right
  // after a start, when the output must not run dry while they go
  for (uint32_t chunks = 0, steps = 0; chunks < MAX_CHUNKS_PER_STEP && steps < MAX_STEPS_PER_POLL; steps++) {
    if (!this->write_pending_output_(now_ms))
      return;
    chunks++;
    if (this->silence_pending_frames_ > 0) {
      this->queue_silence_output_();
      continue;
    }
    if (this->buffered_packets_() == 0) {
      if (this->speaker_queued_frames_() == 0)
        this->playback_started_ = false;  // Ran dry, so start again once there is enough audio
      return;
    }
    const uint32_t written_before = static_cast<uint32_t>(this->frames_written_);
    const bool queued_before = this->output_offset_ < this->output_length_;
    if (!(this->synced_ ? this->synced_step_(now_us) : this->unsynced_step_()))
      return;
    if (!queued_before && this->output_offset_ >= this->output_length_ &&
        static_cast<uint32_t>(this->frames_written_) == written_before)
      chunks--;  // Nothing for the output
  }
}

bool Receiver::start_playback_() {
  const uint32_t buffered = this->buffered_packets_();
  if (buffered == 0)
    return false;  // Nothing to play, e.g. at the end of a stream
  const uint32_t capacity_frames = this->slot_count_ * FRAMES_PER_PACKET;
  const bool fits = capacity_frames >= this->sender_latency_frames_ + SYNC_MARGIN_FRAMES;

  if (this->clock_locked_ && this->anchor_valid_ && fits && !this->played_reports_missing_ &&
      !this->timeline_unusable_) {
    this->synced_ = true;
  } else {
    // Wait for the sender's clock while the buffer has room, unless synchronized playback is impossible anyway.
    // Packets that become due in the meantime are dropped once playback starts.
    const bool may_sync = !this->played_reports_missing_ && (!this->anchor_valid_ || fits);
    if (may_sync && buffered + 1 < this->slot_count_)
      return false;
    const uint32_t level = this->speaker_queued_frames_() + buffered * FRAMES_PER_PACKET;
    if (level < this->fill_target_frames_ && buffered + 1 < this->slot_count_)
      return false;
    this->synced_ = false;
  }

  if (!this->sync_logged_) {
    this->sync_logged_ = true;
    if (this->synced_) {
      AIRPLAY_LOGI("Playback synchronized to the sender (latency %" PRIu32 " ms)",
                   static_cast<uint32_t>(frames_to_us(this->sender_latency_frames_) / 1000));
    } else if (this->anchor_valid_ && !fits) {
      AIRPLAY_LOGW("Playback not synchronized: the sender needs %" PRIu32 " ms of buffer, set buffer_ms to at "
                   "least %" PRIu32,
                   static_cast<uint32_t>(frames_to_us(this->sender_latency_frames_) / 1000),
                   static_cast<uint32_t>(frames_to_us(this->sender_latency_frames_ + SYNC_MARGIN_FRAMES) / 1000));
    } else {
      AIRPLAY_LOGI("Playback not synchronized to the sender");
    }
  } else {
    // After a pause, a seek or an underrun. When the output takes nothing (e.g. another source plays on the speaker),
    // this repeats for every packet, so only every 100th is logged.
    if (this->restarts_++ % 100 == 0) {
      AIRPLAY_LOGD("Playback restarted (%s, %" PRIu32 " times)", this->synced_ ? "synchronized" : "not synchronized",
                   this->restarts_);
    }
  }
  this->playback_started_ = true;
  this->output_starting_ = false;
  this->start_aligned_ = false;
  this->kick_output_ = this->speaker_queued_frames_() == 0;
  this->waiting_for_output_ = false;
  this->servo_error_us_ = 0;
  this->servo_engaged_ = false;
  this->drift_error_ = 0;
  return true;
}

bool Receiver::synced_step_(int64_t now_us) {
  const PacketSlot &slot = this->slots_[this->head_slot_];
  const bool present = slot.valid && slot.seq == this->next_seq_;
  if (!present && !this->have_next_rtp_) {
    // Nothing to time a missing first packet against
    this->advance_head_();
    return true;
  }
  const uint32_t rtp = present ? slot.rtp : this->next_rtp_;
  int64_t target_us;
  if (!this->rtp_to_local_us_(rtp, &target_us)) {
    // Lost the timing reference (e.g. a seek and no sync packet yet): wait, then start over
    this->playback_started_ = false;
    return false;
  }

  const int64_t queued_us = frames_to_us(this->speaker_queued_frames_());
  if (queued_us >= static_cast<int64_t>(this->config_.output_queue_ms) * 1000)
    return false;
  // The output reports played audio in chunks. The audio it reported last ended at the report's timestamp,
  // and the queued audio follows on from there, which is more precise than counting from now.
  int64_t heard_us = now_us + queued_us;
  const uint32_t reported_at = this->played_timestamp_.load(std::memory_order_relaxed);
  if (queued_us > 0 && reported_at != 0) {
    const auto age_us = static_cast<int32_t>(static_cast<uint32_t>(now_us) - reported_at);
    if (age_us < REPORT_MAX_AGE_US)
      heard_us = std::max(now_us, now_us - age_us + queued_us);
  }
  // Positive: the packet would be heard too early; negative: too late
  const int64_t error_us = target_us - heard_us;
  if (error_us < -MAX_TIMELINE_ERROR_US && this->buffered_stream_ && this->anchor_fits_clock_) {
    // Audio from before a new anchor that fits the clock (Music Assistant resumes a pause further on its timeline)
    if (present)
      this->stats_.late_packets++;
    this->advance_head_();
    return true;
  }
  if ((error_us > MAX_TIMELINE_ERROR_US || error_us < -MAX_TIMELINE_ERROR_US) && this->ptp_timing_) {
    // The sender joined a group and its time is now another speaker's clock's: follow that clock
    if (this->choose_ptp_clock_(now_us, false))
      return false;
    // A PTP clock that jumped (its sender slept) gives a wrong time until its next samples: wait for them
    if (!this->ptp_error_logged_) {
      this->ptp_error_logged_ = true;
      AIRPLAY_LOGW("The anchor is %" PRId64 " s off the PTP clock, waiting for the clock", error_us / 1000000);
    }
    this->playback_started_ = false;
    return false;
  }
  if (error_us > MAX_TIMELINE_ERROR_US || error_us < -MAX_TIMELINE_ERROR_US) {
    // The sender's sync packets and its clock disagree: Music Assistant answers clock requests on a group's PTP
    // timeline, or 70 years apart, but sends its own time in sync packets. Its sync packets are followed instead,
    // which only adds the network delay; if that does not fit either, it plays without synchronization.
    if (!this->timeline_mismatch_) {
      AIRPLAY_LOGW("The sender's timeline is %" PRId64 " s off its clock, following its sync packets",
                   error_us / 1000000);
      this->timeline_mismatch_ = true;
    } else {
      AIRPLAY_LOGW("The sender's timeline does not fit its sync packets either, playing without synchronization");
      this->timeline_unusable_ = true;
    }
    this->playback_started_ = false;
    return false;
  }
  // An empty output (not started yet, or run dry) may play its own silence that nobody counts (ESPHome's I2S
  // speaker keeps 50 ms of DMA buffers full), and may take a while to start. It is started with a little silence
  // ahead of time, and the audio is lined up once it reports what it played.
  const uint32_t played = this->frames_played_.load(std::memory_order_relaxed);
  if (this->kick_output_) {
    if (error_us > OUTPUT_START_LEAD_US)
      return false;
    this->kick_output_ = false;
    this->waiting_for_output_ = true;
    this->played_at_kick_ = played;
    this->kick_ms_ = nonzero_ms(to_ms(now_us));
    this->silence_pending_frames_ = OUTPUT_START_FRAMES;
    return true;
  }
  if (this->waiting_for_output_) {
    // An output that never reports plays unsynchronized after a timeout; one that stopped reporting goes on
    if (played == this->played_at_kick_ && to_ms(now_us) - this->kick_ms_ < PLAYED_REPORT_TIMEOUT_MS)
      return false;
    this->waiting_for_output_ = false;
    this->output_starting_ = true;
  }
  // Once the output plays, the audio is lined up at once, before the output runs dry again
  if (error_us > START_WINDOW_US && !this->output_starting_)
    return false;
  this->output_starting_ = false;

  if (!present) {
    if (error_us > CONCEAL_MARGIN_US)
      return false;  // Still time for the retransmission
    // Fill the gap with silence, unless it is long past already
    if (error_us > -EARLY_LATE_THRESHOLD_US)
      this->silence_pending_frames_ = FRAMES_PER_PACKET;
    this->stats_.lost_packets++;
    this->advance_head_();
    return true;
  }

  if (error_us < -EARLY_LATE_THRESHOLD_US) {
    AIRPLAY_LOGV("Packet %u is %" PRId32 " ms late", this->next_seq_, static_cast<int32_t>(-error_us / 1000));
    if (!this->late_logged_) {
      // Once per stream: tells a sender's timing that does not fit its audio from a short hold-up
      this->late_logged_ = true;
      AIRPLAY_LOGD("First late packet: %" PRId32 " ms late, %" PRIu32 " packets buffered, sender %u, "
                   "latency %" PRIu32 " ms",
                   static_cast<int32_t>(-error_us / 1000), this->buffered_packets_(), this->sender_version_,
                   static_cast<uint32_t>(frames_to_us(this->sender_latency_frames_) / 1000));
    }
    if (!this->late_detail_logged_) {
      // At most once per statistics line: whether the output queue or an old report made the packet late
      this->late_detail_logged_ = true;
      // A report may have come in after now_us was taken
      const int32_t report_age_ms =
          reported_at != 0
              ? std::max<int32_t>(static_cast<int32_t>(static_cast<uint32_t>(now_us) - reported_at), 0) / 1000
              : -1;
      AIRPLAY_LOGD("Late packet: %" PRId32 " ms late, output queue %" PRIu32 " ms, last output report %" PRId32
                   " ms ago, servo %" PRId32 " us",
                   static_cast<int32_t>(-error_us / 1000), static_cast<uint32_t>(queued_us / 1000), report_age_ms,
                   this->servo_error_us_);
    }
    this->stats_.late_packets++;
    this->advance_head_();
    return true;
  }
  // The first packets after a start may be due already (macOS anchors a stream at the present): those that are
  // past are dropped and the late part of the next one is left out, which lines up exactly instead of trimming
  // frames for seconds
  if (!this->start_aligned_ && error_us < 0) {
    const auto late_frames = static_cast<uint32_t>(-error_us * SAMPLE_RATE / 1000000);
    if (late_frames >= slot.frames) {
      this->stats_.late_packets++;
      this->advance_head_();
      return true;
    }
    this->start_aligned_ = true;
    this->servo_error_us_ = 0;
    this->queue_packet_output_(slot, 0, late_frames);
    this->advance_head_();
    return true;
  }
  // Line up with silence when far too early, and the first packet after a start exactly
  if (error_us > EARLY_LATE_THRESHOLD_US || (error_us > 0 && (queued_us == 0 || !this->start_aligned_))) {
    this->silence_pending_frames_ = static_cast<uint32_t>(error_us * SAMPLE_RATE / 1000000);
    this->servo_error_us_ = 0;
    if (this->silence_pending_frames_ > 0)
      return true;
  }

  // Filter the timing error; one reading can move it only a little, because late readings are common
  // when the driving thread was briefly held up
  const auto innovation = static_cast<int32_t>(
      std::clamp<int64_t>(error_us - this->servo_error_us_, -SERVO_INNOVATION_CLAMP_US, SERVO_INNOVATION_CLAMP_US));
  this->servo_error_us_ += innovation / SERVO_FILTER_DIV;
  const int32_t magnitude = std::abs(this->servo_error_us_);
  if (magnitude > SERVO_ENGAGE_US) {
    this->servo_engaged_ = true;
  } else if (magnitude < SERVO_DISENGAGE_US) {
    this->servo_engaged_ = false;
  }
  // Larger errors (e.g. after the clock estimate moved) are corrected on every packet, small ones slowly
  const uint32_t interval = magnitude > SERVO_FAST_US ? 1 : SERVO_TRIM_INTERVAL;
  int32_t trim = 0;
  if (this->servo_engaged_ && ++this->trim_counter_ >= interval) {
    this->trim_counter_ = 0;
    // Large errors several frames at once. The current reading limits it too, so that it stops in time when the
    // filtered error lags behind.
    int32_t frames = 1;
    if (magnitude > SERVO_LARGE_US && (error_us > 0) == (this->servo_error_us_ > 0)) {
      const auto smaller = static_cast<int32_t>(std::min<int64_t>(magnitude, std::abs(error_us)));
      frames = std::clamp<int32_t>(smaller / SERVO_FAST_FRAME_US, 1, MAX_TRIM_FRAMES);
    }
    trim = this->servo_error_us_ > 0 ? frames : -frames;  // Early: repeat frames; late: drop some
  }

  this->start_aligned_ = true;
  this->queue_packet_output_(slot, trim);
  this->advance_head_();
  return true;
}

bool Receiver::unsynced_step_() {
  const uint32_t buffered = this->buffered_packets_();
  const uint32_t queued = this->speaker_queued_frames_();
  const bool have_reports = this->frames_played_.load(std::memory_order_relaxed) != 0;

  const PacketSlot &slot = this->slots_[this->head_slot_];
  if (have_reports && buffered > 1 &&
      queued + buffered * FRAMES_PER_PACKET > this->fill_target_frames_ + OVERFILL_FRAMES) {
    // Far too much audio, e.g. it piled up while the output was busy: skip whole packets, which is much
    // quicker than the level control
    this->advance_head_();
    return true;
  }

  if (!slot.valid || slot.seq != this->next_seq_) {
    // Missing packet: wait for the retransmission while the output still has audio
    if (queued > CONCEAL_THRESHOLD_FRAMES && buffered + 1 < this->slot_count_)
      return false;
    this->silence_pending_frames_ = FRAMES_PER_PACKET;
    this->stats_.lost_packets++;
    this->advance_head_();
    return true;
  }

  // The sender's clock and the output's clock drift apart slowly. Keep the buffer level on target by
  // dropping or repeating single frames. Needs the output's playback reports to measure the level.
  int32_t trim = 0;
  if (have_reports) {
    const auto level = static_cast<int32_t>(queued + (buffered - 1) * FRAMES_PER_PACKET);
    const int32_t error = level - static_cast<int32_t>(this->fill_target_frames_);
    this->drift_error_ += (error - this->drift_error_) >> FILL_SMOOTHING_SHIFT;
    if (std::abs(this->drift_error_) > FILL_DEADBAND_FRAMES && ++this->trim_counter_ >= SERVO_TRIM_INTERVAL) {
      this->trim_counter_ = 0;
      trim = this->drift_error_ > 0 ? -1 : 1;  // Too much audio: drop a frame; too little: repeat one
    }
  }
  this->queue_packet_output_(slot, trim);
  this->advance_head_();
  return true;
}

}  // namespace airplay
