// AirPlay 2 part of the receiver: transient pairing, the encrypted RTSP connection, session and stream setup
// with property lists, and the encrypted audio of realtime streams.

#include "airplay_fairplay.h"
#include "airplay_log.h"
#include "airplay_plist.h"
#include "airplay_receiver.h"
#include "airplay_srp.h"
#include "airplay_tlv8.h"
#include "airplay_util.h"

#include <algorithm>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <utility>

namespace airplay {

// Feature bits, as in the "features" TXT record: audio (9), redundant audio (11), FairPlay (14), audio formats
// (18-20, 22), unified advertiser info (30), control channel encryption (38), buffered audio (40), NTP timing (45),
// HomeKit pairing and peer management (46, 47) and transient pairing (48). iOS streams only to receivers with
// FairPlay; without buffered audio it falls back to ANNOUNCE with a FairPlay encrypted key, and with NTP instead
// of PTP timing (41) it uses NTP, as the experiments in openairplay/airplay2-receiver noted.
static constexpr uint64_t DEFAULT_FEATURES = 0x1E140405C4A00ULL;
/// Status flags: an audio receiver
static constexpr int64_t STATUS_FLAGS = 0x4;

static constexpr char CONTENT_TYPE_PLIST[] = "application/x-apple-binary-plist";
static constexpr char CONTENT_TYPE_OCTET_STREAM[] = "application/octet-stream";

// Transient pair-setup: the PIN is fixed and the result is only used for this connection
static constexpr char PAIR_SETUP_USERNAME[] = "Pair-Setup";
static constexpr char TRANSIENT_PIN[] = "3939";
static constexpr char CONTROL_SALT[] = "Control-Salt";
static constexpr char CONTROL_SENDER_WRITE_INFO[] = "Control-Write-Encryption-Key";
static constexpr char CONTROL_SENDER_READ_INFO[] = "Control-Read-Encryption-Key";

/// Stream type of realtime audio over UDP; 103 is buffered audio over TCP
static constexpr int64_t STREAM_TYPE_REALTIME = 96;
static constexpr int64_t STREAM_TYPE_BUFFERED = 103;
/// Compression types ("ct") of a stream
static constexpr int64_t COMPRESSION_PCM = 1;
static constexpr int64_t COMPRESSION_ALAC = 2;
static constexpr int64_t COMPRESSION_AAC = 4;
/// "audioFormat" of AAC-LC, 44.1 kHz, stereo
static constexpr int64_t AUDIO_FORMAT_AAC_44100 = 0x400000;

/// Encrypted audio ends with the tag and the last 8 bytes of the nonce
static constexpr size_t AUDIO_NONCE_SIZE = 8;

static void make_nonce(uint64_t counter, uint8_t *nonce) {
  std::memset(nonce, 0, CHACHA_NONCE_SIZE);
  for (int i = 0; i < 8; i++)
    nonce[4 + i] = static_cast<uint8_t>(counter >> (8 * i));
}

/// Whether the request's path (up to any query) is `path`
static bool path_is(const char *request, const char *path) {
  const char *start = std::strchr(request, ' ');
  if (start == nullptr)
    return false;
  start++;
  const size_t length = std::strlen(path);
  return std::strncmp(start, path, length) == 0 && (start[length] == ' ' || start[length] == '?');
}

void Receiver::init_airplay2_() {
  const uint8_t *mac = this->config_.mac;
  std::snprintf(this->device_id_, sizeof(this->device_id_), "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2],
                mac[3], mac[4], mac[5]);
  this->airplay2_features_ = this->config_.airplay2_features != 0 ? this->config_.airplay2_features : DEFAULT_FEATURES;
  // Lower 32 bits first
  std::snprintf(this->features_, sizeof(this->features_), "0x%" PRIX32 ",0x%" PRIX32,
                static_cast<uint32_t>(this->airplay2_features_), static_cast<uint32_t>(this->airplay2_features_ >> 32));

  // Key and pairing id stay the same across restarts. Senders only show the key; transient pairing does not use it.
  uint8_t digest[SHA512_SIZE];
  Sha512 hash;
  hash.update(reinterpret_cast<const uint8_t *>("airplay-cpp"), 11);
  hash.update(mac, 6);
  hash.finish(digest);
  std::memcpy(this->public_key_, digest, sizeof(this->public_key_));
  for (size_t i = 0; i < sizeof(this->public_key_); i++)
    std::snprintf(this->public_key_hex_ + 2 * i, 3, "%02x", this->public_key_[i]);
  for (auto [id_text, id] :
       {std::pair{this->pairing_id_, digest + 32}, std::pair{this->public_session_id_, digest + 48}}) {
    std::snprintf(id_text, sizeof(this->pairing_id_),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", id[0], id[1], id[2], id[3],
                  id[4], id[5], id[6], id[7], id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]);
  }
  uint8_t feature_bytes[8];
  for (size_t i = 0; i < sizeof(feature_bytes); i++)
    feature_bytes[i] = static_cast<uint8_t>(this->airplay2_features_ >> (8 * i));
  base64_encode_unpadded(feature_bytes, sizeof(feature_bytes), this->features_base64_, sizeof(this->features_base64_));

  const TxtRecord records[] = {
      {"deviceid", this->device_id_},
      {"features", this->features_},
      {"flags", "0x4"},
      {"model", this->config_.model},
      {"pk", this->public_key_hex_},
      {"pi", this->pairing_id_},
      {"srcvers", AIRPLAY2_SOURCE_VERSION},
      {"protovers", "1.1"},
      {"acl", "0"},
      // Group details, as shairport-sync announces them: not in a group
      {"gid", this->pairing_id_},
      {"igl", "0"},
      {"gcgl", "0"},
      {"psi", this->public_session_id_},
      {"fex", this->features_base64_},
      {"vv", "2"},
  };
  static_assert(sizeof(records) / sizeof(records[0]) <= MAX_AIRPLAY_TXT_RECORDS, "Too many TXT records");
  this->airplay_txt_record_count_ = 0;
  for (const TxtRecord &record : records)
    this->airplay_txt_records_[this->airplay_txt_record_count_++] = record;
}

const TxtRecord *Receiver::airplay_txt_records(size_t *count) const {
  *count = this->airplay2_ ? this->airplay_txt_record_count_ : 0;
  return this->airplay_txt_records_;
}

// ===== Encrypted connection =====

void Receiver::receive_encrypted_(uint8_t connection, const uint8_t *data, size_t length, int64_t now_us) {
  Connection &c = this->connections_[connection];
  while (length > 0 && c.open) {
    // The length (2 bytes, little endian), then the data and the tag
    size_t needed = 2;
    if (c.frame_length >= 2) {
      const size_t data_length = c.frame[0] | (static_cast<size_t>(c.frame[1]) << 8);
      if (data_length > HAP_FRAME_DATA_SIZE) {
        AIRPLAY_LOGW("Encrypted frame too large");
        this->close_connection_(connection);
        return;
      }
      needed = 2 + data_length + POLY1305_TAG_SIZE;
    }
    const size_t take = std::min(needed - c.frame_length, length);
    std::memcpy(c.frame + c.frame_length, data, take);
    c.frame_length += take;
    data += take;
    length -= take;
    if (c.frame_length < needed || needed == 2)
      continue;

    const size_t data_length = needed - 2 - POLY1305_TAG_SIZE;
    uint8_t nonce[CHACHA_NONCE_SIZE];
    make_nonce(c.read_counter++, nonce);
    if (!chacha20_poly1305_decrypt(c.read_key, nonce, c.frame, 2, c.frame + 2, data_length, c.frame + 2 + data_length,
                                   c.frame + 2)) {
      AIRPLAY_LOGW("Failed to decrypt a request");
      this->close_connection_(connection);
      return;
    }
    c.frame_length = 0;
    this->pass_plain_(connection, c.frame + 2, data_length, now_us);
  }
}

bool Receiver::send_(uint8_t connection, const uint8_t *data, size_t length) {
  Connection &c = this->connections_[connection];
  if (!c.encrypted)
    return this->transport_.send(connection, data, length);
  while (length > 0) {
    const size_t piece = std::min(length, HAP_FRAME_DATA_SIZE);
    uint8_t *frame = this->send_buffer_;
    frame[0] = static_cast<uint8_t>(piece);
    frame[1] = static_cast<uint8_t>(piece >> 8);
    uint8_t nonce[CHACHA_NONCE_SIZE];
    make_nonce(c.write_counter++, nonce);
    chacha20_poly1305_encrypt(c.write_key, nonce, frame, 2, data, piece, frame + 2, frame + 2 + piece);
    if (!this->transport_.send(connection, frame, 2 + piece + POLY1305_TAG_SIZE))
      return false;
    data += piece;
    length -= piece;
  }
  return true;
}

// ===== Requests =====

bool Receiver::handle_airplay2_request_(uint8_t connection, const char *method, const char *request,
                                        size_t header_length, const char *body, size_t body_length, Response &response,
                                        int64_t now_us) {
  char content_type[48] = "";
  get_header(request, header_length, "Content-Type", content_type, sizeof(content_type));
  const bool plist = equals_ignore_case(content_type, CONTENT_TYPE_PLIST, sizeof(CONTENT_TYPE_PLIST) - 1);
  const auto *data = reinterpret_cast<const uint8_t *>(body);
  // AirPlay 2 support is new: show what senders ask for (the feedback every 2 seconds only at verbose level)
  const char *line_end = std::strstr(request, "\r\n");
  const int line_length = line_end != nullptr ? static_cast<int>(std::min<ptrdiff_t>(line_end - request, 96)) : 0;
  if (path_is(request, "/feedback")) {
    AIRPLAY_LOGV("Request: %.*s", line_length, request);
  } else {
    AIRPLAY_LOGD("Request: %.*s (%s, %u bytes%s)", line_length, request, content_type[0] != '\0' ? content_type : "-",
                 static_cast<unsigned>(body_length), this->connections_[connection].encrypted ? ", encrypted" : "");
  }
  // Headers of the requests that come before a session, and the content of property lists
  if (std::strcmp(method, "OPTIONS") == 0 ||
      ((std::strcmp(method, "GET") == 0 || std::strcmp(method, "POST") == 0) && !path_is(request, "/feedback"))) {
    for (const char *line = line_end; line != nullptr && line + 2 < request + header_length;) {
      line += 2;
      const char *next = std::strstr(line, "\r\n");
      if (next == nullptr || next == line)
        break;
      AIRPLAY_LOGD("  %.*s", static_cast<int>(std::min<ptrdiff_t>(next - line, 160)), line);
      line = next;
    }
  }
  if (plist && data != nullptr) {
    PlistReader reader;
    if (reader.parse(data, body_length)) {
      // The response body buffer is free until the response is built
      auto *text = reinterpret_cast<char *>(this->body_buffer_);
      const size_t length = reader.describe(reader.root(), text, AIRPLAY2_BODY_SIZE);
      for (size_t offset = 0; offset < length; offset += 150)
        AIRPLAY_LOGD("  plist: %.*s", static_cast<int>(std::min<size_t>(length - offset, 150)), text + offset);
    } else {
      AIRPLAY_LOGD("  not a binary property list");
    }
  }

  if (std::strcmp(method, "GET") == 0 || std::strcmp(method, "POST") == 0) {
    if (path_is(request, "/info")) {
      this->build_info_(response);
    } else if (path_is(request, "/fp-setup")) {
      response.body_length =
          fairplay_setup_reply(data, data != nullptr ? body_length : 0, this->body_buffer_, AIRPLAY2_BODY_SIZE);
      if (response.body_length == 0) {
        AIRPLAY_LOGW("Unsupported FairPlay setup message");
        response.status = 400;
        response.status_text = "Bad Request";
      } else {
        response.content_type = CONTENT_TYPE_OCTET_STREAM;
        response.body = this->body_buffer_;
      }
    } else if (path_is(request, "/pair-setup")) {
      this->handle_pair_setup_(connection, data, body_length, response);
    } else if (path_is(request, "/pair-verify")) {
      // Only transient pairing is offered, which needs no verification
      AIRPLAY_LOGW("pair-verify is not supported, only transient pair-setup");
      Tlv8Writer writer(this->body_buffer_, AIRPLAY2_BODY_SIZE);
      writer.add_byte(TLV_STATE, 2);
      writer.add_byte(TLV_ERROR, TLV_ERROR_AUTHENTICATION);
      response.content_type = CONTENT_TYPE_OCTET_STREAM;
      response.body = this->body_buffer_;
      response.body_length = writer.length();
    } else if (path_is(request, "/feedback") && this->buffered_stream_) {
      // Keeps buffered streams alive while paused
      PlistWriter writer(this->body_buffer_, AIRPLAY2_BODY_SIZE);
      writer.begin_dict(1);
      writer.key("streams");
      writer.begin_array(1);
      writer.begin_dict(2);
      writer.key("type");
      writer.integer(STREAM_TYPE_BUFFERED);
      writer.key("sr");
      writer.real(SAMPLE_RATE);
      response.body_length = writer.finish();
      if (response.body_length > 0) {
        response.content_type = CONTENT_TYPE_PLIST;
        response.body = this->body_buffer_;
      }
    } else if (!path_is(request, "/pair-pin-start") && !path_is(request, "/feedback") &&
               !path_is(request, "/command") && !path_is(request, "/audioMode")) {
      return false;
    }
    return true;
  }
  if (std::strcmp(method, "SETUP") == 0 && plist) {
    this->handle_airplay2_setup_(connection, request, header_length, data, data != nullptr ? body_length : 0, response,
                                 now_us);
    return true;
  }
  if (std::strcmp(method, "TEARDOWN") == 0 && plist && data != nullptr && connection == this->session_owner_) {
    // With a list of streams only the streams end; the session stays for the next track
    PlistReader reader;
    if (!reader.parse(data, body_length) || reader.get(reader.root(), "streams") == PlistReader::NONE)
      return false;
    AIRPLAY_LOGI("Stream stopped");
    this->stop_audio_();
    this->stop_buffered_audio_();
    if (this->session_state_ == SessionState::PLAYING)
      this->set_session_state_(SessionState::PAUSED);
    return true;
  }
  if (std::strcmp(method, "SETRATEANCHORTIME") == 0) {
    if (connection == this->session_owner_ && data != nullptr)
      this->handle_rate_anchor_(data, body_length);
    return true;
  }
  if (std::strcmp(method, "FLUSHBUFFERED") == 0) {
    if (connection == this->session_owner_ && data != nullptr)
      this->handle_flush_buffered_(data, body_length);
    return true;
  }
  // Timing peers for PTP, which is not used
  return std::strcmp(method, "SETPEERS") == 0 || std::strcmp(method, "SETPEERSX") == 0;
}

void Receiver::handle_pair_setup_(uint8_t connection, const uint8_t *body, size_t length, Response &response) {
  Connection &c = this->connections_[connection];
  Tlv8Writer writer(this->body_buffer_, AIRPLAY2_BODY_SIZE);
  response.content_type = CONTENT_TYPE_OCTET_STREAM;
  response.body = this->body_buffer_;

  uint8_t state = 0;
  size_t value_length = 0;
  if (body != nullptr)
    tlv8_find(body, length, TLV_STATE, &state, 1, &value_length);

  if (state == 1) {
    uint8_t flags = 0;
    if (!tlv8_find(body, length, TLV_FLAGS, &flags, 1, &value_length) || (flags & TLV_FLAG_TRANSIENT) == 0) {
      AIRPLAY_LOGW("Only transient pairing is supported");
      writer.add_byte(TLV_STATE, 2);
      writer.add_byte(TLV_ERROR, TLV_ERROR_AUTHENTICATION);
      response.body_length = writer.length();
      return;
    }
    uint8_t salt[SRP_SALT_SIZE];
    uint8_t secret[SRP_SECRET_SIZE];
    this->config_.random(salt, sizeof(salt));
    this->config_.random(secret, sizeof(secret));
    this->srp_->begin(PAIR_SETUP_USERNAME, TRANSIENT_PIN, salt, secret);
    std::memset(secret, 0, sizeof(secret));
    this->pairing_connection_ = connection;
    writer.add_byte(TLV_STATE, 2);
    writer.add(TLV_SALT, this->srp_->salt(), SRP_SALT_SIZE);
    writer.add(TLV_PUBLIC_KEY, this->srp_->public_key(), SRP_KEY_SIZE);
  } else if (state == 3 && connection == this->pairing_connection_) {
    this->pairing_connection_ = NO_CONNECTION;
    uint8_t client_key[SRP_KEY_SIZE];
    size_t client_key_length = 0;
    uint8_t proof[SHA512_SIZE];
    size_t proof_length = 0;
    uint8_t server_proof[SHA512_SIZE];
    writer.add_byte(TLV_STATE, 4);
    if (tlv8_find(body, length, TLV_PUBLIC_KEY, client_key, sizeof(client_key), &client_key_length) &&
        tlv8_find(body, length, TLV_PROOF, proof, sizeof(proof), &proof_length) &&
        this->srp_->verify(client_key, client_key_length, proof, proof_length, server_proof)) {
      writer.add(TLV_PROOF, server_proof, sizeof(server_proof));
      // The sender's write key is the receiver's read key
      const uint8_t *secret = this->srp_->session_key();
      hkdf_sha512_key(CONTROL_SALT, CONTROL_SENDER_WRITE_INFO, secret, SHA512_SIZE, c.read_key);
      hkdf_sha512_key(CONTROL_SALT, CONTROL_SENDER_READ_INFO, secret, SHA512_SIZE, c.write_key);
      c.encrypt_after_response = true;
      AIRPLAY_LOGD("Paired");
    } else {
      AIRPLAY_LOGW("Pairing failed");
      writer.add_byte(TLV_ERROR, TLV_ERROR_AUTHENTICATION);
    }
  } else {
    writer.add_byte(TLV_STATE, static_cast<uint8_t>(state + 1));
    writer.add_byte(TLV_ERROR, TLV_ERROR_UNKNOWN);
  }
  response.body_length = writer.length();
}

void Receiver::handle_airplay2_setup_(uint8_t connection, const char *request, size_t header_length,
                                      const uint8_t *body, size_t length, Response &response, int64_t now_us) {
  Connection &c = this->connections_[connection];
  response.status = 455;
  response.status_text = "Method Not Valid in This State";
  PlistReader reader;
  if (!c.encrypted) {
    AIRPLAY_LOGW("SETUP before pairing");
    return;
  }
  if (body == nullptr || !reader.parse(body, length)) {
    response.status = 400;
    response.status_text = "Bad Request";
    return;
  }
  const PlistReader::Object root = reader.root();
  const PlistReader::Object streams = reader.get(root, "streams");
  PlistWriter writer(this->body_buffer_, AIRPLAY2_BODY_SIZE);

  if (streams == PlistReader::NONE) {
    // The session: the clock exchange and the event connection
    const PlistReader::Object timing_protocol = reader.get(root, "timingProtocol");
    bool remote_control_only = false;
    reader.get_bool(reader.get(root, "isRemoteControlOnly"), &remote_control_only);
    if (remote_control_only || reader.string_equals(timing_protocol, "None")) {
      // iOS opens extra sessions only to control playback; they must not take over the speaker
      AIRPLAY_LOGD("Remote control session");
      this->event_channel_pending_ = true;
      this->event_channel_address_ = c.peer.address;
      writer.begin_dict(1);
      writer.key("eventPort");
      writer.integer(c.local.port);
      response.body_length = writer.finish();
      if (response.body_length > 0) {
        response.status = 200;
        response.status_text = "OK";
        response.content_type = CONTENT_TYPE_PLIST;
        response.body = this->body_buffer_;
      }
      return;
    }
    if (timing_protocol != PlistReader::NONE && !reader.string_equals(timing_protocol, "NTP")) {
      AIRPLAY_LOGW("Only NTP timing is supported");
      return;
    }
    int64_t timing_port = 0;
    reader.get_integer(reader.get(root, "timingPort"), &timing_port);
    if (this->session_owner_ != NO_CONNECTION && this->session_owner_ != connection && this->udp_open_ &&
        this->connections_[this->session_owner_].peer.address == c.peer.address) {
      // iOS sets up another session while one plays. The playing one goes on until this one sets up a stream.
      AIRPLAY_LOGD("Another session of the sender; it takes over once it sets up a stream");
      c.session_pending = true;
      c.pending_recording = false;
      c.pending_timing_port = static_cast<uint16_t>(timing_port);
      this->event_channel_pending_ = true;
      this->event_channel_address_ = c.peer.address;
      writer.begin_dict(2);
      writer.key("eventPort");
      writer.integer(c.local.port);
      writer.key("timingPort");
      writer.integer(this->udp_ports_[static_cast<size_t>(UdpChannel::TIMING)]);
      response.body_length = writer.finish();
      if (response.body_length > 0) {
        response.status = 200;
        response.status_text = "OK";
        response.content_type = CONTENT_TYPE_PLIST;
        response.body = this->body_buffer_;
      }
      return;
    }
    this->take_session_(connection, request, header_length);
    this->stop_buffered_audio_();
    this->airplay2_recording_ = false;
    this->have_session_stream_key_ = false;
    this->codec_ = Codec::NONE;
    this->encrypted_ = false;
    this->airplay2_audio_ = false;
    if (!this->open_udp_(connection, 0, static_cast<uint32_t>(timing_port), this->udp_ports_))
      return;
    this->event_channel_pending_ = true;
    this->event_channel_address_ = c.peer.address;
    // The event connection uses the RTSP port; nothing is read from it
    writer.begin_dict(2);
    writer.key("eventPort");
    writer.integer(c.local.port);
    writer.key("timingPort");
    writer.integer(this->udp_ports_[static_cast<size_t>(UdpChannel::TIMING)]);
  } else {
    // An audio stream
    if (c.session_pending && this->udp_open_)
      this->adopt_session_(connection, request, header_length);
    if (connection != this->session_owner_ || !this->udp_open_)
      return;
    const PlistReader::Object stream = reader.at(streams, 0);
    int64_t type = 0;
    int64_t compression = 0;
    int64_t frames_per_packet = FRAMES_PER_PACKET;
    int64_t sample_rate = SAMPLE_RATE;
    int64_t control_port = 0;
    const uint8_t *key = nullptr;
    size_t key_length = 0;
    reader.get_integer(reader.get(stream, "type"), &type);
    reader.get_integer(reader.get(stream, "ct"), &compression);
    reader.get_integer(reader.get(stream, "spf"), &frames_per_packet);
    reader.get_integer(reader.get(stream, "sr"), &sample_rate);
    reader.get_integer(reader.get(stream, "controlPort"), &control_port);
    reader.get_data(reader.get(stream, "shk"), &key, &key_length);
    // iOS sends the key with the first stream it offers, also one this receiver turns down, and leaves it out of
    // later ones
    if (key != nullptr && key_length == CHACHA_KEY_SIZE) {
      std::memcpy(this->session_stream_key_, key, sizeof(this->session_stream_key_));
      this->have_session_stream_key_ = true;
    }
    if (type == STREAM_TYPE_BUFFERED) {
      int64_t audio_format = 0;
      reader.get_integer(reader.get(stream, "audioFormat"), &audio_format);
      if (this->buffered_storage_ == nullptr) {
        AIRPLAY_LOGW("Buffered audio needs an AAC decoder");
        return;
      }
      if (compression != COMPRESSION_AAC || audio_format != AUDIO_FORMAT_AAC_44100 ||
          frames_per_packet != AAC_FRAMES_PER_PACKET || (key == nullptr && !this->have_session_stream_key_)) {
        AIRPLAY_LOGW("Unsupported buffered stream (ct %" PRId64 ", format 0x%" PRIx64 ")", compression, audio_format);
        return;
      }
      this->stop_audio_();
      this->stop_buffered_audio_();
      if (!this->config_.aac_decoder->begin()) {
        AIRPLAY_LOGW("Failed to start the AAC decoder");
        return;
      }
      std::memcpy(this->audio_key_, key != nullptr ? key : this->session_stream_key_, sizeof(this->audio_key_));
      this->codec_ = Codec::AAC;
      this->buffered_stream_ = true;
      this->airplay2_audio_ = false;
      this->encrypted_ = false;
      this->buffered_next_seq_ = 0;
      // The sender connects to the RTSP port for the audio, as for its events
      this->data_channel_pending_ = true;
      AIRPLAY_LOGD("Stream: AAC, AirPlay 2 buffered");
      if (this->airplay2_recording_ && this->start_audio_(now_us))
        AIRPLAY_LOGI("Playback started");

      writer.begin_dict(1);
      writer.key("streams");
      writer.begin_array(1);
      writer.begin_dict(3);
      writer.key("type");
      writer.integer(STREAM_TYPE_BUFFERED);
      writer.key("dataPort");
      writer.integer(c.local.port);
      writer.key("audioBufferSize");
      writer.integer(static_cast<int64_t>(this->buffered_queue_.size()));
    } else if (type != STREAM_TYPE_REALTIME) {
      AIRPLAY_LOGW("Unsupported stream type %" PRId64, type);
      return;
    } else {
      if ((key != nullptr && key_length != CHACHA_KEY_SIZE) || sample_rate != SAMPLE_RATE || frames_per_packet <= 0 ||
          frames_per_packet > FRAMES_PER_PACKET) {
        AIRPLAY_LOGW("Unsupported stream parameters");
        return;
      }
      this->stop_audio_();
      this->stop_buffered_audio_();
      this->codec_ = Codec::NONE;
      if (compression == COMPRESSION_ALAC) {
        ALACConfig alac;
        alac.frame_length = static_cast<uint32_t>(frames_per_packet);
        if (this->decoder_.configure(alac))
          this->codec_ = Codec::ALAC;
      } else if (compression == COMPRESSION_PCM) {
        this->codec_ = Codec::PCM;
      }
      if (this->codec_ == Codec::NONE) {
        AIRPLAY_LOGW("Unsupported audio format %" PRId64, compression);
        return;
      }
      // iOS leaves the key out of realtime streams. Whether their audio is then encrypted with a zero key (as
      // openairplay/airplay2-receiver assumes) or not at all is told by the first packet.
      if (key != nullptr) {
        std::memcpy(this->audio_key_, key, sizeof(this->audio_key_));
        this->audio_encryption_ = AudioEncryption::KEY;
      } else {
        // Tried in this order: the key of an earlier stream of the session, a zero key, no encryption
        if (this->have_session_stream_key_) {
          std::memcpy(this->audio_key_, this->session_stream_key_, sizeof(this->audio_key_));
        } else {
          std::memset(this->audio_key_, 0, sizeof(this->audio_key_));
        }
        this->audio_encryption_ = AudioEncryption::UNKNOWN;
      }
      this->airplay2_audio_ = true;
      this->encrypted_ = false;
      this->client_control_.port = static_cast<uint16_t>(control_port);
      AIRPLAY_LOGD("Stream: %s, AirPlay 2", this->codec_ == Codec::ALAC ? "ALAC" : "PCM");
      if (this->airplay2_recording_ && this->start_audio_(now_us)) {
        AIRPLAY_LOGI("Playback started");
        this->set_session_state_(SessionState::PLAYING);
      }

      writer.begin_dict(1);
      writer.key("streams");
      writer.begin_array(1);
      writer.begin_dict(3);
      writer.key("type");
      writer.integer(STREAM_TYPE_REALTIME);
      writer.key("dataPort");
      writer.integer(this->udp_ports_[static_cast<size_t>(UdpChannel::AUDIO)]);
      writer.key("controlPort");
      writer.integer(this->udp_ports_[static_cast<size_t>(UdpChannel::CONTROL)]);
    }
  }

  response.body_length = writer.finish();
  if (response.body_length == 0)
    return;
  response.status = 200;
  response.status_text = "OK";
  response.content_type = CONTENT_TYPE_PLIST;
  response.body = this->body_buffer_;
}

void Receiver::build_info_(Response &response) {
  PlistWriter writer(this->body_buffer_, AIRPLAY2_BODY_SIZE);
  writer.begin_dict(11);
  writer.key("deviceID");
  writer.string(this->device_id_);
  writer.key("macAddress");
  writer.string(this->device_id_);
  writer.key("features");
  writer.integer(static_cast<int64_t>(this->airplay2_features_));
  writer.key("statusFlags");
  writer.integer(STATUS_FLAGS);
  writer.key("model");
  writer.string(this->config_.model);
  writer.key("name");
  writer.string(this->config_.name);
  writer.key("protocolVersion");
  writer.string("1.1");
  writer.key("sourceVersion");
  writer.string(AIRPLAY2_SOURCE_VERSION);
  writer.key("pi");
  writer.string(this->pairing_id_);
  writer.key("pk");
  writer.data(this->public_key_, sizeof(this->public_key_));
  writer.key("vv");
  writer.integer(2);
  response.body_length = writer.finish();
  if (response.body_length == 0) {
    response.status = 500;
    response.status_text = "Internal Server Error";
    return;
  }
  response.content_type = CONTENT_TYPE_PLIST;
  response.body = this->body_buffer_;
}

// ===== Audio =====

size_t Receiver::decrypt_airplay2_audio_(const uint8_t *header, const uint8_t *payload, size_t length,
                                         uint8_t *output) {
  if (this->audio_encryption_ == AudioEncryption::NONE) {
    std::memcpy(output, payload, length);
    return length;
  }
  if (length <= POLY1305_TAG_SIZE + AUDIO_NONCE_SIZE)
    return this->audio_encryption_ == AudioEncryption::UNKNOWN ? this->detect_plain_audio_(payload, length, output) : 0;
  const size_t audio_length = length - POLY1305_TAG_SIZE - AUDIO_NONCE_SIZE;
  uint8_t nonce[CHACHA_NONCE_SIZE] = {};
  std::memcpy(nonce + 4, payload + length - AUDIO_NONCE_SIZE, AUDIO_NONCE_SIZE);
  // The timestamp and SSRC of the RTP header are authenticated
  if (chacha20_poly1305_decrypt(this->audio_key_, nonce, header + 4, 8, payload, audio_length, payload + audio_length,
                                output)) {
    if (this->audio_encryption_ == AudioEncryption::UNKNOWN) {
      const uint8_t zero[CHACHA_KEY_SIZE] = {};
      AIRPLAY_LOGI("Audio encrypted with %s", std::memcmp(this->audio_key_, zero, sizeof(zero)) == 0
                                                  ? "a zero key"
                                                  : "the key of an earlier stream");
      this->audio_encryption_ = AudioEncryption::KEY;
    }
    return audio_length;
  }
  if (this->audio_encryption_ != AudioEncryption::UNKNOWN)
    return 0;
  const uint8_t zero[CHACHA_KEY_SIZE] = {};
  if (std::memcmp(this->audio_key_, zero, sizeof(zero)) != 0) {
    std::memset(this->audio_key_, 0, sizeof(this->audio_key_));
    return this->decrypt_airplay2_audio_(header, payload, length, output);
  }
  return this->detect_plain_audio_(payload, length, output);
}

size_t Receiver::detect_plain_audio_(const uint8_t *payload, size_t length, uint8_t *output) {
  AIRPLAY_LOGI("Audio not encrypted (starts with %02x %02x %02x %02x, %u bytes)", payload[0],
               length > 1 ? payload[1] : 0, length > 2 ? payload[2] : 0, length > 3 ? payload[3] : 0,
               static_cast<unsigned>(length));
  this->audio_encryption_ = AudioEncryption::NONE;
  std::memcpy(output, payload, length);
  return length;
}

// ===== Buffered audio =====

/// A buffered stream sends each packet as its length (2 bytes, big endian, including these 2), the RTP header, the
/// encrypted audio, the tag and the last 8 bytes of the nonce
static constexpr size_t BUFFERED_LENGTH_SIZE = 2;
static constexpr size_t BUFFERED_RTP_HEADER_SIZE = 12;
/// The connection is paused while less than this is free in the buffer, and resumed once twice as much is
static constexpr size_t BUFFERED_PAUSE_BYTES = 8 * 1024;
/// Packets decoded per poll, to spread the work
static constexpr uint32_t BUFFERED_DECODES_PER_POLL = 2;
static constexpr int64_t NTP_UNIX_OFFSET_S = 2208988800LL;

/// Whether 24-bit sequence number a comes before b
static bool seq24_before(uint32_t a, uint32_t b) { return ((a - b) & 0xffffff) > 0x800000; }

void Receiver::receive_buffered_audio_(uint8_t connection, const uint8_t *data, size_t length, uint32_t now_ms) {
  Connection &c = this->connections_[connection];
  auto *packet = reinterpret_cast<uint8_t *>(c.buffer);
  this->last_packet_ms_ = now_ms;
  while (length > 0 && c.open) {
    size_t needed = BUFFERED_LENGTH_SIZE;
    if (c.rx_length >= BUFFERED_LENGTH_SIZE) {
      needed = (static_cast<size_t>(packet[0]) << 8) | packet[1];
      if (needed < BUFFERED_LENGTH_SIZE + BUFFERED_RTP_HEADER_SIZE + POLY1305_TAG_SIZE + AUDIO_NONCE_SIZE ||
          needed > RTSP_BUFFER_SIZE) {
        AIRPLAY_LOGW("Invalid buffered audio packet (%u bytes)", static_cast<unsigned>(needed));
        this->close_connection_(connection);
        return;
      }
    }
    const size_t take = std::min(needed - c.rx_length, length);
    std::memcpy(packet + c.rx_length, data, take);
    c.rx_length += take;
    data += take;
    length -= take;
    if (c.rx_length < needed || needed == BUFFERED_LENGTH_SIZE)
      continue;
    c.rx_length = 0;

    uint8_t *rtp_packet = packet + BUFFERED_LENGTH_SIZE;
    const size_t rtp_length = needed - BUFFERED_LENGTH_SIZE;
    const uint32_t seq =
        (static_cast<uint32_t>(rtp_packet[1]) << 16) | (static_cast<uint32_t>(rtp_packet[2]) << 8) | rtp_packet[3];
    const uint32_t rtp = (static_cast<uint32_t>(rtp_packet[4]) << 24) | (static_cast<uint32_t>(rtp_packet[5]) << 16) |
                         (static_cast<uint32_t>(rtp_packet[6]) << 8) | rtp_packet[7];
    if (this->flush_active_) {
      if (seq24_before(seq, this->flush_until_seq_))
        continue;  // Flushed
      this->flush_active_ = false;
    }
    const size_t audio_length = rtp_length - BUFFERED_RTP_HEADER_SIZE - POLY1305_TAG_SIZE - AUDIO_NONCE_SIZE;
    uint8_t *audio = rtp_packet + BUFFERED_RTP_HEADER_SIZE;
    uint8_t nonce[CHACHA_NONCE_SIZE] = {};
    std::memcpy(nonce + 4, rtp_packet + rtp_length - AUDIO_NONCE_SIZE, AUDIO_NONCE_SIZE);
    if (!chacha20_poly1305_decrypt(this->audio_key_, nonce, rtp_packet + 4, 8, audio, audio_length,
                                   audio + audio_length, audio)) {
      if (this->buffered_dropped_++ == 0)
        AIRPLAY_LOGW("Failed to decrypt buffered audio (packet %" PRIu32 ")", seq);
      continue;
    }
    if (audio_length == 0)
      continue;  // iOS sends one without audio after a flush
    if (!this->buffered_queue_.push(rtp, seq, audio, static_cast<uint16_t>(audio_length))) {
      if (this->buffered_dropped_++ == 0)
        AIRPLAY_LOGW("Buffered audio dropped: the buffer is full");
    }
  }
  this->update_receive_pause_();
}

void Receiver::update_receive_pause_() {
  if (this->data_connection_ == NO_CONNECTION)
    return;
  const size_t free_bytes = this->buffered_queue_.free_bytes();
  if (!this->receive_paused_ && free_bytes < BUFFERED_PAUSE_BYTES) {
    this->receive_paused_ = true;
    this->transport_.pause_receiving(this->data_connection_, true);
  } else if (this->receive_paused_ && free_bytes >= 2 * BUFFERED_PAUSE_BYTES) {
    this->receive_paused_ = false;
    this->transport_.pause_receiving(this->data_connection_, false);
  }
}

void Receiver::decode_buffered_audio_(uint32_t now_ms) {
  if (!this->audio_active_)
    return;
  const uint32_t pieces = (AAC_FRAMES_PER_PACKET + FRAMES_PER_PACKET - 1) / FRAMES_PER_PACKET;
  for (uint32_t i = 0; i < BUFFERED_DECODES_PER_POLL; i++) {
    // Room in the jitter buffer for the pieces of one packet
    if (this->have_seq_ &&
        static_cast<uint16_t>(this->buffered_next_seq_ - this->next_seq_) + pieces > this->slot_count_)
      break;
    uint32_t rtp;
    uint32_t seq;
    const uint8_t *data;
    uint16_t length;
    if (!this->buffered_queue_.front(&rtp, &seq, &data, &length))
      break;
    const size_t frames = this->config_.aac_decoder->decode(data, length, this->aac_samples_, AAC_FRAMES_PER_PACKET);
    this->buffered_queue_.pop();
    this->last_packet_ms_ = now_ms;
    if (frames == 0 || frames > AAC_FRAMES_PER_PACKET) {
      if (this->stats_.decode_errors++ == 0)
        AIRPLAY_LOGW("Failed to decode buffered audio (packet %" PRIu32 ", %u bytes)", seq, length);
      continue;
    }
    // Into the jitter buffer in pieces of at most FRAMES_PER_PACKET
    for (size_t offset = 0; offset < frames; offset += FRAMES_PER_PACKET) {
      const uint16_t piece_seq = this->buffered_next_seq_++;
      if (!this->have_seq_) {
        this->have_seq_ = true;
        this->next_seq_ = piece_seq;
        this->highest_seq_ = piece_seq - 1;
        this->head_slot_ = 0;
      }
      const int32_t ahead = static_cast<int16_t>(piece_seq - this->next_seq_);
      if (ahead < 0 || static_cast<uint32_t>(ahead) >= this->slot_count_) {
        this->stats_.late_packets++;
        continue;
      }
      PacketSlot &slot = this->slots_[(this->head_slot_ + static_cast<uint32_t>(ahead)) % this->slot_count_];
      const size_t piece_frames = std::min<size_t>(frames - offset, FRAMES_PER_PACKET);
      std::memcpy(slot.samples, this->aac_samples_ + offset * NUM_CHANNELS, piece_frames * BYTES_PER_FRAME);
      slot.seq = piece_seq;
      slot.rtp = rtp + static_cast<uint32_t>(offset);
      slot.frames = static_cast<uint16_t>(piece_frames);
      slot.valid = true;
      slot.missing_since_ms = 0;
      this->highest_seq_ = piece_seq;
    }
  }
  this->update_receive_pause_();
}

void Receiver::handle_rate_anchor_(const uint8_t *body, size_t length) {
  PlistReader reader;
  if (!reader.parse(body, length))
    return;
  const PlistReader::Object root = reader.root();
  int64_t seconds = 0;
  int64_t fraction = 0;
  int64_t rtp = 0;
  if (reader.get_integer(reader.get(root, "networkTimeSecs"), &seconds) &&
      reader.get_integer(reader.get(root, "rtpTime"), &rtp)) {
    reader.get_integer(reader.get(root, "networkTimeFrac"), &fraction);
    // The fraction is of a second in 64 bits
    const uint64_t fraction_ns = ((static_cast<uint64_t>(fraction) >> 32) * 1000000000ULL) >> 32;
    // The NTP timeline counts from 1900; a time from 1970 is moved onto it
    if (seconds < NTP_UNIX_OFFSET_S)
      seconds += NTP_UNIX_OFFSET_S;
    this->anchor_rtp_ = static_cast<uint32_t>(rtp);
    this->anchor_remote_ns_ = seconds * 1000000000LL + static_cast<int64_t>(fraction_ns);
    this->anchor_valid_ = true;
    this->sender_latency_frames_ = 0;
  }
  int64_t rate = 0;
  double real_rate = 0;
  if (!reader.get_integer(reader.get(root, "rate"), &rate) && reader.get_real(reader.get(root, "rate"), &real_rate))
    rate = real_rate > 0 ? 1 : 0;
  const bool playing = (rate & 1) != 0;
  AIRPLAY_LOGD("Rate %d from %" PRIu32, playing ? 1 : 0, this->anchor_rtp_);
  if (playing != this->buffered_playing_) {
    this->buffered_playing_ = playing;
    this->playback_started_ = false;  // Lines up with the new anchor
    this->set_session_state_(playing ? SessionState::PLAYING : SessionState::PAUSED);
  }
}

void Receiver::handle_flush_buffered_(const uint8_t *body, size_t length) {
  PlistReader reader;
  if (!reader.parse(body, length))
    return;
  const PlistReader::Object root = reader.root();
  int64_t until = 0;
  if (!reader.get_integer(reader.get(root, "flushUntilSeq"), &until))
    return;
  int64_t from = 0;
  const bool has_from = reader.get_integer(reader.get(root, "flushFromSeq"), &from);
  AIRPLAY_LOGD("Flush until %" PRId64 "%s", until, has_from ? " (from a later packet)" : "");
  const auto until_seq = static_cast<uint32_t>(until) & 0xffffff;
  // Queued packets before the flush point are dropped; with a start of the flush, those before it stay
  uint32_t rtp;
  uint32_t seq;
  const uint8_t *data;
  uint16_t queued;
  while (this->buffered_queue_.front(&rtp, &seq, &data, &queued) && seq24_before(seq, until_seq) &&
         (!has_from || !seq24_before(seq, static_cast<uint32_t>(from) & 0xffffff))) {
    this->buffered_queue_.pop();
  }
  if (!has_from) {
    // Decoded audio goes too; the next anchor tells where playback continues
    this->reset_playback_();
  }
  this->flush_until_seq_ = until_seq;
  this->flush_active_ = true;
  this->update_receive_pause_();
}

void Receiver::stop_buffered_audio_() {
  if (this->buffered_stream_)
    this->config_.aac_decoder->end();
  this->buffered_stream_ = false;
  this->buffered_playing_ = false;
  this->data_channel_pending_ = false;
  this->flush_active_ = false;
  this->buffered_dropped_ = 0;
  this->buffered_queue_.clear();
  if (this->codec_ == Codec::AAC)
    this->codec_ = Codec::NONE;
  if (this->data_connection_ != NO_CONNECTION) {
    const uint8_t connection = this->data_connection_;
    this->data_connection_ = NO_CONNECTION;
    if (this->connections_[connection].open) {
      this->connections_[connection].open = false;
      this->connections_[connection].audio_data = false;
      this->transport_.close(connection);
    }
  }
  this->receive_paused_ = false;
}

}  // namespace airplay
