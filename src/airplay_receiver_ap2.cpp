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
#include <iterator>
#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <utility>

namespace airplay {

// Feature bits, as in the "features" TXT record: audio (9), redundant audio (11), FairPlay (14), audio formats
// (18-20, 22), unified advertiser info (30), control channel encryption (38), buffered audio (40),
// HomeKit pairing and peer management (46, 47) and transient pairing (48), and cover art, progress and text in
// the AirPlay 1 way (15-17). iOS streams only to receivers with
// FairPlay; without buffered audio it falls back to ANNOUNCE with a FairPlay encrypted key, and with NTP instead
// of PTP timing (41) it uses NTP, as the experiments in openairplay/airplay2-receiver noted.
static constexpr uint64_t DEFAULT_FEATURES = 0x1C140405FCA00ULL;
/// PTP timing (41), with ReceiverConfig::ptp. macOS only streams to receivers with it, and then only with PTP.
static constexpr uint64_t FEATURE_PTP = 1ULL << 41;
/// Status flags: an audio receiver
static constexpr int64_t STATUS_FLAGS = 0x4;

static constexpr char CONTENT_TYPE_PLIST[] = "application/x-apple-binary-plist";
static constexpr char CONTENT_TYPE_OCTET_STREAM[] = "application/octet-stream";

// Pair-setup: the PIN is fixed. Senders use it for transient pairing, and the Home app for HomeKit pairing.
static constexpr char PAIR_SETUP_USERNAME[] = "Pair-Setup";
static constexpr char PAIR_SETUP_PIN[] = "3939";
// HomeKit pairing (HAP specification, chapter 5)
static constexpr char PAIR_SETUP_ENCRYPT_SALT[] = "Pair-Setup-Encrypt-Salt";
static constexpr char PAIR_SETUP_ENCRYPT_INFO[] = "Pair-Setup-Encrypt-Info";
static constexpr char PAIR_SETUP_CONTROLLER_SALT[] = "Pair-Setup-Controller-Sign-Salt";
static constexpr char PAIR_SETUP_CONTROLLER_INFO[] = "Pair-Setup-Controller-Sign-Info";
static constexpr char PAIR_SETUP_ACCESSORY_SALT[] = "Pair-Setup-Accessory-Sign-Salt";
static constexpr char PAIR_SETUP_ACCESSORY_INFO[] = "Pair-Setup-Accessory-Sign-Info";
static constexpr char PAIR_VERIFY_ENCRYPT_SALT[] = "Pair-Verify-Encrypt-Salt";
static constexpr char PAIR_VERIFY_ENCRYPT_INFO[] = "Pair-Verify-Encrypt-Info";
static constexpr uint8_t PAIRING_METHOD_ADD = 3;
static constexpr uint8_t PAIRING_METHOD_REMOVE = 4;
static constexpr uint8_t PAIRING_METHOD_LIST = 5;
static constexpr uint8_t PERMISSION_ADMIN = 1;
// Kept with a pairing made with the Home app's password, not passed on: such pairings go when the password changes
static constexpr uint8_t PERMISSION_WITH_PASSWORD = 0x80;
static constexpr uint8_t TLV_PERMISSIONS = 0x0b;
static constexpr uint8_t TLV_SEPARATOR = 0xff;
static constexpr uint8_t TLV_ERROR_MAX_PEERS = 0x04;
/// Status flag: a password is required (the Home app's "Require password")
static constexpr int64_t STATUS_FLAG_PASSWORD = 1 << 7;
/// Status flag: set up for HomeKit access control through the Home app
static constexpr int64_t STATUS_FLAG_HOMEKIT_ACCESS_CONTROL = 1 << 10;
/// Remote control relay: iOS connects to get what plays. Other AirPlay 2 speakers announce it while they play in a
/// sender's group; the receiver does whenever a session plays (with remote control), so that the devices that do
/// not play (also the one another sender displaced) show what plays.
static constexpr int64_t STATUS_FLAG_REMOTE_CONTROL_RELAY = 1 << 11;
/// Longest encrypted TLV of a pairing step: identifier, public key and signature, with the tag
static constexpr size_t PAIRING_SUB_TLV_SIZE = 256;
static constexpr char CONTROL_SALT[] = "Control-Salt";
static constexpr char CONTROL_SENDER_WRITE_INFO[] = "Control-Write-Encryption-Key";
static constexpr char CONTROL_SENDER_READ_INFO[] = "Control-Read-Encryption-Key";
// The receiver writes on the event connection with this key, though the sender opened it
static constexpr char EVENTS_SALT[] = "Events-Salt";
static constexpr char EVENTS_RECEIVER_WRITE_INFO[] = "Events-Write-Encryption-Key";
static constexpr char EVENTS_RECEIVER_READ_INFO[] = "Events-Read-Encryption-Key";
// The key of a realtime stream that came without one; the salt gets the stream's connection ID appended
static constexpr char DATA_STREAM_SALT[] = "DataStream-Salt";
static constexpr char DATA_STREAM_SENDER_WRITE_INFO[] = "DataStream-Output-Encryption-Key";

/// Unanswered requests after which nothing more is sent on an event connection. Music Assistant never reads it, and
/// the requests that pile up there made the receiver lose audio packets.
static constexpr uint16_t MAX_UNANSWERED_REQUESTS = 3;
/// Apple's senders answer requests on the event connection at once; one that has not answered this long never does
static constexpr uint32_t EVENT_ANSWER_TIMEOUT_MS = 2000;
/// Stream type of realtime audio over UDP; 103 is buffered audio over TCP
static constexpr int64_t STREAM_TYPE_REALTIME = 96;
static constexpr int64_t STREAM_TYPE_BUFFERED = 103;
/// Remote control through the receiver: a controller's MediaRemote messages for the playing sender
static constexpr int64_t STREAM_TYPE_REMOTE_CONTROL = 130;
/// The relayed stream that carries MediaRemote messages (2 is not relayed, as other speakers do)
static constexpr int64_t CONTROL_TYPE_MEDIA_REMOTE = 1;
/// Compression types ("ct") of a stream
static constexpr int64_t COMPRESSION_PCM = 1;
static constexpr int64_t COMPRESSION_ALAC = 2;
static constexpr int64_t COMPRESSION_AAC = 4;
/// "audioFormat" of AAC-LC, 44.1 kHz, stereo
static constexpr int64_t AUDIO_FORMAT_AAC_44100 = 0x400000;
static constexpr int64_t AUDIO_FORMAT_ALAC_44100 = 0x40000;  // 16-bit stereo

/// Encrypted audio ends with the tag and the last 8 bytes of the nonce
static constexpr size_t AUDIO_NONCE_SIZE = 8;

static void make_nonce(uint64_t counter, uint8_t *nonce) {
  std::memset(nonce, 0, CHACHA_NONCE_SIZE);
  for (int i = 0; i < 8; i++)
    nonce[4 + i] = static_cast<uint8_t>(counter >> (8 * i));
}

/// Nonce of a pairing message: 4 zero bytes and an 8 character name such as "PS-Msg05"
static const char *access_control_name(uint8_t access) {
  switch (access) {
    case HomeKitPairings::ACCESS_CONTROL_OFF:
      return "not set up";
    case HomeKitPairings::ACCESS_CONTROL_HOME:
      return "people sharing the Home";
    default:
      return "everyone on the network";
  }
}

static void pairing_nonce(const char *name, uint8_t *nonce) {
  std::memset(nonce, 0, CHACHA_NONCE_SIZE);
  std::memcpy(nonce + 4, name, 8);
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
  this->airplay2_features_ = this->config_.airplay2_features != 0
                                 ? this->config_.airplay2_features
                                 : DEFAULT_FEATURES | (this->config_.ptp ? FEATURE_PTP : 0);
  // Lower 32 bits first
  std::snprintf(this->features_, sizeof(this->features_), "0x%" PRIX32 ",0x%" PRIX32,
                static_cast<uint32_t>(this->airplay2_features_), static_cast<uint32_t>(this->airplay2_features_ >> 32));

  // Key and pairing id stay the same across restarts
  uint8_t digest[SHA512_SIZE];
  Sha512 hash;
  hash.update(reinterpret_cast<const uint8_t *>("airplay-cpp"), 11);
  hash.update(mac, 6);
  const uint32_t identity = this->config_.homekit_identity;
  const uint8_t identity_bytes[4] = {static_cast<uint8_t>(identity >> 24), static_cast<uint8_t>(identity >> 16),
                                     static_cast<uint8_t>(identity >> 8), static_cast<uint8_t>(identity)};
  if (identity != 0)
    hash.update(identity_bytes, sizeof(identity_bytes));
  hash.finish(digest);
  // The HomeKit key pair; derived from the MAC address like shairport-sync derives it from the device ID
  uint8_t seed[SHA512_SIZE];
  Sha512 seed_hash;
  seed_hash.update(reinterpret_cast<const uint8_t *>("airplay-cpp-ed25519"), 19);
  seed_hash.update(mac, 6);
  if (identity != 0)
    seed_hash.update(identity_bytes, sizeof(identity_bytes));
  seed_hash.finish(seed);
  ed25519_key_pair(seed, this->accessory_secret_key_, this->public_key_);
  for (size_t i = 0; i < sizeof(this->public_key_); i++)
    std::snprintf(this->public_key_hex_ + 2 * i, 3, "%02x", this->public_key_[i]);
  for (auto [id_text, id] :
       {std::pair{this->pairing_id_, digest + 32}, std::pair{this->public_session_id_, digest + 48}}) {
    std::snprintf(id_text, sizeof(this->pairing_id_),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", id[0], id[1], id[2], id[3],
                  id[4], id[5], id[6], id[7], id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]);
  }
  // Not in a sender's group: its own
  std::snprintf(this->group_id_, sizeof(this->group_id_), "%s", this->pairing_id_);

  const TxtRecord records[] = {
      {"deviceid", this->device_id_},
      {"features", this->features_},
      {"flags", this->status_flags_},
      {"model", this->config_.model},
      {"pk", this->public_key_hex_},
      {"pi", this->pairing_id_},
      {"srcvers", AIRPLAY2_SOURCE_VERSION},
      {"protovers", "1.1"},
      {"acl", "0"},
      // The group the receiver plays in; isGroupLeader=0 is added while it is in a sender's group (on_group())
      {"gid", this->group_id_},
      {"gcgl", this->group_leader_},
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

void Receiver::receive_event_answer_(uint8_t connection, const uint8_t *data, size_t length) {
  Connection &c = this->connections_[connection];
  const auto *ip = reinterpret_cast<const uint8_t *>(&c.peer.address);
  if (!c.encrypted) {
    AIRPLAY_LOGV("Event answer from %u.%u.%u.%u: %u bytes", ip[0], ip[1], ip[2], ip[3], static_cast<unsigned>(length));
    return;
  }
  while (length > 0) {
    size_t needed = 2;
    if (c.frame_length >= 2) {
      const size_t data_length = c.frame[0] | (static_cast<size_t>(c.frame[1]) << 8);
      if (data_length > HAP_FRAME_DATA_SIZE) {
        c.frame_length = 0;
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
    c.frame_length = 0;
    uint8_t nonce[CHACHA_NONCE_SIZE];
    make_nonce(c.read_counter++, nonce);
    if (!chacha20_poly1305_decrypt(c.read_key, nonce, c.frame, 2, c.frame + 2, data_length, c.frame + 2 + data_length,
                                   c.frame + 2)) {
      AIRPLAY_LOGV("Event answer from %u.%u.%u.%u: %u bytes, not decrypted", ip[0], ip[1], ip[2], ip[3],
                   static_cast<unsigned>(data_length));
      continue;
    }
    // The status line, and where the body starts its first bytes
    const auto *text = reinterpret_cast<const char *>(c.frame + 2);
    size_t line = 0;
    while (line < data_length && line < 80 && text[line] != '\r')
      line++;
    size_t body = 0;
    for (size_t i = 0; i + 3 < data_length; i++) {
      if (std::memcmp(text + i, "\r\n\r\n", 4) == 0) {
        body = i + 4;
        break;
      }
    }
    char hex[2 * 32 + 1] = "";
    for (size_t i = 0; body != 0 && body + i < data_length && i < 32; i++)
      std::snprintf(hex + 2 * i, 3, "%02x", c.frame[2 + body + i]);
    AIRPLAY_LOGV("Event answer from %u.%u.%u.%u: %.*s, %u bytes, body %u bytes %s", ip[0], ip[1], ip[2], ip[3],
                 static_cast<int>(line), text, static_cast<unsigned>(data_length),
                 static_cast<unsigned>(body != 0 ? data_length - body : 0), hex);
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
  // What senders ask for; the details only at verbose level, as logging them can hold up the audio
  const char *line_end = std::strstr(request, "\r\n");
  const int line_length = line_end != nullptr ? static_cast<int>(std::min<ptrdiff_t>(line_end - request, 96)) : 0;
  if (path_is(request, "/feedback")) {
    AIRPLAY_LOGV("Request: %.*s", line_length, request);
  } else {
    const auto *ip = reinterpret_cast<const uint8_t *>(&this->connections_[connection].peer.address);
    char stream_header[16] = "";
    const bool streamed = get_header(request, header_length, "X-Apple-StreamID", stream_header, sizeof(stream_header));
    // Relayed remote control messages come in bursts: only at verbose level
    AIRPLAY_LOG_(streamed ? LogLevel::LOG_LEVEL_VERBOSE : LogLevel::LOG_LEVEL_DEBUG,
                 "Request: %.*s (%s, %u bytes%s) from %u.%u.%u.%u%s%s%s", line_length, request,
                 content_type[0] != '\0' ? content_type : "-", static_cast<unsigned>(body_length),
                 this->connections_[connection].encrypted ? ", encrypted" : "", ip[0], ip[1], ip[2], ip[3],
                 streamed ? ", stream " : "", stream_header,
                 body != nullptr || body_length == 0 ? "" : ", body not buffered");
  }
  const bool verbose = detail::g_log_level >= LogLevel::LOG_LEVEL_VERBOSE;
  // Headers of the requests that come before a session, and the content of property lists
  if (verbose &&
      (std::strcmp(method, "OPTIONS") == 0 ||
       ((std::strcmp(method, "GET") == 0 || std::strcmp(method, "POST") == 0) && !path_is(request, "/feedback")))) {
    for (const char *line = line_end; line != nullptr && line + 2 < request + header_length;) {
      line += 2;
      const char *next = std::strstr(line, "\r\n");
      if (next == nullptr || next == line)
        break;
      AIRPLAY_LOGV("  %.*s", static_cast<int>(std::min<ptrdiff_t>(next - line, 160)), line);
      line = next;
    }
  }
  if (verbose && plist && data != nullptr) {
    PlistReader reader;
    if (reader.parse(data, body_length)) {
      // The response body buffer is free until the response is built
      auto *text = reinterpret_cast<char *>(this->body_buffer_);
      const size_t length = reader.describe(reader.root(), text, AIRPLAY2_BODY_SIZE);
      for (size_t offset = 0; offset < length; offset += 150)
        AIRPLAY_LOGV("  plist: %.*s", static_cast<int>(std::min<size_t>(length - offset, 150)), text + offset);
    } else {
      AIRPLAY_LOGV("  not a binary property list");
    }
  }
  // Remote control relay: requests of a relayed stream carry its number
  char stream_text[16] = "";
  const bool has_stream = get_header(request, header_length, "X-Apple-StreamID", stream_text, sizeof(stream_text));
  Connection &relay = this->connections_[connection];
  if (relay.relay_latest != 0 && std::strcmp(method, "TEARDOWN") == 0) {
    // The streams it names end, all without names
    PlistReader reader;
    const PlistReader::Object streams = plist && data != nullptr && reader.parse(data, body_length)
                                            ? reader.get(reader.root(), "streams")
                                            : PlistReader::NONE;
    bool named = false;
    for (size_t i = 0; streams != PlistReader::NONE && i < 4; i++) {
      int64_t id = 0;
      if (reader.get_integer(reader.get(reader.at(streams, i), "streamID"), &id) && id > 0) {
        this->end_relay_(connection, static_cast<uint32_t>(id));
        named = true;
      }
    }
    if (!named)
      this->end_relay_(connection);
    return true;
  }
  // A message of a relayed stream: from the controller to the sender, or back. The stream comes from the
  // connection it was set up on or from X-Apple-StreamID; the direction from where it comes from, as a controller may
  // send on another connection than the one it set up the stream on.
  const uint32_t stream_id =
      has_stream ? static_cast<uint32_t>(std::strtoul(stream_text, nullptr, 10)) : relay.relay_latest;
  if (stream_id != 0 && std::strcmp(method, "POST") == 0 && path_is(request, "/command") && body_length > 0) {
    Connection *controller = nullptr;
    for (Connection &other : this->connections_) {
      if (other.open && std::find(std::begin(other.relay_streams), std::end(other.relay_streams), stream_id) !=
                            std::end(other.relay_streams))
        controller = &other;
    }
    const uint32_t sender =
        this->session_owner_ != NO_CONNECTION ? this->connections_[this->session_owner_].peer.address : 0;
    const uint32_t from = this->connections_[connection].peer.address;
    if (controller == nullptr || sender == 0) {
      AIRPLAY_LOGD("Nothing to relay stream %" PRIu32 " to (%s)", stream_id,
                   controller == nullptr ? "no controller" : "no sender");
      return true;
    }
    const bool to_sender = from == controller->peer.address;
    const uint32_t to = to_sender ? sender : controller->peer.address;
    if (to_sender && data != nullptr && !this->connections_[this->session_owner_].sender_answers_remote &&
        this->answer_controller_(*controller, stream_id, data, body_length, plist))
      return true;
    if (data == nullptr) {
      // Too large for the buffer (now playing details with cover art): the header now, the body as it comes
      uint8_t target = NO_CONNECTION;
      const bool sent = this->send_event_request_(to, stream_id, nullptr, body_length, &target);
      this->connections_[connection].relay_target = sent ? target : NO_CONNECTION;
      if (!sent) {
        controller->relay_not_sent++;
      } else if (to_sender) {
        controller->relayed_to_sender++;
      } else {
        controller->relayed_to_controller++;
      }
      AIRPLAY_LOG_(sent ? LogLevel::LOG_LEVEL_VERBOSE : LogLevel::LOG_LEVEL_WARN,
                   "Relay stream %" PRIu32 " %s: %u bytes, passed on as they come%s", stream_id,
                   to_sender ? "to the sender" : "to the controller", static_cast<unsigned>(body_length),
                   sent ? "" : ", not sent");
      return true;
    }
    // Without a property list, the data goes in one, as other speakers relay it
    const uint8_t *forward = data;
    size_t forward_length = body_length;
    if (!plist) {
      PlistWriter writer(this->body_buffer_, AIRPLAY2_BODY_SIZE);
      writer.begin_dict(1);
      writer.key("params");
      writer.begin_dict(1);
      writer.key("data");
      writer.data(data, body_length);
      forward = this->body_buffer_;
      forward_length = writer.finish();
    }
    const auto *from_ip = reinterpret_cast<const uint8_t *>(&from);
    const auto *to_ip = reinterpret_cast<const uint8_t *>(&to);
    const bool sent = forward_length > 0 && this->send_event_request_(to, stream_id, forward, forward_length);
    if (!sent) {
      controller->relay_not_sent++;
    } else if (to_sender) {
      controller->relayed_to_sender++;
    } else {
      controller->relayed_to_controller++;
    }
    AIRPLAY_LOG_(sent ? LogLevel::LOG_LEVEL_VERBOSE : LogLevel::LOG_LEVEL_WARN,
                 "Relay stream %" PRIu32 " %s: %u.%u.%u.%u -> %u.%u.%u.%u, %u bytes%s", stream_id,
                 to_sender ? "to the sender" : "to the controller", from_ip[0], from_ip[1], from_ip[2], from_ip[3],
                 to_ip[0], to_ip[1], to_ip[2], to_ip[3], static_cast<unsigned>(forward_length),
                 sent ? "" : ", not sent");
    return true;
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
      this->handle_pair_verify_(connection, data, body_length, response);
    } else if (path_is(request, "/pair-add") || path_is(request, "/pair-remove") || path_is(request, "/pair-list")) {
      // Only after pairing
      if (!this->connections_[connection].encrypted) {
        response.status = 470;
        response.status_text = "Connection Authorization Required";
      } else {
        this->handle_pairings_(data, data != nullptr ? body_length : 0, response);
      }
    } else if (path_is(request, "/configure")) {
      if (!this->connections_[connection].encrypted) {
        response.status = 470;
        response.status_text = "Connection Authorization Required";
      } else {
        this->handle_configure_(data, data != nullptr ? body_length : 0, response);
      }
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
  if (std::strcmp(method, "TEARDOWN") == 0 && plist && data != nullptr &&
      (connection == this->session_owner_ || this->connections_[connection].session_pending)) {
    // With a list of streams only the streams end; the session stays for the next track
    PlistReader reader;
    if (!reader.parse(data, body_length) || reader.get(reader.root(), "streams") == PlistReader::NONE)
      return false;
    if (connection != this->session_owner_) {
      // A sender that was set aside ends the stream it had (iOS does on the pause it gets); it stays connected to
      // come back with a new one
      AIRPLAY_LOGD("The paused sender ended its stream");
      return true;
    }
    AIRPLAY_LOGI("Stream stopped");
    this->stop_audio_();
    this->stop_buffered_audio_();
    if (this->session_state_ == SessionState::PLAYING)
      this->set_session_state_(SessionState::PAUSED);
    return true;
  }
  if (std::strcmp(method, "SETRATEANCHORTIME") == 0) {
    if (connection == this->session_owner_ && data != nullptr)
      this->handle_rate_anchor_(data, body_length, now_us);
    return true;
  }
  if (std::strcmp(method, "FLUSHBUFFERED") == 0) {
    if (connection == this->session_owner_ && data != nullptr)
      this->handle_flush_buffered_(data, body_length);
    return true;
  }
  if (std::strcmp(method, "SETPEERS") == 0 || std::strcmp(method, "SETPEERSX") == 0) {
    // The devices of a PTP group (macOS sends it as "/peer-list-changed", a property list all the same)
    if (data != nullptr && detail::g_log_level >= LogLevel::LOG_LEVEL_DEBUG) {
      PlistReader reader;
      auto *text = reinterpret_cast<char *>(this->body_buffer_);
      const size_t length = reader.parse(data, body_length) ? reader.describe(reader.root(), text, 1024) : 0;
      for (size_t offset = 0; offset < length; offset += 150)
        AIRPLAY_LOGD("%s: %.*s", method, static_cast<int>(std::min<size_t>(length - offset, 150)), text + offset);
    }
    return true;
  }
  return false;
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
    // Transient for a sender's session, otherwise a HomeKit pairing by the Home app
    uint8_t flags = 0;
    this->pairing_transient_ =
        tlv8_find(body, length, TLV_FLAGS, &flags, 1, &value_length) && (flags & TLV_FLAG_TRANSIENT) != 0;
    if (this->refuse_(connection, this->pairing_transient_ ? "pairing for a session" : "HomeKit pairing")) {
      // Forbidden rather than a pairing error, which senders take for a wrong password (Music Assistant then asks
      // for one even after access is opened again)
      response.status = 403;
      response.status_text = "Forbidden";
      response.content_type = nullptr;
      response.body = nullptr;
      return;
    }
    uint8_t salt[SRP_SALT_SIZE];
    uint8_t secret[SRP_SECRET_SIZE];
    this->config_.random(salt, sizeof(salt));
    this->config_.random(secret, sizeof(secret));
    // With the Home app's password, senders enter it instead of the fixed PIN
    const char *pin = this->homekit_.password[0] != '\0' ? this->homekit_.password : PAIR_SETUP_PIN;
    this->srp_->begin(PAIR_SETUP_USERNAME, pin, salt, secret);
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
      if (!this->pairing_transient_) {
        // The keys are exchanged next, in M5 and M6
        this->pairing_connection_ = connection;
        response.body_length = writer.length();
        return;
      }
      // The sender's write key is the receiver's read key
      const uint8_t *secret = this->srp_->session_key();
      hkdf_sha512_key(CONTROL_SALT, CONTROL_SENDER_WRITE_INFO, secret, SHA512_SIZE, c.read_key);
      hkdf_sha512_key(CONTROL_SALT, CONTROL_SENDER_READ_INFO, secret, SHA512_SIZE, c.write_key);
      hkdf_sha512_key(EVENTS_SALT, EVENTS_RECEIVER_WRITE_INFO, secret, SHA512_SIZE, c.event_key);
      hkdf_sha512_key(EVENTS_SALT, EVENTS_RECEIVER_READ_INFO, secret, SHA512_SIZE, c.event_read_key);
      std::memcpy(c.pair_secret, secret, sizeof(c.pair_secret));
      c.pair_secret_length = SHA512_SIZE;
      c.encrypt_after_response = true;
      AIRPLAY_LOGD("Paired");
    } else {
      // A sender that pairs with a password (not transient) when none is set fails here too (Music Assistant)
      AIRPLAY_LOGW("Pairing failed (%s)%s", this->pairing_transient_ ? "transient" : "with a PIN or password",
                   this->homekit_.password[0] != '\0' ? ": wrong password?" : "");
      writer.add_byte(TLV_ERROR, TLV_ERROR_AUTHENTICATION);
    }
  } else if (state == 5 && connection == this->pairing_connection_ && !this->pairing_transient_) {
    this->pairing_connection_ = NO_CONNECTION;
    writer.add_byte(TLV_STATE, 6);
    if (this->finish_pair_setup_(body, length, writer)) {
      AIRPLAY_LOGI("Paired with HomeKit");
    } else {
      AIRPLAY_LOGW("HomeKit pairing failed");
      writer.add_byte(TLV_ERROR, TLV_ERROR_AUTHENTICATION);
    }
  } else {
    writer.add_byte(TLV_STATE, static_cast<uint8_t>(state + 1));
    writer.add_byte(TLV_ERROR, TLV_ERROR_UNKNOWN);
  }
  response.body_length = writer.length();
}

bool Receiver::finish_pair_setup_(const uint8_t *body, size_t length, Tlv8Writer &writer) {
  uint8_t encrypted[PAIRING_SUB_TLV_SIZE];
  size_t encrypted_length = 0;
  if (!tlv8_find(body, length, TLV_ENCRYPTED_DATA, encrypted, sizeof(encrypted), &encrypted_length) ||
      encrypted_length < POLY1305_TAG_SIZE)
    return false;
  const uint8_t *session_key = this->srp_->session_key();
  uint8_t key[CHACHA_KEY_SIZE];
  uint8_t nonce[CHACHA_NONCE_SIZE];
  hkdf_sha512_key(PAIR_SETUP_ENCRYPT_SALT, PAIR_SETUP_ENCRYPT_INFO, session_key, SHA512_SIZE, key);
  pairing_nonce("PS-Msg05", nonce);
  uint8_t plain[PAIRING_SUB_TLV_SIZE];
  const size_t plain_length = encrypted_length - POLY1305_TAG_SIZE;
  if (!chacha20_poly1305_decrypt(key, nonce, nullptr, 0, encrypted, plain_length, encrypted + plain_length, plain))
    return false;

  // The controller signs its pairing identifier and long-term key
  uint8_t id[HOMEKIT_ID_SIZE];
  size_t id_length = 0;
  uint8_t public_key[ED25519_PUBLIC_KEY_SIZE];
  size_t public_key_length = 0;
  uint8_t signature[ED25519_SIGNATURE_SIZE];
  size_t signature_length = 0;
  if (!tlv8_find(plain, plain_length, TLV_IDENTIFIER, id, sizeof(id) - 1, &id_length) || id_length == 0 ||
      !tlv8_find(plain, plain_length, TLV_PUBLIC_KEY, public_key, sizeof(public_key), &public_key_length) ||
      public_key_length != sizeof(public_key) ||
      !tlv8_find(plain, plain_length, TLV_SIGNATURE, signature, sizeof(signature), &signature_length) ||
      signature_length != sizeof(signature))
    return false;
  uint8_t info[CHACHA_KEY_SIZE + HOMEKIT_ID_SIZE + ED25519_PUBLIC_KEY_SIZE];
  hkdf_sha512_key(PAIR_SETUP_CONTROLLER_SALT, PAIR_SETUP_CONTROLLER_INFO, session_key, SHA512_SIZE, info);
  std::memcpy(info + CHACHA_KEY_SIZE, id, id_length);
  std::memcpy(info + CHACHA_KEY_SIZE + id_length, public_key, sizeof(public_key));
  if (!ed25519_verify(signature, public_key, info, CHACHA_KEY_SIZE + id_length + sizeof(public_key)))
    return false;
  // The Home app adding the receiver, or a sender that knows the password (no admin then)
  const bool with_password = this->homekit_.password[0] != '\0';
  if (!this->add_controller_(id, id_length, public_key, with_password ? PERMISSION_WITH_PASSWORD : PERMISSION_ADMIN))
    return false;
  this->homekit_changed_();

  // The receiver answers with its own
  const size_t accessory_id_length = std::strlen(this->pairing_id_);
  hkdf_sha512_key(PAIR_SETUP_ACCESSORY_SALT, PAIR_SETUP_ACCESSORY_INFO, session_key, SHA512_SIZE, info);
  std::memcpy(info + CHACHA_KEY_SIZE, this->pairing_id_, accessory_id_length);
  std::memcpy(info + CHACHA_KEY_SIZE + accessory_id_length, this->public_key_, sizeof(this->public_key_));
  ed25519_sign(this->accessory_secret_key_, info, CHACHA_KEY_SIZE + accessory_id_length + sizeof(this->public_key_),
               signature);
  Tlv8Writer sub(plain, sizeof(plain) - POLY1305_TAG_SIZE);
  sub.add(TLV_IDENTIFIER, reinterpret_cast<const uint8_t *>(this->pairing_id_), accessory_id_length);
  sub.add(TLV_PUBLIC_KEY, this->public_key_, sizeof(this->public_key_));
  sub.add(TLV_SIGNATURE, signature, sizeof(signature));
  const size_t sub_length = sub.length();
  if (sub_length == 0)
    return false;
  pairing_nonce("PS-Msg06", nonce);
  chacha20_poly1305_encrypt(key, nonce, nullptr, 0, plain, sub_length, plain, plain + sub_length);
  writer.add(TLV_ENCRYPTED_DATA, plain, sub_length + POLY1305_TAG_SIZE);
  return true;
}

void Receiver::handle_pair_verify_(uint8_t connection, const uint8_t *body, size_t length, Response &response) {
  Connection &c = this->connections_[connection];
  Tlv8Writer writer(this->body_buffer_, AIRPLAY2_BODY_SIZE);
  response.content_type = CONTENT_TYPE_OCTET_STREAM;
  response.body = this->body_buffer_;

  uint8_t state = 0;
  size_t value_length = 0;
  if (body != nullptr)
    tlv8_find(body, length, TLV_STATE, &state, 1, &value_length);
  uint8_t key[CHACHA_KEY_SIZE];
  uint8_t nonce[CHACHA_NONCE_SIZE];
  uint8_t plain[PAIRING_SUB_TLV_SIZE];
  const size_t accessory_id_length = std::strlen(this->pairing_id_);

  uint8_t *own_public = c.verify_keys;
  uint8_t *peer_public = c.verify_keys + X25519_KEY_SIZE;
  uint8_t *shared = c.verify_keys + 2 * X25519_KEY_SIZE;
  if (state == 1) {
    writer.add_byte(TLV_STATE, 2);
    c.verify_pending = false;
    size_t peer_length = 0;
    uint8_t secret[X25519_KEY_SIZE];
    this->config_.random(secret, sizeof(secret));
    x25519_public_key(secret, own_public);
    const bool agreed = tlv8_find(body, length, TLV_PUBLIC_KEY, peer_public, X25519_KEY_SIZE, &peer_length) &&
                        peer_length == X25519_KEY_SIZE && x25519(secret, peer_public, shared);
    std::memset(secret, 0, sizeof(secret));
    if (!agreed) {
      writer.add_byte(TLV_ERROR, TLV_ERROR_AUTHENTICATION);
      response.body_length = writer.length();
      return;
    }
    // The receiver signs both ephemeral keys and its identifier
    uint8_t info[2 * X25519_KEY_SIZE + HOMEKIT_ID_SIZE];
    std::memcpy(info, own_public, X25519_KEY_SIZE);
    std::memcpy(info + X25519_KEY_SIZE, this->pairing_id_, accessory_id_length);
    std::memcpy(info + X25519_KEY_SIZE + accessory_id_length, peer_public, X25519_KEY_SIZE);
    uint8_t signature[ED25519_SIGNATURE_SIZE];
    ed25519_sign(this->accessory_secret_key_, info, 2 * X25519_KEY_SIZE + accessory_id_length, signature);
    Tlv8Writer sub(plain, sizeof(plain) - POLY1305_TAG_SIZE);
    sub.add(TLV_IDENTIFIER, reinterpret_cast<const uint8_t *>(this->pairing_id_), accessory_id_length);
    sub.add(TLV_SIGNATURE, signature, sizeof(signature));
    const size_t sub_length = sub.length();
    hkdf_sha512_key(PAIR_VERIFY_ENCRYPT_SALT, PAIR_VERIFY_ENCRYPT_INFO, shared, X25519_KEY_SIZE, key);
    pairing_nonce("PV-Msg02", nonce);
    chacha20_poly1305_encrypt(key, nonce, nullptr, 0, plain, sub_length, plain, plain + sub_length);
    writer.add(TLV_PUBLIC_KEY, own_public, X25519_KEY_SIZE);
    writer.add(TLV_ENCRYPTED_DATA, plain, sub_length + POLY1305_TAG_SIZE);
    c.verify_pending = true;
  } else if (state == 3 && c.verify_pending) {
    c.verify_pending = false;
    writer.add_byte(TLV_STATE, 4);
    uint8_t encrypted[PAIRING_SUB_TLV_SIZE];
    size_t encrypted_length = 0;
    uint8_t id[HOMEKIT_ID_SIZE];
    size_t id_length = 0;
    uint8_t signature[ED25519_SIGNATURE_SIZE];
    size_t signature_length = 0;
    hkdf_sha512_key(PAIR_VERIFY_ENCRYPT_SALT, PAIR_VERIFY_ENCRYPT_INFO, shared, X25519_KEY_SIZE, key);
    pairing_nonce("PV-Msg03", nonce);
    bool ok = tlv8_find(body, length, TLV_ENCRYPTED_DATA, encrypted, sizeof(encrypted), &encrypted_length) &&
              encrypted_length >= POLY1305_TAG_SIZE;
    const size_t plain_length = ok ? encrypted_length - POLY1305_TAG_SIZE : 0;
    ok = ok &&
         chacha20_poly1305_decrypt(key, nonce, nullptr, 0, encrypted, plain_length, encrypted + plain_length, plain) &&
         tlv8_find(plain, plain_length, TLV_IDENTIFIER, id, sizeof(id) - 1, &id_length) && id_length > 0 &&
         tlv8_find(plain, plain_length, TLV_SIGNATURE, signature, sizeof(signature), &signature_length) &&
         signature_length == sizeof(signature);
    // A known controller must sign with its key. One that is not known (the pairings are lost on restart) is let
    // in like a transient pairing.
    const Controller *controller = ok ? this->find_controller_(id, id_length) : nullptr;
    if (ok && controller != nullptr) {
      uint8_t info[2 * X25519_KEY_SIZE + HOMEKIT_ID_SIZE];
      std::memcpy(info, peer_public, X25519_KEY_SIZE);
      std::memcpy(info + X25519_KEY_SIZE, id, id_length);
      std::memcpy(info + X25519_KEY_SIZE + id_length, own_public, X25519_KEY_SIZE);
      ok = ed25519_verify(signature, controller->public_key, info, 2 * X25519_KEY_SIZE + id_length);
    }
    c.homekit_controller = ok && controller != nullptr;
    if (ok && controller == nullptr && this->refuse_(connection, "controller that is not paired")) {
      response.status = 403;
      response.status_text = "Forbidden";
      response.content_type = nullptr;
      response.body = nullptr;
      return;
    } else if (!ok) {
      AIRPLAY_LOGW("pair-verify failed");
      writer.add_byte(TLV_ERROR, TLV_ERROR_AUTHENTICATION);
    } else {
      const uint8_t *secret = shared;
      hkdf_sha512_key(CONTROL_SALT, CONTROL_SENDER_WRITE_INFO, secret, X25519_KEY_SIZE, c.read_key);
      hkdf_sha512_key(CONTROL_SALT, CONTROL_SENDER_READ_INFO, secret, X25519_KEY_SIZE, c.write_key);
      hkdf_sha512_key(EVENTS_SALT, EVENTS_RECEIVER_WRITE_INFO, secret, X25519_KEY_SIZE, c.event_key);
      hkdf_sha512_key(EVENTS_SALT, EVENTS_RECEIVER_READ_INFO, secret, X25519_KEY_SIZE, c.event_read_key);
      std::memcpy(c.pair_secret, secret, X25519_KEY_SIZE);
      c.pair_secret_length = X25519_KEY_SIZE;
      c.encrypt_after_response = true;
      AIRPLAY_LOGD("Verified %s", controller != nullptr ? "a paired controller" : "a controller paired before");
    }
  } else {
    writer.add_byte(TLV_STATE, static_cast<uint8_t>(state + 1));
    writer.add_byte(TLV_ERROR, TLV_ERROR_UNKNOWN);
  }
  response.body_length = writer.length();
}

Receiver::Controller *Receiver::find_controller_(const uint8_t *id, size_t length) {
  for (Controller &controller : this->homekit_.controllers) {
    if (controller.id[0] != '\0' && std::strlen(controller.id) == length && std::memcmp(controller.id, id, length) == 0)
      return &controller;
  }
  return nullptr;
}

bool Receiver::add_controller_(const uint8_t *id, size_t length, const uint8_t *public_key, uint8_t permissions) {
  if (length == 0 || length >= HOMEKIT_ID_SIZE)
    return false;
  Controller *controller = this->find_controller_(id, length);
  for (size_t i = 0; controller == nullptr && i < HomeKitPairings::MAX_CONTROLLERS; i++) {
    if (this->homekit_.controllers[i].id[0] == '\0')
      controller = &this->homekit_.controllers[i];
  }
  // When full, a pairing made with the password makes room
  for (size_t i = 0; controller == nullptr && i < HomeKitPairings::MAX_CONTROLLERS; i++) {
    if ((this->homekit_.controllers[i].permissions & PERMISSION_WITH_PASSWORD) != 0)
      controller = &this->homekit_.controllers[i];
  }
  if (controller == nullptr)
    return false;
  std::memcpy(controller->id, id, length);
  controller->id[length] = '\0';
  std::memcpy(controller->public_key, public_key, ED25519_PUBLIC_KEY_SIZE);
  controller->permissions = permissions;
  return true;
}

bool Receiver::refuse_(uint8_t connection, const char *reason) {
  const Connection &c = this->connections_[connection];
  if (this->homekit_.access_control != HomeKitPairings::ACCESS_CONTROL_HOME || c.homekit_controller)
    return false;
  const auto *ip = reinterpret_cast<const uint8_t *>(&c.peer.address);
  AIRPLAY_LOGW("Refused %u.%u.%u.%u (%s): the Home app allows only people sharing the Home", ip[0], ip[1], ip[2], ip[3],
               reason);
  return true;
}

void Receiver::homekit_changed_() {
  if (this->homekit_.access_control != HomeKitPairings::ACCESS_CONTROL_OFF) {
    bool admin = false;
    for (const Controller &controller : this->homekit_.controllers)
      admin = admin || (controller.id[0] != '\0' && (controller.permissions & PERMISSION_ADMIN) != 0);
    if (!admin) {
      // Nobody left who could set it up again
      this->homekit_.access_control = HomeKitPairings::ACCESS_CONTROL_OFF;
      this->homekit_.password[0] = '\0';
      AIRPLAY_LOGI("HomeKit access control disabled: no admin is paired");
    }
  }
  this->update_status_flags_();
  if (this->listener_ != nullptr)
    this->listener_->on_homekit_pairings(this->homekit_);
}

int64_t Receiver::status_flags_value_() const {
  return STATUS_FLAGS |
         (this->homekit_.access_control != HomeKitPairings::ACCESS_CONTROL_OFF ? STATUS_FLAG_HOMEKIT_ACCESS_CONTROL
                                                                               : 0) |
         (this->homekit_.password[0] != '\0' ? STATUS_FLAG_PASSWORD : 0) |
         (this->in_group_ || (this->config_.remote_control && this->session_state_ != SessionState::NONE)
              ? STATUS_FLAG_REMOTE_CONTROL_RELAY
              : 0);
}

void Receiver::update_status_flags_() {
  char flags[sizeof(this->status_flags_)];
  std::snprintf(flags, sizeof(flags), "0x%" PRIx64, static_cast<uint64_t>(this->status_flags_value_()));
  std::snprintf(this->password_required_, sizeof(this->password_required_), "%s",
                this->config_.password != nullptr || this->homekit_.password[0] != '\0' ? "true" : "false");
  if (std::strcmp(flags, this->status_flags_) == 0)
    return;
  std::memcpy(this->status_flags_, flags, sizeof(flags));
  AIRPLAY_LOGD("Status flags %s", this->status_flags_);
  if (this->listener_ != nullptr)
    this->listener_->on_status_flags(this->status_flags_);
}

void Receiver::update_group_() {
  const Connection *owner = this->session_owner_ != NO_CONNECTION ? &this->connections_[this->session_owner_] : nullptr;
  const bool in_group = owner != nullptr && owner->group_id[0] != '\0';
  const char *group_id = in_group ? owner->group_id : this->pairing_id_;
  const char *leader = in_group && owner->group_leader ? "1" : "0";
  if (in_group == this->in_group_ && std::strcmp(group_id, this->group_id_) == 0 && leader[0] == this->group_leader_[0])
    return;
  std::snprintf(this->group_id_, sizeof(this->group_id_), "%s", group_id);
  this->group_leader_[0] = leader[0];
  this->in_group_ = in_group;
  AIRPLAY_LOGD("Group %s (gcgl %s)", this->group_id_, this->group_leader_);
  this->update_status_flags_();
  if (this->listener_ != nullptr)
    this->listener_->on_group(this->group_id_, this->group_leader_, this->in_group_);
}

void Receiver::set_homekit_pairings(const HomeKitPairings &pairings) {
  this->homekit_ = pairings;
  this->homekit_.password[sizeof(this->homekit_.password) - 1] = '\0';
  size_t paired = 0;
  for (Controller &controller : this->homekit_.controllers) {
    controller.id[sizeof(controller.id) - 1] = '\0';
    paired += controller.id[0] != '\0' ? 1 : 0;
  }
  AIRPLAY_LOGD("HomeKit: %u paired controllers, access %s", static_cast<unsigned>(paired),
               access_control_name(this->homekit_.access_control));
  this->update_status_flags_();
}

void Receiver::handle_pairings_(const uint8_t *body, size_t length, Response &response) {
  Tlv8Writer writer(this->body_buffer_, AIRPLAY2_BODY_SIZE);
  response.content_type = CONTENT_TYPE_OCTET_STREAM;
  response.body = this->body_buffer_;
  writer.add_byte(TLV_STATE, 2);

  uint8_t method = 0xff;
  size_t value_length = 0;
  tlv8_find(body, length, TLV_METHOD, &method, 1, &value_length);
  uint8_t id[HOMEKIT_ID_SIZE];
  size_t id_length = 0;
  const bool has_id = tlv8_find(body, length, TLV_IDENTIFIER, id, sizeof(id) - 1, &id_length) && id_length > 0;
  if (method == PAIRING_METHOD_ADD) {
    uint8_t public_key[ED25519_PUBLIC_KEY_SIZE];
    size_t public_key_length = 0;
    uint8_t permissions = 0;
    tlv8_find(body, length, TLV_PERMISSIONS, &permissions, 1, &value_length);
    permissions &= PERMISSION_ADMIN;
    if (!has_id || !tlv8_find(body, length, TLV_PUBLIC_KEY, public_key, sizeof(public_key), &public_key_length) ||
        public_key_length != sizeof(public_key)) {
      writer.add_byte(TLV_ERROR, TLV_ERROR_UNKNOWN);
    } else if (!this->add_controller_(id, id_length, public_key, permissions)) {
      writer.add_byte(TLV_ERROR, TLV_ERROR_MAX_PEERS);
    } else {
      AIRPLAY_LOGD("HomeKit pairing added: %.*s", static_cast<int>(id_length), reinterpret_cast<const char *>(id));
      this->homekit_changed_();
    }
  } else if (method == PAIRING_METHOD_REMOVE) {
    Controller *controller = has_id ? this->find_controller_(id, id_length) : nullptr;
    if (controller != nullptr) {
      AIRPLAY_LOGD("HomeKit pairing removed: %s", controller->id);
      controller->id[0] = '\0';
      this->homekit_changed_();
    }
  } else if (method == PAIRING_METHOD_LIST) {
    bool first = true;
    for (const Controller &controller : this->homekit_.controllers) {
      if (controller.id[0] == '\0')
        continue;
      if (!first)
        writer.add(TLV_SEPARATOR, nullptr, 0);
      first = false;
      writer.add(TLV_IDENTIFIER, reinterpret_cast<const uint8_t *>(controller.id), std::strlen(controller.id));
      writer.add(TLV_PUBLIC_KEY, controller.public_key, sizeof(controller.public_key));
      writer.add_byte(TLV_PERMISSIONS, controller.permissions & PERMISSION_ADMIN);
    }
  } else {
    writer.add_byte(TLV_ERROR, TLV_ERROR_UNKNOWN);
  }
  response.body_length = writer.length();
}

void Receiver::handle_configure_(const uint8_t *body, size_t length, Response &response) {
  PlistReader reader;
  if (body == nullptr || !reader.parse(body, length)) {
    response.status = 400;
    response.status_text = "Bad Request";
    return;
  }
  const PlistReader::Object settings = reader.get(reader.root(), "ConfigurationDictionary");
  // Level 1 is for the people sharing the Home, 0 for everyone on the network. The Home app sends a lower level only
  // to a receiver that answered with the level it has (shairport-sync answers 0), and nothing when a password goes.
  bool enable = false;
  int64_t level = 0;
  const bool has_enable = reader.get_bool(reader.get(settings, "Enable_HK_Access_Control"), &enable);
  const bool has_level = reader.get_integer(reader.get(settings, "Access_Control_Level"), &level);
  const char *password = nullptr;
  size_t password_length = 0;
  if (reader.get_string(reader.get(settings, "Password"), &password, &password_length)) {
    // Empty when it is turned off
    password_length = std::min(password_length, sizeof(this->homekit_.password) - 1);
    const bool changed = std::strncmp(this->homekit_.password, password, password_length) != 0 ||
                         this->homekit_.password[password_length] != '\0';
    std::memcpy(this->homekit_.password, password, password_length);
    this->homekit_.password[password_length] = '\0';
    if (changed) {
      // A new password shuts out those that paired with the old one; without one, everybody may play anyway
      for (Controller &controller : this->homekit_.controllers) {
        if (password_length > 0 && (controller.permissions & PERMISSION_WITH_PASSWORD) != 0)
          controller = Controller{};
      }
      if (password_length > 0) {
        AIRPLAY_LOGI("Password required (%u characters)", static_cast<unsigned>(password_length));
      } else {
        AIRPLAY_LOGI("Password no longer required");
      }
      this->homekit_changed_();
    }
  }
  if (has_enable || has_level) {
    if (has_enable && !enable) {
      this->homekit_.access_control = HomeKitPairings::ACCESS_CONTROL_OFF;
    } else if (has_enable || this->homekit_.access_control != HomeKitPairings::ACCESS_CONTROL_OFF) {
      this->homekit_.access_control =
          level >= 1 ? HomeKitPairings::ACCESS_CONTROL_HOME : HomeKitPairings::ACCESS_CONTROL_NETWORK;
    }
    AIRPLAY_LOGI("HomeKit access: %s", access_control_name(this->homekit_.access_control));
    this->homekit_changed_();
  }
  // The receiver's identity and the access it has
  PlistWriter writer(this->body_buffer_, AIRPLAY2_BODY_SIZE);
  const bool with_password = this->homekit_.password[0] != '\0';
  if (this->homekit_.access_control != HomeKitPairings::ACCESS_CONTROL_OFF) {
    writer.begin_dict(with_password ? 6 : 5);
    writer.key("Identifier");
    writer.string(this->pairing_id_);
    writer.key("Enable_HK_Access_Control");
    writer.boolean(true);
    writer.key("PublicKey");
    writer.data(this->public_key_, sizeof(this->public_key_));
    writer.key("Device_Name");
    writer.string(this->config_.name);
    writer.key("Access_Control_Level");
    writer.integer(this->homekit_.access_control == HomeKitPairings::ACCESS_CONTROL_HOME ? 1 : 0);
    if (with_password) {
      // Echoed like the level, which the Home app needs to turn it off again
      writer.key("Password");
      writer.string(this->homekit_.password);
    }
  } else {
    writer.begin_dict(0);
  }
  response.body_length = writer.finish();
  response.content_type = CONTENT_TYPE_PLIST;
  response.body = this->body_buffer_;
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
      c.remote_control = true;
      this->event_channel_pending_ = true;
      this->event_channel_address_ = c.peer.address;
      this->event_channel_source_ = connection;
      this->event_channel_since_ms_ = this->poll_ms_;
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
    // The group the sender plays in, announced while its session plays
    const char *group = nullptr;
    size_t group_length = 0;
    if (reader.get_string(reader.get(root, "groupUUID"), &group, &group_length) && group_length < sizeof(c.group_id)) {
      std::memcpy(c.group_id, group, group_length);
      c.group_id[group_length] = '\0';
      c.group_leader = false;
      reader.get_bool(reader.get(root, "groupContainsGroupLeader"), &c.group_leader);
    }
    const bool ptp = reader.string_equals(timing_protocol, "PTP");
    if (timing_protocol != PlistReader::NONE && !reader.string_equals(timing_protocol, "NTP") &&
        !(ptp && this->ptp_open_)) {
      AIRPLAY_LOGW(ptp ? "PTP timing is not enabled (ReceiverConfig::ptp)" : "Only NTP and PTP timing are supported");
      return;
    }
    char local_address[16];
    {
      const auto *ip = reinterpret_cast<const uint8_t *>(&c.local.address);
      std::snprintf(local_address, sizeof(local_address), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    }
    // With PTP the answer names the receiver as a timing peer with its clock, as the sender names itself, and no
    // port for clock requests
    const auto write_timing = [&](PlistWriter &out) {
      out.key("timingPort");
      out.integer(ptp ? 0 : this->udp_ports_[static_cast<size_t>(UdpChannel::TIMING)]);
      if (ptp) {
        out.key("timingPeerInfo");
        out.begin_dict(3);
        out.key("Addresses");
        out.begin_array(1);
        out.string(local_address);
        out.key("ID");
        out.string(local_address);
        out.key("ClockID");
        out.integer(static_cast<int64_t>(this->ptp_clocks_.identity()));
      }
    };
    const char *name = nullptr;
    size_t name_length = 0;
    if (reader.get_string(reader.get(root, "name"), &name, &name_length))
      copy_utf8(c.sender_name, sizeof(c.sender_name), reinterpret_cast<const uint8_t *>(name), name_length);
    const char *os_name = nullptr;
    size_t os_name_length = 0;
    // Only iOS answers the controllers' messages; for others (macOS, Music Assistant) the receiver does
    c.sender_answers_remote = false;
    if (reader.get_string(reader.get(root, "osName"), &os_name, &os_name_length)) {
      for (const char *answering : {"iPhone OS", "iPadOS", "iOS"}) {
        c.sender_answers_remote |=
            os_name_length == std::strlen(answering) && std::memcmp(os_name, answering, os_name_length) == 0;
      }
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
      this->event_channel_source_ = connection;
      this->event_channel_since_ms_ = this->poll_ms_;
      c.pending_ptp = ptp;
      writer.begin_dict(ptp ? 3 : 2);
      writer.key("eventPort");
      writer.integer(c.local.port);
      write_timing(writer);
      response.body_length = writer.finish();
      if (response.body_length > 0) {
        response.status = 200;
        response.status_text = "OK";
        response.content_type = CONTENT_TYPE_PLIST;
        response.body = this->body_buffer_;
      }
      return;
    }
    c.pending_timing_port = static_cast<uint16_t>(timing_port);  // Kept, should it be set aside and come back
    c.pending_ptp = ptp;
    this->take_session_(connection, request, header_length);
    this->stop_buffered_audio_();
    this->airplay2_recording_ = false;
    this->have_session_stream_key_ = false;
    this->codec_ = Codec::NONE;
    this->encrypted_ = false;
    this->airplay2_audio_ = false;
    if (!this->open_udp_(connection, 0, static_cast<uint32_t>(timing_port), this->udp_ports_))
      return;
    this->set_ptp_timing_(ptp);
    this->event_channel_pending_ = true;
    this->event_channel_address_ = c.peer.address;
    this->event_channel_source_ = connection;
    this->event_channel_since_ms_ = this->poll_ms_;
    // The event connection uses the RTSP port; nothing is read from it
    writer.begin_dict(ptp ? 3 : 2);
    writer.key("eventPort");
    writer.integer(c.local.port);
    write_timing(writer);
  } else {
    const PlistReader::Object first = reader.at(streams, 0);
    int64_t first_type = 0;
    reader.get_integer(reader.get(first, "type"), &first_type);
    if (first_type == STREAM_TYPE_REMOTE_CONTROL) {
      int64_t control_type = 0;
      reader.get_integer(reader.get(first, "controlType"), &control_type);
      char client_uuid[64] = "";
      char client_type_uuid[64] = "";
      for (auto [key, out] : {std::pair{"clientUUID", client_uuid}, std::pair{"clientTypeUUID", client_type_uuid}}) {
        const char *text = nullptr;
        size_t text_length = 0;
        if (reader.get_string(reader.get(first, key), &text, &text_length) && text_length < 64) {
          std::memcpy(out, text, text_length);
          out[text_length] = '\0';
        }
      }
      this->setup_relay_(connection, control_type, client_uuid, client_type_uuid, response);
      return;
    }
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
      std::memcpy(this->remembered_stream_key_, key, sizeof(this->remembered_stream_key_));
      this->remembered_key_address_ = c.peer.address;
    }
    if (type == STREAM_TYPE_BUFFERED) {
      int64_t audio_format = 0;
      reader.get_integer(reader.get(stream, "audioFormat"), &audio_format);
      // iOS sends AAC, Music Assistant ALAC (when PTP is offered)
      const bool aac = compression == COMPRESSION_AAC && audio_format == AUDIO_FORMAT_AAC_44100 &&
                       frames_per_packet == AAC_FRAMES_PER_PACKET && this->config_.aac_decoder != nullptr;
      const bool alac = compression == COMPRESSION_ALAC && audio_format == AUDIO_FORMAT_ALAC_44100 &&
                        frames_per_packet > 0 && frames_per_packet <= FRAMES_PER_PACKET;
      if (this->buffered_storage_ == nullptr || (!aac && !alac) ||
          (key == nullptr && !this->have_session_stream_key_)) {
        AIRPLAY_LOGW("Unsupported buffered stream (ct %" PRId64 ", format 0x%" PRIx64 "%s)", compression, audio_format,
                     compression == COMPRESSION_AAC && this->config_.aac_decoder == nullptr ? ", no AAC decoder" : "");
        return;
      }
      this->stop_audio_();
      this->stop_buffered_audio_();
      this->forget_timeline_();
      if (aac && !this->config_.aac_decoder->begin()) {
        AIRPLAY_LOGW("Failed to start the AAC decoder");
        return;
      }
      if (alac) {
        ALACConfig alac_config;
        alac_config.frame_length = static_cast<uint32_t>(frames_per_packet);
        if (!this->decoder_.configure(alac_config)) {
          AIRPLAY_LOGW("Unsupported ALAC stream");
          return;
        }
      }
      std::memcpy(this->audio_key_, key != nullptr ? key : this->session_stream_key_, sizeof(this->audio_key_));
      this->codec_ = aac ? Codec::AAC : Codec::ALAC;
      this->buffered_frames_per_packet_ = static_cast<uint32_t>(frames_per_packet);
      this->buffered_aac_ = aac;
      this->buffered_stream_ = true;
      this->airplay2_audio_ = false;
      this->encrypted_ = false;
      this->buffered_next_seq_ = 0;
      // The sender connects to the RTSP port for the audio, as for its events
      this->data_channel_pending_ = true;
      AIRPLAY_LOGD("Stream: %s, AirPlay 2 buffered", aac ? "AAC" : "ALAC");
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
      this->forget_timeline_();
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
      // iOS leaves the key out of realtime streams it starts a session with. Which key it uses then (or none) is
      // told by the first packets.
      if (key != nullptr) {
        std::memcpy(this->audio_key_, key, sizeof(this->audio_key_));
        this->audio_encryption_ = AudioEncryption::KEY;
      } else {
        int64_t stream_id = 0;
        const bool has_stream_id = reader.get_integer(reader.get(stream, "streamConnectionID"), &stream_id);
        this->prepare_key_candidates_(c, has_stream_id ? &stream_id : nullptr);
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

bool Receiver::request_sender_volume(float volume) {
  if (!this->event_channel_ready_.load(std::memory_order_acquire))
    return false;
  this->sender_volume_request_.store(std::clamp(volume, 0.0f, 1.0f), std::memory_order_release);
  return true;
}

void Receiver::update_event_channel_ready_(uint32_t now_ms) {
  bool ready = false;
  if (this->session_owner_ != NO_CONNECTION) {
    const uint32_t address = this->connections_[this->session_owner_].peer.address;
    for (Connection &c : this->connections_) {
      if (!c.open || !c.event_channel || !c.encrypted || c.peer.address != address)
        continue;
      if (!c.event_silent && c.event_answers == 0 && c.event_requests > 0 &&
          (c.event_requests >= MAX_UNANSWERED_REQUESTS ||
           now_ms - c.event_first_request_ms >= EVENT_ANSWER_TIMEOUT_MS)) {
        c.event_silent = true;
        AIRPLAY_LOGI("The sender does not answer on its event connection; nothing more is sent on it");
        if (this->listener_ != nullptr)
          this->listener_->on_event_channel_silent();
      }
      ready |= !c.event_silent;
    }
  }
  this->event_channel_ready_.store(ready, std::memory_order_release);
}

bool Receiver::request_sender_command(SenderCommand command) {
  if (!this->event_channel_ready_.load(std::memory_order_acquire))
    return false;
  this->sender_command_requests_.fetch_or(static_cast<uint8_t>(1u << static_cast<uint8_t>(command)),
                                          std::memory_order_acq_rel);
  return true;
}

void Receiver::send_sender_requests_(uint32_t now_ms) {
  // While a knob turns, only the latest volume goes out every so often
  static constexpr uint32_t VOLUME_INTERVAL_MS = 100;
  if (now_ms - this->last_sender_volume_ms_ >= VOLUME_INTERVAL_MS) {
    const float volume = this->sender_volume_request_.exchange(-1.0f, std::memory_order_acq_rel);
    // A sender whose audio is held does not have the speaker, so its volume is left alone
    if (volume >= 0.0f && !this->audio_held_) {
      this->last_sender_volume_ms_ = now_ms;
      if (this->send_media_remote_command_("dvlc", volume))
        AIRPLAY_LOGD("Volume %.2f sent to the sender", static_cast<double>(volume));
    }
  }
  const uint8_t commands = this->sender_command_requests_.exchange(0, std::memory_order_acq_rel);
  // The codes a HomePod sends for its buttons, in the order of SenderCommand
  static constexpr const char *CODES[] = {"play", "paus", "plps", "nitm", "pitm"};
  for (uint8_t i = 0; i < sizeof(CODES) / sizeof(CODES[0]); i++) {
    if ((commands & (1u << i)) != 0) {
      if (this->send_media_remote_command_(CODES[i], -1.0f))
        AIRPLAY_LOGD("Command %s sent to the sender", CODES[i]);
    }
  }
}

void Receiver::setup_relay_(uint8_t connection, int64_t control_type, const char *client_uuid,
                            const char *client_type_uuid, Response &response) {
  Connection &c = this->connections_[connection];
  // While a sender has a session, paused too: the controller offers to play again
  const bool session = this->session_owner_ != NO_CONNECTION;
  if (!this->config_.remote_control || !c.remote_control || control_type != CONTROL_TYPE_MEDIA_REMOTE || !session) {
    AIRPLAY_LOGD("Remote control stream (control type %" PRId64 ") refused%s", control_type,
                 !this->config_.remote_control ? ": remote control is off"
                 : session                     ? ""
                                               : ": no sender has a session");
    response.status = 400;
    response.status_text = "Bad Request";
    return;
  }
  // A stream of its own for every SETUP: one device has several (its apps)
  uint32_t *slot = std::find(std::begin(c.relay_streams), std::end(c.relay_streams), 0);
  if (slot == std::end(c.relay_streams)) {
    AIRPLAY_LOGW("Too many remote control streams of one controller");
    response.status = 400;
    response.status_text = "Bad Request";
    return;
  }
  const uint32_t stream_id = this->relay_next_stream_++;
  *slot = stream_id;
  c.relay_latest = stream_id;
  const auto *ip = reinterpret_cast<const uint8_t *>(&c.peer.address);
  AIRPLAY_LOGI("Remote control stream %" PRIu32 " for controller %s (%s) at %u.%u.%u.%u", stream_id, client_uuid,
               client_type_uuid, ip[0], ip[1], ip[2], ip[3]);
  PlistWriter writer(this->body_buffer_, AIRPLAY2_BODY_SIZE);
  writer.begin_dict(1);
  writer.key("streams");
  writer.begin_array(1);
  writer.begin_dict(2);
  writer.key("streamID");
  writer.integer(stream_id);
  writer.key("type");
  writer.integer(STREAM_TYPE_REMOTE_CONTROL);
  response.body_length = writer.finish();
  if (response.body_length == 0)
    return;
  response.status = 200;
  response.status_text = "OK";
  response.content_type = CONTENT_TYPE_PLIST;
  response.body = this->body_buffer_;
  // The sender hears of the controller, as AirPlay 2 speakers tell it ("remoteConrolSessionCreate", sic)
  uint8_t body[256];
  PlistWriter create(body, sizeof(body));
  create.begin_dict(4);
  create.key("type");
  create.string("remoteConrolSessionCreate");
  create.key("streamID");
  create.integer(stream_id);
  create.key("clientTypeUUID");
  create.string(client_type_uuid);
  create.key("clientUUID");
  create.string(client_uuid);
  const size_t length = create.finish();
  if (length == 0 || !this->send_event_request_(this->connections_[this->session_owner_].peer.address, 0, body, length))
    AIRPLAY_LOGW("Could not tell the sender of remote control stream %" PRIu32, stream_id);
}

// ===== Controllers answered here =====

void Receiver::make_message_id_(char *id) {
  uint8_t bytes[16];
  this->config_.random(bytes, sizeof(bytes));
  bytes[6] = static_cast<uint8_t>((bytes[6] & 0x0f) | 0x40);
  bytes[8] = static_cast<uint8_t>((bytes[8] & 0x3f) | 0x80);
  std::snprintf(id, 37, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", bytes[0], bytes[1],
                bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15]);
}

bool Receiver::cover_info_(mrp::Cover *cover, char *identifier, bool with_data) const {
  if (!this->cover_complete_)
    return false;
  std::snprintf(identifier, 12, "%08" PRIx32, this->cover_hash_);
  *cover = mrp::Cover{this->cover_png_ ? "image/png" : "image/jpeg",
                      identifier,
                      this->cover_width_,
                      this->cover_height_,
                      this->cover_length_,
                      with_data};
  return true;
}

mrp::NowPlaying Receiver::now_playing_info_(uint32_t now_ms) const {
  mrp::NowPlaying now{};
  now.title = this->now_playing_.title;
  now.artist = this->now_playing_.artist;
  now.album = this->now_playing_.album;
  now.sender = this->session_owner_ != NO_CONNECTION ? this->connections_[this->session_owner_].sender_name : "";
  now.playing =
      this->expected_playing_ >= 0 ? this->expected_playing_ == 1 : this->session_state_ == SessionState::PLAYING;
  if (this->progress_duration_ms_ != 0) {
    uint32_t position = this->progress_position_ms_;
    if (now.playing)
      position += now_ms - this->progress_at_ms_;
    position = std::min(position, this->progress_duration_ms_);
    now.duration_s = this->progress_duration_ms_ / 1000.0;
    now.elapsed_s = position / 1000.0;
  }
  return now;
}

bool Receiver::send_to_controller_(const Connection &controller, uint32_t stream_id, size_t length) {
  if (length == 0) {
    AIRPLAY_LOGW("A remote control message for stream %" PRIu32 " does not fit", stream_id);
    return false;
  }
  PlistWriter writer(this->body_buffer_, AIRPLAY2_BODY_SIZE);
  writer.begin_dict(1);
  writer.key("params");
  writer.begin_dict(1);
  writer.key("data");
  writer.data(this->mrp_buffer_, length);
  const size_t body_length = writer.finish();
  return body_length > 0 &&
         this->send_event_request_(controller.peer.address, stream_id, this->body_buffer_, body_length);
}

bool Receiver::answer_controller_(Connection &controller, uint32_t stream_id, const uint8_t *data, size_t length,
                                  bool plist) {
  const uint8_t *messages = data;
  size_t messages_length = length;
  PlistReader reader;
  if (plist && (!reader.parse(data, length) ||
                !reader.get_data(reader.get(reader.get(reader.root(), "params"), "data"), &messages, &messages_length)))
    return false;
  mrp::Request requests[4];
  const size_t count = mrp::parse(messages, messages_length, requests, 4);
  if (count == 0)
    return false;
  controller.remote_answered = true;
  const uint32_t now_ms = this->poll_ms_;
  const mrp::NowPlaying now = this->now_playing_info_(now_ms);
  mrp::Cover cover{};
  char cover_id[12];
  const bool cover_known = this->cover_info_(&cover, cover_id, false);
  bool pending_update = false;
  char id[37];
  // The app that plays and its state, in one request
  auto send_now_playing = [&]() {
    size_t used = 0;
    bool fits = true;
    auto add = [&](size_t length) {
      fits = fits && length != 0;
      used += length;
    };
    this->make_message_id_(id);
    add(mrp::write_now_playing_client(this->mrp_buffer_, sizeof(this->mrp_buffer_), id));
    this->make_message_id_(id);
    if (fits)
      add(mrp::write_update_client(this->mrp_buffer_ + used, sizeof(this->mrp_buffer_) - used, id));
    this->make_message_id_(id);
    if (fits)
      add(mrp::write_state(this->mrp_buffer_ + used, sizeof(this->mrp_buffer_) - used, nullptr, id, now,
                           cover_known ? &cover : nullptr));
    this->make_message_id_(id);
    if (fits)
      add(mrp::write_player_properties(this->mrp_buffer_ + used, sizeof(this->mrp_buffer_) - used, id, now));
    if (fits) {
      this->send_to_controller_(controller, stream_id, used);
    } else {
      AIRPLAY_LOGW("Remote control stream %" PRIu32 ": the now playing details do not fit", stream_id);
    }
  };
  for (size_t i = 0; i < count; i++) {
    const mrp::Request &request = requests[i];
    AIRPLAY_LOGD("Remote control stream %" PRIu32 ": message %" PRIu32 " answered here", stream_id, request.type);
    switch (request.type) {
      case mrp::MESSAGE_TYPE_DEVICE_INFO: {
        char mac[18];
        const uint8_t *m = this->config_.mac;
        std::snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
        const mrp::DeviceInfo info{this->pairing_id_, this->config_.name, this->config_.model, mac};
        this->make_message_id_(id);
        this->send_to_controller_(
            controller, stream_id,
            mrp::write_device_info(this->mrp_buffer_, sizeof(this->mrp_buffer_), request.identifier, id, info));
        break;
      }
      case mrp::MESSAGE_TYPE_SET_CONNECTION_STATE:
        // A controller that connects (a Home hub for the tile) may ask for no updates: it gets the state anyway
        send_now_playing();
        break;
      case mrp::MESSAGE_TYPE_CLIENT_UPDATES_CONFIG:
        // As iOS answers it: the app that plays and its state, then the confirmation the controller waits for
        send_now_playing();
        this->make_message_id_(id);
        this->send_to_controller_(
            controller, stream_id,
            mrp::write_reply(this->mrp_buffer_, sizeof(this->mrp_buffer_), request.identifier, id));
        break;
      case mrp::MESSAGE_TYPE_PLAYBACK_QUEUE_REQUEST:
        if (request.wants_artwork && cover_known && this->cover_send_connection_ != NO_CONNECTION) {
          // One cover at a time: this one is answered once the other is through
          controller.cover_wanted_stream = stream_id;
          std::snprintf(controller.cover_wanted_reply, sizeof(controller.cover_wanted_reply), "%s", request.identifier);
          break;
        }
        if (request.wants_artwork && this->send_cover_state_(controller, stream_id, request.identifier))
          break;
        this->make_message_id_(id);
        this->send_to_controller_(controller, stream_id,
                                  mrp::write_state(this->mrp_buffer_, sizeof(this->mrp_buffer_), request.identifier, id,
                                                   now, cover_known ? &cover : nullptr));
        break;
      case mrp::MESSAGE_TYPE_SEND_COMMAND: {
        bool known = true;
        SenderCommand command = SenderCommand::SENDER_COMMAND_PLAY;
        switch (request.command) {
          case mrp::COMMAND_PLAY:
            break;
          case mrp::COMMAND_PAUSE:
          case mrp::COMMAND_STOP:
            command = SenderCommand::SENDER_COMMAND_PAUSE;
            break;
          case mrp::COMMAND_TOGGLE_PLAY_PAUSE:
            command = SenderCommand::SENDER_COMMAND_PLAY_PAUSE;
            break;
          case mrp::COMMAND_NEXT_TRACK:
            command = SenderCommand::SENDER_COMMAND_NEXT;
            break;
          case mrp::COMMAND_PREVIOUS_TRACK:
            command = SenderCommand::SENDER_COMMAND_PREVIOUS;
            break;
          default:
            known = false;
        }
        const bool passed = known && (this->request_sender_command(command) ||
                                      (this->listener_ != nullptr && this->listener_->on_sender_command(command)));
        AIRPLAY_LOGI("Remote control stream %" PRIu32 ": command %" PRIu32 " %s", stream_id, request.command,
                     passed  ? "passed on to the sender"
                     : known ? "not passed on, the sender does not answer"
                             : "not supported");
        this->make_message_id_(id);
        this->send_to_controller_(controller, stream_id,
                                  mrp::write_command_result(this->mrp_buffer_, sizeof(this->mrp_buffer_),
                                                            request.identifier, id, request.command_id, now));
        if (passed && command != SenderCommand::SENDER_COMMAND_NEXT &&
            command != SenderCommand::SENDER_COMMAND_PREVIOUS) {
          // The controllers show the new state at once, not only once the sender has faded out
          this->expected_playing_ = command == SenderCommand::SENDER_COMMAND_PLAY    ? 1
                                    : command == SenderCommand::SENDER_COMMAND_PAUSE ? 0
                                    : now.playing                                    ? 0
                                                                                     : 1;
          this->expected_at_ms_ = now_ms;
          pending_update = true;
        }
        break;
      }
      default:
        break;
    }
  }
  controller.relayed_to_sender++;
  if (pending_update)
    this->update_controllers_();
  return true;
}

bool Receiver::send_cover_state_(Connection &controller, uint32_t stream_id, const char *reply_to) {
  if (this->cover_send_connection_ != NO_CONNECTION)
    return false;
  mrp::Cover cover{};
  char cover_id[12];
  if (!this->cover_info_(&cover, cover_id, true))
    return false;
  char id[37];
  this->make_message_id_(id);
  const size_t start = mrp::write_state(this->mrp_buffer_, sizeof(this->mrp_buffer_), reply_to, id,
                                        this->now_playing_info_(this->poll_ms_), &cover);
  if (start == 0)
    return false;
  // A binary property list {params: {data: <messages>}}, as iOS sends it, with the data's length known up front
  const size_t data_length = start + this->cover_length_;
  uint8_t head[40];
  static constexpr uint8_t HEAD[] = {'b', 'p', 'l', 'i', 's',  't',  '0',  '0',  0xd1, 0x01, 0x02, 0x56, 'p',  'a',
                                     'r', 'a', 'm', 's', 0xd1, 0x03, 0x04, 0x54, 'd',  'a',  't',  'a',  0x4f, 0x12};
  std::memcpy(head, HEAD, sizeof(HEAD));
  for (size_t i = 0; i < 4; i++)
    head[sizeof(HEAD) + i] = static_cast<uint8_t>(data_length >> (24 - 8 * i));
  const size_t head_length = sizeof(HEAD) + 4;
  // The offsets of the five objects (4 bytes each), then the trailer
  static constexpr uint32_t OFFSETS[] = {8, 11, 18, 21, 26};
  const uint64_t table = head_length + data_length;
  size_t end = 0;
  for (const uint32_t offset : OFFSETS) {
    for (size_t i = 0; i < 4; i++)
      this->cover_send_end_[end++] = static_cast<uint8_t>(offset >> (24 - 8 * i));
  }
  std::memset(this->cover_send_end_ + end, 0, 32);
  this->cover_send_end_[end + 6] = 4;   // Offset size
  this->cover_send_end_[end + 7] = 1;   // Object reference size
  this->cover_send_end_[end + 15] = 5;  // Objects
  for (size_t i = 0; i < 8; i++)
    this->cover_send_end_[end + 24 + i] = static_cast<uint8_t>(table >> (56 - 8 * i));
  this->cover_send_end_length_ = end + 32;
  uint8_t connection = NO_CONNECTION;
  if (!this->send_event_request_(controller.peer.address, stream_id, nullptr,
                                 head_length + data_length + this->cover_send_end_length_, &connection) ||
      !this->send_(connection, head, head_length) || !this->send_(connection, this->mrp_buffer_, start))
    return false;
  AIRPLAY_LOGD("Remote control stream %" PRIu32 ": cover art follows, %u bytes", stream_id,
               static_cast<unsigned>(this->cover_length_));
  this->cover_send_connection_ = connection;
  this->cover_send_offset_ = 0;
  this->cover_send_ms_ = this->poll_ms_;
  return true;
}

void Receiver::send_cover_piece_(bool all) {
  // A frame at a time, paced: what the network stack holds until the controller takes it is internal RAM, which
  // is short on an ESP32, and a full send buffer would hold up the audio
  static constexpr size_t PIECE = HAP_FRAME_DATA_SIZE;  // Within one chunk of the cover
  static_assert(COVER_CHUNK_SIZE % PIECE == 0);
  static constexpr uint32_t PIECE_INTERVAL_MS = 25;  // About 40 KB/s
  static constexpr uint32_t MAX_PIECES = 4;
  const uint8_t connection = this->cover_send_connection_;
  if (connection == NO_CONNECTION)
    return;
  uint32_t pieces = MAX_PIECES;
  if (!all) {
    pieces = std::min(MAX_PIECES, (this->poll_ms_ - this->cover_send_ms_) / PIECE_INTERVAL_MS);
    if (pieces == 0)
      return;
    this->cover_send_ms_ = this->poll_ms_;
  }
  bool ok = this->connections_[connection].open;
  while (ok && this->cover_send_offset_ < this->cover_length_) {
    if (!all && (pieces == 0 || !this->transport_.can_send(connection)))
      return;
    pieces--;
    const size_t length = std::min(PIECE, this->cover_length_ - this->cover_send_offset_);
    const size_t offset = this->cover_send_offset_;
    ok = this->send_(connection, this->cover_chunks_[offset / COVER_CHUNK_SIZE] + offset % COVER_CHUNK_SIZE, length);
    this->cover_send_offset_ += length;
  }
  if (ok)
    this->send_(connection, this->cover_send_end_, this->cover_send_end_length_);
  this->cover_send_connection_ = NO_CONNECTION;
}

void Receiver::send_waiting_cover_() {
  for (Connection &c : this->connections_) {
    if (!c.open || c.cover_wanted_stream == 0)
      continue;
    const uint32_t stream_id = c.cover_wanted_stream;
    c.cover_wanted_stream = 0;
    if (this->send_cover_state_(c, stream_id, c.cover_wanted_reply))
      return;
    // The cover went in the meantime: the state without it
    mrp::Cover cover{};
    char cover_id[12];
    const bool cover_known = this->cover_info_(&cover, cover_id, false);
    char id[37];
    this->make_message_id_(id);
    this->send_to_controller_(
        c, stream_id,
        mrp::write_state(this->mrp_buffer_, sizeof(this->mrp_buffer_), c.cover_wanted_reply, id,
                         this->now_playing_info_(this->poll_ms_), cover_known ? &cover : nullptr));
  }
}

void Receiver::update_controllers_() {
  if (this->session_owner_ == NO_CONNECTION || this->connections_[this->session_owner_].sender_answers_remote)
    return;
  const uint32_t now_ms = this->poll_ms_;
  const mrp::NowPlaying now = this->now_playing_info_(now_ms);
  mrp::Cover cover{};
  char cover_id[12];
  const bool cover_known = this->cover_info_(&cover, cover_id, false);
  char id[37];
  for (Connection &c : this->connections_) {
    if (!c.open || !c.remote_answered || c.relay_latest == 0)
      continue;
    if (this->cover_send_connection_ != NO_CONNECTION &&
        this->connections_[this->cover_send_connection_].peer.address == c.peer.address) {
      // Sent once its cover is through: sending now would push all of the cover out at once
      this->controllers_stale_ = true;
      continue;
    }
    this->make_message_id_(id);
    this->send_to_controller_(c, c.relay_latest,
                              mrp::write_state(this->mrp_buffer_, sizeof(this->mrp_buffer_), nullptr, id, now,
                                               cover_known ? &cover : nullptr));
  }
}

void Receiver::end_relay_(uint8_t connection, uint32_t stream_id) {
  Connection &c = this->connections_[connection];
  bool ended = false;
  for (uint32_t &stream : c.relay_streams) {
    if (stream == 0 || (stream_id != 0 && stream != stream_id))
      continue;
    this->end_relay_stream_(c, stream);
    stream = 0;
    ended = true;
  }
  c.relay_latest = 0;
  for (uint32_t stream : c.relay_streams)
    c.relay_latest = std::max(c.relay_latest, stream);
  if (ended && c.relay_latest == 0) {
    // What the log may have lost of it
    const auto *ip = reinterpret_cast<const uint8_t *>(&c.peer.address);
    AIRPLAY_LOGI("Relayed for %u.%u.%u.%u: %u messages to the sender, %u to it, %u not sent", ip[0], ip[1], ip[2],
                 ip[3], c.relayed_to_sender, c.relayed_to_controller, c.relay_not_sent);
    c.relayed_to_sender = 0;
    c.relayed_to_controller = 0;
    c.relay_not_sent = 0;
  }
}

void Receiver::end_relay_stream_(const Connection &c, uint32_t stream) {
  const auto *ip = reinterpret_cast<const uint8_t *>(&c.peer.address);
  AIRPLAY_LOGI("Remote control stream %" PRIu32 " of %u.%u.%u.%u ended", stream, ip[0], ip[1], ip[2], ip[3]);
  if (this->session_owner_ != NO_CONNECTION) {
    uint8_t body[128];
    PlistWriter invalidate(body, sizeof(body));
    invalidate.begin_dict(2);
    invalidate.key("type");
    invalidate.string("remoteControlSessionInvalidate");
    invalidate.key("streamID");
    invalidate.integer(stream);
    const size_t length = invalidate.finish();
    if (length == 0 ||
        !this->send_event_request_(this->connections_[this->session_owner_].peer.address, 0, body, length))
      AIRPLAY_LOGW("Could not tell the sender that remote control stream %" PRIu32 " ended", stream);
  }
}

bool Receiver::send_event_request_(uint32_t address, uint32_t stream_id, const uint8_t *body, size_t length,
                                   uint8_t *to_connection) {
  for (uint8_t i = 0; i < MAX_CONNECTIONS; i++) {
    Connection &c = this->connections_[i];
    if (!c.open || !c.event_channel || !c.encrypted || c.peer.address != address)
      continue;
    if (i == this->cover_send_connection_)
      this->send_cover_piece_(true);  // The rest of the cover first: requests do not interleave
    char header[192];
    char stream_header[48] = "";
    if (stream_id != 0)
      std::snprintf(stream_header, sizeof(stream_header), "X-Apple-StreamID: %" PRIu32 "\r\n", stream_id);
    const int header_length =
        std::snprintf(header, sizeof(header),
                      "POST /command RTSP/1.0\r\nCSeq: %" PRIu32 "\r\nContent-Type: %s\r\nContent-Length: %u\r\n%s\r\n",
                      ++this->event_cseq_, CONTENT_TYPE_PLIST, static_cast<unsigned>(length), stream_header);
    if (header_length <= 0 || static_cast<size_t>(header_length) >= sizeof(header))
      return false;
    // Header and body in frames of their own: the stream does not care where frames end
    if (!this->send_(i, reinterpret_cast<const uint8_t *>(header), static_cast<size_t>(header_length)) ||
        (body != nullptr && !this->send_(i, body, length)))
      return false;
    c.event_requests++;
    if (to_connection != nullptr)
      *to_connection = i;
    const auto *ip = reinterpret_cast<const uint8_t *>(&address);
    AIRPLAY_LOGD("Event request to %u.%u.%u.%u: %u bytes%s%s", ip[0], ip[1], ip[2], ip[3],
                 static_cast<unsigned>(length), stream_header[0] != '\0' ? " (relayed)" : "",
                 body == nullptr ? ", the body follows as it comes" : "");
    return true;
  }
  return false;
}

bool Receiver::send_media_remote_command_(const char *value, float volume) {
  if (this->session_owner_ == NO_CONNECTION)
    return false;
  const uint32_t address = this->connections_[this->session_owner_].peer.address;
  for (uint8_t i = 0; i < MAX_CONNECTIONS; i++) {
    Connection &c = this->connections_[i];
    if (!c.open || !c.event_channel || !c.encrypted || c.peer.address != address)
      continue;
    if (c.event_silent)
      return false;
    // A volume is given at the top level and in the parameters; senders read either
    uint8_t body[192];
    PlistWriter writer(body, sizeof(body));
    const bool with_volume = volume >= 0.0f;
    writer.begin_dict(with_volume ? 4 : 2);
    writer.key("type");
    writer.string("sendMediaRemoteCommand");
    writer.key("value");
    writer.string(value);
    if (with_volume) {
      writer.key("volume");
      writer.real(volume);
      writer.key("params");
      writer.begin_dict(1);
      writer.key("volume");
      writer.real(volume);
    }
    const size_t body_length = writer.finish();
    if (body_length == 0)
      return false;
    char message[512];
    const int header_length =
        std::snprintf(message, sizeof(message),
                      "POST /command RTSP/1.0\r\nCSeq: %" PRIu32 "\r\nContent-Type: %s\r\nContent-Length: %u\r\n\r\n",
                      ++this->event_cseq_, CONTENT_TYPE_PLIST, static_cast<unsigned>(body_length));
    if (header_length <= 0 || static_cast<size_t>(header_length) + body_length > sizeof(message))
      return false;
    std::memcpy(message + header_length, body, body_length);
    this->send_(i, reinterpret_cast<const uint8_t *>(message), static_cast<size_t>(header_length) + body_length);
    c.event_requests++;
    if (c.event_answers == 0 && c.event_first_request_ms == 0)
      c.event_first_request_ms = this->poll_ms_ != 0 ? this->poll_ms_ : 1;
    return true;
  }
  return false;
}

void Receiver::build_info_(Response &response) {
  PlistWriter writer(this->body_buffer_, AIRPLAY2_BODY_SIZE);
  const float device_volume = this->device_volume_.load(std::memory_order_relaxed);
  writer.begin_dict(device_volume >= 0.0f ? 14 : 13);
  writer.key("deviceID");
  writer.string(this->device_id_);
  writer.key("macAddress");
  writer.string(this->device_id_);
  writer.key("features");
  writer.integer(static_cast<int64_t>(this->airplay2_features_));
  writer.key("statusFlags");
  writer.integer(this->status_flags_value_());
  writer.key("gid");
  writer.string(this->group_id_);
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
  // The receiver sets its own volume: without this macOS shows no volume control and sends no volume changes
  // (3 as shairport-sync announces it)
  writer.key("volumeControlType");
  writer.integer(3);
  if (device_volume >= 0.0f) {
    // In AirPlay's dB: -30 to 0, -144 for silence
    writer.key("initialVolume");
    writer.real(device_volume <= 0.0f ? -144.0 : static_cast<double>(device_volume) * 30.0 - 30.0);
  }
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

void Receiver::add_key_candidate_(const uint8_t *key, const char *name) {
  if (this->key_candidate_count_ >= MAX_KEY_CANDIDATES)
    return;
  for (uint8_t i = 0; i < this->key_candidate_count_; i++) {
    if (std::memcmp(this->key_candidates_[i].key, key, CHACHA_KEY_SIZE) == 0)
      return;
  }
  KeyCandidate &candidate = this->key_candidates_[this->key_candidate_count_++];
  std::memcpy(candidate.key, key, CHACHA_KEY_SIZE);
  candidate.name = name;
}

void Receiver::prepare_key_candidates_(const Connection &c, const int64_t *stream_id) {
  this->key_candidate_count_ = 0;
  this->undecryptable_packets_ = 0;
  this->plain_packets_ = 0;
  // iOS 26: derived from pair-setup's secret like a data stream key, with the stream's connection ID (an unsigned
  // 64-bit number) appended to the salt
  if (stream_id != nullptr && c.encrypted) {
    char salt[sizeof(DATA_STREAM_SALT) + 20];
    std::snprintf(salt, sizeof(salt), "%s%" PRIu64, DATA_STREAM_SALT, static_cast<uint64_t>(*stream_id));
    uint8_t derived[CHACHA_KEY_SIZE];
    hkdf_sha512_key(salt, DATA_STREAM_SENDER_WRITE_INFO, c.pair_secret, c.pair_secret_length, derived);
    this->add_key_candidate_(derived, "the key of the stream connection");
  }
  // Earlier: the key of an earlier stream of the session, also one this receiver turned down
  if (this->have_session_stream_key_)
    this->add_key_candidate_(this->session_stream_key_, "the key of an earlier stream");
  if (this->remembered_key_address_ == c.peer.address)
    this->add_key_candidate_(this->remembered_stream_key_, "the key of the sender's previous session");
  const uint8_t zero[CHACHA_KEY_SIZE] = {};
  this->add_key_candidate_(zero, "a zero key");
}

size_t Receiver::decrypt_airplay2_audio_(const uint8_t *header, const uint8_t *payload, size_t length,
                                         uint8_t *output) {
  if (this->audio_encryption_ == AudioEncryption::NONE) {
    std::memcpy(output, payload, length);
    return length;
  }
  if (this->audio_encryption_ == AudioEncryption::FAILED)
    return 0;
  if (length <= POLY1305_TAG_SIZE + AUDIO_NONCE_SIZE)
    return this->audio_encryption_ == AudioEncryption::UNKNOWN
               ? this->detect_plain_audio_(header, payload, length, output)
               : 0;
  const size_t audio_length = length - POLY1305_TAG_SIZE - AUDIO_NONCE_SIZE;
  uint8_t nonce[CHACHA_NONCE_SIZE] = {};
  std::memcpy(nonce + 4, payload + length - AUDIO_NONCE_SIZE, AUDIO_NONCE_SIZE);
  // The timestamp and SSRC of the RTP header are authenticated
  if (this->audio_encryption_ == AudioEncryption::KEY) {
    return chacha20_poly1305_decrypt(this->audio_key_, nonce, header + 4, 8, payload, audio_length,
                                     payload + audio_length, output)
               ? audio_length
               : 0;
  }
  for (uint8_t i = 0; i < this->key_candidate_count_; i++) {
    const KeyCandidate &candidate = this->key_candidates_[i];
    if (chacha20_poly1305_decrypt(candidate.key, nonce, header + 4, 8, payload, audio_length, payload + audio_length,
                                  output)) {
      AIRPLAY_LOGI("Audio encrypted with %s", candidate.name);
      std::memcpy(this->audio_key_, candidate.key, sizeof(this->audio_key_));
      this->audio_encryption_ = AudioEncryption::KEY;
      return audio_length;
    }
  }
  return this->detect_plain_audio_(header, payload, length, output);
}

static constexpr size_t REALTIME_RTP_HEADER_SIZE = 12;

/// Logs bytes in hex at debug level, 32 per line
static void log_hex(const char *label, const uint8_t *data, size_t length) {
  for (size_t offset = 0; offset < length; offset += 32) {
    char text[32 * 2 + 1];
    const size_t count = std::min<size_t>(length - offset, 32);
    for (size_t i = 0; i < count; i++)
      std::snprintf(text + 2 * i, sizeof(text) - 2 * i, "%02x", data[offset + i]);
    AIRPLAY_LOGD("%s %u: %s", label, static_cast<unsigned>(offset), text);
  }
}

size_t Receiver::detect_plain_audio_(const uint8_t *header, const uint8_t *payload, size_t length, uint8_t *output) {
  // A stereo ALAC frame starts with the type of its first element, a channel pair (1). Encrypted data passes that by
  // chance one time in eight, so several packets in a row must agree.
  static constexpr uint8_t PACKETS_TO_DECIDE = 4;
  const bool plausible = this->codec_ != Codec::ALAC || (payload[0] >> 5) == 1;
  if (!plausible) {
    this->plain_packets_ = 0;
    if (++this->undecryptable_packets_ >= PACKETS_TO_DECIDE) {
      AIRPLAY_LOGW("The audio cannot be decrypted: the sender's key is unknown (%u bytes)",
                   static_cast<unsigned>(length));
      this->audio_encryption_ = AudioEncryption::FAILED;
      if (detail::g_log_level >= LogLevel::LOG_LEVEL_DEBUG && this->session_owner_ != NO_CONNECTION) {
        // To work out the sender's encryption offline; pairing secrets are new for every connection
        log_hex("RTP header", header, REALTIME_RTP_HEADER_SIZE);
        log_hex("Payload", payload, std::min<size_t>(length, 128));
        if (this->have_session_stream_key_)
          log_hex("Session stream key", this->session_stream_key_, CHACHA_KEY_SIZE);
      }
    }
    return 0;
  }
  if (++this->plain_packets_ < PACKETS_TO_DECIDE && this->codec_ == Codec::ALAC)
    return 0;
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
/// Audio decoded per poll, to spread the work: one AAC packet (23 ms; three ALAC packets), a poll comes every few ms
static constexpr uint32_t BUFFERED_FRAMES_PER_POLL = AAC_FRAMES_PER_PACKET;
/// While the jitter buffer holds less than this, more is decoded per poll, so that it fills up even when polls come
/// late (a busy thread, or much logging)
static constexpr uint32_t BUFFERED_LOW_FRAMES = SAMPLE_RATE / 4;
static constexpr uint32_t BUFFERED_FRAMES_PER_POLL_LOW = 4 * AAC_FRAMES_PER_PACKET;
/// Packets that are due already and dropped without decoding, at most per poll
static constexpr uint32_t MAX_SKIPPED_PER_POLL = 64;
static constexpr int64_t NTP_UNIX_OFFSET_S = 2208988800LL;

/// Whether 24-bit sequence number a comes before b
static bool seq24_before(uint32_t a, uint32_t b) { return ((a - b) & 0xffffff) > 0x800000; }
/// Whether buffered packet sequence number seq comes before flush point `point`. iOS counts in 24 bits; Music
/// Assistant counts in 16 and puts the payload type in the byte above, so a point that fits in 16 bits is compared
/// in 16 (which gives the same for iOS).
static bool seq_before_flush(uint32_t seq, uint32_t point) {
  if (point <= 0xffff)
    return static_cast<int16_t>(static_cast<uint16_t>(seq - point)) < 0;
  return seq24_before(seq, point);
}

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
      if (seq_before_flush(seq, this->flush_until_seq_))
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
    int64_t due_us = 0;
    if (detail::g_log_level >= LogLevel::LOG_LEVEL_VERBOSE && this->buffered_playing_ &&
        this->rtp_to_local_us_(rtp, &due_us)) {
      const auto lead_ms = static_cast<int32_t>((due_us - static_cast<int64_t>(now_ms) * 1000) / 1000);
      this->lead_min_ms_ = std::min(this->lead_min_ms_, lead_ms);
      this->lead_max_ms_ = std::max(this->lead_max_ms_, lead_ms);
      if (now_ms - this->lead_log_ms_ >= 5000) {
        AIRPLAY_LOGV("Buffered audio arrives %" PRId32 " to %" PRId32 " ms before it is due", this->lead_min_ms_,
                     this->lead_max_ms_);
        this->lead_log_ms_ = now_ms;
        this->lead_min_ms_ = INT32_MAX;
        this->lead_max_ms_ = INT32_MIN;
      }
    }
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

void Receiver::decode_buffered_audio_(int64_t now_us) {
  if (!this->audio_active_)
    return;
  const auto now_ms = static_cast<uint32_t>(now_us / 1000);
  const uint32_t pieces = (this->buffered_frames_per_packet_ + FRAMES_PER_PACKET - 1) / FRAMES_PER_PACKET;
  const uint32_t decode_frames = this->buffered_packets_() * FRAMES_PER_PACKET < BUFFERED_LOW_FRAMES
                                     ? BUFFERED_FRAMES_PER_POLL_LOW
                                     : BUFFERED_FRAMES_PER_POLL;
  const uint32_t decodes = std::max<uint32_t>(decode_frames / this->buffered_frames_per_packet_, 1);
  uint32_t skipped = 0;
  for (uint32_t i = 0; i < decodes;) {
    // Playback filled in for audio that was not decoded in time (it goes to the output ahead of its time): what
    // follows goes on from there, rather than behind playback for the rest of the stream
    if (this->have_seq_ && static_cast<int16_t>(this->buffered_next_seq_ - this->next_seq_) < 0)
      this->buffered_next_seq_ = this->next_seq_;
    // Room in the jitter buffer for the pieces of one packet. An empty one starts over: late audio that was
    // dropped moved past it while nothing played, and waiting would stop reading the sender for good.
    if (this->have_seq_ &&
        static_cast<uint16_t>(this->buffered_next_seq_ - this->next_seq_) + pieces > this->slot_count_) {
      if (this->buffered_packets_() > 0)
        break;
      this->reset_playback_();
    }
    uint32_t rtp;
    uint32_t seq;
    const uint8_t *data;
    uint16_t length;
    if (!this->buffered_queue_.front(&rtp, &seq, &data, &length))
      break;
    // Audio that is due already is dropped without decoding it: macOS starts each stream with seconds of audio
    // from before its anchor, and decoding that held up the audio that can still be played
    int64_t due_us = 0;
    if (this->buffered_playing_ && skipped < MAX_SKIPPED_PER_POLL &&
        this->rtp_to_local_us_(rtp + this->buffered_frames_per_packet_, &due_us) && due_us < now_us) {
      if (!this->late_logged_) {
        // Once per stream: whether the sender sends too late or its clock is read wrong
        this->late_logged_ = true;
        AIRPLAY_LOGD("First late buffered packet: %" PRId32 " ms late, %" PRId32 " ms after the anchor, %" PRIu32
                     " packets buffered",
                     static_cast<int32_t>((now_us - due_us) / 1000),
                     static_cast<int32_t>(static_cast<int64_t>(static_cast<int32_t>(rtp - this->anchor_rtp_)) * 1000 /
                                          SAMPLE_RATE),
                     this->buffered_packets_());
      }
      this->buffered_queue_.pop();
      this->buffered_next_seq_ += pieces;
      this->stats_.late_packets += pieces;
      skipped++;
      continue;
    }
    i++;
    size_t frames = 0;
    if (this->codec_ == Codec::ALAC) {
      const int32_t decoded = this->decoder_.decode(data, length, this->aac_samples_);
      frames = decoded > 0 ? static_cast<size_t>(decoded) : 0;
    } else {
      frames = this->config_.aac_decoder->decode(data, length, this->aac_samples_, AAC_FRAMES_PER_PACKET);
    }
    this->buffered_queue_.pop();
    this->last_packet_ms_ = now_ms;
    if (frames == 0 || frames > this->buffered_frames_per_packet_) {
      if (this->stats_.decode_errors++ == 0)
        AIRPLAY_LOGW("Failed to decode buffered audio (packet %" PRIu32 ", %u bytes)", seq, length);
      continue;
    }
    if (this->codec_ == Codec::ALAC && !this->alac_logged_) {
      this->alac_logged_ = true;
      AIRPLAY_LOGD("ALAC packets of %u bytes, %s", static_cast<unsigned>(length),
                   this->decoder_.last_uncompressed() ? "stored uncompressed" : "compressed");
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

/// An anchor further from now on the sender's clock than this means our estimate of the clock is wrong (it jumped)
static constexpr int64_t MAX_ANCHOR_DISTANCE_US = 10000000;

void Receiver::handle_rate_anchor_(const uint8_t *body, size_t length, int64_t now_us) {
  PlistReader reader;
  if (!reader.parse(body, length))
    return;
  const PlistReader::Object root = reader.root();
  int64_t seconds = 0;
  int64_t fraction = 0;
  int64_t rtp = 0;
  // Realtime streams take their timeline from sync packets, which also carry the sender's latency
  if (this->buffered_stream_ && reader.get_integer(reader.get(root, "networkTimeSecs"), &seconds) &&
      reader.get_integer(reader.get(root, "rtpTime"), &rtp)) {
    reader.get_integer(reader.get(root, "networkTimeFrac"), &fraction);
    // The fraction is of a second in 64 bits
    const uint64_t fraction_ns = ((static_cast<uint64_t>(fraction) >> 32) * 1000000000ULL) >> 32;
    if (this->ptp_timing_) {
      // On the PTP clock that names the timeline
      int64_t timeline = 0;
      if (reader.get_integer(reader.get(root, "networkTimeTimelineID"), &timeline) &&
          static_cast<uint64_t>(timeline) != this->ptp_timeline_) {
        this->ptp_timeline_ = static_cast<uint64_t>(timeline);
        this->ptp_clock_ = 0;
        this->clock_locked_ = false;
        AIRPLAY_LOGD("Timeline on PTP clock %016" PRIx64, this->ptp_timeline_);
      }
    } else if (seconds < NTP_UNIX_OFFSET_S) {
      // The NTP timeline counts from 1900; a time from 1970 is moved onto it
      seconds += NTP_UNIX_OFFSET_S;
    }
    this->anchor_rtp_ = static_cast<uint32_t>(rtp);
    this->anchor_remote_ns_ = seconds * 1000000000LL + static_cast<int64_t>(fraction_ns);
    this->anchor_valid_ = true;
    this->sender_latency_frames_ = 0;
    this->choose_ptp_clock_(now_us, true);
    int64_t offset = 0;
    if (this->ptp_timing_ &&
        this->ptp_clocks_.offset_ns(this->ptp_clock_ != 0 ? this->ptp_clock_ : this->ptp_timeline_, now_us, &offset)) {
      // How far ahead of the sender's present the anchor is, on our estimate of its clock
      AIRPLAY_LOGD("Anchor at %" PRId64 ".%09" PRId64 " s, %" PRId32 " ms from now on the PTP clock",
                   this->anchor_remote_ns_ / 1000000000, this->anchor_remote_ns_ % 1000000000,
                   static_cast<int32_t>((this->anchor_remote_ns_ - (now_us * 1000 + offset)) / 1000000));
    }
    // Near now on the clock that times the stream: audio far off it is from before the anchor, not a clock that
    // jumped
    int64_t anchor_us = 0;
    this->anchor_fits_clock_ = this->rtp_to_local_us_(this->anchor_rtp_, &anchor_us) &&
                               anchor_us - now_us > -MAX_ANCHOR_DISTANCE_US &&
                               anchor_us - now_us < MAX_ANCHOR_DISTANCE_US;
  }
  int64_t rate = 0;
  double real_rate = 0;
  if (!reader.get_integer(reader.get(root, "rate"), &rate) && reader.get_real(reader.get(root, "rate"), &real_rate))
    rate = real_rate > 0 ? 1 : 0;
  const bool playing = (rate & 1) != 0;
  AIRPLAY_LOGD("Rate %d from %" PRIu32, playing ? 1 : 0, this->anchor_rtp_);
  if (playing != this->buffered_playing_) {
    this->buffered_playing_ = playing;
    // Nothing was decoded while paused: the time without audio counts from now
    this->last_packet_ms_ = static_cast<uint32_t>(now_us / 1000);
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
  while (this->buffered_queue_.front(&rtp, &seq, &data, &queued) && seq_before_flush(seq, until_seq) &&
         (!has_from || !seq_before_flush(seq, static_cast<uint32_t>(from) & 0xffffff))) {
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
  if (this->buffered_stream_ && this->buffered_aac_)
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
