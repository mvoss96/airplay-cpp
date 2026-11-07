#include "airplay_mrp.h"

#include <algorithm>
#include <cstring>

namespace airplay {

// ===== Protocol buffers =====

static constexpr uint8_t WIRE_VARINT = 0;
static constexpr uint8_t WIRE_FIXED64 = 1;
static constexpr uint8_t WIRE_BYTES = 2;
static constexpr uint8_t WIRE_FIXED32 = 5;

static size_t varint_size(uint64_t value) {
  size_t size = 1;
  while (value >= 0x80) {
    value >>= 7;
    size++;
  }
  return size;
}

void ProtoWriter::raw_(const void *data, size_t length) {
  if (this->failed_ || this->length_ + length > this->size_) {
    this->failed_ = true;
    return;
  }
  std::memcpy(this->buffer_ + this->length_, data, length);
  this->length_ += length;
}

void ProtoWriter::raw_varint_(uint64_t value) {
  uint8_t bytes[10];
  size_t count = 0;
  do {
    bytes[count] = static_cast<uint8_t>(value & 0x7f);
    value >>= 7;
    if (value != 0)
      bytes[count] |= 0x80;
    count++;
  } while (value != 0);
  this->raw_(bytes, count);
}

void ProtoWriter::varint(uint32_t field, uint64_t value) {
  this->raw_varint_(static_cast<uint64_t>(field) << 3 | WIRE_VARINT);
  this->raw_varint_(value);
}

void ProtoWriter::string(uint32_t field, const char *text) {
  this->bytes(field, reinterpret_cast<const uint8_t *>(text), text != nullptr ? std::strlen(text) : 0);
}

void ProtoWriter::bytes(uint32_t field, const uint8_t *data, size_t length) {
  this->raw_varint_(static_cast<uint64_t>(field) << 3 | WIRE_BYTES);
  this->raw_varint_(length);
  if (length > 0)
    this->raw_(data, length);
}

void ProtoWriter::real(uint32_t field, double value) {
  this->raw_varint_(static_cast<uint64_t>(field) << 3 | WIRE_FIXED64);
  uint64_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  uint8_t bytes[8];
  for (size_t i = 0; i < 8; i++)
    bytes[i] = static_cast<uint8_t>(bits >> (8 * i));
  this->raw_(bytes, sizeof(bytes));
}

void ProtoWriter::real32(uint32_t field, float value) {
  this->raw_varint_(static_cast<uint64_t>(field) << 3 | WIRE_FIXED32);
  uint32_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  uint8_t bytes[4];
  for (size_t i = 0; i < 4; i++)
    bytes[i] = static_cast<uint8_t>(bits >> (8 * i));
  this->raw_(bytes, sizeof(bytes));
}

void ProtoWriter::begin(uint32_t field) {
  if (this->depth_ >= MAX_DEPTH) {
    this->failed_ = true;
    return;
  }
  this->raw_varint_(static_cast<uint64_t>(field) << 3 | WIRE_BYTES);
  // One byte for the length; moved along if the message turns out longer
  this->starts_[this->depth_++] = this->length_;
  const uint8_t placeholder = 0;
  this->raw_(&placeholder, 1);
}

void ProtoWriter::end() {
  if (this->depth_ == 0) {
    this->failed_ = true;
    return;
  }
  const size_t start = this->starts_[--this->depth_];
  if (this->failed_)
    return;
  const size_t length = this->length_ - start - 1;
  const size_t extra = varint_size(length) - 1;
  if (this->length_ + extra > this->size_) {
    this->failed_ = true;
    return;
  }
  std::memmove(this->buffer_ + start + 1 + extra, this->buffer_ + start + 1, length);
  size_t at = start;
  uint64_t value = length;
  do {
    uint8_t byte = static_cast<uint8_t>(value & 0x7f);
    value >>= 7;
    if (value != 0)
      byte |= 0x80;
    this->buffer_[at++] = byte;
  } while (value != 0);
  this->length_ += extra;
}

bool ProtoReader::read_varint_(uint64_t *value) {
  *value = 0;
  for (int shift = 0; shift < 64 && this->data_ < this->end_; shift += 7) {
    const uint8_t byte = *this->data_++;
    *value |= static_cast<uint64_t>(byte & 0x7f) << shift;
    if ((byte & 0x80) == 0)
      return true;
  }
  return false;
}

bool ProtoReader::next() {
  uint64_t tag = 0;
  if (this->data_ >= this->end_ || !this->read_varint_(&tag))
    return false;
  this->field_ = static_cast<uint32_t>(tag >> 3);
  this->wire_ = static_cast<uint8_t>(tag & 7);
  this->value_ = 0;
  this->field_data_ = nullptr;
  this->field_size_ = 0;
  switch (this->wire_) {
    case WIRE_VARINT:
      return this->read_varint_(&this->value_);
    case WIRE_FIXED64:
    case WIRE_FIXED32: {
      const size_t size = this->wire_ == WIRE_FIXED64 ? 8 : 4;
      if (static_cast<size_t>(this->end_ - this->data_) < size)
        return false;
      for (size_t i = 0; i < size; i++)
        this->value_ |= static_cast<uint64_t>(this->data_[i]) << (8 * i);
      this->data_ += size;
      return true;
    }
    case WIRE_BYTES: {
      uint64_t size = 0;
      if (!this->read_varint_(&size) || size > static_cast<uint64_t>(this->end_ - this->data_))
        return false;
      this->field_data_ = this->data_;
      this->field_size_ = static_cast<size_t>(size);
      this->data_ += size;
      return true;
    }
    default:
      return false;
  }
}

// ===== MediaRemote =====

namespace mrp {

// Fields of ProtocolMessage, and the numbers of the messages it carries as extensions
static constexpr uint32_t FIELD_TYPE = 1;
static constexpr uint32_t FIELD_IDENTIFIER = 2;
static constexpr uint32_t FIELD_UNIQUE_IDENTIFIER = 85;
static constexpr uint32_t EXT_SEND_COMMAND = 6;
static constexpr uint32_t EXT_SEND_COMMAND_RESULT = 7;
static constexpr uint32_t EXT_SET_STATE = 9;
static constexpr uint32_t EXT_DEVICE_INFO = 20;
// SendCommandMessage
static constexpr uint32_t SEND_COMMAND_COMMAND = 1;
static constexpr uint32_t SEND_COMMAND_OPTIONS = 2;
static constexpr uint32_t OPTIONS_COMMAND_ID = 32;

static constexpr const char PLAYER_ID[] = "MediaRemote-DefaultPlayer";
static constexpr const char PLAYER_NAME[] = "Default Player";
static constexpr const char MUSIC_APP[] = "com.apple.Music";
static constexpr uint32_t PLAYBACK_STATE_PLAYING = 1;
static constexpr uint32_t PLAYBACK_STATE_PAUSED = 2;

static void copy_text(char *to, size_t size, const uint8_t *data, size_t length) {
  const size_t count = std::min(length, size - 1);
  std::memcpy(to, data, count);
  to[count] = '\0';
}

size_t parse(const uint8_t *data, size_t length, Request *requests, size_t max) {
  size_t count = 0;
  const uint8_t *end = data + length;
  while (data < end && count < max) {
    // The message's length as a varint
    uint64_t size = 0;
    int shift = 0;
    bool done = false;
    while (data < end && shift < 64) {
      const uint8_t byte = *data++;
      size |= static_cast<uint64_t>(byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) == 0) {
        done = true;
        break;
      }
    }
    if (!done || size > static_cast<uint64_t>(end - data))
      break;
    Request &request = requests[count++];
    request = Request{};
    ProtoReader message(data, static_cast<size_t>(size));
    while (message.next()) {
      if (message.field() == FIELD_TYPE) {
        request.type = static_cast<uint32_t>(message.value());
      } else if (message.field() == FIELD_IDENTIFIER && message.is_bytes()) {
        copy_text(request.identifier, sizeof(request.identifier), message.data(), message.size());
      } else if (message.field() == EXT_SEND_COMMAND && message.is_bytes()) {
        ProtoReader command(message.data(), message.size());
        while (command.next()) {
          if (command.field() == SEND_COMMAND_COMMAND) {
            request.command = static_cast<uint32_t>(command.value());
          } else if (command.field() == SEND_COMMAND_OPTIONS && command.is_bytes()) {
            ProtoReader options(command.data(), command.size());
            while (options.next()) {
              if (options.field() == OPTIONS_COMMAND_ID && options.is_bytes())
                copy_text(request.command_id, sizeof(request.command_id), options.data(), options.size());
            }
          }
        }
      }
    }
    data += size;
  }
  return count;
}

/// The player that plays: the sender's music app, as controllers know it from other speakers
static void write_player_path(ProtoWriter &w, uint32_t field, const NowPlaying &now) {
  w.begin(field);
  w.begin(1);  // Origin
  w.string(2, now.sender != nullptr && now.sender[0] != '\0' ? now.sender : "AirPlay");
  w.varint(3, 1);
  w.end();
  w.begin(2);  // NowPlayingClient
  w.varint(1, 1);
  w.string(2, MUSIC_APP);
  w.end();
  w.begin(3);  // NowPlayingPlayer
  w.string(1, PLAYER_ID);
  w.string(2, PLAYER_NAME);
  w.end();
  w.end();
}

/// Starts a ProtocolMessage after room for its length
static void begin_message(ProtoWriter &w, uint32_t type, const char *reply_to) {
  w.varint(FIELD_TYPE, type);
  if (reply_to != nullptr && reply_to[0] != '\0')
    w.string(FIELD_IDENTIFIER, reply_to);
}

/// Puts the message's length in front of it
static size_t finish_message(uint8_t *buffer, size_t size, ProtoWriter &w, const char *message_id) {
  w.string(FIELD_UNIQUE_IDENTIFIER, message_id);
  const size_t length = w.length();
  if (length == 0)
    return 0;
  const size_t prefix = varint_size(length);
  if (prefix + length > size)
    return 0;
  std::memmove(buffer + prefix, buffer, length);
  size_t at = 0;
  uint64_t value = length;
  do {
    uint8_t byte = static_cast<uint8_t>(value & 0x7f);
    value >>= 7;
    if (value != 0)
      byte |= 0x80;
    buffer[at++] = byte;
  } while (value != 0);
  return prefix + length;
}

// The message is written from the start of the buffer and moved behind its length at the end: the writer leaves
// room for that
static constexpr size_t MAX_PREFIX = 3;

size_t write_device_info(uint8_t *buffer, size_t size, const char *reply_to, const char *message_id,
                         const DeviceInfo &info) {
  if (size <= MAX_PREFIX)
    return 0;
  ProtoWriter w(buffer, size - MAX_PREFIX);
  begin_message(w, MESSAGE_TYPE_DEVICE_INFO, reply_to);
  w.begin(EXT_DEVICE_INFO);
  w.string(1, info.unique_id);
  w.string(2, info.name);
  w.string(3, "Speaker");                 // localizedModelName
  w.string(4, "1.0");                     // systemBuildVersion
  w.string(5, "com.apple.mediaremoted");  // applicationBundleIdentifier
  w.varint(7, 1);                         // protocolVersion
  w.varint(8, 139);                       // lastSupportedMessageType, as iOS 26
  w.boolean(9, true);                     // supportsSystemPairing
  w.boolean(10, true);                    // allowsPairing
  w.string(12, MUSIC_APP);                // systemMediaApplication
  w.boolean(13, true);                    // supportsACL
  w.boolean(14, true);                    // supportsSharedQueue
  w.varint(17, 3);                        // sharedQueueVersion
  w.string(20, info.mac);                 // managedConfigDeviceID
  w.varint(21, 7);                        // deviceClass: accessory
  w.varint(22, 1);                        // logicalDeviceCount
  w.boolean(29, true);                    // isGroupLeader
  w.boolean(30, true);                    // isAirplayActive
  w.string(39, info.model);               // modelID
  w.end();
  return finish_message(buffer, size, w, message_id);
}

size_t write_state(uint8_t *buffer, size_t size, const char *reply_to, const char *message_id, const NowPlaying &now) {
  if (size <= MAX_PREFIX)
    return 0;
  ProtoWriter w(buffer, size - MAX_PREFIX);
  begin_message(w, MESSAGE_TYPE_SET_STATE, reply_to);
  w.begin(EXT_SET_STATE);
  w.begin(1);  // NowPlayingInfo
  if (now.album != nullptr && now.album[0] != '\0')
    w.string(1, now.album);
  if (now.artist != nullptr && now.artist[0] != '\0')
    w.string(2, now.artist);
  if (now.duration_s > 0) {
    w.real(3, now.duration_s);
    w.real(4, now.elapsed_s);
  }
  w.real32(5, now.playing ? 1.0f : 0.0f);
  if (now.title != nullptr && now.title[0] != '\0')
    w.string(9, now.title);
  w.end();
  w.begin(2);  // SupportedCommands
  for (const uint32_t command :
       {COMMAND_PLAY, COMMAND_PAUSE, COMMAND_TOGGLE_PLAY_PAUSE, COMMAND_NEXT_TRACK, COMMAND_PREVIOUS_TRACK}) {
    w.begin(1);
    w.varint(1, command);
    w.boolean(2, true);
    w.end();
  }
  w.end();
  w.begin(3);  // PlaybackQueue: the item that plays
  w.varint(1, 0);
  w.begin(2);
  w.string(1, "airplay-now-playing");
  w.begin(2);  // ContentItemMetadata
  if (now.title != nullptr && now.title[0] != '\0')
    w.string(1, now.title);
  w.boolean(4, true);  // isPlayable
  if (now.album != nullptr && now.album[0] != '\0')
    w.string(6, now.album);
  if (now.artist != nullptr && now.artist[0] != '\0')
    w.string(7, now.artist);
  if (now.duration_s > 0) {
    w.real(14, now.duration_s);
    w.real(35, now.elapsed_s);
  }
  w.boolean(27, true);  // isCurrentlyPlaying
  w.real32(39, now.playing ? 1.0f : 0.0f);
  w.end();
  w.end();
  w.end();
  w.varint(6, now.playing ? PLAYBACK_STATE_PLAYING : PLAYBACK_STATE_PAUSED);
  w.begin(8);  // PlaybackQueueCapabilities
  w.end();
  write_player_path(w, 9, now);
  w.end();
  return finish_message(buffer, size, w, message_id);
}

size_t write_command_result(uint8_t *buffer, size_t size, const char *reply_to, const char *message_id,
                            const char *command_id, const NowPlaying &now) {
  if (size <= MAX_PREFIX)
    return 0;
  ProtoWriter w(buffer, size - MAX_PREFIX);
  begin_message(w, MESSAGE_TYPE_SEND_COMMAND_RESULT, reply_to);
  w.begin(EXT_SEND_COMMAND_RESULT);
  w.varint(1, 0);  // sendError: none
  w.varint(2, 0);  // handlerReturnStatus: success
  if (command_id != nullptr && command_id[0] != '\0')
    w.string(4, command_id);
  w.begin(6);  // The command's result, as iOS sends it
  write_player_path(w, 1, now);
  w.varint(2, 0);
  w.begin(3);
  w.varint(1, 0);
  w.varint(2, 1);
  w.end();
  w.string(4, "None");
  w.end();
  w.end();
  return finish_message(buffer, size, w, message_id);
}

}  // namespace mrp
}  // namespace airplay
