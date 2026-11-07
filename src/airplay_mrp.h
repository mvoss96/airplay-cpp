#pragma once

#include <cstddef>
#include <cstdint>

namespace airplay {

/// Writes protocol buffer fields in order. Nested messages go between begin() and end(). length() is 0 after an
/// overflow.
class ProtoWriter {
 public:
  ProtoWriter(uint8_t *buffer, size_t size) : buffer_(buffer), size_(size) {}
  void varint(uint32_t field, uint64_t value);
  void boolean(uint32_t field, bool value) { this->varint(field, value ? 1 : 0); }
  void string(uint32_t field, const char *text);
  void bytes(uint32_t field, const uint8_t *data, size_t length);
  void real(uint32_t field, double value);   // A double
  void real32(uint32_t field, float value);  // A float
  void begin(uint32_t field);
  void end();
  size_t length() const { return this->failed_ || this->depth_ != 0 ? 0 : this->length_; }

 private:
  static constexpr size_t MAX_DEPTH = 8;
  void raw_varint_(uint64_t value);
  void raw_(const void *data, size_t length);
  uint8_t *buffer_;
  size_t size_;
  size_t length_{0};
  size_t starts_[MAX_DEPTH]{};
  size_t depth_{0};
  bool failed_{false};
};

/// Reads the fields of a protocol buffer message one after another
class ProtoReader {
 public:
  ProtoReader(const uint8_t *data, size_t length) : data_(data), end_(data + length) {}
  /// Moves to the next field; false at the end or when the message is broken
  bool next();
  uint32_t field() const { return this->field_; }
  /// Of a varint or fixed field
  uint64_t value() const { return this->value_; }
  /// Of a length-delimited field (a string, bytes or a nested message)
  const uint8_t *data() const { return this->field_data_; }
  size_t size() const { return this->field_size_; }
  bool is_bytes() const { return this->wire_ == 2; }

 private:
  bool read_varint_(uint64_t *value);
  const uint8_t *data_;
  const uint8_t *end_;
  uint32_t field_{0};
  uint8_t wire_{0};
  uint64_t value_{0};
  const uint8_t *field_data_{nullptr};
  size_t field_size_{0};
};

/// MediaRemote messages, which controllers (the Home app's tile on an iPad) exchange with the device that plays.
/// Each message is a protocol buffer after its length as a varint; several may follow one another.
namespace mrp {

enum MessageType : uint32_t {
  MESSAGE_TYPE_SEND_COMMAND = 1,
  MESSAGE_TYPE_SEND_COMMAND_RESULT = 2,
  MESSAGE_TYPE_SET_STATE = 4,
  MESSAGE_TYPE_DEVICE_INFO = 15,
  MESSAGE_TYPE_CLIENT_UPDATES_CONFIG = 16,
  MESSAGE_TYPE_PLAYBACK_QUEUE_REQUEST = 32,
  MESSAGE_TYPE_SET_CONNECTION_STATE = 38,
  MESSAGE_TYPE_UPDATE_CONTENT_ITEM = 56,
};

enum Command : uint32_t {
  COMMAND_PLAY = 1,
  COMMAND_PAUSE = 2,
  COMMAND_TOGGLE_PLAY_PAUSE = 3,
  COMMAND_STOP = 4,
  COMMAND_NEXT_TRACK = 5,
  COMMAND_PREVIOUS_TRACK = 6,
};

/// A message from a controller: its type, the identifier an answer repeats, and for SEND_COMMAND the command
struct Request {
  uint32_t type;
  char identifier[48];
  uint32_t command;
  char command_id[48];  // Of a SEND_COMMAND, which its result repeats
};

/// Reads the messages in data; returns how many were written to requests
size_t parse(const uint8_t *data, size_t length, Request *requests, size_t max);

/// The receiver as a MediaRemote device
struct DeviceInfo {
  const char *unique_id;  // The receiver's pairing identifier
  const char *name;
  const char *model;
  const char *mac;  // "aa:bb:cc:dd:ee:ff"
};

/// What plays now
struct NowPlaying {
  const char *title;
  const char *artist;
  const char *album;
  const char *sender;  // Name of the device that plays
  double duration_s;   // 0 when unknown
  double elapsed_s;
  bool playing;
};

/// Each writes one message (its length first) to buffer, answering the request with reply_to (nullptr for none)
/// and with message_id as its own identifier; returns its size, 0 if it does not fit.
size_t write_device_info(uint8_t *buffer, size_t size, const char *reply_to, const char *message_id,
                         const DeviceInfo &info);
/// Playback state, now playing details and the commands that work (play, pause, next, previous)
size_t write_state(uint8_t *buffer, size_t size, const char *reply_to, const char *message_id, const NowPlaying &now);
size_t write_command_result(uint8_t *buffer, size_t size, const char *reply_to, const char *message_id,
                            const char *command_id, const NowPlaying &now);

}  // namespace mrp
}  // namespace airplay
