#pragma once

#include <cstddef>
#include <cstdint>

namespace airplay {

/// Item types of the TLV8 messages of HomeKit pairing
enum TlvType : uint8_t {
  TLV_METHOD = 0x00,
  TLV_IDENTIFIER = 0x01,
  TLV_SALT = 0x02,
  TLV_PUBLIC_KEY = 0x03,
  TLV_PROOF = 0x04,
  TLV_ENCRYPTED_DATA = 0x05,
  TLV_STATE = 0x06,
  TLV_ERROR = 0x07,
  TLV_SIGNATURE = 0x0a,
  TLV_FLAGS = 0x13,
};

/// Error codes of TLV_ERROR
enum TlvError : uint8_t {
  TLV_ERROR_UNKNOWN = 0x01,
  TLV_ERROR_AUTHENTICATION = 0x02,
  TLV_ERROR_BUSY = 0x07,
};

/// Flag of TLV_FLAGS: pair for this session only (PIN 3939), as AirPlay 2 senders do
inline constexpr uint8_t TLV_FLAG_TRANSIENT = 0x10;

/// @brief Finds an item in a TLV8 message. Values longer than 255 bytes are split into consecutive items of the
/// same type; they are joined.
/// @param value_length Receives the length of the value.
/// @return false if the item is missing, the message is malformed or the value does not fit.
bool tlv8_find(const uint8_t *data, size_t length, uint8_t type, uint8_t *value, size_t size, size_t *value_length);

/// Builds a TLV8 message
class Tlv8Writer {
 public:
  Tlv8Writer(uint8_t *buffer, size_t size) : buffer_(buffer), size_(size) {}
  /// Adds an item, split into pieces of at most 255 bytes
  void add(uint8_t type, const uint8_t *value, size_t length);
  void add_byte(uint8_t type, uint8_t value) { this->add(type, &value, 1); }
  /// Length of the message; 0 if it did not fit
  size_t length() const { return this->overflow_ ? 0 : this->length_; }

 private:
  uint8_t *buffer_;
  size_t size_;
  size_t length_{0};
  bool overflow_{false};
};

}  // namespace airplay
