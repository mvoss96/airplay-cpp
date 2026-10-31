#include "airplay_tlv8.h"

#include <cstring>

namespace airplay {

bool tlv8_find(const uint8_t *data, size_t length, uint8_t type, uint8_t *value, size_t size, size_t *value_length) {
  size_t offset = 0;
  while (offset + 2 <= length) {
    const uint8_t item_type = data[offset];
    size_t item_length = data[offset + 1];
    if (offset + 2 + item_length > length)
      return false;
    if (item_type != type) {
      offset += 2 + item_length;
      continue;
    }
    // A full item is followed by the next piece of the same value
    size_t total = 0;
    while (true) {
      if (total + item_length > size)
        return false;
      std::memcpy(value + total, data + offset + 2, item_length);
      total += item_length;
      offset += 2 + item_length;
      if (item_length < 255 || offset + 2 > length || data[offset] != type)
        break;
      item_length = data[offset + 1];
      if (offset + 2 + item_length > length)
        return false;
    }
    *value_length = total;
    return true;
  }
  return false;
}

void Tlv8Writer::add(uint8_t type, const uint8_t *value, size_t length) {
  do {
    const size_t piece = length < 255 ? length : 255;
    if (this->length_ + 2 + piece > this->size_) {
      this->overflow_ = true;
      return;
    }
    this->buffer_[this->length_] = type;
    this->buffer_[this->length_ + 1] = static_cast<uint8_t>(piece);
    if (piece > 0)
      std::memcpy(this->buffer_ + this->length_ + 2, value, piece);
    this->length_ += 2 + piece;
    value += piece;
    length -= piece;
  } while (length > 0);
}

}  // namespace airplay
