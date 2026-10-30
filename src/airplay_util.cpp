#include "airplay_util.h"

#include <algorithm>
#include <cstring>

namespace airplay {

static int8_t base64_value(char c) {
  if (c >= 'A' && c <= 'Z')
    return static_cast<int8_t>(c - 'A');
  if (c >= 'a' && c <= 'z')
    return static_cast<int8_t>(c - 'a' + 26);
  if (c >= '0' && c <= '9')
    return static_cast<int8_t>(c - '0' + 52);
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  return -1;
}

size_t base64_decode(const char *input, size_t input_length, uint8_t *output, size_t output_size) {
  uint32_t accumulator = 0;
  uint32_t bits = 0;
  size_t written = 0;
  for (size_t i = 0; i < input_length; i++) {
    const int8_t value = base64_value(input[i]);
    if (value < 0)
      break;
    accumulator = (accumulator << 6) | static_cast<uint32_t>(value);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (written >= output_size)
        return 0;
      output[written++] = static_cast<uint8_t>(accumulator >> bits);
    }
  }
  return written;
}

size_t base64_encode_unpadded(const uint8_t *input, size_t input_length, char *output, size_t output_size) {
  static constexpr char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const size_t encoded_length = (input_length * 4 + 2) / 3;
  if (encoded_length + 1 > output_size)
    return 0;
  uint32_t accumulator = 0;
  uint32_t bits = 0;
  size_t written = 0;
  for (size_t i = 0; i < input_length; i++) {
    accumulator = (accumulator << 8) | input[i];
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      output[written++] = ALPHABET[(accumulator >> bits) & 0x3f];
    }
  }
  if (bits > 0)
    output[written++] = ALPHABET[(accumulator << (6 - bits)) & 0x3f];
  output[written] = '\0';
  return written;
}

void copy_utf8(char *destination, size_t size, const uint8_t *source, size_t length) {
  if (size == 0)
    return;
  size_t count = std::min(length, size - 1);
  if (count < length) {
    while (count > 0 && (source[count] & 0xc0) == 0x80)
      count--;
  }
  std::memcpy(destination, source, count);
  destination[count] = '\0';
}

void parse_dmap_metadata(const uint8_t *data, size_t length, Metadata &metadata) {
  // Items: a 4 character tag, a 32-bit big endian length and the value
  size_t position = 0;
  while (position + 8 <= length) {
    const uint8_t *tag = data + position;
    const uint32_t item_length = (static_cast<uint32_t>(tag[4]) << 24) | (static_cast<uint32_t>(tag[5]) << 16) |
                                 (static_cast<uint32_t>(tag[6]) << 8) | tag[7];
    position += 8;
    if (item_length > length - position)
      return;
    const uint8_t *value = data + position;
    if (std::memcmp(tag, "mlit", 4) == 0) {
      parse_dmap_metadata(value, item_length, metadata);  // Container of the items below
    } else if (std::memcmp(tag, "minm", 4) == 0) {
      copy_utf8(metadata.title, sizeof(metadata.title), value, item_length);
    } else if (std::memcmp(tag, "asar", 4) == 0) {
      copy_utf8(metadata.artist, sizeof(metadata.artist), value, item_length);
    } else if (std::memcmp(tag, "asal", 4) == 0) {
      copy_utf8(metadata.album, sizeof(metadata.album), value, item_length);
    }
    position += item_length;
  }
}

}  // namespace airplay
