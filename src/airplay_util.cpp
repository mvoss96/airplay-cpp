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

/// A big endian integer of up to 4 bytes; DMAP stores year and track number as 2 bytes
static uint32_t read_dmap_integer(const uint8_t *value, size_t length) {
  if (length > 4)
    return 0;
  uint32_t result = 0;
  for (size_t i = 0; i < length; i++)
    result = (result << 8) | value[i];
  return result;
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
    } else if (std::memcmp(tag, "asaa", 4) == 0) {
      copy_utf8(metadata.album_artist, sizeof(metadata.album_artist), value, item_length);
    } else if (std::memcmp(tag, "asyr", 4) == 0) {
      metadata.year = static_cast<uint16_t>(read_dmap_integer(value, item_length));
    } else if (std::memcmp(tag, "astn", 4) == 0) {
      metadata.track = static_cast<uint16_t>(read_dmap_integer(value, item_length));
    }
    position += item_length;
  }
}

// ===== MD5 (RFC 1321) =====

static uint32_t rotate_left(uint32_t value, uint32_t shift) { return (value << shift) | (value >> (32 - shift)); }

static void md5_block(uint32_t *state, const uint8_t *block) {
  static const uint32_t K[64] = {
      0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
      0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
      0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
      0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
      0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
      0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
      0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
      0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
  };
  static const uint8_t SHIFTS[16] = {7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21};
  uint32_t words[16];
  for (int i = 0; i < 16; i++) {
    words[i] = static_cast<uint32_t>(block[i * 4]) | static_cast<uint32_t>(block[i * 4 + 1]) << 8 |
               static_cast<uint32_t>(block[i * 4 + 2]) << 16 | static_cast<uint32_t>(block[i * 4 + 3]) << 24;
  }
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  for (int i = 0; i < 64; i++) {
    uint32_t f;
    int g;
    if (i < 16) {
      f = (b & c) | (~b & d);
      g = i;
    } else if (i < 32) {
      f = (d & b) | (~d & c);
      g = (5 * i + 1) % 16;
    } else if (i < 48) {
      f = b ^ c ^ d;
      g = (3 * i + 5) % 16;
    } else {
      f = c ^ (b | ~d);
      g = (7 * i) % 16;
    }
    const uint32_t next = d;
    d = c;
    c = b;
    b = b + rotate_left(a + f + K[i] + words[g], SHIFTS[(i / 16) * 4 + i % 4]);
    a = next;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

void md5(const uint8_t *data, size_t length, uint8_t *digest) {
  uint32_t state[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
  size_t offset = 0;
  for (; offset + 64 <= length; offset += 64)
    md5_block(state, data + offset);
  // The rest, a one bit, zeros and the length in bits, in one or two blocks
  uint8_t tail[128] = {};
  const size_t rest = length - offset;
  std::memcpy(tail, data + offset, rest);
  tail[rest] = 0x80;
  const size_t tail_size = rest < 56 ? 64 : 128;
  const uint64_t bits = static_cast<uint64_t>(length) * 8;
  for (int i = 0; i < 8; i++)
    tail[tail_size - 8 + i] = static_cast<uint8_t>(bits >> (8 * i));
  md5_block(state, tail);
  if (tail_size == 128)
    md5_block(state, tail + 64);
  for (int i = 0; i < 16; i++)
    digest[i] = static_cast<uint8_t>(state[i / 4] >> (8 * (i % 4)));
}

void md5_hex(const char *text, size_t length, char *hex) {
  static const char DIGITS[] = "0123456789abcdef";
  uint8_t digest[MD5_SIZE];
  md5(reinterpret_cast<const uint8_t *>(text), length, digest);
  for (size_t i = 0; i < MD5_SIZE; i++) {
    hex[i * 2] = DIGITS[digest[i] >> 4];
    hex[i * 2 + 1] = DIGITS[digest[i] & 0x0f];
  }
  hex[MD5_SIZE * 2] = '\0';
}

bool equals_ignore_case(const char *a, const char *b, size_t length) {
  for (size_t i = 0; i < length; i++) {
    char x = a[i];
    char y = b[i];
    if (x >= 'A' && x <= 'Z')
      x = static_cast<char>(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z')
      y = static_cast<char>(y - 'A' + 'a');
    if (x != y)
      return false;
    if (x == '\0')
      return true;
  }
  return true;
}

bool get_header(const char *block, size_t block_length, const char *name, char *value, size_t value_size) {
  const size_t name_length = std::strlen(name);
  const char *end = block + block_length;
  const char *line = block;
  while (line < end) {
    const char *line_end = line;
    while (line_end < end && *line_end != '\r' && *line_end != '\n')
      line_end++;
    if (static_cast<size_t>(line_end - line) > name_length && equals_ignore_case(line, name, name_length) &&
        line[name_length] == ':') {
      const char *start = line + name_length + 1;
      while (start < line_end && (*start == ' ' || *start == '\t'))
        start++;
      const char *stop = line_end;
      while (stop > start && (stop[-1] == ' ' || stop[-1] == '\t'))
        stop--;
      const size_t length = std::min(static_cast<size_t>(stop - start), value_size - 1);
      std::memcpy(value, start, length);
      value[length] = '\0';
      return true;
    }
    line = line_end;
    while (line < end && (*line == '\r' || *line == '\n'))
      line++;
  }
  return false;
}

}  // namespace airplay
