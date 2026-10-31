#pragma once

#include "airplay_types.h"

#include <cstddef>
#include <cstdint>

namespace airplay {

/// @brief Decodes base64 text, with or without '=' padding. Stops at the first character outside the alphabet.
/// @return Number of bytes written, or 0 if the output buffer is too small.
size_t base64_decode(const char *input, size_t input_length, uint8_t *output, size_t output_size);

/// @brief Encodes data as base64 without '=' padding, as AirPlay expects. The output is null terminated.
/// @return Length of the encoded text, or 0 if the output buffer is too small.
size_t base64_encode_unpadded(const uint8_t *input, size_t input_length, char *output, size_t output_size);

/// @brief Picks title, artist, album, album artist, year and track number out of DMAP data (the body of a SET_PARAMETER
/// with Content-Type application/x-dmap-tagged). Fields that are not present are left untouched.
void parse_dmap_metadata(const uint8_t *data, size_t length, Metadata &metadata);

/// @brief Copies UTF-8 text into a fixed buffer, shortened if needed without cutting a character in half.
void copy_utf8(char *destination, size_t size, const uint8_t *source, size_t length);

inline constexpr size_t MD5_SIZE = 16;
/// @brief MD5 digest (RFC 1321), for the password check of RTSP Digest authentication.
void md5(const uint8_t *data, size_t length, uint8_t *digest);
/// @brief MD5 digest of a string as 32 lowercase hex characters plus a terminating zero.
void md5_hex(const char *text, size_t length, char *hex);

}  // namespace airplay
