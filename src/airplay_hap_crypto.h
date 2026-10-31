#pragma once

// Built-in cryptography for AirPlay 2 pairing and encryption: SHA-512, HMAC/HKDF-SHA512 and ChaCha20-Poly1305.
// Built in like MD5, so that the library needs nothing beyond what AirPlay 1 needs and does not clash with other
// copies of these algorithms (e.g. libsodium) in the firmware.

#include <cstddef>
#include <cstdint>

namespace airplay {

inline constexpr size_t SHA512_SIZE = 64;
inline constexpr size_t CHACHA_KEY_SIZE = 32;
inline constexpr size_t CHACHA_NONCE_SIZE = 12;
inline constexpr size_t POLY1305_TAG_SIZE = 16;

/// SHA-512 (FIPS 180-4), fed in pieces
class Sha512 {
 public:
  Sha512();
  void update(const uint8_t *data, size_t length);
  /// Writes SHA512_SIZE bytes. The object must not be used afterwards.
  void finish(uint8_t *digest);

 private:
  void process_block_(const uint8_t *block);

  uint64_t state_[8];
  uint64_t length_{0};  // Bytes so far
  uint8_t buffer_[128];
  size_t used_{0};
};

void sha512(const uint8_t *data, size_t length, uint8_t *digest);

/// HMAC-SHA512 (RFC 2104). Writes SHA512_SIZE bytes.
void hmac_sha512(const uint8_t *key, size_t key_length, const uint8_t *data, size_t length, uint8_t *mac);

/// HKDF with SHA-512 (RFC 5869), as HomeKit uses it to derive keys from a shared secret.
/// @param output_length At most 255 * SHA512_SIZE.
void hkdf_sha512(const uint8_t *salt, size_t salt_length, const uint8_t *secret, size_t secret_length,
                 const uint8_t *info, size_t info_length, uint8_t *output, size_t output_length);

/// HKDF-SHA512 with text salt and info, and a 32 byte output: a ChaCha20 key
void hkdf_sha512_key(const char *salt, const char *info, const uint8_t *secret, size_t secret_length,
                     uint8_t *key);

/// ChaCha20-Poly1305 AEAD (RFC 8439). The output may be the input.
/// @param tag Receives POLY1305_TAG_SIZE bytes.
void chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_length,
                               const uint8_t *input, size_t length, uint8_t *output, uint8_t *tag);

/// @return false, with the output left untouched, if the tag does not match.
bool chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_length,
                               const uint8_t *input, size_t length, const uint8_t *tag, uint8_t *output);

/// Compares without an early exit, so that the time taken does not tell where the first difference is
bool equal_constant_time(const uint8_t *a, const uint8_t *b, size_t length);

}  // namespace airplay
