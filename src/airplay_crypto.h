#pragma once

#include <cstddef>
#include <cstdint>

namespace airplay {

inline constexpr size_t RSA_SIGNATURE_SIZE = 256;
inline constexpr size_t AES_KEY_SIZE = 16;
inline constexpr size_t AES_BLOCK_SIZE = 16;

/// Private key of the AirPort Express (PEM, null terminated), published in 2011 and used by every open source
/// AirPlay 1 receiver. Senders check the Apple-Challenge signature and encrypt the session key with it.
extern const char AIRPORT_PRIVATE_KEY_PEM[];
extern const size_t AIRPORT_PRIVATE_KEY_PEM_SIZE;  // Including the terminating null

/// Cryptography needed by an AirPlay 1 receiver. Implement it for your platform, or use MbedtlsCrypto.
class Crypto {
 public:
  virtual ~Crypto() = default;

  /// @brief Answers an Apple-Challenge: a raw PKCS#1 v1.5 (type 1) signature of `data` with the AirPort key.
  /// @param signature Receives RSA_SIGNATURE_SIZE bytes.
  virtual bool sign_challenge(const uint8_t *data, size_t length, uint8_t *signature) = 0;

  /// @brief Decrypts the session key from the "rsaaeskey" SDP attribute (RSA-OAEP with SHA-1).
  /// @param key Receives AES_KEY_SIZE bytes.
  virtual bool decrypt_session_key(const uint8_t *encrypted, size_t length, uint8_t *key) = 0;

  /// @brief Sets the AES-128 key for decrypt_audio().
  virtual bool set_audio_key(const uint8_t *key) = 0;

  /// @brief AES-128-CBC decryption of whole blocks.
  /// @param iv AES_BLOCK_SIZE bytes; updated like a CBC chain.
  /// @param length A multiple of AES_BLOCK_SIZE.
  virtual bool decrypt_audio(uint8_t *iv, const uint8_t *input, uint8_t *output, size_t length) = 0;
};

}  // namespace airplay
