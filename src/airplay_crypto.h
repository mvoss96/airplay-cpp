#pragma once

#include <cstddef>
#include <cstdint>

namespace airplay {

inline constexpr size_t RSA_SIGNATURE_SIZE = 256;
inline constexpr size_t AES_KEY_SIZE = 16;
inline constexpr size_t AES_BLOCK_SIZE = 16;
inline constexpr size_t FAIRPLAY_SETUP_FIRST_SIZE = 16;  // The sender's first FairPlay setup message
inline constexpr size_t FAIRPLAY_SETUP_P2_SIZE = 142;    // The first FairPlay setup reply (this receiver sends it)
inline constexpr size_t FAIRPLAY_SETUP_P3_SIZE = 164;    // The second FairPlay setup message (the sender sends it)
inline constexpr size_t FAIRPLAY_KEY_SIZE = 72;          // The decoded "fpaeskey" SDP attribute

/// Private key of the AirPort Express (PEM, null terminated), published in 2011 and used by every open source
/// AirPlay 1 receiver. Senders check the Apple-Challenge signature and encrypt the session key with it.
extern const char AIRPORT_PRIVATE_KEY_PEM[];
extern const size_t AIRPORT_PRIVATE_KEY_PEM_SIZE;  // Including the terminating null
/// The same key as DER (PKCS#1 RSAPrivateKey)
extern const uint8_t AIRPORT_PRIVATE_KEY_DER[];
extern const size_t AIRPORT_PRIVATE_KEY_DER_SIZE;

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

  /// @brief Recovers the AirPlay 1 audio key from iTunes's FairPlay "fpaeskey" SDP attribute (FairPlay v2),
  /// using the two messages of the /fp-setup handshake. iTunes sends fpaeskey instead of
  /// rsaaeskey when the receiver announces FairPlay (feature bit 14). The default returns false, so receivers that
  /// do not implement it fall back to the rsaaeskey path.
  /// @param p2 The FAIRPLAY_SETUP_P2_SIZE-byte setup reply this receiver sent (fairplay_setup_reply, sequence 2).
  /// @param p3 The FAIRPLAY_SETUP_P3_SIZE-byte second setup message from the sender (sequence 3).
  /// @param blob The FAIRPLAY_KEY_SIZE-byte decoded fpaeskey.
  /// @param key Receives AES_KEY_SIZE bytes.
  /// @return false when FairPlay is not supported or the key does not authenticate.
  virtual bool decrypt_fairplay_key(const uint8_t * /*p2*/, const uint8_t * /*p3*/, const uint8_t * /*blob*/,
                                    uint8_t * /*key*/) {
    return false;
  }

  /// @brief Sets the AES-128 key for decrypt_audio().
  virtual bool set_audio_key(const uint8_t *key) = 0;

  /// @brief AES-128-CBC decryption of whole blocks.
  /// @param iv AES_BLOCK_SIZE bytes; updated like a CBC chain.
  /// @param length A multiple of AES_BLOCK_SIZE.
  virtual bool decrypt_audio(uint8_t *iv, const uint8_t *input, uint8_t *output, size_t length) = 0;

  /// @brief Optional: result = base ^ exponent mod modulus, numbers big endian, base, modulus and result of `size`
  /// bytes. AirPlay 2 pairing needs a few of these with a 3072-bit modulus, which a hardware accelerator does much
  /// faster than the built-in arithmetic.
  /// @return false if not available; the built-in arithmetic is used then.
  virtual bool mod_exp(const uint8_t * /*base*/, const uint8_t * /*exponent*/, size_t /*exponent_length*/,
                       const uint8_t * /*modulus*/, size_t /*size*/, uint8_t * /*result*/) {
    return false;
  }
};

}  // namespace airplay
