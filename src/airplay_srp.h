#pragma once

#include "airplay_crypto.h"
#include "airplay_hap_crypto.h"

#include <cstddef>
#include <cstdint>

namespace airplay {

inline constexpr size_t SRP_KEY_SIZE = 384;  // 3072 bits
inline constexpr size_t SRP_SALT_SIZE = 16;
inline constexpr size_t SRP_SECRET_SIZE = 32;

/// Server side of SRP-6a with the 3072-bit group of RFC 5054 and SHA-512, as HomeKit pair-setup uses it.
///
/// Numbers are hashed in their shortest form (no leading zero bytes), except in k and u, where they are padded to
/// the size of the prime. Apple's senders and the srptools library used by pyatv agree on this.
class SrpServer {
 public:
  /// @brief Lets the exponentiations use Crypto::mod_exp, e.g. a hardware accelerator, where available.
  void set_crypto(Crypto *crypto) { this->crypto_ = crypto; }

  /// @brief Prepares an exchange: computes the password verifier and the public key B.
  ///
  /// The salt and password verifier of the first call are kept for later calls with the same username and password,
  /// which saves the slowest step. That suits transient pairing, whose password is public anyway.
  /// @param salt SRP_SALT_SIZE random bytes. The first byte is made nonzero, as senders differ on how they hash a
  /// salt with a leading zero.
  /// @param secret SRP_SECRET_SIZE random bytes: the private value b.
  void begin(const char *username, const char *password, const uint8_t *salt, const uint8_t *secret);

  const uint8_t *salt() const { return this->salt_; }
  /// Public key B, SRP_KEY_SIZE bytes
  const uint8_t *public_key() const { return this->public_key_; }

  /// @brief Checks the client's public key A and proof M1.
  /// @param server_proof Receives SHA512_SIZE bytes, the proof M2 for the client.
  /// @return false if A is invalid or the proof does not match, e.g. because of a wrong password.
  bool verify(const uint8_t *client_key, size_t client_key_length, const uint8_t *client_proof,
              size_t client_proof_length, uint8_t *server_proof);

  /// Session key K, SHA512_SIZE bytes; valid after verify() succeeded
  const uint8_t *session_key() const { return this->session_key_; }

 private:
  static constexpr size_t LIMBS = SRP_KEY_SIZE / 4;
  /// A number below the prime, least significant 32 bits first
  struct Number {
    uint32_t limb[LIMBS];
  };

  /// Montgomery multiplication: out = a * b / 2^3072 mod N. out may be a or b.
  void mont_mul_(Number &out, const Number &a, const Number &b);
  /// out = base ^ exponent mod N in Montgomery form, the exponent as big endian bytes. out must not be base.
  void mod_pow_(Number &out, const Number &base, const uint8_t *exponent, size_t exponent_length);
  /// out = base ^ exponent mod N; with Crypto::mod_exp where available
  void pow_(Number &out, const Number &base, const uint8_t *exponent, size_t exponent_length);
  /// out = a * b mod N. out may be a or b.
  void mul_(Number &out, const Number &a, const Number &b);
  /// Sets up the prime's constants
  void init_();

  // Kept here rather than on the stack, which is small on embedded tasks
  Crypto *crypto_{nullptr};
  bool initialized_{false};
  bool verifier_ready_{false};
  Number r2_;        // 2^6144 mod N, to convert into Montgomery form
  Number one_;       // 1, to convert out of Montgomery form
  Number verifier_;  // v
  Number pow_base_;  // Scratch for pow_
  Number work_[3];
  uint8_t modulus_[SRP_KEY_SIZE];          // N as big endian bytes, for Crypto::mod_exp
  uint8_t scratch_[2][SRP_KEY_SIZE];       // Numbers as bytes, for Crypto::mod_exp
  uint8_t credentials_hash_[SHA512_SIZE];  // H(username ":" password) of the verifier
  uint32_t product_[LIMBS + 2];            // Scratch for mont_mul_
  uint32_t n0_inverse_;                    // -1/N mod 2^32
  uint8_t secret_[SRP_SECRET_SIZE];
  uint8_t salt_[SRP_SALT_SIZE];
  uint8_t username_hash_[SHA512_SIZE];
  uint8_t public_key_[SRP_KEY_SIZE];
  uint8_t session_key_[SHA512_SIZE];
};

}  // namespace airplay
