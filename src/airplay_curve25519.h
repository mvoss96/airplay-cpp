#pragma once

// Ed25519 signatures and X25519 key agreement, for HomeKit pairing (pair-setup and pair-verify). Built in like the
// other AirPlay 2 cryptography, from Monocypher.

#include <cstddef>
#include <cstdint>

namespace airplay {

inline constexpr size_t ED25519_SEED_SIZE = 32;
inline constexpr size_t ED25519_SECRET_KEY_SIZE = 64;  // The seed followed by the public key
inline constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
inline constexpr size_t ED25519_SIGNATURE_SIZE = 64;
inline constexpr size_t X25519_KEY_SIZE = 32;

void ed25519_key_pair(const uint8_t *seed, uint8_t *secret_key, uint8_t *public_key);
void ed25519_sign(const uint8_t *secret_key, const uint8_t *message, size_t length, uint8_t *signature);
bool ed25519_verify(const uint8_t *signature, const uint8_t *public_key, const uint8_t *message, size_t length);

void x25519_public_key(const uint8_t *secret_key, uint8_t *public_key);
/// @return false if the result is all zeros, i.e. the peer's key is one of the few weak points
bool x25519(const uint8_t *secret_key, const uint8_t *peer_public_key, uint8_t *shared_secret);

}  // namespace airplay
