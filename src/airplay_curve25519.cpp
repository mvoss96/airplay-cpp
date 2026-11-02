#include "airplay_curve25519.h"

#include <cstring>

#define MONOCYPHER_CPP_NAMESPACE airplay_monocypher
#include "third_party/monocypher/monocypher-ed25519.h"
#include "third_party/monocypher/monocypher.h"

namespace airplay {

void ed25519_key_pair(const uint8_t *seed, uint8_t *secret_key, uint8_t *public_key) {
  uint8_t copy[ED25519_SEED_SIZE];  // Monocypher wipes the seed it is given
  std::memcpy(copy, seed, sizeof(copy));
  airplay_monocypher::crypto_ed25519_key_pair(secret_key, public_key, copy);
}

void ed25519_sign(const uint8_t *secret_key, const uint8_t *message, size_t length, uint8_t *signature) {
  airplay_monocypher::crypto_ed25519_sign(signature, secret_key, message, length);
}

bool ed25519_verify(const uint8_t *signature, const uint8_t *public_key, const uint8_t *message, size_t length) {
  return airplay_monocypher::crypto_ed25519_check(signature, public_key, message, length) == 0;
}

void x25519_public_key(const uint8_t *secret_key, uint8_t *public_key) {
  airplay_monocypher::crypto_x25519_public_key(public_key, secret_key);
}

bool x25519(const uint8_t *secret_key, const uint8_t *peer_public_key, uint8_t *shared_secret) {
  airplay_monocypher::crypto_x25519(shared_secret, secret_key, peer_public_key);
  uint8_t any = 0;
  for (size_t i = 0; i < X25519_KEY_SIZE; i++)
    any |= shared_secret[i];
  return any != 0;
}

}  // namespace airplay
