#pragma once

// Crypto backend on top of mbedTLS 2.28 or 3.x (ESP-IDF, Arduino-ESP32, Zephyr, desktop with libmbedtls).
// Compiled only where mbedTLS is available; define AIRPLAY_NO_MBEDTLS to leave it out.

#if !defined(AIRPLAY_NO_MBEDTLS) && defined(__has_include)
#if __has_include(<mbedtls/version.h>) && __has_include(<mbedtls/pk.h>)
#define AIRPLAY_HAS_MBEDTLS 1
#endif
#endif

#ifdef AIRPLAY_HAS_MBEDTLS

#include "airplay_crypto.h"

#include <mbedtls/aes.h>
#include <mbedtls/pk.h>

namespace airplay {

class MbedtlsCrypto final : public Crypto {
 public:
  MbedtlsCrypto();
  ~MbedtlsCrypto() override;
  MbedtlsCrypto(const MbedtlsCrypto &) = delete;
  MbedtlsCrypto &operator=(const MbedtlsCrypto &) = delete;

  /// @brief Parses the AirPort key. Call once before use.
  bool init();

  bool sign_challenge(const uint8_t *data, size_t length, uint8_t *signature) override;
  bool decrypt_session_key(const uint8_t *encrypted, size_t length, uint8_t *key) override;
  bool set_audio_key(const uint8_t *key) override;
  bool decrypt_audio(uint8_t *iv, const uint8_t *input, uint8_t *output, size_t length) override;

 private:
  mbedtls_pk_context pk_;
  mbedtls_aes_context aes_;
  bool ready_{false};
};

}  // namespace airplay

#endif  // AIRPLAY_HAS_MBEDTLS
