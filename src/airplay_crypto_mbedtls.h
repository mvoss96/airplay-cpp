#pragma once

// Crypto backend on top of mbedTLS: the classic RSA, AES and PK functions of 2.28 and 3.x (ESP-IDF 5, Arduino-ESP32,
// Zephyr, desktop with libmbedtls), or the PSA crypto API of mbedTLS 4 (ESP-IDF 6). Define AIRPLAY_NO_MBEDTLS to
// leave it out.

#if !defined(AIRPLAY_NO_MBEDTLS) && defined(__has_include)
#if __has_include(<mbedtls/version.h>) && __has_include(<mbedtls/pk.h>)
#define AIRPLAY_HAS_MBEDTLS 1
#endif
#endif

#ifdef AIRPLAY_HAS_MBEDTLS
#include <mbedtls/version.h>
// mbedTLS 4 offers only the PSA crypto API for RSA and AES
#if MBEDTLS_VERSION_MAJOR >= 4
#define AIRPLAY_MBEDTLS_PSA 1
#endif
#endif

#ifdef AIRPLAY_HAS_MBEDTLS

#include "airplay_crypto.h"

#ifdef AIRPLAY_MBEDTLS_PSA
#include <psa/crypto.h>
#else
#include <mbedtls/aes.h>
#include <mbedtls/pk.h>
#endif

namespace airplay {

class MbedtlsCrypto final : public Crypto {
 public:
  MbedtlsCrypto();
  ~MbedtlsCrypto() override;
  MbedtlsCrypto(const MbedtlsCrypto &) = delete;
  MbedtlsCrypto &operator=(const MbedtlsCrypto &) = delete;

  /// @brief Loads the AirPort key. Call once before use.
  bool init();

  bool sign_challenge(const uint8_t *data, size_t length, uint8_t *signature) override;
  bool decrypt_session_key(const uint8_t *encrypted, size_t length, uint8_t *key) override;
  bool set_audio_key(const uint8_t *key) override;
  bool decrypt_audio(uint8_t *iv, const uint8_t *input, uint8_t *output, size_t length) override;

 private:
#ifdef AIRPLAY_MBEDTLS_PSA
  // PSA allows one algorithm per key, so the RSA key is imported twice
  mbedtls_svc_key_id_t sign_key_{MBEDTLS_SVC_KEY_ID_INIT};
  mbedtls_svc_key_id_t decrypt_key_{MBEDTLS_SVC_KEY_ID_INIT};
  mbedtls_svc_key_id_t aes_key_{MBEDTLS_SVC_KEY_ID_INIT};
#else
  mbedtls_pk_context pk_;
  mbedtls_aes_context aes_;
#endif
  bool ready_{false};
};

}  // namespace airplay

#endif  // AIRPLAY_HAS_MBEDTLS
