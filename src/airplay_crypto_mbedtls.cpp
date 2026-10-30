#include "airplay_crypto_mbedtls.h"

#ifdef AIRPLAY_HAS_MBEDTLS

#include <mbedtls/rsa.h>
#include <mbedtls/version.h>

#include <cstring>

#if defined(ESP_PLATFORM)
#include <esp_random.h>
#elif defined(__ZEPHYR__)
#if __has_include(<zephyr/random/random.h>)
#include <zephyr/random/random.h>
#else
#include <zephyr/random/rand32.h>
#endif
#else
#include <random>
#endif

namespace airplay {

static int random_bytes(void * /*context*/, unsigned char *output, size_t length) {
#if defined(ESP_PLATFORM)
  esp_fill_random(output, length);
#elif defined(__ZEPHYR__)
  sys_rand_get(output, length);
#else
  static std::random_device device;
  for (size_t i = 0; i < length; i++)
    output[i] = static_cast<unsigned char>(device());
#endif
  return 0;
}

MbedtlsCrypto::MbedtlsCrypto() {
  mbedtls_pk_init(&this->pk_);
  mbedtls_aes_init(&this->aes_);
}

MbedtlsCrypto::~MbedtlsCrypto() {
  mbedtls_aes_free(&this->aes_);
  mbedtls_pk_free(&this->pk_);
}

bool MbedtlsCrypto::init() {
  const auto *key = reinterpret_cast<const unsigned char *>(AIRPORT_PRIVATE_KEY_PEM);
#if MBEDTLS_VERSION_MAJOR >= 3
  const int result =
      mbedtls_pk_parse_key(&this->pk_, key, AIRPORT_PRIVATE_KEY_PEM_SIZE, nullptr, 0, random_bytes, nullptr);
#else
  const int result = mbedtls_pk_parse_key(&this->pk_, key, AIRPORT_PRIVATE_KEY_PEM_SIZE, nullptr, 0);
#endif
  this->ready_ = result == 0 && mbedtls_pk_get_type(&this->pk_) == MBEDTLS_PK_RSA;
  return this->ready_;
}

bool MbedtlsCrypto::sign_challenge(const uint8_t *data, size_t length, uint8_t *signature) {
  if (!this->ready_)
    return false;
  // mbedTLS checks the padding mode of the key, so it is set before each operation.
  // MBEDTLS_MD_NONE signs the raw bytes with type 1 padding.
  mbedtls_rsa_context *rsa = mbedtls_pk_rsa(this->pk_);
  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
#if MBEDTLS_VERSION_MAJOR >= 3
  return mbedtls_rsa_rsassa_pkcs1_v15_sign(rsa, random_bytes, nullptr, MBEDTLS_MD_NONE,
                                           static_cast<unsigned int>(length), data, signature) == 0;
#else
  return mbedtls_rsa_rsassa_pkcs1_v15_sign(rsa, random_bytes, nullptr, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_NONE,
                                           static_cast<unsigned int>(length), data, signature) == 0;
#endif
}

bool MbedtlsCrypto::decrypt_session_key(const uint8_t *encrypted, size_t length, uint8_t *key) {
  if (!this->ready_ || length != RSA_SIGNATURE_SIZE)
    return false;
  mbedtls_rsa_context *rsa = mbedtls_pk_rsa(this->pk_);
  mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
  uint8_t plain[RSA_SIGNATURE_SIZE];
  size_t plain_length = 0;
#if MBEDTLS_VERSION_MAJOR >= 3
  const int result = mbedtls_rsa_rsaes_oaep_decrypt(rsa, random_bytes, nullptr, nullptr, 0, &plain_length, encrypted,
                                                    plain, sizeof(plain));
#else
  const int result = mbedtls_rsa_rsaes_oaep_decrypt(rsa, random_bytes, nullptr, MBEDTLS_RSA_PRIVATE, nullptr, 0,
                                                    &plain_length, encrypted, plain, sizeof(plain));
#endif
  if (result != 0 || plain_length != AES_KEY_SIZE)
    return false;
  std::memcpy(key, plain, AES_KEY_SIZE);
  return true;
}

bool MbedtlsCrypto::set_audio_key(const uint8_t *key) {
  return mbedtls_aes_setkey_dec(&this->aes_, key, AES_KEY_SIZE * 8) == 0;
}

bool MbedtlsCrypto::decrypt_audio(uint8_t *iv, const uint8_t *input, uint8_t *output, size_t length) {
  return mbedtls_aes_crypt_cbc(&this->aes_, MBEDTLS_AES_DECRYPT, length, iv, input, output) == 0;
}

}  // namespace airplay

#endif  // AIRPLAY_HAS_MBEDTLS
