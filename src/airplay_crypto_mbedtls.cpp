#include "airplay_crypto_mbedtls.h"

#ifdef AIRPLAY_HAS_MBEDTLS

#ifdef AIRPLAY_MBEDTLS_PSA

#include <cstring>

namespace airplay {

MbedtlsCrypto::MbedtlsCrypto() = default;

MbedtlsCrypto::~MbedtlsCrypto() {
  psa_destroy_key(this->aes_key_);
  psa_destroy_key(this->decrypt_key_);
  psa_destroy_key(this->sign_key_);
}

static bool import_rsa_key(psa_key_usage_t usage, psa_algorithm_t algorithm, mbedtls_svc_key_id_t *key) {
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
  psa_set_key_usage_flags(&attributes, usage);
  psa_set_key_algorithm(&attributes, algorithm);
  const psa_status_t status = psa_import_key(&attributes, AIRPORT_PRIVATE_KEY_DER, AIRPORT_PRIVATE_KEY_DER_SIZE, key);
  psa_reset_key_attributes(&attributes);
  return status == PSA_SUCCESS;
}

bool MbedtlsCrypto::init() {
  this->ready_ = psa_crypto_init() == PSA_SUCCESS &&
                 import_rsa_key(PSA_KEY_USAGE_SIGN_HASH, PSA_ALG_RSA_PKCS1V15_SIGN_RAW, &this->sign_key_) &&
                 import_rsa_key(PSA_KEY_USAGE_DECRYPT, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_1), &this->decrypt_key_);
  return this->ready_;
}

bool MbedtlsCrypto::sign_challenge(const uint8_t *data, size_t length, uint8_t *signature) {
  if (!this->ready_)
    return false;
  size_t signature_length = 0;
  return psa_sign_hash(this->sign_key_, PSA_ALG_RSA_PKCS1V15_SIGN_RAW, data, length, signature, RSA_SIGNATURE_SIZE,
                       &signature_length) == PSA_SUCCESS &&
         signature_length == RSA_SIGNATURE_SIZE;
}

bool MbedtlsCrypto::decrypt_session_key(const uint8_t *encrypted, size_t length, uint8_t *key) {
  if (!this->ready_ || length != RSA_SIGNATURE_SIZE)
    return false;
  uint8_t plain[RSA_SIGNATURE_SIZE];
  size_t plain_length = 0;
  if (psa_asymmetric_decrypt(this->decrypt_key_, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_1), encrypted, length, nullptr, 0, plain,
                             sizeof(plain), &plain_length) != PSA_SUCCESS ||
      plain_length != AES_KEY_SIZE) {
    return false;
  }
  std::memcpy(key, plain, AES_KEY_SIZE);
  return true;
}

bool MbedtlsCrypto::set_audio_key(const uint8_t *key) {
  psa_destroy_key(this->aes_key_);
  this->aes_key_ = MBEDTLS_SVC_KEY_ID_INIT;
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attributes, AES_KEY_SIZE * 8);
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);
  const psa_status_t status = psa_import_key(&attributes, key, AES_KEY_SIZE, &this->aes_key_);
  psa_reset_key_attributes(&attributes);
  return status == PSA_SUCCESS;
}

bool MbedtlsCrypto::decrypt_audio(uint8_t *iv, const uint8_t *input, uint8_t *output, size_t length) {
  if (length == 0)
    return true;
  // The IV for a following call is the last cipher block, read before output may overwrite input
  uint8_t next_iv[AES_BLOCK_SIZE];
  std::memcpy(next_iv, input + length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
  psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
  size_t written = 0;
  size_t finished = 0;
  const bool ok = psa_cipher_decrypt_setup(&operation, this->aes_key_, PSA_ALG_CBC_NO_PADDING) == PSA_SUCCESS &&
                  psa_cipher_set_iv(&operation, iv, AES_BLOCK_SIZE) == PSA_SUCCESS &&
                  psa_cipher_update(&operation, input, length, output, length, &written) == PSA_SUCCESS &&
                  psa_cipher_finish(&operation, output + written, length - written, &finished) == PSA_SUCCESS &&
                  written + finished == length;
  psa_cipher_abort(&operation);
  if (ok)
    std::memcpy(iv, next_iv, AES_BLOCK_SIZE);
  return ok;
}

}  // namespace airplay

#else  // mbedTLS 2.28 and 3.x

#include <mbedtls/bignum.h>
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

bool MbedtlsCrypto::mod_exp(const uint8_t *base, const uint8_t *exponent, size_t exponent_length,
                            const uint8_t *modulus, size_t size, uint8_t *result) {
  mbedtls_mpi a, e, n, x;
  mbedtls_mpi_init(&a);
  mbedtls_mpi_init(&e);
  mbedtls_mpi_init(&n);
  mbedtls_mpi_init(&x);
  const bool ok = mbedtls_mpi_read_binary(&a, base, size) == 0 &&
                  mbedtls_mpi_read_binary(&e, exponent, exponent_length) == 0 &&
                  mbedtls_mpi_read_binary(&n, modulus, size) == 0 &&
                  mbedtls_mpi_exp_mod(&x, &a, &e, &n, nullptr) == 0 && mbedtls_mpi_write_binary(&x, result, size) == 0;
  mbedtls_mpi_free(&a);
  mbedtls_mpi_free(&e);
  mbedtls_mpi_free(&n);
  mbedtls_mpi_free(&x);
  return ok;
}

}  // namespace airplay

#endif  // AIRPLAY_MBEDTLS_PSA

#endif  // AIRPLAY_HAS_MBEDTLS
