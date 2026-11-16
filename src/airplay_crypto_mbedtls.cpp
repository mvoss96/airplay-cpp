#include "airplay_crypto_mbedtls.h"

#include "airplay_util.h"

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

// The primitives of the FairPlay key (decrypt_fairplay_key() below)
static bool fairplay_aes_decrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *input, uint8_t *output,
                                 size_t length) {
  const psa_algorithm_t algorithm = iv != nullptr ? PSA_ALG_CBC_NO_PADDING : PSA_ALG_ECB_NO_PADDING;
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attributes, AES_KEY_SIZE * 8);
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attributes, algorithm);
  mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
  bool ok = psa_import_key(&attributes, key, AES_KEY_SIZE, &id) == PSA_SUCCESS;
  psa_reset_key_attributes(&attributes);
  psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
  size_t written = 0;
  size_t finished = 0;
  ok = ok && psa_cipher_decrypt_setup(&operation, id, algorithm) == PSA_SUCCESS &&
       (iv == nullptr || psa_cipher_set_iv(&operation, iv, AES_BLOCK_SIZE) == PSA_SUCCESS) &&
       psa_cipher_update(&operation, input, length, output, length, &written) == PSA_SUCCESS &&
       psa_cipher_finish(&operation, output + written, length - written, &finished) == PSA_SUCCESS &&
       written + finished == length;
  psa_cipher_abort(&operation);
  psa_destroy_key(id);
  return ok;
}

static bool fairplay_sha1(const uint8_t *data, size_t length, uint8_t *digest) {
  size_t digest_length = 0;
  return psa_hash_compute(PSA_ALG_SHA_1, data, length, digest, 20, &digest_length) == PSA_SUCCESS &&
         digest_length == 20;
}

static bool fairplay_hmac_sha1(const uint8_t *key, size_t key_length, const uint8_t *data, size_t length,
                               uint8_t *mac) {
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_1));
  mbedtls_svc_key_id_t id = MBEDTLS_SVC_KEY_ID_INIT;
  bool ok = psa_import_key(&attributes, key, key_length, &id) == PSA_SUCCESS;
  psa_reset_key_attributes(&attributes);
  size_t mac_length = 0;
  ok = ok && psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_1), data, length, mac, 20, &mac_length) == PSA_SUCCESS &&
       mac_length == 20;
  psa_destroy_key(id);
  return ok;
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
#include <mbedtls/md.h>
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

// The primitives of the FairPlay key (decrypt_fairplay_key() below)
static bool fairplay_aes_decrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *input, uint8_t *output,
                                 size_t length) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  bool ok = mbedtls_aes_setkey_dec(&aes, key, AES_KEY_SIZE * 8) == 0;
  if (iv != nullptr) {
    uint8_t chain[AES_BLOCK_SIZE];
    std::memcpy(chain, iv, sizeof(chain));
    ok = ok && mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, chain, input, output) == 0;
  } else {
    for (size_t i = 0; ok && i < length; i += AES_BLOCK_SIZE)
      ok = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, input + i, output + i) == 0;
  }
  mbedtls_aes_free(&aes);
  return ok;
}

static bool fairplay_sha1(const uint8_t *data, size_t length, uint8_t *digest) {
  return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), data, length, digest) == 0;
}

static bool fairplay_hmac_sha1(const uint8_t *key, size_t key_length, const uint8_t *data, size_t length,
                               uint8_t *mac) {
  return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), key, key_length, data, length, mac) == 0;
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

namespace airplay {

// iTunes for Windows wraps the audio key in a 72-byte blob: HEADER, A (16 bytes), LENGTH, an HMAC-SHA1 tag
// (20 bytes) and the encrypted key (16 bytes). Its keys come from the two FairPlay setup messages.
bool MbedtlsCrypto::decrypt_fairplay_key(const uint8_t *p2, const uint8_t *p3, const uint8_t *blob, uint8_t *key) {
  static const uint8_t HEADER[16] = {0x46, 0x50, 0x4c, 0x59, 0x01, 0x02, 0x01, 0x00,
                                     0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00};
  static const uint8_t LENGTH[4] = {0x00, 0x00, 0x00, 0x10};
  if (std::memcmp(blob, HEADER, sizeof(HEADER)) != 0 || std::memcmp(blob + 32, LENGTH, sizeof(LENGTH)) != 0)
    return false;

  // 128 bytes of each setup message (the reply's after its header, the second message's), each decrypted with
  // AES-128-CBC under a fixed key and IV of the mode the sender chose (the reply's byte 13); then salt || second ||
  // reply || salt is hashed into the keys
  static const uint8_t KEYS[4][16] = {
      {0xb5, 0xf1, 0x26, 0xdd, 0x6e, 0x3e, 0x05, 0xa4, 0x1a, 0x96, 0x33, 0x61, 0x15, 0x3e, 0xe5, 0xdc},
      {0xeb, 0xa1, 0xf1, 0x18, 0xef, 0x08, 0xb7, 0x1c, 0x60, 0xd5, 0x0f, 0xf0, 0xa9, 0x8c, 0x94, 0xb4},
      {0x29, 0x7b, 0x84, 0x83, 0x41, 0x7c, 0xc9, 0xd5, 0x1b, 0x82, 0xd1, 0x7b, 0xba, 0xa7, 0x61, 0x9d},
      {0x21, 0x41, 0x78, 0x3a, 0xac, 0x0b, 0x0b, 0x27, 0x19, 0x56, 0xcd, 0x1d, 0xbd, 0x01, 0x95, 0xc2},
  };
  static const uint8_t IVS[4][16] = {
      {0xe7, 0xc3, 0x45, 0xf5, 0x00, 0x13, 0xe4, 0x93, 0x1e, 0x0a, 0x33, 0xe2, 0x39, 0xe8, 0xb3, 0xdb},
      {0x3e, 0x08, 0x3f, 0x58, 0x4f, 0xf9, 0x88, 0x3e, 0x49, 0x2c, 0xf3, 0x65, 0x49, 0x02, 0x78, 0xe2},
      {0xa7, 0xed, 0x28, 0xe5, 0x6a, 0x2f, 0x8a, 0x6f, 0x7e, 0x46, 0xfa, 0x76, 0x5a, 0x6c, 0x04, 0x0a},
      {0x69, 0x8a, 0x2b, 0x3c, 0xf2, 0x6a, 0xa8, 0x29, 0xb1, 0x75, 0xba, 0x84, 0x2c, 0xec, 0x84, 0x21},
  };
  const uint8_t mode = p2[13];
  if (mode >= 4)
    return false;
  uint8_t message[16 + 256 + 16];
  if (!fairplay_aes_decrypt(KEYS[mode], IVS[mode], p3 + 16, message + 16, 128) ||
      !fairplay_aes_decrypt(KEYS[mode], IVS[mode], p2 + 14, message + 16 + 128, 128))
    return false;

  // Kaes = MD5(salt || D || salt), Kmac = SHA-1(salt || D || salt), each with its own fixed salts
  uint8_t kaes[16];
  uint8_t kmac[20];
  std::memcpy(message, "#l*GY&cqnwo*&5sd", 16);
  std::memcpy(message + 16 + 256, "57bv&%niulqpdg3z", 16);
  md5(message, sizeof(message), kaes);  // The library's own: MD5 may be left out of mbedTLS
  std::memcpy(message, "asdiuAD8AKA9a>/?", 16);
  std::memcpy(message + 16 + 256, "!D4H&2*203kjgha9", 16);
  if (!fairplay_sha1(message, sizeof(message), kmac))
    return false;

  // The key is AES-128-ECB(Kaes) decrypted, xor A, and must carry the tag HMAC-SHA1(Kmac, HEADER || A || LENGTH ||
  // key)
  uint8_t mac_message[36 + AES_KEY_SIZE];
  if (!fairplay_aes_decrypt(kaes, nullptr, blob + 56, mac_message + 36, AES_KEY_SIZE))
    return false;
  for (size_t i = 0; i < AES_KEY_SIZE; i++)
    mac_message[36 + i] ^= blob[16 + i];
  std::memcpy(mac_message, blob, 36);
  uint8_t tag[20];
  if (!fairplay_hmac_sha1(kmac, sizeof(kmac), mac_message, sizeof(mac_message), tag))
    return false;
  uint8_t differ = 0;
  for (size_t i = 0; i < sizeof(tag); i++)
    differ |= tag[i] ^ blob[36 + i];
  if (differ != 0)
    return false;
  std::memcpy(key, mac_message + 36, AES_KEY_SIZE);
  return true;
}

}  // namespace airplay

#endif  // AIRPLAY_HAS_MBEDTLS
