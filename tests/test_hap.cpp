// Built-in AirPlay 2 cryptography: SHA-512, HMAC, HKDF, ChaCha20-Poly1305 and SRP-6a
#include "airplay_hap_crypto.h"
#include "airplay_srp.h"
#include "test_common.h"

#include <cstring>
#include <string>
#include <vector>

using namespace airplay;

static std::vector<uint8_t> hex(const char *text) {
  std::vector<uint8_t> bytes;
  for (size_t i = 0; text[i] != 0 && text[i + 1] != 0; i += 2)
    bytes.push_back(static_cast<uint8_t>(std::stoi(std::string(text + i, 2), nullptr, 16)));
  return bytes;
}

static bool same(const uint8_t *data, const char *expected_hex) {
  const std::vector<uint8_t> expected = hex(expected_hex);
  return std::memcmp(data, expected.data(), expected.size()) == 0;
}

static const uint8_t *text(const char *s) { return reinterpret_cast<const uint8_t *>(s); }

static void test_sha512() {
  uint8_t digest[SHA512_SIZE];
  sha512(nullptr, 0, digest);
  CHECK(same(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                     "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));
  sha512(text("abc"), 3, digest);
  CHECK(same(digest, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                     "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
  // Two blocks, fed in pieces
  const char *message = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  Sha512 hash;
  for (size_t i = 0; message[i] != 0; i += 7)
    hash.update(text(message + i), std::strlen(message + i) < 7 ? std::strlen(message + i) : 7);
  hash.finish(digest);
  CHECK(same(digest, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                     "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"));
}

static void test_hmac_hkdf() {
  // RFC 4231 test case 2
  uint8_t mac[SHA512_SIZE];
  const char *data = "what do ya want for nothing?";
  hmac_sha512(text("Jefe"), 4, text(data), std::strlen(data), mac);
  CHECK(same(mac, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                  "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"));

  // Python cryptography HKDF(SHA512, length=32)
  uint8_t secret[64];
  for (size_t i = 0; i < sizeof(secret); i++)
    secret[i] = static_cast<uint8_t>(i);
  uint8_t key[CHACHA_KEY_SIZE];
  hkdf_sha512_key("Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", secret, sizeof(secret), key);
  CHECK(same(key, "b6335536162d6629e4c0bade85f1b712c85a364bab0dedb25014cfb814489273"));
}

static void test_chacha20_poly1305() {
  // RFC 8439 section 2.8.2
  const std::vector<uint8_t> key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  const std::vector<uint8_t> nonce = hex("070000004041424344454647");
  const std::vector<uint8_t> aad = hex("50515253c0c1c2c3c4c5c6c7");
  const char *plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
                          "future, sunscreen would be it.";
  const size_t length = std::strlen(plaintext);
  std::vector<uint8_t> ciphertext(length);
  uint8_t tag[POLY1305_TAG_SIZE];
  chacha20_poly1305_encrypt(key.data(), nonce.data(), aad.data(), aad.size(), text(plaintext), length,
                            ciphertext.data(), tag);
  CHECK(same(ciphertext.data(), "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                                "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                                "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                                "3ff4def08e4b7a9de576d26586cec64b6116"));
  CHECK(same(tag, "1ae10b594f09e26a7e902ecbd0600691"));

  std::vector<uint8_t> decrypted(length);
  CHECK(chacha20_poly1305_decrypt(key.data(), nonce.data(), aad.data(), aad.size(), ciphertext.data(), length, tag,
                                  decrypted.data()));
  CHECK(std::memcmp(decrypted.data(), plaintext, length) == 0);
  // In place
  CHECK(chacha20_poly1305_decrypt(key.data(), nonce.data(), aad.data(), aad.size(), ciphertext.data(), length, tag,
                                  ciphertext.data()));
  CHECK(std::memcmp(ciphertext.data(), plaintext, length) == 0);

  // A changed tag, AAD or ciphertext is rejected and leaves the output alone
  chacha20_poly1305_encrypt(key.data(), nonce.data(), aad.data(), aad.size(), text(plaintext), length,
                            ciphertext.data(), tag);
  std::fill(decrypted.begin(), decrypted.end(), 0);
  tag[3] ^= 0x20;
  CHECK(!chacha20_poly1305_decrypt(key.data(), nonce.data(), aad.data(), aad.size(), ciphertext.data(), length, tag,
                                   decrypted.data()));
  tag[3] ^= 0x20;
  CHECK(!chacha20_poly1305_decrypt(key.data(), nonce.data(), aad.data(), aad.size() - 1, ciphertext.data(), length,
                                   tag, decrypted.data()));
  ciphertext[10] ^= 1;
  CHECK(!chacha20_poly1305_decrypt(key.data(), nonce.data(), aad.data(), aad.size(), ciphertext.data(), length, tag,
                                   decrypted.data()));
  CHECK(decrypted[0] == 0);
}

// Computed with srptools, as used by pyatv: salt and secrets fixed, user "Pair-Setup", PIN 3939.
// B happens to have a leading zero byte, which is left out where it is hashed in its shortest form.
static const char SRP_B[] =
    "004fc85c6697a821e9c9e10ab1062d8bb622afc53a910ca03ef7833caf95a283facd75634f968951f9d5f430c53fbea9"
    "921a0658533bfb7a2eec9ab8c5c9717b808d1ed1be311f7d1ea3ae239013d7139d9f8aa5e2663c1915fad9d574309e70"
    "6f3e2f9e19efead4467d9c069bf7fee78679af6898573c3e03afe54f16c2761c1f62e5496fbfb7c2f268c843c9759db8"
    "4f30dfd93432b00806d60dfec06d79056b1e31443196f68855ebf4b94c53e12b095b61c02a545689f26fd36495148b8c"
    "63e4d706fd0b8af21e32120acd5e1938241fb6dbb8ddd540819350ed8b8e206a38bb45c954a59790834e2c6122139527"
    "7023ea2cd32ec4d023fec531b547f2cd5911041ba909d5f8b26ecd69d71823c4b053d943793af03ea1b70d2923b191d5"
    "132336c0fcf3f67490fe5235c7b70d069117198be5f4dc8bcf7592126d6a72e41ae2e4e5b2f0fc78cdedb0953ba720e7"
    "419a69cb947581361f08ee35ecb3766dbf361403882b8b63e51f029b9a85bbc5d520040ebab93a1f64eeeed9647fc568";
static const char SRP_A[] =
    "bbfa9d2795070162515f91af378d13ab40bc8fca706e5ed4ffe18450e4eab82a3e1e83f9c379247f8084aa3a917afc6c"
    "690ff362e768d72266e616eb9d3f39d4b6cc9876b4a9a4d1da2cf10310aa304b9e367a96af7886a44ba801673c6de61b"
    "686ee6899d71ee78dbfd9815d3cf0782e2898efffd38b9d9f1e9001c837fb095db838f5704bec6c0448d49602536e624"
    "5c2acba82633da86d3569b71aa0796dcfb17940fd66b1e5608e12fa719c41f7e8a00a1df4700661dad015e98db719226"
    "f66055fe712c34c339e289a669a98bb7db10573b758a67399e510bef19f26e5b3322db42abce179a9670e7b187bfc07a"
    "5fe38780c2c89413d442103f44e5ab94ac327932a58bf8c22d465dad84f9966e49503e119b9426f3c53209acd9039aad"
    "f3c3df1ebac14dad88fec0dd09e8e1a57dc1895137e1cf083fe84ffe47ec2624992d2d28c84cd237142386c90b53184e"
    "11c96f2a38d120fd13dfed4fca81dd5769b5c4a4973049cd8de31263f9b209a4257471447a9d49f083c13b09af43b93c";
static const char SRP_M1[] =
    "f82893b150c529d515ad5bf3cd57ad828785d0ea4925df9bcef7bf302a63d24f00d038149889e28ba2736347ba74b76b"
    "15803a64d88e857f9769f9930e8c705e";
static const char SRP_M2[] =
    "8cda6ad8cc7312ac026e769447571321086f45188393dadfba43334a06d3e4112265bea1436647336096ca8c9d2cf2ce"
    "0df2803c9415fca45d26c66a238dfdc8";
static const char SRP_K[] =
    "94f89f43f7a3a4181d5fef35f82c5ed661d161ea9eb30c9dd248fb52d562aaeef7f2939ffe8f3cfefa4734f9cb49da46"
    "7405520fc33c8a301986a7765fb12c97";

static void test_srp() {
  static SrpServer server;  // Large; not on the stack
  const std::vector<uint8_t> salt = hex("8f1c2d3e4a5b6c7d8e9fa0b1c2d3e4f5");
  const std::vector<uint8_t> secret(SRP_SECRET_SIZE, 0x1f);
  server.begin("Pair-Setup", "3939", salt.data(), secret.data());
  CHECK(std::memcmp(server.salt(), salt.data(), SRP_SALT_SIZE) == 0);
  CHECK(same(server.public_key(), SRP_B));

  const std::vector<uint8_t> a = hex(SRP_A);
  std::vector<uint8_t> m1 = hex(SRP_M1);
  uint8_t m2[SHA512_SIZE];
  CHECK(server.verify(a.data(), a.size(), m1.data(), m1.size(), m2));
  CHECK(same(m2, SRP_M2));
  CHECK(same(server.session_key(), SRP_K));

  // A wrong proof, as from a wrong PIN
  m1[0] ^= 1;
  CHECK(!server.verify(a.data(), a.size(), m1.data(), m1.size(), m2));
  m1[0] ^= 1;
  // A of 0 or a multiple of the prime would make the session key predictable
  const std::vector<uint8_t> zero(SRP_KEY_SIZE, 0);
  CHECK(!server.verify(zero.data(), zero.size(), m1.data(), m1.size(), m2));
  const std::vector<uint8_t> all_ones(SRP_KEY_SIZE, 0xff);
  CHECK(!server.verify(all_ones.data(), all_ones.size(), m1.data(), m1.size(), m2));
  CHECK(!server.verify(a.data(), a.size(), m1.data(), m1.size() - 1, m2));
}

int main() {
  test_sha512();
  test_hmac_hkdf();
  test_chacha20_poly1305();
  test_srp();
  return finish("test_hap");
}
