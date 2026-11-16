// AirPlay 2 building blocks: SHA-512, HMAC, HKDF, ChaCha20-Poly1305, SRP-6a, Ed25519, X25519, TLV8 and binary
// property lists
#include "airplay_crypto_mbedtls.h"
#include "airplay_curve25519.h"
#include "airplay_fairplay.h"
#include "airplay_hap_crypto.h"
#include "airplay_packet_queue.h"
#include "airplay_plist.h"
#include "airplay_srp.h"
#include "airplay_tlv8.h"
#include "test_common.h"

#include <cstdlib>
#include <cstring>
#include <deque>
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
  CHECK(!chacha20_poly1305_decrypt(key.data(), nonce.data(), aad.data(), aad.size() - 1, ciphertext.data(), length, tag,
                                   decrypted.data()));
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

  // A later exchange with the same credentials keeps the salt and verifier: the same secret gives the same key
  const std::vector<uint8_t> other_salt(SRP_SALT_SIZE, 0x55);
  server.begin("Pair-Setup", "3939", other_salt.data(), secret.data());
  CHECK(std::memcmp(server.salt(), salt.data(), SRP_SALT_SIZE) == 0);
  CHECK(same(server.public_key(), SRP_B));
  CHECK(server.verify(a.data(), a.size(), m1.data(), m1.size(), m2));
  CHECK(same(m2, SRP_M2));

#if defined(AIRPLAY_HAS_MBEDTLS) && !defined(AIRPLAY_MBEDTLS_PSA)
  // The same with mbedTLS doing the exponentiations
  static SrpServer accelerated;
  MbedtlsCrypto crypto;
  accelerated.set_crypto(&crypto);
  accelerated.begin("Pair-Setup", "3939", salt.data(), secret.data());
  CHECK(same(accelerated.public_key(), SRP_B));
  CHECK(accelerated.verify(a.data(), a.size(), m1.data(), m1.size(), m2));
  CHECK(same(m2, SRP_M2));
  CHECK(same(accelerated.session_key(), SRP_K));
#endif

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

static void test_curve25519() {
  // RFC 8032, section 7.1, test 1 (empty message) and test 2
  const std::vector<uint8_t> seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  uint8_t secret_key[ED25519_SECRET_KEY_SIZE];
  uint8_t public_key[ED25519_PUBLIC_KEY_SIZE];
  ed25519_key_pair(seed.data(), secret_key, public_key);
  CHECK(same(public_key, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
  uint8_t signature[ED25519_SIGNATURE_SIZE];
  ed25519_sign(secret_key, nullptr, 0, signature);
  CHECK(same(signature, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b4"
                        "6bd25bf5f0595bbe24655141438e7a100b"));
  CHECK(ed25519_verify(signature, public_key, nullptr, 0));
  signature[10] ^= 1;
  CHECK(!ed25519_verify(signature, public_key, nullptr, 0));

  const std::vector<uint8_t> seed2 = hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
  const uint8_t message[] = {0x72};
  ed25519_key_pair(seed2.data(), secret_key, public_key);
  CHECK(same(public_key, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"));
  ed25519_sign(secret_key, message, sizeof(message), signature);
  CHECK(same(signature, "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d"
                        "8c387b2eaeb4302aeeb00d291612bb0c00"));
  CHECK(ed25519_verify(signature, public_key, message, sizeof(message)));

  // RFC 7748, section 6.1
  const std::vector<uint8_t> alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  const std::vector<uint8_t> bob = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
  uint8_t alice_public[X25519_KEY_SIZE];
  uint8_t bob_public[X25519_KEY_SIZE];
  x25519_public_key(alice.data(), alice_public);
  x25519_public_key(bob.data(), bob_public);
  CHECK(same(alice_public, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
  CHECK(same(bob_public, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
  uint8_t shared[X25519_KEY_SIZE];
  CHECK(x25519(alice.data(), bob_public, shared));
  CHECK(same(shared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
  CHECK(x25519(bob.data(), alice_public, shared));
  CHECK(same(shared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
  const uint8_t zero[X25519_KEY_SIZE] = {};
  CHECK(!x25519(alice.data(), zero, shared));  // A weak point gives an all-zero secret
}

static void test_tlv8() {
  uint8_t message[1024];
  Tlv8Writer writer(message, sizeof(message));
  uint8_t key[600];
  for (size_t i = 0; i < sizeof(key); i++)
    key[i] = static_cast<uint8_t>(i);
  writer.add_byte(TLV_STATE, 2);
  writer.add(TLV_PUBLIC_KEY, key, sizeof(key));  // Split into 255 + 255 + 90
  writer.add(TLV_SALT, key, 16);
  const size_t length = writer.length();
  CHECK(length == 3 + (600 + 6) + 18);
  CHECK(message[3] == TLV_PUBLIC_KEY && message[4] == 255 && message[260] == TLV_PUBLIC_KEY);

  uint8_t value[700];
  size_t value_length = 0;
  CHECK(tlv8_find(message, length, TLV_PUBLIC_KEY, value, sizeof(value), &value_length));
  CHECK(value_length == sizeof(key) && std::memcmp(value, key, sizeof(key)) == 0);
  CHECK(tlv8_find(message, length, TLV_STATE, value, sizeof(value), &value_length));
  CHECK(value_length == 1 && value[0] == 2);
  CHECK(tlv8_find(message, length, TLV_SALT, value, sizeof(value), &value_length));
  CHECK(value_length == 16 && value[15] == 15);
  CHECK(!tlv8_find(message, length, TLV_PUBLIC_KEY, value, 100, &value_length));  // Does not fit
  CHECK(!tlv8_find(message, length, TLV_ERROR, value, sizeof(value), &value_length));
  CHECK(!tlv8_find(message, length - 5, TLV_SALT, value, sizeof(value), &value_length));  // Truncated

  Tlv8Writer small(message, 10);
  small.add(TLV_SALT, key, 16);
  CHECK(small.length() == 0);
}

// From Python's plistlib: {"streams": [{"type": 96, "ct": 2, "shk": bytes(range(32)), "controlPort": 6001,
// "spf": 352}], "timingProtocol": "NTP", "timingPort": 6002, "name": "Küche", "latency": 1.25,
// "isMultiSelectAirPlay": True, "big": -3}
static const char PLIST[] =
    "62706c6973743030d70102030405060708090a0b0c1819536269675f101469734d756c746953656c656374416972506c"
    "6179576c6174656e6379546e616d655773747265616d735a74696d696e67506f72745e74696d696e6750726f746f636f"
    "6c13fffffffffffffffd09233ff400000000000065004b00fc006300680065a10dd50e0f10111213141516175b636f6e"
    "74726f6c506f72745263745373686b53737066547479706511177110024f1020000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f1101601060111772534e545008171b323a3f4752616a6b747f818c989b9fa3a8"
    "abadd0d3d5d80000000000000101000000000000001a000000000000000000000000000000dc";

static void test_plist_reader() {
  const std::vector<uint8_t> data = hex(PLIST);
  PlistReader reader;
  CHECK(reader.parse(data.data(), data.size()));
  const PlistReader::Object root = reader.root();
  CHECK(reader.count(root) == 7);

  int64_t integer = 0;
  CHECK(reader.get_integer(reader.get(root, "timingPort"), &integer) && integer == 6002);
  CHECK(reader.get_integer(reader.get(root, "big"), &integer) && integer == -3);
  CHECK(reader.string_equals(reader.get(root, "timingProtocol"), "NTP"));
  const char *text = nullptr;
  size_t length = 0;
  CHECK(reader.get_string(reader.get(root, "timingProtocol"), &text, &length) && length == 3);
  CHECK(!reader.get_string(reader.get(root, "name"), &text, &length));  // UTF-16
  double real = 0;
  CHECK(reader.get_real(reader.get(root, "latency"), &real) && real == 1.25);
  CHECK(reader.get_real(reader.get(root, "timingPort"), &real) && real == 6002.0);
  bool flag = false;
  CHECK(reader.get_bool(reader.get(root, "isMultiSelectAirPlay"), &flag) && flag);
  CHECK(reader.get(root, "missing") == PlistReader::NONE);

  const PlistReader::Object streams = reader.get(root, "streams");
  CHECK(reader.count(streams) == 1);
  const PlistReader::Object stream = reader.at(streams, 0);
  CHECK(reader.at(streams, 1) == PlistReader::NONE);
  CHECK(reader.get_integer(reader.get(stream, "type"), &integer) && integer == 96);
  CHECK(reader.get_integer(reader.get(stream, "spf"), &integer) && integer == 352);
  const uint8_t *bytes = nullptr;
  CHECK(reader.get_data(reader.get(stream, "shk"), &bytes, &length) && length == 32 && bytes[31] == 31);
  CHECK(!reader.get_integer(reader.get(stream, "shk"), &integer));

  // Damaged data is rejected, not read out of bounds
  CHECK(!reader.parse(data.data(), 20));
  std::vector<uint8_t> damaged = data;
  damaged[damaged.size() - 1] = 0xff;  // Offset table beyond the end
  CHECK(!reader.parse(damaged.data(), damaged.size()));
  damaged = data;
  damaged[8] = 0xdf;  // Root dictionary with a missing length
  CHECK(!reader.parse(damaged.data(), damaged.size()) || reader.count(reader.root()) == 0);
}

static void test_plist_writer() {
  uint8_t buffer[1024];
  PlistWriter writer(buffer, sizeof(buffer));
  writer.begin_dict(3);
  writer.key("eventPort");
  writer.integer(7001);
  writer.key("streams");
  writer.begin_array(2);
  writer.begin_dict(2);
  writer.key("type");
  writer.integer(96);
  writer.key("dataPort");
  writer.integer(50000);
  writer.begin_dict(0);
  writer.key("a key longer than fifteen");
  const uint8_t key[20] = {1, 2, 3};
  writer.data(key, sizeof(key));
  const size_t length = writer.finish();
  CHECK(length > 0);

  PlistReader reader;
  CHECK(reader.parse(buffer, length));
  int64_t integer = 0;
  CHECK(reader.get_integer(reader.get(reader.root(), "eventPort"), &integer) && integer == 7001);
  const PlistReader::Object streams = reader.get(reader.root(), "streams");
  CHECK(reader.count(streams) == 2);
  CHECK(reader.get_integer(reader.get(reader.at(streams, 0), "dataPort"), &integer) && integer == 50000);
  CHECK(reader.count(reader.at(streams, 1)) == 0);
  const uint8_t *bytes = nullptr;
  size_t data_length = 0;
  CHECK(reader.get_data(reader.get(reader.root(), "a key longer than fifteen"), &bytes, &data_length) &&
        data_length == 20 && bytes[2] == 3);

  PlistWriter small(buffer, 20);
  small.begin_dict(1);
  small.key("x");
  small.string("too long for the buffer");
  CHECK(small.finish() == 0);
  PlistWriter incomplete(buffer, sizeof(buffer));
  incomplete.begin_dict(2);
  incomplete.key("x");
  incomplete.integer(1);
  CHECK(incomplete.finish() == 0);
}

static void test_fairplay_setup() {
  // The first message of each mode gets the matching fixed reply (as shairport-sync answers)
  uint8_t message[164] = {'F', 'P', 'L', 'Y', 3, 1, 1, 0, 0, 0, 0, 4, 2, 0, 2, 0xbb};
  uint8_t reply[FAIRPLAY_SETUP_REPLY_SIZE];
  CHECK(fairplay_setup_reply(message, 16, reply, sizeof(reply)) == 142);
  CHECK(same(reply, "46504c5903010200000000820202c169a352eeed"));
  message[14] = 0;
  CHECK(fairplay_setup_reply(message, 16, reply, sizeof(reply)) == 142);
  CHECK(same(reply, "46504c59030102000000008202000f9f"));
  message[14] = 4;
  CHECK(fairplay_setup_reply(message, 16, reply, sizeof(reply)) == 0);

  // The second reply echoes the last 20 bytes of the message
  message[6] = 3;
  for (size_t i = 144; i < 164; i++)
    message[i] = static_cast<uint8_t>(i);
  CHECK(fairplay_setup_reply(message, 164, reply, sizeof(reply)) == 32);
  CHECK(same(reply, "46504c590301040000000014"));
  CHECK(reply[12] == 144 && reply[31] == 163);

  message[0] = 'X';
  CHECK(fairplay_setup_reply(message, 164, reply, sizeof(reply)) == 0);

  // iTunes for Windows (AirPlay 1) sends FairPlay version 2: the same reply bodies, its version echoed
  uint8_t v2[164] = {'F', 'P', 'L', 'Y', 2, 1, 1, 0, 0, 0, 0, 4, 2, 0, 1, 0xbb};
  CHECK(fairplay_setup_reply(v2, 16, reply, sizeof(reply)) == 142);
  CHECK(same(reply, "46504c5902010200000000820201cf32a257"));
  v2[6] = 3;
  for (size_t i = 144; i < 164; i++)
    v2[i] = static_cast<uint8_t>(i);
  CHECK(fairplay_setup_reply(v2, 164, reply, sizeof(reply)) == 32);
  CHECK(same(reply, "46504c590201040000000014"));
  CHECK(reply[12] == 144 && reply[31] == 163);
}

static void test_fairplay_key() {
#ifdef AIRPLAY_HAS_MBEDTLS
  // An iTunes FairPlay session: the receiver's setup reply, the sender's second setup message
  // and its a=fpaeskey give this audio key
  const std::vector<uint8_t> reply = hex(
      "46504c5902010200000000820201cf32a25714b2524f8aa0ad7af164e37bcf4424e200047efc0ad67afcd95ded1c2730bb591b962ed63a9"
      "c4ded88ba8fc78de64d91ccfd5c7b56da88e31f5cceafc7431995a01665a54e1939d25b94db64b9e45d8d063e1e6af07e9656162b0efa40"
      "4275ea5a44d9591c7256b9fbe6513898b80227721988571650942ad946688a");
  const std::vector<uint8_t> second = hex(
      "46504c590201030000000098018f1a9c50a2b1a02325ec8e046547d1c18f3daf2808117aa3d8fc1a96bdfe68c3d25180f8536161439026e"
      "5865c06a43f701762be9745a8cbdf81df3f67705aa13493489bfe9e235e26c6b7b18c97d02b8e2912fb39eff643b2b832b8819103b5fdc3"
      "cbd806e47f4fc2d42b607270ec497c0c73fae9842af6e3d71245a2c5c27e69972a6d4867913cdf0b69f1c2491f5de54a6a6cb55e14");
  const std::vector<uint8_t> blob = hex(
      "46504c59010201000000003c00000000bcb464d6e39a9582900f566ccea7d1b9000000100ed6a4cbb73dbcd4afe8a76236167ca510cbf00"
      "6af22fc5289fbfdc2bb423fd2cc48b82c");
  CHECK(reply.size() == FAIRPLAY_SETUP_P2_SIZE && second.size() == FAIRPLAY_SETUP_P3_SIZE &&
        blob.size() == FAIRPLAY_KEY_SIZE);
  // The reply is the one fairplay_setup_reply() gives for its first message (version 2, mode 1)
  const uint8_t first[FAIRPLAY_SETUP_FIRST_SIZE] = {'F', 'P', 'L', 'Y', 2, 1, 1, 0, 0, 0, 0, 4, 2, 0, 1, 0xbb};
  uint8_t made[FAIRPLAY_SETUP_REPLY_SIZE];
  CHECK(fairplay_setup_reply(first, sizeof(first), made, sizeof(made)) == sizeof(made) &&
        std::memcmp(made, reply.data(), sizeof(made)) == 0);
  MbedtlsCrypto crypto;
  CHECK(crypto.init());
  uint8_t key[AES_KEY_SIZE];
  CHECK(crypto.decrypt_fairplay_key(reply.data(), second.data(), blob.data(), key));
  CHECK(same(key, "de19c9c675978ff4b788d26d7bbd0e3f"));
  // A wrong authentication tag is refused
  std::vector<uint8_t> tampered = blob;
  tampered[36] ^= 0x01;
  CHECK(!crypto.decrypt_fairplay_key(reply.data(), second.data(), tampered.data(), key));
  // Sessions in the other modes, each with its own AES key and IV
  struct Session {
    const char *reply;
    const char *second;
    const char *blob;
    const char *key;
  };
  static const Session SESSIONS[] = {
      {"46504c59020102000000008202000f9f3f9e0a2521dbdf312ab2bfb29e8d232b6376a8c818701d22ae93d82737feaf9db4fdf41c2dba"
       "9d1f49caaabf6591ac1f7bc6f7e0663d21afe01565953eab81f418ceed095adb7c3d0e254909a79831d49c3982973434facb42c63a1c"
       "d911a6fe941a8a6d4a743b46c3a7649e44c78955e49d8155009549c4e2f7a3f6d5ba",
       "46504c590201030000000098008f1a9c97be1b192e55304c25698fa2bdb61135239b9721f558ecf9a1d94342cca2cdea20ef4ae24be7"
       "7ccb8c7de780fa9a4838b23b845dcc9a827e849be84638cacdd90736bc81d20099d368055b2c3b60ee7a4711f53101024078fe6ab7ff"
       "723e2b8a4d66dc434cd83b17d9492476d38f8e0709e23e5577e39075067f72de9ccbe063340579b05e51b115d9261b44aab161804d65"
       "5e91",
       "46504c59010201000000003c000000001acc14be13cd47dd6fa975f243fd484900000010d8b1777d9c20c60c62b5e8da4ba34eda3a04"
       "f09331fd9f264a9d69b63d1a281cd87a7c99",
       "7f08d6ff14862c7e09ed76dd22ea8b75"},
      {"46504c5902010200000000820202c169a352eeed35b18cdd9c58d64f16c1519a89eb5317bd0d4336cd68f638ff9d016a5b52b7fa9216"
       "b2b65482c78444118121a2c7fed83db7119e9182aad7d18c7063e2a457555910af9e0efc76347d164043807f581ee4fbe42ca9dedc1b"
       "5eb2a3aa3d2ecd59e7eee70b3629f22afd161d877353ddb99adc8e07006e56f850ce",
       "46504c590201030000000098028f1a9cd6c300b29df398432eaa8803de5c59aa898bfccfb8c06285722d9a9b15789108419c0603bb3d"
       "741d025b86ef3f9796f723f3aef708318c23f886bdf91145422f7d9b8cdd57de73726ddfbf4f0faf69c467db66d3157af57efe88e776"
       "3d26c26bde8234cf89b06ca046fe6831d7260fb983bf1e382fb11df7460b405c62fa3fcfd8faf7e9e35efee9b6e86cb0a742df301b4c"
       "daf4",
       "46504c59010201000000003c00000000189a010ee1cbf6c69e8c3bc746cc5d71000000100c4a64d74e9aabd01fb678c9b70138ba08a5"
       "94e91bd18bea9792f7b97705c0a00cf324ea",
       "e6498a1ce9c22e759fe5bc3cfb8419ed"},
      {"46504c59020102000000008202039001e1727e0f57f9f5880db104a6257a23f5cfff1abbe1e93045251afb97eb9fc0011ebe0f3a81df"
       "5b691d76acb2f7a5c708e3d328f56bb39dbde5f29c8a17f481487e3ae863c678325422e6f78e166d18aa7fd636258bce28726f661f73"
       "8893ce44311e4be6c0535193e5ef72e8686233729c227d820c999445d89246c8c359",
       "46504c590201030000000098038f1a9c79f96dac8eb34b6347a7feb1814f2b4155c76f3a113cb93307cdfdabce507787e288d19eab6b"
       "670fa27edca827b1d78a7ee10ef97c1738919c6d09157820429bc01b18cce7ce9ad65371239a788a9a9551e6afecaae7878e05080863"
       "54565c02ff5eb1e0b7c97abb7f71ed730bc106177545e2dc86c99b47068c8ced4a48eb0a3a3bb7d54e65bb30ce9d93bc3af5b255b716"
       "aab2",
       "46504c59010201000000003c000000009d23a162313c610929d6b275a527606500000010957993f7d592292ef3806152f2d2488c13ca"
       "6625d8c5102ba4dcecf5dc166bb08daecb73",
       "b3c7113bbd42b3db233b33c953428ce6"},
  };
  for (const Session &session : SESSIONS) {
    const std::vector<uint8_t> session_reply = hex(session.reply);
    const std::vector<uint8_t> session_second = hex(session.second);
    const std::vector<uint8_t> session_blob = hex(session.blob);
    CHECK(session_reply.size() == FAIRPLAY_SETUP_P2_SIZE && session_second.size() == FAIRPLAY_SETUP_P3_SIZE &&
          session_blob.size() == FAIRPLAY_KEY_SIZE);
    // The reply is the receiver's own for that mode
    uint8_t mode_first[FAIRPLAY_SETUP_FIRST_SIZE];
    std::memcpy(mode_first, first, sizeof(mode_first));
    mode_first[14] = session_reply[13];
    CHECK(fairplay_setup_reply(mode_first, sizeof(mode_first), made, sizeof(made)) == sizeof(made) &&
          std::memcmp(made, session_reply.data(), sizeof(made)) == 0);
    CHECK(crypto.decrypt_fairplay_key(session_reply.data(), session_second.data(), session_blob.data(), key) &&
          same(key, session.key));
  }
  // Only modes 0 to 3 exist
  std::vector<uint8_t> unknown_mode = reply;
  unknown_mode[13] = 4;
  CHECK(!crypto.decrypt_fairplay_key(unknown_mode.data(), second.data(), blob.data(), key));
#endif
}

static void test_packet_queue() {
  // Random pushes and pops against a simple model, in buffers of several sizes
  struct Packet {
    uint32_t rtp;
    uint32_t seq;
    std::vector<uint8_t> data;
  };
  for (size_t size : {64u, 1000u, 4096u}) {
    std::vector<uint8_t> storage(size);
    PacketQueue queue;
    queue.init(storage.data(), size);
    std::deque<Packet> model;
    std::srand(static_cast<unsigned>(size));
    bool ok = true;
    for (int step = 0; step < 20000 && ok; step++) {
      if (std::rand() % 2 == 0) {
        Packet packet{static_cast<uint32_t>(std::rand()), static_cast<uint32_t>(std::rand()),
                      std::vector<uint8_t>(static_cast<size_t>(std::rand()) % (size / 3 + 1))};
        for (uint8_t &byte : packet.data)
          byte = static_cast<uint8_t>(std::rand());
        if (queue.push(packet.rtp, packet.seq, packet.data.data(), static_cast<uint16_t>(packet.data.size()))) {
          model.push_back(packet);
        } else {
          ok = !model.empty();  // A packet that fits the buffer always fits an empty queue
        }
      } else {
        uint32_t rtp, seq;
        const uint8_t *data;
        uint16_t length;
        const bool found = queue.front(&rtp, &seq, &data, &length);
        ok = found == !model.empty();
        if (found && ok) {
          const Packet &expected = model.front();
          ok = rtp == expected.rtp && seq == expected.seq && length == expected.data.size() &&
               (length == 0 || std::memcmp(data, expected.data.data(), length) == 0);
          queue.pop();
          model.pop_front();
        }
      }
      ok = ok && queue.empty() == model.empty();
    }
    CHECK(ok);
  }
}

// A realtime stream packet from iOS 26 (Spotify), whose stream setup had no key: the key is derived from the transient
// pairing's secret with the stream's connection ID appended to the salt
static void test_realtime_stream_key() {
  const std::vector<uint8_t> secret = hex("e565269a980b49ef12d95fc0f6c70bcf8f337d4576f48d72bac2000fc574341b"
                                          "e1689f0dd8bf07919b43f7a72efe40dcb0268d4e3688f13130ca9beab2e64198");
  const std::vector<uint8_t> header = hex("80603de8f624815f00000000");
  const std::vector<uint8_t> payload = hex("9f79d02de8b962326edca0380227377a1b99478c7a03b7cb8dd3f8a7101e07e7"
                                           "c454662f42591d2949e2fd0012e349820700000000000000");
  uint8_t key[CHACHA_KEY_SIZE];
  hkdf_sha512_key("DataStream-Salt3864104479819057726", "DataStream-Output-Encryption-Key", secret.data(),
                  secret.size(), key);
  uint8_t nonce[CHACHA_NONCE_SIZE] = {};
  std::memcpy(nonce + 4, payload.data() + payload.size() - 8, 8);
  const size_t length = payload.size() - POLY1305_TAG_SIZE - 8;
  uint8_t plain[64];
  CHECK(chacha20_poly1305_decrypt(key, nonce, header.data() + 4, 8, payload.data(), length, payload.data() + length,
                                  plain));
  CHECK(plain[0] >> 5 == 1);  // An ALAC frame with a channel pair
}

int main() {
  test_sha512();
  test_hmac_hkdf();
  test_chacha20_poly1305();
  test_srp();
  test_curve25519();
  test_tlv8();
  test_plist_reader();
  test_plist_writer();
  test_fairplay_setup();
  test_fairplay_key();
  test_packet_queue();
  test_realtime_stream_key();
  return finish("test_hap");
}
