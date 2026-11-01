// AirPlay 2 building blocks: SHA-512, HMAC, HKDF, ChaCha20-Poly1305, SRP-6a, TLV8 and binary property lists
#include "airplay_fairplay.h"
#include "airplay_hap_crypto.h"
#include "airplay_plist.h"
#include "airplay_srp.h"
#include "airplay_tlv8.h"
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
}

int main() {
  test_sha512();
  test_hmac_hkdf();
  test_chacha20_poly1305();
  test_srp();
  test_tlv8();
  test_plist_reader();
  test_plist_writer();
  test_fairplay_setup();
  return finish("test_hap");
}
