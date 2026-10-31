#include "airplay_hap_crypto.h"

#include <cstring>

namespace airplay {

// ===== SHA-512 =====

static const uint64_t SHA512_K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
    0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
    0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
    0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
    0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
    0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

static inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static inline uint64_t load_be64(const uint8_t *p) {
  uint64_t value = 0;
  for (int i = 0; i < 8; i++)
    value = (value << 8) | p[i];
  return value;
}

static inline void store_be64(uint8_t *p, uint64_t value) {
  for (int i = 7; i >= 0; i--) {
    p[i] = static_cast<uint8_t>(value);
    value >>= 8;
  }
}

Sha512::Sha512()
    : state_{0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
             0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL} {}

void Sha512::process_block_(const uint8_t *block) {
  // A 16 word ring instead of the full 80 word schedule keeps the stack small
  uint64_t w[16];
  for (int i = 0; i < 16; i++)
    w[i] = load_be64(block + 8 * i);
  uint64_t a = this->state_[0], b = this->state_[1], c = this->state_[2], d = this->state_[3];
  uint64_t e = this->state_[4], f = this->state_[5], g = this->state_[6], h = this->state_[7];
  for (int i = 0; i < 80; i++) {
    if (i >= 16) {
      const uint64_t w15 = w[(i - 15) & 15];
      const uint64_t w2 = w[(i - 2) & 15];
      const uint64_t s0 = rotr64(w15, 1) ^ rotr64(w15, 8) ^ (w15 >> 7);
      const uint64_t s1 = rotr64(w2, 19) ^ rotr64(w2, 61) ^ (w2 >> 6);
      w[i & 15] += s0 + w[(i - 7) & 15] + s1;
    }
    const uint64_t t1 =
        h + (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)) + ((e & f) ^ (~e & g)) + SHA512_K[i] + w[i & 15];
    const uint64_t t2 = (rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  this->state_[0] += a;
  this->state_[1] += b;
  this->state_[2] += c;
  this->state_[3] += d;
  this->state_[4] += e;
  this->state_[5] += f;
  this->state_[6] += g;
  this->state_[7] += h;
}

void Sha512::update(const uint8_t *data, size_t length) {
  if (length == 0)
    return;
  this->length_ += length;
  if (this->used_ > 0) {
    const size_t take = length < sizeof(this->buffer_) - this->used_ ? length : sizeof(this->buffer_) - this->used_;
    std::memcpy(this->buffer_ + this->used_, data, take);
    this->used_ += take;
    data += take;
    length -= take;
    if (this->used_ < sizeof(this->buffer_))
      return;
    this->process_block_(this->buffer_);
    this->used_ = 0;
  }
  for (; length >= sizeof(this->buffer_); data += sizeof(this->buffer_), length -= sizeof(this->buffer_))
    this->process_block_(data);
  std::memcpy(this->buffer_, data, length);
  this->used_ = length;
}

void Sha512::finish(uint8_t *digest) {
  const uint64_t bits = this->length_ * 8;
  this->buffer_[this->used_++] = 0x80;
  if (this->used_ > 112) {
    std::memset(this->buffer_ + this->used_, 0, sizeof(this->buffer_) - this->used_);
    this->process_block_(this->buffer_);
    this->used_ = 0;
  }
  // The length takes 16 bytes; its upper 8 are always zero here
  std::memset(this->buffer_ + this->used_, 0, 120 - this->used_);
  store_be64(this->buffer_ + 120, bits);
  this->process_block_(this->buffer_);
  for (int i = 0; i < 8; i++)
    store_be64(digest + 8 * i, this->state_[i]);
}

void sha512(const uint8_t *data, size_t length, uint8_t *digest) {
  Sha512 hash;
  hash.update(data, length);
  hash.finish(digest);
}

// ===== HMAC and HKDF =====

static constexpr size_t SHA512_BLOCK_SIZE = 128;

void hmac_sha512(const uint8_t *key, size_t key_length, const uint8_t *data, size_t length, uint8_t *mac) {
  uint8_t pad[SHA512_BLOCK_SIZE] = {};
  if (key_length > SHA512_BLOCK_SIZE) {
    sha512(key, key_length, pad);
  } else if (key_length > 0) {
    std::memcpy(pad, key, key_length);
  }
  for (uint8_t &byte : pad)
    byte ^= 0x36;
  uint8_t inner[SHA512_SIZE];
  Sha512 hash;
  hash.update(pad, sizeof(pad));
  hash.update(data, length);
  hash.finish(inner);

  for (uint8_t &byte : pad)
    byte ^= 0x36 ^ 0x5c;
  Sha512 outer;
  outer.update(pad, sizeof(pad));
  outer.update(inner, sizeof(inner));
  outer.finish(mac);
}

void hkdf_sha512(const uint8_t *salt, size_t salt_length, const uint8_t *secret, size_t secret_length,
                 const uint8_t *info, size_t info_length, uint8_t *output, size_t output_length) {
  uint8_t prk[SHA512_SIZE];
  hmac_sha512(salt, salt_length, secret, secret_length, prk);

  // T(i) = HMAC(PRK, T(i-1) | info | i)
  uint8_t block[SHA512_SIZE];
  size_t block_length = 0;
  for (uint8_t counter = 1; output_length > 0; counter++) {
    uint8_t pad[SHA512_BLOCK_SIZE];
    std::memcpy(pad, prk, sizeof(prk));
    std::memset(pad + sizeof(prk), 0, sizeof(pad) - sizeof(prk));
    for (uint8_t &byte : pad)
      byte ^= 0x36;
    uint8_t inner[SHA512_SIZE];
    Sha512 hash;
    hash.update(pad, sizeof(pad));
    hash.update(block, block_length);
    hash.update(info, info_length);
    hash.update(&counter, 1);
    hash.finish(inner);
    for (uint8_t &byte : pad)
      byte ^= 0x36 ^ 0x5c;
    Sha512 outer;
    outer.update(pad, sizeof(pad));
    outer.update(inner, sizeof(inner));
    outer.finish(block);
    block_length = sizeof(block);

    const size_t take = output_length < sizeof(block) ? output_length : sizeof(block);
    std::memcpy(output, block, take);
    output += take;
    output_length -= take;
  }
}

void hkdf_sha512_key(const char *salt, const char *info, const uint8_t *secret, size_t secret_length, uint8_t *key) {
  hkdf_sha512(reinterpret_cast<const uint8_t *>(salt), std::strlen(salt), secret, secret_length,
              reinterpret_cast<const uint8_t *>(info), std::strlen(info), key, CHACHA_KEY_SIZE);
}

// ===== ChaCha20 =====

static inline uint32_t load_le32(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

static inline void store_le32(uint8_t *p, uint32_t value) {
  p[0] = static_cast<uint8_t>(value);
  p[1] = static_cast<uint8_t>(value >> 8);
  p[2] = static_cast<uint8_t>(value >> 16);
  p[3] = static_cast<uint8_t>(value >> 24);
}

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static inline void quarter_round(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
  a += b;
  d = rotl32(d ^ a, 16);
  c += d;
  b = rotl32(b ^ c, 12);
  a += b;
  d = rotl32(d ^ a, 8);
  c += d;
  b = rotl32(b ^ c, 7);
}

static void chacha20_block(const uint32_t *input, uint8_t *output) {
  uint32_t x[16];
  std::memcpy(x, input, sizeof(x));
  for (int i = 0; i < 10; i++) {
    quarter_round(x[0], x[4], x[8], x[12]);
    quarter_round(x[1], x[5], x[9], x[13]);
    quarter_round(x[2], x[6], x[10], x[14]);
    quarter_round(x[3], x[7], x[11], x[15]);
    quarter_round(x[0], x[5], x[10], x[15]);
    quarter_round(x[1], x[6], x[11], x[12]);
    quarter_round(x[2], x[7], x[8], x[13]);
    quarter_round(x[3], x[4], x[9], x[14]);
  }
  for (int i = 0; i < 16; i++)
    store_le32(output + 4 * i, x[i] + input[i]);
}

static void chacha20_init(uint32_t *state, const uint8_t *key, const uint8_t *nonce, uint32_t counter) {
  state[0] = 0x61707865;  // "expand 32-byte k"
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  for (int i = 0; i < 8; i++)
    state[4 + i] = load_le32(key + 4 * i);
  state[12] = counter;
  for (int i = 0; i < 3; i++)
    state[13 + i] = load_le32(nonce + 4 * i);
}

static void chacha20_xor(uint32_t *state, const uint8_t *input, uint8_t *output, size_t length) {
  uint8_t stream[64];
  while (length > 0) {
    chacha20_block(state, stream);
    state[12]++;
    const size_t take = length < sizeof(stream) ? length : sizeof(stream);
    for (size_t i = 0; i < take; i++)
      output[i] = input[i] ^ stream[i];
    input += take;
    output += take;
    length -= take;
  }
}

// ===== Poly1305 =====

/// Poly1305 over 16 byte blocks, with a short last piece padded with zeros as the AEAD construction pads it.
/// 26 bit limbs, as in poly1305-donna.
class Poly1305 {
 public:
  explicit Poly1305(const uint8_t *key) {
    this->r_[0] = load_le32(key) & 0x3ffffff;
    this->r_[1] = (load_le32(key + 3) >> 2) & 0x3ffff03;
    this->r_[2] = (load_le32(key + 6) >> 4) & 0x3ffc0ff;
    this->r_[3] = (load_le32(key + 9) >> 6) & 0x3f03fff;
    this->r_[4] = (load_le32(key + 12) >> 8) & 0x00fffff;
    for (int i = 0; i < 4; i++)
      this->pad_[i] = load_le32(key + 16 + 4 * i);
  }

  /// Authenticates the data followed by zeros up to a multiple of 16 bytes
  void update_padded(const uint8_t *data, size_t length) {
    for (; length >= 16; data += 16, length -= 16)
      this->block_(data);
    if (length > 0) {
      uint8_t block[16] = {};
      std::memcpy(block, data, length);
      this->block_(block);
    }
  }

  void finish(uint8_t *tag) {
    uint32_t h0 = this->h_[0], h1 = this->h_[1], h2 = this->h_[2], h3 = this->h_[3], h4 = this->h_[4];
    uint32_t c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    // h - p, used if it does not go negative
    uint32_t g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1UL << 26);
    uint32_t mask = (g4 >> 31) - 1;  // All ones if h >= p
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    const uint32_t w0 = h0 | (h1 << 26);
    const uint32_t w1 = (h1 >> 6) | (h2 << 20);
    const uint32_t w2 = (h2 >> 12) | (h3 << 14);
    const uint32_t w3 = (h3 >> 18) | (h4 << 8);
    uint64_t f = static_cast<uint64_t>(w0) + this->pad_[0];
    store_le32(tag, static_cast<uint32_t>(f));
    f = static_cast<uint64_t>(w1) + this->pad_[1] + (f >> 32);
    store_le32(tag + 4, static_cast<uint32_t>(f));
    f = static_cast<uint64_t>(w2) + this->pad_[2] + (f >> 32);
    store_le32(tag + 8, static_cast<uint32_t>(f));
    f = static_cast<uint64_t>(w3) + this->pad_[3] + (f >> 32);
    store_le32(tag + 12, static_cast<uint32_t>(f));
  }

 private:
  void block_(const uint8_t *m) {
    const uint32_t r0 = this->r_[0], r1 = this->r_[1], r2 = this->r_[2], r3 = this->r_[3], r4 = this->r_[4];
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = this->h_[0] + (load_le32(m) & 0x3ffffff);
    uint32_t h1 = this->h_[1] + ((load_le32(m + 3) >> 2) & 0x3ffffff);
    uint32_t h2 = this->h_[2] + ((load_le32(m + 6) >> 4) & 0x3ffffff);
    uint32_t h3 = this->h_[3] + ((load_le32(m + 9) >> 6) & 0x3ffffff);
    uint32_t h4 = this->h_[4] + ((load_le32(m + 12) >> 8) | (1UL << 24));

    using u64 = uint64_t;
    const u64 d0 = (u64) h0 * r0 + (u64) h1 * s4 + (u64) h2 * s3 + (u64) h3 * s2 + (u64) h4 * s1;
    u64 d1 = (u64) h0 * r1 + (u64) h1 * r0 + (u64) h2 * s4 + (u64) h3 * s3 + (u64) h4 * s2;
    u64 d2 = (u64) h0 * r2 + (u64) h1 * r1 + (u64) h2 * r0 + (u64) h3 * s4 + (u64) h4 * s3;
    u64 d3 = (u64) h0 * r3 + (u64) h1 * r2 + (u64) h2 * r1 + (u64) h3 * r0 + (u64) h4 * s4;
    u64 d4 = (u64) h0 * r4 + (u64) h1 * r3 + (u64) h2 * r2 + (u64) h3 * r1 + (u64) h4 * r0;

    uint32_t c = static_cast<uint32_t>(d0 >> 26);
    h0 = static_cast<uint32_t>(d0) & 0x3ffffff;
    d1 += c;
    c = static_cast<uint32_t>(d1 >> 26);
    h1 = static_cast<uint32_t>(d1) & 0x3ffffff;
    d2 += c;
    c = static_cast<uint32_t>(d2 >> 26);
    h2 = static_cast<uint32_t>(d2) & 0x3ffffff;
    d3 += c;
    c = static_cast<uint32_t>(d3 >> 26);
    h3 = static_cast<uint32_t>(d3) & 0x3ffffff;
    d4 += c;
    c = static_cast<uint32_t>(d4 >> 26);
    h4 = static_cast<uint32_t>(d4) & 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    this->h_[0] = h0;
    this->h_[1] = h1;
    this->h_[2] = h2;
    this->h_[3] = h3;
    this->h_[4] = h4;
  }

  uint32_t r_[5];
  uint32_t h_[5]{};
  uint32_t pad_[4];
};

// ===== ChaCha20-Poly1305 =====

static void aead_tag(uint32_t *state, const uint8_t *aad, size_t aad_length, const uint8_t *ciphertext, size_t length,
                     uint8_t *tag) {
  // The Poly1305 key is the first half of block 0
  uint8_t block[64];
  state[12] = 0;
  chacha20_block(state, block);
  Poly1305 mac(block);
  mac.update_padded(aad, aad_length);
  mac.update_padded(ciphertext, length);
  uint8_t lengths[16];
  store_le32(lengths, static_cast<uint32_t>(aad_length));
  store_le32(lengths + 4, static_cast<uint32_t>(static_cast<uint64_t>(aad_length) >> 32));
  store_le32(lengths + 8, static_cast<uint32_t>(length));
  store_le32(lengths + 12, static_cast<uint32_t>(static_cast<uint64_t>(length) >> 32));
  mac.update_padded(lengths, sizeof(lengths));
  mac.finish(tag);
}

void chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_length,
                               const uint8_t *input, size_t length, uint8_t *output, uint8_t *tag) {
  uint32_t state[16];
  chacha20_init(state, key, nonce, 1);
  chacha20_xor(state, input, output, length);
  aead_tag(state, aad, aad_length, output, length, tag);
}

bool chacha20_poly1305_decrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad, size_t aad_length,
                               const uint8_t *input, size_t length, const uint8_t *tag, uint8_t *output) {
  uint32_t state[16];
  chacha20_init(state, key, nonce, 0);
  uint8_t expected[POLY1305_TAG_SIZE];
  aead_tag(state, aad, aad_length, input, length, expected);
  if (!equal_constant_time(expected, tag, sizeof(expected)))
    return false;
  state[12] = 1;
  chacha20_xor(state, input, output, length);
  return true;
}

bool equal_constant_time(const uint8_t *a, const uint8_t *b, size_t length) {
  uint8_t difference = 0;
  for (size_t i = 0; i < length; i++)
    difference |= a[i] ^ b[i];
  return difference == 0;
}

}  // namespace airplay
