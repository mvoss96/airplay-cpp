#include "airplay_srp.h"

#include <cstring>

namespace airplay {

// The 3072-bit prime of RFC 5054, least significant 32 bits first. The generator is 5.
static const uint32_t PRIME[SRP_KEY_SIZE / 4] = {
    0xffffffff, 0xffffffff, 0xa93ad2ca, 0x4b82d120, 0xe0fd108e, 0x43db5bfc, 0x74e5ab31, 0x08e24fa0, 0xbad946e2,
    0x770988c0, 0x7a615d6c, 0xbbe11757, 0x177b200c, 0x521f2b18, 0x3ec86a64, 0xd8760273, 0xd98a0864, 0xf12ffa06,
    0x1ad2ee6b, 0xcee3d226, 0x4a25619d, 0x1e8c94e0, 0xdb0933d7, 0xabf5ae8c, 0xa6e1e4c7, 0xb3970f85, 0x5d060c7d,
    0x8aea7157, 0x58dbef0a, 0xecfb8504, 0xdf1cba64, 0xa85521ab, 0x04507a33, 0xad33170d, 0x8aaac42d, 0x15728e5a,
    0x98fa0510, 0x15d22618, 0xea956ae5, 0x3995497c, 0x95581718, 0xde2bcbf6, 0x6f4c52c9, 0xb5c55df0, 0xec07a28f,
    0x9b2783a2, 0x180e8603, 0xe39e772c, 0x2e36ce3b, 0x32905e46, 0xca18217c, 0xf1746c08, 0x4abc9804, 0x670c354e,
    0x7096966d, 0x9ed52907, 0x208552bb, 0x1c62f356, 0xdca3ad96, 0x83655d23, 0xfd24cf5f, 0x69163fa8, 0x1c55d39a,
    0x98da4836, 0xa163bf05, 0xc2007cb8, 0xece45b3d, 0x49286651, 0x7c4b1fe6, 0xae9f2411, 0x5a899fa5, 0xee386bfb,
    0xf406b7ed, 0x0bff5cb6, 0xa637ed6b, 0xf44c42e9, 0x625e7ec6, 0xe485b576, 0x6d51c245, 0x4fe1356d, 0xf25f1437,
    0x302b0a6d, 0xcd3a431b, 0xef9519b3, 0x8e3404dd, 0x514a0879, 0x3b139b22, 0x020bbea6, 0x8a67cc74, 0x29024e08,
    0x80dc1cd1, 0xc4c6628b, 0x2168c234, 0xc90fdaa2, 0xffffffff, 0xffffffff,
};
static constexpr uint32_t GENERATOR = 5;

/// Hashes a number as SRP_KEY_SIZE big endian bytes
static void hash_padded(Sha512 &hash, const uint32_t *limbs, size_t count) {
  uint8_t bytes[4];
  for (size_t i = count; i-- > 0;) {
    bytes[0] = static_cast<uint8_t>(limbs[i] >> 24);
    bytes[1] = static_cast<uint8_t>(limbs[i] >> 16);
    bytes[2] = static_cast<uint8_t>(limbs[i] >> 8);
    bytes[3] = static_cast<uint8_t>(limbs[i]);
    hash.update(bytes, sizeof(bytes));
  }
}

/// Skips leading zero bytes: the shortest form, in which SRP hashes most numbers
static const uint8_t *shortest(const uint8_t *bytes, size_t &length) {
  while (length > 1 && bytes[0] == 0) {
    bytes++;
    length--;
  }
  return bytes;
}

template<size_t N> static void from_bytes(uint32_t (&limbs)[N], const uint8_t *bytes, size_t length) {
  std::memset(limbs, 0, sizeof(limbs));
  for (size_t i = 0; i < length; i++) {
    const size_t position = length - 1 - i;  // Byte position counted from the least significant end
    limbs[position / 4] |= static_cast<uint32_t>(bytes[i]) << (8 * (position % 4));
  }
}

template<size_t N> static void to_bytes(const uint32_t (&limbs)[N], uint8_t *bytes) {
  for (size_t i = 0; i < N; i++) {
    const uint32_t limb = limbs[N - 1 - i];
    bytes[4 * i] = static_cast<uint8_t>(limb >> 24);
    bytes[4 * i + 1] = static_cast<uint8_t>(limb >> 16);
    bytes[4 * i + 2] = static_cast<uint8_t>(limb >> 8);
    bytes[4 * i + 3] = static_cast<uint8_t>(limb);
  }
}

/// a >= the prime
static bool at_least_prime(const uint32_t *a) {
  for (size_t i = SRP_KEY_SIZE / 4; i-- > 0;) {
    if (a[i] != PRIME[i])
      return a[i] > PRIME[i];
  }
  return true;
}

/// a -= the prime, ignoring a borrow out of the top
static void subtract_prime(uint32_t *a) {
  uint64_t borrow = 0;
  for (size_t i = 0; i < SRP_KEY_SIZE / 4; i++) {
    const uint64_t difference = static_cast<uint64_t>(a[i]) - PRIME[i] - borrow;
    a[i] = static_cast<uint32_t>(difference);
    borrow = (difference >> 32) & 1;
  }
}

void SrpServer::init_() {
  // -1/N mod 2^32 by Newton's iteration; each step doubles the correct bits
  uint32_t inverse = 1;
  for (int i = 0; i < 5; i++)
    inverse *= 2 - PRIME[0] * inverse;
  this->n0_inverse_ = 0 - inverse;

  // 2^3072 mod N is 2^3072 - N, as the prime's top bit is set; 3072 doublings make it 2^6144 mod N
  uint32_t *r = this->r2_.limb;
  std::memset(r, 0, sizeof(this->r2_.limb));
  subtract_prime(r);
  for (size_t bit = 0; bit < SRP_KEY_SIZE * 8; bit++) {
    uint32_t carry = 0;
    for (size_t i = 0; i < LIMBS; i++) {
      const uint32_t next = r[i] >> 31;
      r[i] = (r[i] << 1) | carry;
      carry = next;
    }
    if (carry != 0 || at_least_prime(r))
      subtract_prime(r);
  }
}

void SrpServer::mont_mul_(Number &out, const Number &a, const Number &b) {
  // Coarsely integrated operand scanning (CIOS)
  uint32_t *t = this->product_;
  std::memset(t, 0, sizeof(this->product_));
  for (size_t i = 0; i < LIMBS; i++) {
    uint64_t carry = 0;
    const uint64_t bi = b.limb[i];
    for (size_t j = 0; j < LIMBS; j++) {
      const uint64_t sum = t[j] + a.limb[j] * bi + carry;
      t[j] = static_cast<uint32_t>(sum);
      carry = sum >> 32;
    }
    uint64_t sum = t[LIMBS] + carry;
    t[LIMBS] = static_cast<uint32_t>(sum);
    t[LIMBS + 1] = static_cast<uint32_t>(sum >> 32);

    const uint64_t m = static_cast<uint32_t>(t[0] * this->n0_inverse_);
    carry = (t[0] + m * PRIME[0]) >> 32;
    for (size_t j = 1; j < LIMBS; j++) {
      sum = t[j] + m * PRIME[j] + carry;
      t[j - 1] = static_cast<uint32_t>(sum);
      carry = sum >> 32;
    }
    sum = t[LIMBS] + carry;
    t[LIMBS - 1] = static_cast<uint32_t>(sum);
    t[LIMBS] = t[LIMBS + 1] + static_cast<uint32_t>(sum >> 32);
  }
  if (t[LIMBS] != 0 || at_least_prime(t))
    subtract_prime(t);
  std::memcpy(out.limb, t, sizeof(out.limb));
}

void SrpServer::mod_pow_(Number &out, const Number &base, const uint8_t *exponent, size_t exponent_length) {
  // Square and multiply, from the top bit, in Montgomery form
  std::memset(out.limb, 0, sizeof(out.limb));
  out.limb[0] = 1;
  this->mont_mul_(out, out, this->r2_);
  for (size_t i = 0; i < exponent_length; i++) {
    for (int bit = 7; bit >= 0; bit--) {
      this->mont_mul_(out, out, out);
      if ((exponent[i] >> bit) & 1)
        this->mont_mul_(out, out, base);
    }
  }
}

void SrpServer::begin(const char *username, const char *password, const uint8_t *salt, const uint8_t *secret) {
  this->init_();
  std::memcpy(this->salt_, salt, SRP_SALT_SIZE);
  if (this->salt_[0] == 0)
    this->salt_[0] = 1;
  std::memcpy(this->secret_, secret, SRP_SECRET_SIZE);
  sha512(reinterpret_cast<const uint8_t *>(username), std::strlen(username), this->username_hash_);

  // x = H(salt | H(username ":" password)), v = g^x
  uint8_t digest[SHA512_SIZE];
  Sha512 credentials;
  credentials.update(reinterpret_cast<const uint8_t *>(username), std::strlen(username));
  credentials.update(reinterpret_cast<const uint8_t *>(":"), 1);
  credentials.update(reinterpret_cast<const uint8_t *>(password), std::strlen(password));
  credentials.finish(digest);
  Sha512 x_hash;
  x_hash.update(this->salt_, sizeof(this->salt_));
  x_hash.update(digest, sizeof(digest));
  x_hash.finish(digest);

  Number &generator = this->work_[0];
  std::memset(generator.limb, 0, sizeof(generator.limb));
  generator.limb[0] = GENERATOR;
  this->mont_mul_(generator, generator, this->r2_);
  this->mod_pow_(this->verifier_, generator, digest, sizeof(digest));

  // k = H(N | PAD(g))
  Sha512 k_hash;
  hash_padded(k_hash, PRIME, LIMBS);
  uint32_t padded_generator[LIMBS] = {GENERATOR};
  hash_padded(k_hash, padded_generator, LIMBS);
  k_hash.finish(digest);

  // B = k * v + g^b
  Number &public_key = this->work_[1];
  from_bytes(public_key.limb, digest, sizeof(digest));
  this->mont_mul_(public_key, public_key, this->r2_);
  this->mont_mul_(public_key, public_key, this->verifier_);
  Number &power = this->work_[2];
  this->mod_pow_(power, generator, this->secret_, sizeof(this->secret_));
  uint64_t carry = 0;
  for (size_t i = 0; i < LIMBS; i++) {
    const uint64_t sum = static_cast<uint64_t>(public_key.limb[i]) + power.limb[i] + carry;
    public_key.limb[i] = static_cast<uint32_t>(sum);
    carry = sum >> 32;
  }
  if (carry != 0 || at_least_prime(public_key.limb))
    subtract_prime(public_key.limb);
  Number &one = this->work_[2];
  std::memset(one.limb, 0, sizeof(one.limb));
  one.limb[0] = 1;
  this->mont_mul_(public_key, public_key, one);
  to_bytes(public_key.limb, this->public_key_);
}

bool SrpServer::verify(const uint8_t *client_key, size_t client_key_length, const uint8_t *client_proof,
                       size_t client_proof_length, uint8_t *server_proof) {
  if (client_key_length == 0 || client_key_length > SRP_KEY_SIZE || client_proof_length != SHA512_SIZE)
    return false;
  // A must be below the prime and not 0 (mod N), or the session key would be predictable
  Number &a = this->work_[0];
  from_bytes(a.limb, client_key, client_key_length);
  bool zero = true;
  for (uint32_t limb : a.limb)
    zero = zero && limb == 0;
  if (zero || at_least_prime(a.limb))
    return false;
  size_t a_length = client_key_length;
  const uint8_t *a_bytes = shortest(client_key, a_length);

  // u = H(PAD(A) | PAD(B))
  uint8_t u[SHA512_SIZE];
  Sha512 u_hash;
  hash_padded(u_hash, a.limb, LIMBS);
  u_hash.update(this->public_key_, sizeof(this->public_key_));
  u_hash.finish(u);

  // S = (A * v^u)^b, K = H(S)
  this->mont_mul_(a, a, this->r2_);
  Number &base = this->work_[1];
  this->mod_pow_(base, this->verifier_, u, sizeof(u));
  this->mont_mul_(base, base, a);
  Number &shared = this->work_[2];
  this->mod_pow_(shared, base, this->secret_, sizeof(this->secret_));
  Number &one = this->work_[0];
  std::memset(one.limb, 0, sizeof(one.limb));
  one.limb[0] = 1;
  this->mont_mul_(shared, shared, one);
  uint8_t shared_bytes[SRP_KEY_SIZE];
  to_bytes(shared.limb, shared_bytes);
  size_t shared_length = sizeof(shared_bytes);
  const uint8_t *shared_shortest = shortest(shared_bytes, shared_length);
  sha512(shared_shortest, shared_length, this->session_key_);

  // M1 = H(H(N) xor H(g) | H(username) | salt | A | B | K)
  uint8_t prime_hash[SHA512_SIZE];
  Sha512 n_hash;
  hash_padded(n_hash, PRIME, LIMBS);
  n_hash.finish(prime_hash);
  const uint8_t generator = GENERATOR;
  uint8_t generator_hash[SHA512_SIZE];
  sha512(&generator, 1, generator_hash);
  for (size_t i = 0; i < SHA512_SIZE; i++)
    prime_hash[i] ^= generator_hash[i];
  size_t b_length = sizeof(this->public_key_);
  const uint8_t *b_bytes = shortest(this->public_key_, b_length);
  uint8_t expected[SHA512_SIZE];
  Sha512 m1_hash;
  m1_hash.update(prime_hash, sizeof(prime_hash));
  m1_hash.update(this->username_hash_, sizeof(this->username_hash_));
  m1_hash.update(this->salt_, sizeof(this->salt_));
  m1_hash.update(a_bytes, a_length);
  m1_hash.update(b_bytes, b_length);
  m1_hash.update(this->session_key_, sizeof(this->session_key_));
  m1_hash.finish(expected);
  if (!equal_constant_time(expected, client_proof, SHA512_SIZE)) {
    std::memset(this->session_key_, 0, sizeof(this->session_key_));
    return false;
  }

  // M2 = H(A | M1 | K)
  Sha512 m2_hash;
  m2_hash.update(a_bytes, a_length);
  m2_hash.update(client_proof, SHA512_SIZE);
  m2_hash.update(this->session_key_, sizeof(this->session_key_));
  m2_hash.finish(server_proof);
  return true;
}

}  // namespace airplay
