// A whole session as a sender would run it, with the real mbedTLS backend: Apple-Challenge, encrypted
// session key and audio, retransmission, flush, volume, metadata, cover art, take-over and teardown.
#include "airplay_crypto_mbedtls.h"
#include "airplay_util.h"
#include "fake_network.h"
#include "test_common.h"

#include <mbedtls/aes.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/version.h>

#include <random>

using namespace airplay;
using namespace test;

static const uint8_t MAC[6] = {0x24, 0x0a, 0xc4, 0x12, 0x34, 0x56};
static const uint32_t SENDER_IP = ipv4(192, 168, 1, 20);
static const uint32_t RECEIVER_IP = ipv4(192, 168, 1, 10);

static int random_bytes(void *, unsigned char *output, size_t length) {
  static std::mt19937 rng(42);
  for (size_t i = 0; i < length; i++)
    output[i] = static_cast<unsigned char>(rng());
  return 0;
}

/// The sender's view of the AirPort key: only the public half is used
struct SenderKey {
  SenderKey() {
    mbedtls_pk_init(&this->pk);
    const auto *pem = reinterpret_cast<const unsigned char *>(AIRPORT_PRIVATE_KEY_PEM);
#if MBEDTLS_VERSION_MAJOR >= 3
    this->ok =
        mbedtls_pk_parse_key(&this->pk, pem, AIRPORT_PRIVATE_KEY_PEM_SIZE, nullptr, 0, random_bytes, nullptr) == 0;
#else
    this->ok = mbedtls_pk_parse_key(&this->pk, pem, AIRPORT_PRIVATE_KEY_PEM_SIZE, nullptr, 0) == 0;
#endif
  }
  ~SenderKey() { mbedtls_pk_free(&this->pk); }

  /// Checks a raw PKCS#1 v1.5 type 1 signature of 32 bytes
  bool verify(const uint8_t *signature, const uint8_t *expected) {
    uint8_t block[RSA_SIGNATURE_SIZE];
    if (mbedtls_rsa_public(mbedtls_pk_rsa(this->pk), signature, block) != 0)
      return false;
    static constexpr size_t DATA = 32;
    if (block[0] != 0x00 || block[1] != 0x01 || block[RSA_SIGNATURE_SIZE - DATA - 1] != 0x00)
      return false;
    for (size_t i = 2; i < RSA_SIGNATURE_SIZE - DATA - 1; i++) {
      if (block[i] != 0xff)
        return false;
    }
    return std::memcmp(block + RSA_SIGNATURE_SIZE - DATA, expected, DATA) == 0;
  }

  bool encrypt_key(const uint8_t *key, uint8_t *output) {
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(this->pk);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
#if MBEDTLS_VERSION_MAJOR >= 3
    return mbedtls_rsa_rsaes_oaep_encrypt(rsa, random_bytes, nullptr, nullptr, 0, AES_KEY_SIZE, key, output) == 0;
#else
    return mbedtls_rsa_rsaes_oaep_encrypt(rsa, random_bytes, nullptr, MBEDTLS_RSA_PUBLIC, nullptr, 0, AES_KEY_SIZE, key,
                                          output) == 0;
#endif
  }

  mbedtls_pk_context pk;
  bool ok{false};
};

static const uint8_t AES_KEY[16] = {0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
                                    0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f};
static const uint8_t AES_IV[16] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
                                   0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f};

/// Encrypts whole blocks with AES-128-CBC; the IV restarts with every packet and a partial block stays plain
static std::vector<uint8_t> encrypt_payload(const std::vector<uint8_t> &plain) {
  std::vector<uint8_t> out(plain);
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, AES_KEY, 128);
  uint8_t iv[16];
  std::memcpy(iv, AES_IV, 16);
  const size_t whole = plain.size() & ~static_cast<size_t>(15);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, whole, iv, plain.data(), out.data());
  mbedtls_aes_free(&aes);
  return out;
}

struct Fixture {
  explicit Fixture(bool metadata = true, uint32_t buffer_ms = 500, bool artwork = true, bool progress = false,
                   const char *password = nullptr)
      : sink(SAMPLE_RATE / 5),
        receiver(make_config(metadata, buffer_ms, artwork, progress, password), crypto, transport, sink, &listener) {
    CHECK(this->crypto.init());
    CHECK(this->receiver.begin());
  }
  static ReceiverConfig make_config(bool metadata, uint32_t buffer_ms, bool artwork, bool progress,
                                    const char *password) {
    ReceiverConfig config;
    config.name = "Kitchen";
    std::memcpy(config.mac, MAC, 6);
    config.metadata = metadata;
    config.artwork = artwork;
    config.progress = progress;
    config.password = password;
    config.buffer_ms = buffer_ms;
    return config;
  }
  void open(uint8_t connection) {
    this->receiver.connection_opened(connection, Endpoint{SENDER_IP, static_cast<uint16_t>(50000 + connection)},
                                     Endpoint{RECEIVER_IP, 5000});
  }
  std::string request(uint8_t connection, const char *method, const std::string &headers = "",
                      const std::string &body = "") {
    send_request(this->receiver, connection, rtsp_request(method, ++this->cseq, headers, body), this->now_us);
    return this->transport.take(connection);
  }
  /// Advances the clock in 1 ms steps; the sink plays and reports in 10 ms chunks
  void run(int64_t duration_us) {
    const int64_t end = this->now_us + duration_us;
    while (this->now_us < end) {
      this->now_us += 1000;
      this->phase += 44.1;
      while (this->phase >= 1.0) {
        this->phase -= 1.0;
        std::pair<int16_t, int16_t> frame;
        if (this->sink.play(&frame)) {
          this->played.push_back(frame);
          this->unreported++;
        } else if (!this->played.empty()) {
          this->underruns++;
        }
      }
      if (this->unreported >= 441) {
        this->receiver.notify_played(this->unreported, this->now_us);
        this->unreported = 0;
      }
      this->receiver.poll(this->now_us);
    }
  }
  void udp(UdpChannel channel, const std::vector<uint8_t> &packet) {
    this->receiver.udp_packet(channel, packet.data(), packet.size(), Endpoint{SENDER_IP, 6100}, this->now_us);
  }

  MbedtlsCrypto crypto;
  FakeTransport transport;
  FakeSink sink;
  RecordingListener listener;
  Receiver receiver;
  int cseq{0};
  int64_t now_us{1000000};
  double phase{0};
  uint32_t unreported{0};
  std::vector<std::pair<int16_t, int16_t>> played;
  uint32_t underruns{0};
};

static std::string encrypted_sdp(SenderKey &key) {
  uint8_t encrypted[RSA_SIGNATURE_SIZE];
  CHECK(key.encrypt_key(AES_KEY, encrypted));
  char rsa_text[400];
  char iv_text[32];
  base64_encode_unpadded(encrypted, sizeof(encrypted), rsa_text, sizeof(rsa_text));
  base64_encode_unpadded(AES_IV, sizeof(AES_IV), iv_text, sizeof(iv_text));
  return std::string(PCM_SDP) + "a=rsaaeskey:" + rsa_text + "\r\na=aesiv:" + iv_text + "\r\n";
}

static void test_challenge() {
  Fixture f;
  SenderKey key;
  CHECK(key.ok);
  f.open(0);
  const uint8_t challenge[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  char challenge_text[32];
  base64_encode_unpadded(challenge, sizeof(challenge), challenge_text, sizeof(challenge_text));
  const std::string response = f.request(0, "OPTIONS", std::string("Apple-Challenge: ") + challenge_text + "\r\n");
  CHECK(status_code(response) == 200);
  CHECK(response.find("Public: ANNOUNCE, SETUP, RECORD") != std::string::npos);
  CHECK(header_value(response, "CSeq") == "1");

  const std::string answer = header_value(response, "Apple-Response");
  CHECK(answer.size() == 342 && answer.find('=') == std::string::npos);  // 256 bytes, unpadded base64
  uint8_t signature[RSA_SIGNATURE_SIZE];
  CHECK(base64_decode(answer.data(), answer.size(), signature, sizeof(signature)) == RSA_SIGNATURE_SIZE);
  uint8_t expected[32] = {};
  std::memcpy(expected, challenge, 16);
  std::memcpy(expected + 16, &RECEIVER_IP, 4);
  std::memcpy(expected + 20, MAC, 6);
  CHECK(key.verify(signature, expected));
}

static void test_encrypted_session() {
  Fixture f;
  SenderKey key;
  f.open(0);

  std::string response = f.request(0, "ANNOUNCE",
                                   "Content-Type: application/sdp\r\nUser-Agent: AirPlay/381.13\r\n"
                                   "DACP-ID: A1B2C3D4E5F60718\r\nActive-Remote: 1986535575\r\n",
                                   encrypted_sdp(key));
  CHECK(status_code(response) == 200);
  CHECK(f.receiver.is_session_owner(0));
  CHECK(f.listener.remote_count == 1);
  CHECK(std::strcmp(f.listener.remote.dacp_id, "A1B2C3D4E5F60718") == 0);
  CHECK(std::strcmp(f.listener.remote.active_remote, "1986535575") == 0);
  CHECK(f.listener.remote.address == SENDER_IP);

  response = f.request(0, "SETUP",
                       "Transport: RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=6001;"
                       "timing_port=6002\r\n");
  CHECK(status_code(response) == 200);
  CHECK(header_value(response, "Transport") ==
        "RTP/AVP/UDP;unicast;mode=record;server_port=6000;control_port=6001;timing_port=6002");
  CHECK(header_value(response, "Session") == "1");
  CHECK(f.transport.udp_open);

  response = f.request(0, "RECORD", "RTP-Info: seq=100;rtptime=10000\r\nRange: npt=0-\r\n");
  CHECK(status_code(response) == 200);
  CHECK(header_value(response, "Audio-Latency") == "11025");
  CHECK(f.listener.last_state() == SessionState::PLAYING);
  CHECK(f.receiver.needs_fast_polling());

  // Sync packet: frame 10000 - 77175 is due now, so the sender's latency is 77175 + 11025 frames (2 s),
  // too much for this 500 ms buffer
  uint8_t sync[20] = {0x90, 0xd4, 0x00, 0x07};
  put_be32(sync + 4, 10000 - 77175);
  put_ntp(sync + 8, 3900000000LL * 1000000000LL);
  put_be32(sync + 16, 10000);
  f.udp(UdpChannel::CONTROL, std::vector<uint8_t>(sync, sync + 20));

  // A packet from before RECORD is ignored
  f.udp(UdpChannel::AUDIO, rtp_packet(0x60, 99, 10000 - 352, encrypt_payload(marked_pcm(10000 - 352))));

  // Packets of 351 frames leave a partial block of 12 plain bytes at the end. Packet 105 is lost and resent.
  uint32_t rtp = 10000;
  for (uint16_t seq = 100; seq < 250; seq++) {
    if (seq != 105)
      f.udp(UdpChannel::AUDIO, rtp_packet(0x60, seq, rtp, encrypt_payload(marked_pcm(rtp, 351)), seq == 100));
    rtp += 351;
    f.run(7959);  // 351 frames
    if (seq == 115) {
      // The receiver asked for 105 on the control channel
      bool asked = false;
      for (const UdpSent &sent : f.transport.udp) {
        if (sent.channel == UdpChannel::CONTROL && sent.data.size() == 8 && sent.data[1] == 0xd5 && sent.data[4] == 0 &&
            sent.data[5] == 105 && sent.data[7] == 1 && sent.to.port == 6001)
          asked = true;
      }
      CHECK(asked);
      // Retransmission: a 4 byte header and the original packet
      std::vector<uint8_t> resent = {0x80, 0xd6, 0x00, 0x01};
      const std::vector<uint8_t> original =
          rtp_packet(0x60, 105, 10000 + 5 * 351, encrypt_payload(marked_pcm(10000 + 5 * 351, 351)));
      resent.insert(resent.end(), original.begin(), original.end());
      f.udp(UdpChannel::CONTROL, resent);
    }
  }
  f.run(1000000);

  // Timing requests went to the sender's timing port
  bool timing = false;
  for (const UdpSent &sent : f.transport.udp)
    timing |= sent.channel == UdpChannel::TIMING && sent.data[1] == 0xd2 && sent.to.port == 6002;
  CHECK(timing);

  // Everything was played in order. Without the sender's clock playback is unsynchronized and may repeat or
  // drop single frames to keep the buffer level.
  CHECK(!f.played.empty());
  CHECK(f.receiver.stats().lost_packets == 0);
  CHECK(f.receiver.stats().decode_errors == 0);
  uint32_t first = 0;
  uint32_t last = 0;
  size_t steps_bad = 0;
  for (const auto &frame : f.played) {
    if (frame.first == 0 && frame.second == 0)
      continue;
    const uint32_t r = marked_rtp(frame);
    if (first == 0)
      first = r;
    else if (r - last > 2) {
      if (steps_bad++ < 5)
        std::printf("jump %u -> %u\n", last, r);
    }
    last = r;
  }
  CHECK(first == 10000);
  CHECK(last == rtp - 1);
  CHECK(steps_bad == 0);
  CHECK(f.receiver.stats().late_packets == 1);  // Packet 99
}

static void test_control() {
  Fixture f;
  f.open(0);
  CHECK(status_code(f.request(0, "ANNOUNCE", "Content-Type: application/sdp\r\n", PCM_SDP)) == 200);
  CHECK(status_code(f.request(0, "SETUP", "Transport: RTP/AVP/UDP;control_port=6001;timing_port=6002\r\n")) == 200);
  CHECK(status_code(f.request(0, "RECORD", "RTP-Info: seq=1;rtptime=0\r\n")) == 200);

  // Volume and mute
  CHECK(status_code(f.request(0, "SET_PARAMETER", "Content-Type: text/parameters\r\n", "volume: -15.000000\r\n")) ==
        200);
  CHECK(f.listener.volumes.size() == 1 && f.listener.volumes[0] == 0.5f);
  f.request(0, "SET_PARAMETER", "Content-Type: text/parameters\r\n", "volume: -144.000000\r\n");
  CHECK(f.listener.mutes.size() == 1 && f.listener.mutes[0]);
  std::string response = f.request(0, "GET_PARAMETER", "Content-Type: text/parameters\r\n", "volume\r\n");
  CHECK(response.find("\r\n\r\nvolume: -144.000000\r\n") != std::string::npos);
  CHECK(header_value(response, "Content-Length") == "21");
  f.request(0, "SET_PARAMETER", "Content-Type: text/parameters\r\n", "volume: 0.000000\r\n");
  CHECK(f.listener.volumes.size() == 2 && f.listener.volumes[1] == 1.0f);
  CHECK(f.listener.mutes.size() == 2 && !f.listener.mutes[1]);

  // Track details
  const std::string dmap = std::string("mlit\0\0\0\x1b", 8) + std::string("minm\0\0\0\x05", 8) + "Title" +
                           std::string("asar\0\0\0\x06", 8) + "Artist";
  f.request(0, "SET_PARAMETER", "Content-Type: application/x-dmap-tagged\r\n", dmap);
  CHECK(f.listener.metadata_count == 1);
  CHECK(std::strcmp(f.listener.metadata.title, "Title") == 0);
  f.request(0, "SET_PARAMETER", "Content-Type: application/x-dmap-tagged\r\n", dmap);  // Repeated: not passed on
  CHECK(f.listener.metadata_count == 1);
  CHECK(std::strcmp(f.listener.metadata.artist, "Artist") == 0);

  // Cover art larger than the buffer, sent in pieces and passed on in pieces; the next request still works
  std::string art(5000, '\0');
  for (size_t i = 0; i < art.size(); i++)
    art[i] = static_cast<char>(i * 7);
  const std::string big = rtsp_request("SET_PARAMETER", ++f.cseq, "Content-Type: image/jpeg\r\n", art);
  for (size_t i = 0; i < big.size(); i += 700)
    send_request(f.receiver, 0, big.substr(i, 700), f.now_us);
  CHECK(status_code(f.transport.take(0)) == 200);
  CHECK(f.listener.artwork_begins == 1 && f.listener.artwork_ends == 1 && f.listener.artwork_complete);
  CHECK(f.listener.artwork_format == ArtworkFormat::JPEG && f.listener.artwork_size == art.size());
  CHECK(f.listener.artwork == art);
  CHECK(status_code(f.request(0, "OPTIONS")) == 200);

  // Small cover art arrives in one piece
  f.request(0, "SET_PARAMETER", "Content-Type: image/png\r\n", "\x89PNG");
  CHECK(f.listener.artwork_begins == 2 && f.listener.artwork_ends == 2);
  CHECK(f.listener.artwork_format == ArtworkFormat::PNG && f.listener.artwork == "\x89PNG");

  // Rejected by the listener: skipped
  f.listener.artwork_limit = 1000;
  CHECK(status_code(f.request(0, "SET_PARAMETER", "Content-Type: image/jpeg\r\n", art)) == 200);
  CHECK(f.listener.artwork_begins == 3 && f.listener.artwork_ends == 2 && f.listener.artwork.empty());
  f.listener.artwork_limit = 100000;

  // No cover art for this track
  f.request(0, "SET_PARAMETER", "Content-Type: image/none\r\n");
  CHECK(f.listener.artwork_clears == 1);
  CHECK(status_code(f.request(0, "OPTIONS")) == 200);

  // A request sent one byte at a time
  const std::string slow = rtsp_request("OPTIONS", ++f.cseq);
  for (char c : slow)
    send_request(f.receiver, 0, std::string(1, c), f.now_us);
  CHECK(status_code(f.transport.take(0)) == 200);

  // Audio, then a flush pauses until audible audio arrives again
  for (uint16_t seq = 1; seq < 5; seq++)
    f.udp(UdpChannel::AUDIO, rtp_packet(0x60, seq, seq * 352, marked_pcm(seq * 352)));
  f.request(0, "FLUSH", "RTP-Info: seq=20;rtptime=7040\r\n");
  CHECK(f.listener.last_state() == SessionState::PAUSED);
  f.udp(UdpChannel::AUDIO, rtp_packet(0x60, 5, 5 * 352, marked_pcm(5 * 352)));  // Before the flush point
  CHECK(f.listener.last_state() == SessionState::PAUSED);
  f.udp(UdpChannel::AUDIO, rtp_packet(0x60, 20, 7040, std::vector<uint8_t>(1408, 0)));  // Silence
  CHECK(f.listener.last_state() == SessionState::PAUSED);
  f.udp(UdpChannel::AUDIO, rtp_packet(0x60, 21, 7392, marked_pcm(7392)));
  CHECK(f.listener.last_state() == SessionState::PLAYING);

  // A sender that stops sending shows as paused after 10 s
  f.run(11000000);
  CHECK(f.listener.last_state() == SessionState::PAUSED);

  // The sender asks for our time; the reply echoes its transmit time
  uint8_t request[32] = {0x80, 0xd2, 0x00, 0x07};
  put_ntp(request + 24, 123456789000LL);
  f.transport.udp.clear();
  f.udp(UdpChannel::TIMING, std::vector<uint8_t>(request, request + 32));
  CHECK(f.transport.udp.size() == 1);
  if (f.transport.udp.size() == 1) {
    const UdpSent &reply = f.transport.udp[0];
    CHECK(reply.channel == UdpChannel::TIMING && reply.to.port == 6100 && reply.data[1] == 0xd3);
    CHECK(std::memcmp(reply.data.data() + 8, request + 24, 8) == 0);
  }

  // Another sender takes over
  f.open(1);
  CHECK(status_code(f.request(1, "ANNOUNCE", "Content-Type: application/sdp\r\n", PCM_SDP)) == 200);
  CHECK(f.transport.closed[0] == 1);
  CHECK(f.receiver.is_session_owner(1));
  CHECK(f.listener.last_state() == SessionState::NONE);
  CHECK(!f.transport.udp_open);
  CHECK(f.listener.mutes.size() == 2);

  // Teardown closes the connection
  f.request(1, "SETUP", "Transport: RTP/AVP/UDP;control_port=6001;timing_port=6002\r\n");
  f.request(1, "RECORD");
  CHECK(f.listener.last_state() == SessionState::PLAYING);
  response = f.request(1, "TEARDOWN");
  CHECK(status_code(response) == 200);
  CHECK(header_value(response, "Connection") == "close");
  CHECK(f.transport.closed[1] == 1);
  CHECK(f.listener.last_state() == SessionState::NONE);
  CHECK(!f.transport.udp_open);
  CHECK(f.listener.metadata.title[0] == '\0');  // Cleared at the end of the session
  CHECK(f.listener.artwork_clears == 3);        // Also cleared when the first sender was taken over
}

static void test_artwork_interrupted() {
  Fixture f;
  f.open(0);
  CHECK(status_code(f.request(0, "ANNOUNCE", "Content-Type: application/sdp\r\n", PCM_SDP)) == 200);
  // The session ends half-way through a large image
  const std::string big =
      rtsp_request("SET_PARAMETER", ++f.cseq, "Content-Type: image/jpeg\r\n", std::string(9000, 'x'));
  send_request(f.receiver, 0, big.substr(0, 4000), f.now_us);
  CHECK(f.listener.artwork_begins == 1 && f.listener.artwork_ends == 0);
  f.receiver.request_disconnect();
  f.run(1000);
  CHECK(f.listener.artwork_ends == 1 && !f.listener.artwork_complete);
  CHECK(f.listener.artwork_clears == 1);

  // Disabled: not passed on
  Fixture off(true, 500, false);
  off.open(0);
  off.request(0, "ANNOUNCE", "Content-Type: application/sdp\r\n", PCM_SDP);
  off.request(0, "SET_PARAMETER", "Content-Type: image/jpeg\r\n", "abc");
  off.request(0, "SET_PARAMETER", "Content-Type: image/none\r\n");
  CHECK(off.listener.artwork_begins == 0 && off.listener.artwork_clears == 0);
}

static void test_errors_and_disconnect() {
  Fixture f(false);
  f.open(0);
  // Unsupported format
  const std::string aac = "v=0\r\nm=audio 0 RTP/AVP 96\r\na=rtpmap:96 mpeg4-generic/44100/2\r\n";
  CHECK(status_code(f.request(0, "ANNOUNCE", "Content-Type: application/sdp\r\n", aac)) == 415);
  CHECK(status_code(f.request(0, "RECORD")) == 455);
  // Encryption parameters that cannot be decrypted
  const std::string bad_key = std::string(PCM_SDP) + "a=rsaaeskey:AAAA\r\na=aesiv:AAAAAAAAAAAAAAAAAAAAAA\r\n";
  CHECK(status_code(f.request(0, "ANNOUNCE", "Content-Type: application/sdp\r\n", bad_key)) == 415);
  CHECK(status_code(f.request(0, "FOO")) == 501);
  // Track details are ignored when disabled
  f.request(0, "SET_PARAMETER", "Content-Type: application/x-dmap-tagged\r\n", std::string("minm\0\0\0\x01x", 9));
  CHECK(f.listener.metadata_count == 0);

  // UDP sockets that cannot be opened
  CHECK(status_code(f.request(0, "ANNOUNCE", "Content-Type: application/sdp\r\n", PCM_SDP)) == 200);
  f.transport.udp_ok = false;
  CHECK(status_code(f.request(0, "SETUP", "Transport: RTP/AVP/UDP;control_port=1;timing_port=2\r\n")) == 455);
  f.transport.udp_ok = true;
  CHECK(status_code(f.request(0, "SETUP", "Transport: RTP/AVP/UDP;control_port=1;timing_port=2\r\n")) == 200);
  CHECK(status_code(f.request(0, "RECORD")) == 200);

  // Only the session owner may control the session
  f.open(1);
  CHECK(status_code(f.request(1, "SETUP", "Transport: RTP/AVP/UDP;control_port=1;timing_port=2\r\n")) == 455);
  CHECK(status_code(f.request(1, "RECORD")) == 455);

  // The application ends the session
  f.receiver.request_disconnect();
  f.run(1000);
  CHECK(f.transport.closed[0] == 1);
  CHECK(f.listener.last_state() == SessionState::NONE);
  CHECK(!f.receiver.is_session_owner(0));

  // The peer closes a connection
  f.receiver.connection_closed(1);
  CHECK(f.transport.closed[1] == 0);

  // Headers larger than the buffer close the connection
  f.open(0);
  send_request(f.receiver, 0, "OPTIONS * RTSP/1.0\r\nX-Junk: " + std::string(3000, 'x'), f.now_us);
  CHECK(f.transport.closed[0] == 2);
}

/// The Authorization header a sender sends for a request
static std::string digest_authorization(const char *method, const std::string &nonce, const char *password) {
  char ha1[MD5_SIZE * 2 + 1];
  char ha2[MD5_SIZE * 2 + 1];
  char response[MD5_SIZE * 2 + 1];
  const std::string user = std::string("iTunes:raop:") + password;
  md5_hex(user.data(), user.size(), ha1);
  const std::string request = std::string(method) + ":rtsp://192.168.1.10/1234";
  md5_hex(request.data(), request.size(), ha2);
  const std::string combined = std::string(ha1) + ":" + nonce + ":" + ha2;
  md5_hex(combined.data(), combined.size(), response);
  return "Authorization: Digest username=\"iTunes\", realm=\"raop\", nonce=\"" + nonce +
         "\", uri=\"rtsp://192.168.1.10/1234\", response=\"" + response + "\"\r\n";
}

static void test_password() {
  Fixture f(true, 500, true, false, "secret");
  size_t count = 0;
  const TxtRecord *records = f.receiver.txt_records(&count);
  bool pw = false;
  for (size_t i = 0; i < count; i++)
    pw |= std::strcmp(records[i].key, "pw") == 0 && std::strcmp(records[i].value, "true") == 0;
  CHECK(pw);

  f.open(0);
  CHECK(status_code(f.request(0, "OPTIONS")) == 200);  // Needs no password
  std::string response = f.request(0, "ANNOUNCE", "Content-Type: application/sdp\r\n", PCM_SDP);
  CHECK(status_code(response) == 401);
  CHECK(!f.receiver.is_session_owner(0));
  const std::string challenge = header_value(response, "WWW-Authenticate");
  const size_t start = challenge.find("nonce=\"");
  CHECK(challenge.rfind("Digest realm=\"raop\"", 0) == 0 && start != std::string::npos);
  const std::string nonce = challenge.substr(start + 7, challenge.find('"', start + 7) - start - 7);
  CHECK(nonce.size() == 16);

  // Wrong password, then the right one
  CHECK(status_code(f.request(0, "ANNOUNCE",
                              "Content-Type: application/sdp\r\n" + digest_authorization("ANNOUNCE", nonce, "wrong"),
                              PCM_SDP)) == 401);
  CHECK(status_code(f.request(0, "ANNOUNCE",
                              "Content-Type: application/sdp\r\n" + digest_authorization("ANNOUNCE", nonce, "secret"),
                              PCM_SDP)) == 200);
  CHECK(f.receiver.is_session_owner(0));
  // The connection stays authenticated
  CHECK(status_code(f.request(0, "SETUP", "Transport: RTP/AVP/UDP;control_port=6001;timing_port=6002\r\n")) == 200);

  // A new connection gets a new nonce; the old answer does not work there
  f.open(1);
  response = f.request(
      1, "ANNOUNCE", "Content-Type: application/sdp\r\n" + digest_authorization("ANNOUNCE", nonce, "secret"), PCM_SDP);
  CHECK(status_code(response) == 401);
  CHECK(header_value(response, "WWW-Authenticate").find(nonce) == std::string::npos);
  CHECK(f.receiver.is_session_owner(0));
}

static void test_progress() {
  Fixture f(true, 500, true, true);
  size_t count = 0;
  const TxtRecord *records = f.receiver.txt_records(&count);
  CHECK(std::strcmp(records[count - 1].key, "md") == 0 && std::strcmp(records[count - 1].value, "0,1,2") == 0);
  f.open(0);
  f.request(0, "ANNOUNCE", "Content-Type: application/sdp\r\n", PCM_SDP);
  f.request(0, "SET_PARAMETER", "Content-Type: text/parameters\r\n", "progress: 1000/45100/2647000\r\n");
  CHECK(f.listener.progress_count == 1);
  CHECK(f.listener.progress.position_ms == 1000 && f.listener.progress.duration_ms == 60000);
  // RTP timestamps that wrap around
  f.request(0, "SET_PARAMETER", "Content-Type: text/parameters\r\n", "progress: 4294960000/36804/433704");
  CHECK(f.listener.progress.position_ms == 1000 && f.listener.progress.duration_ms == 10000);
  // Volume still works next to it
  f.request(0, "SET_PARAMETER", "Content-Type: text/parameters\r\n", "volume: -15.000000\r\n");
  CHECK(f.listener.volumes.size() == 1);
  // A new track: iOS repeats the previous track's progress first, which is ignored
  f.now_us += 5000000;
  const std::string first = std::string("minm\0\0\0\x05", 8) + "First";
  const std::string second = std::string("minm\0\0\0\x06", 8) + "Second";
  f.request(0, "SET_PARAMETER", "Content-Type: application/x-dmap-tagged\r\n", first);
  CHECK(f.listener.progress_count == 3 && f.listener.progress.duration_ms == 0);  // Unknown until it arrives
  f.request(0, "SET_PARAMETER", "Content-Type: text/parameters\r\n", "progress: 0/0/1323000");
  CHECK(f.listener.progress_count == 4 && f.listener.progress.duration_ms == 30000);  // Different length: taken
  f.now_us += 5000000;
  f.request(0, "SET_PARAMETER", "Content-Type: application/x-dmap-tagged\r\n", second);
  CHECK(f.listener.progress_count == 5 && f.listener.progress.duration_ms == 0);
  f.request(0, "SET_PARAMETER", "Content-Type: text/parameters\r\n", "progress: 0/0/1323000");
  CHECK(f.listener.progress_count == 5);  // The previous track's length: ignored
  f.request(0, "SET_PARAMETER", "Content-Type: text/parameters\r\n", "progress: 0/44100/882000");
  CHECK(f.listener.progress_count == 6 && f.listener.progress.duration_ms == 20000);
  // Seeking within the same track keeps working
  f.request(0, "SET_PARAMETER", "Content-Type: text/parameters\r\n", "progress: 0/441000/882000");
  CHECK(f.listener.progress_count == 7 && f.listener.progress.position_ms == 10000);
  // pyatv sends the position of a new track just before its details: it stays
  f.now_us += 5000000;
  f.request(0, "SET_PARAMETER", "Content-Type: text/parameters\r\n", "progress: 0/0/2205000");
  CHECK(f.listener.progress_count == 8 && f.listener.progress.duration_ms == 50000);
  f.request(0, "SET_PARAMETER", "Content-Type: application/x-dmap-tagged\r\n", first);
  CHECK(f.listener.progress_count == 8);

  f.request(0, "TEARDOWN");
  CHECK(f.listener.progress_count == 9 && f.listener.progress.duration_ms == 0);  // Cleared at the end
}

static void test_mdns() {
  Fixture with(true);
  char name[64];
  CHECK(with.receiver.service_instance_name(name, sizeof(name)) > 0);
  CHECK(std::strcmp(name, "240AC4123456@Kitchen") == 0);
  CHECK(with.receiver.service_instance_name(name, 10) == 0);
  size_t count = 0;
  const TxtRecord *records = with.receiver.txt_records(&count);
  CHECK(count == 17);
  CHECK(std::strcmp(records[count - 1].key, "md") == 0 && std::strcmp(records[count - 1].value, "0,1") == 0);
  Fixture text_only(true, 500, false);
  records = text_only.receiver.txt_records(&count);
  CHECK(count == 17 && std::strcmp(records[count - 1].value, "0") == 0);
  Fixture artwork_only(false, 500, true);
  records = artwork_only.receiver.txt_records(&count);
  CHECK(count == 17 && std::strcmp(records[count - 1].value, "1") == 0);
  Fixture without(false, 500, false);
  without.receiver.txt_records(&count);
  CHECK(count == 16);
}

int main() {
  test_challenge();
  test_encrypted_session();
  test_control();
  test_errors_and_disconnect();
  test_artwork_interrupted();
  test_password();
  test_progress();
  test_mdns();
  return finish("test_session");
}
