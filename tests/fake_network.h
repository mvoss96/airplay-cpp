#pragma once

// Test doubles for the receiver's interfaces and helpers that play the sender's part.

#include "airplay_receiver.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

namespace test {

using namespace airplay;

struct UdpSent {
  UdpChannel channel;
  Endpoint to;
  std::vector<uint8_t> data;
};

class FakeTransport : public Transport {
 public:
  bool send(uint8_t connection, const uint8_t *data, size_t length) override {
    this->sent[connection].append(reinterpret_cast<const char *>(data), length);
    return this->send_ok;
  }
  void close(uint8_t connection) override { this->closed[connection]++; }
  void pause_receiving(uint8_t connection, bool paused) override { this->paused[connection] = paused; }
  bool open_udp(uint16_t *ports) override {
    if (!this->udp_ok)
      return false;
    ports[0] = 6000;
    ports[1] = 6001;
    ports[2] = 6002;
    this->udp_open = true;
    return true;
  }
  void close_udp() override { this->udp_open = false; }
  void send_udp(UdpChannel channel, const Endpoint &to, const uint8_t *data, size_t length) override {
    this->udp.push_back(UdpSent{channel, to, std::vector<uint8_t>(data, data + length)});
  }

  /// Returns and clears what was sent on a connection
  std::string take(uint8_t connection) {
    std::string result;
    result.swap(this->sent[connection]);
    return result;
  }

  std::string sent[Receiver::MAX_CONNECTIONS];
  int closed[Receiver::MAX_CONNECTIONS]{};
  bool paused[Receiver::MAX_CONNECTIONS]{};
  std::vector<UdpSent> udp;
  bool udp_open{false};
  bool send_ok{true};
  bool udp_ok{true};
};

/// An output with a fixed capacity that plays at its own clock and reports what it played
class FakeSink : public AudioSink {
 public:
  explicit FakeSink(size_t capacity_frames) : capacity(capacity_frames) {}
  size_t write(const int16_t *samples, size_t frames) override {
    const size_t accepted = std::min(frames, this->capacity - std::min(this->capacity, this->queue.size()));
    for (size_t i = 0; i < accepted; i++)
      this->queue.emplace_back(samples[2 * i], samples[2 * i + 1]);
    return accepted;
  }
  /// Plays one frame; returns false on underrun
  bool play(std::pair<int16_t, int16_t> *frame) {
    if (this->queue.empty())
      return false;
    *frame = this->queue.front();
    this->queue.pop_front();
    return true;
  }

  size_t capacity;
  std::deque<std::pair<int16_t, int16_t>> queue;
};

class RecordingListener : public Listener {
 public:
  void on_session_state(SessionState state) override { this->states.push_back(state); }
  void on_volume(float value) override { this->volumes.push_back(value); }
  void on_mute(bool value) override { this->mutes.push_back(value); }
  void on_metadata(const Metadata &value) override {
    this->metadata = value;
    this->metadata_count++;
  }
  void on_remote_target(const RemoteTarget &value) override {
    this->remote = value;
    this->remote_count++;
  }
  bool on_artwork_begin(ArtworkFormat format, size_t size) override {
    this->artwork_format = format;
    this->artwork_size = size;
    this->artwork.clear();
    this->artwork_begins++;
    return size <= this->artwork_limit;
  }
  void on_artwork_data(const uint8_t *data, size_t length) override {
    this->artwork.append(data, data + length);
    this->artwork_peak = std::max(this->artwork_peak, this->artwork.size() - this->artwork_used);
  }
  size_t artwork_room() override {
    return this->artwork_capacity - std::min(this->artwork_capacity, this->artwork.size() - this->artwork_used);
  }
  void on_artwork_end(bool complete) override {
    this->artwork_ends++;
    this->artwork_complete = complete;
  }
  void on_artwork_clear() override { this->artwork_clears++; }
  void on_progress(const Progress &value) override {
    this->progress = value;
    this->progress_count++;
  }
  SessionState last_state() const { return this->states.empty() ? SessionState::NONE : this->states.back(); }

  std::vector<SessionState> states;
  std::vector<float> volumes;
  std::vector<bool> mutes;
  Metadata metadata{};
  int metadata_count{0};
  RemoteTarget remote{};
  int remote_count{0};
  size_t artwork_limit{100000};
  ArtworkFormat artwork_format{ArtworkFormat::JPEG};
  size_t artwork_size{0};
  std::string artwork;
  int artwork_begins{0};
  int artwork_ends{0};
  int artwork_clears{0};
  bool artwork_complete{false};
  // A buffer that a decoder empties as artwork_used grows; unlimited unless set
  size_t artwork_capacity{SIZE_MAX};
  size_t artwork_used{0};
  size_t artwork_peak{0};
  Progress progress{};
  int progress_count{0};
};

/// Crypto for unencrypted streams
class NoCrypto : public Crypto {
 public:
  bool sign_challenge(const uint8_t *, size_t, uint8_t *signature) override {
    std::memset(signature, 0, RSA_SIGNATURE_SIZE);
    return true;
  }
  bool decrypt_session_key(const uint8_t *, size_t, uint8_t *) override { return false; }
  bool set_audio_key(const uint8_t *) override { return false; }
  bool decrypt_audio(uint8_t *, const uint8_t *, uint8_t *, size_t) override { return false; }
};

inline uint32_t ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  uint32_t address;
  const uint8_t bytes[4] = {a, b, c, d};
  std::memcpy(&address, bytes, 4);
  return address;
}

inline std::string rtsp_request(const char *method, int cseq, const std::string &headers = "",
                                const std::string &body = "") {
  std::string request =
      std::string(method) + " rtsp://192.168.1.10/1234 RTSP/1.0\r\nCSeq: " + std::to_string(cseq) + "\r\n" + headers;
  if (!body.empty())
    request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  return request + "\r\n" + body;
}

inline void send_request(Receiver &receiver, uint8_t connection, const std::string &request, int64_t now_us) {
  receiver.connection_data(connection, reinterpret_cast<const uint8_t *>(request.data()), request.size(), now_us);
}

inline std::string header_value(const std::string &response, const char *name) {
  const std::string key = std::string("\r\n") + name + ": ";
  const size_t start = response.find(key);
  if (start == std::string::npos)
    return "";
  const size_t value = start + key.size();
  return response.substr(value, response.find("\r\n", value) - value);
}

inline int status_code(const std::string &response) {
  return response.compare(0, 9, "RTSP/1.0 ") == 0 ? std::atoi(response.c_str() + 9) : 0;
}

inline void put_be16(uint8_t *p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v >> 8);
  p[1] = static_cast<uint8_t>(v);
}

inline void put_be32(uint8_t *p, uint32_t v) {
  p[0] = static_cast<uint8_t>(v >> 24);
  p[1] = static_cast<uint8_t>(v >> 16);
  p[2] = static_cast<uint8_t>(v >> 8);
  p[3] = static_cast<uint8_t>(v);
}

inline void put_ntp(uint8_t *p, int64_t ns) {
  const auto v = static_cast<uint64_t>(ns);
  put_be32(p, static_cast<uint32_t>(v / 1000000000ULL));
  put_be32(p + 4, static_cast<uint32_t>(((v % 1000000000ULL) << 32) / 1000000000ULL));
}

/// PCM payload in which every frame carries its RTP timestamp, so the output can tell what it plays
inline std::vector<uint8_t> marked_pcm(uint32_t rtp, uint32_t frames = FRAMES_PER_PACKET) {
  std::vector<uint8_t> payload(frames * 4);
  for (uint32_t i = 0; i < frames; i++) {
    const uint32_t r = rtp + i;
    put_be16(&payload[4 * i], static_cast<uint16_t>(r & 0x7fff));
    put_be16(&payload[4 * i + 2], static_cast<uint16_t>(((r >> 15) & 0x7fff) | 0x4000));  // Never silent
  }
  return payload;
}

inline uint32_t marked_rtp(std::pair<int16_t, int16_t> frame) {
  return (static_cast<uint32_t>(static_cast<uint16_t>(frame.first)) & 0x7fff) |
         ((static_cast<uint32_t>(static_cast<uint16_t>(frame.second)) & 0x3fff) << 15);
}

inline std::vector<uint8_t> rtp_packet(uint8_t type, uint16_t seq, uint32_t rtp, const std::vector<uint8_t> &payload,
                                       bool marker = false) {
  std::vector<uint8_t> packet(12 + payload.size());
  packet[0] = 0x80;
  packet[1] = static_cast<uint8_t>(type | (marker ? 0x80 : 0));
  put_be16(&packet[2], seq);
  put_be32(&packet[4], rtp);
  put_be32(&packet[8], 0x12345678);
  std::memcpy(packet.data() + 12, payload.data(), payload.size());
  return packet;
}

inline const char *const PCM_SDP =
    "v=0\r\no=iTunes 1 0 IN IP4 192.168.1.20\r\ns=iTunes\r\nc=IN IP4 192.168.1.10\r\nt=0 0\r\n"
    "m=audio 0 RTP/AVP 96\r\na=rtpmap:96 L16/44100/2\r\n";

}  // namespace test
