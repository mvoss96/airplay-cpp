// Simulation of a whole stream: a sender with its own clock, a network with delay, jitter, loss and stalls,
// and an output with its own clock. Checks that playback locks to the sender's timeline and stays there,
// and that unsynchronized playback keeps going without gaps.
#include "fake_network.h"
#include "test_common.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <functional>
#include <map>
#include <random>

using namespace airplay;
using namespace test;

struct Scenario {
  const char *name;
  double sender_ppm = -20;
  double output_ppm = 40;
  double loss = 0.0;         // Loss probability of every packet (audio, retransmissions, timing, sync)
  double jitter_ms = 1.0;    // Mean of an exponential extra delay
  double stall_every_s = 0;  // A network stall of stall_ms every this many seconds
  double stall_ms = 0;
  uint32_t buffer_ms = 2500;
  bool output_reports = true;
  double seek_at_s = 0;             // Flush and jump in the timeline at this time
  bool flush_after_record = false;  // Like pyatv: a FLUSH after RECORD, before any audio
  bool sync_before_record = false;  // Like pyatv: the first sync packet comes before RECORD
  int lost_first_syncs = 0;         // The first sync packets after RECORD never arrive
  double duration_s = 60;
  double measure_from_s = 8;         // Errors are measured from this time on, once playback has settled
  double output_start_delay_ms = 0;  // The output plays its first audio this long after it got it (DMA buffers)
  uint32_t report_chunk_frames = 441;
  // Limits
  bool expect_synced = true;
  double max_mean_error_ms = 5.0;  // Mean timing error (synchronized only); the servo dead band is 5 ms
  double max_abs_error_ms = 10.0;  // Largest timing error after settling (synchronized only)
  double max_silence_percent = 0.5;
  uint64_t max_discontinuities = 0;
  uint32_t max_late_packets = UINT32_MAX;
};

static constexpr int64_t NTP_EPOCH_NS = 3900000000LL * 1000000000LL;
static constexpr uint32_t SENDER_LATENCY = 77175;  // iOS; with the fixed 11025 offset 2 s
static constexpr uint32_t RTP0 = 1000000;
static const uint32_t SENDER_IP = ipv4(10, 0, 0, 2);

struct Sim : Transport {
  explicit Sim(const Scenario &scenario)
      : sc(scenario), sink(SAMPLE_RATE / 2), receiver(make_config(scenario), crypto, *this, sink, nullptr) {}

  static ReceiverConfig make_config(const Scenario &scenario) {
    ReceiverConfig config;
    config.buffer_ms = scenario.buffer_ms;
    return config;
  }

  // Transport: RTSP responses are not needed; UDP goes through the simulated network
  bool send(uint8_t, const uint8_t *, size_t) override { return true; }
  void close(uint8_t) override {}
  bool open_udp(uint16_t *ports) override {
    ports[0] = 6000;
    ports[1] = 6001;
    ports[2] = 6002;
    return true;
  }
  void close_udp() override {}
  void send_udp(UdpChannel, const Endpoint &, const uint8_t *p, size_t length) override {
    const uint8_t type = p[1] & 0x7f;
    if (type == 0x52 && length >= 32 && !this->lost()) {
      std::vector<uint8_t> request(p, p + 32);
      const int64_t arrive = this->now_us + this->net_delay_us();
      this->events.emplace(arrive, [this, request, arrive]() {
        std::vector<uint8_t> reply = {0x80, 0xd3, 0x00, 0x07};
        reply.resize(32);
        std::memcpy(&reply[8], &request[24], 8);
        put_ntp(&reply[16], this->sender_ns(arrive));
        put_ntp(&reply[24], this->sender_ns(arrive) + 100000);
        if (!this->lost())
          this->deliver(this->now_us + this->net_delay_us(), UdpChannel::TIMING, reply);
      });
    } else if (type == 0x55 && length >= 8) {
      const auto first = static_cast<uint16_t>((p[4] << 8) | p[5]);
      const auto count = static_cast<uint16_t>((p[6] << 8) | p[7]);
      if (this->lost())
        return;
      this->events.emplace(this->now_us + this->net_delay_us(), [this, first, count]() {
        for (uint16_t i = 0; i < count; i++) {
          const auto seq = static_cast<uint16_t>(first + i);
          const uint32_t rtp = this->next_rtp - static_cast<uint16_t>(this->next_seq - seq) * FRAMES_PER_PACKET;
          std::vector<uint8_t> resent = {0x80, 0xd6, 0x00, 0x01};
          const std::vector<uint8_t> original = rtp_packet(0x60, seq, rtp, marked_pcm(rtp));
          resent.insert(resent.end(), original.begin(), original.end());
          if (!this->lost())
            this->deliver(this->now_us + this->net_delay_us(), UdpChannel::CONTROL, resent);
        }
      });
    }
  }

  double rand01() { return std::uniform_real_distribution<double>(0, 1)(this->rng); }
  bool lost() { return this->rand01() < this->sc.loss; }
  int64_t net_delay_us() {
    double delay = 2000 + std::exponential_distribution<double>(1.0 / (this->sc.jitter_ms * 1000))(this->rng);
    if (this->sc.stall_every_s > 0) {
      // Packets sent during a stall are delayed until it ends
      const double t = static_cast<double>(this->now_us) / 1e6;
      const double phase = std::fmod(t, this->sc.stall_every_s);
      if (t > 5 && phase < this->sc.stall_ms / 1000)
        delay += (this->sc.stall_ms / 1000 - phase) * 1e6;
    }
    return static_cast<int64_t>(delay);
  }
  void deliver(int64_t at, UdpChannel channel, std::vector<uint8_t> packet) {
    this->events.emplace(at, [this, channel, packet]() {
      this->receiver.udp_packet(channel, packet.data(), packet.size(), Endpoint{SENDER_IP, 7000}, this->now_us);
    });
  }

  int64_t sender_ns(int64_t local_us) const {
    return static_cast<int64_t>(static_cast<double>(local_us) * 1000.0 * (1 + this->sc.sender_ppm * 1e-6)) +
           this->sender_offset_ns + NTP_EPOCH_NS;
  }
  int64_t local_us_for_sender(int64_t sender) const {
    return static_cast<int64_t>(static_cast<double>(sender - this->sender_offset_ns - NTP_EPOCH_NS) /
                                (1000.0 * (1 + this->sc.sender_ppm * 1e-6)));
  }
  int64_t due_remote_ns(uint32_t rtp) const {
    return this->base_ntp +
           static_cast<int64_t>(static_cast<int32_t>(rtp - this->base_rtp)) * 1000000000LL / SAMPLE_RATE +
           static_cast<int64_t>(SENDER_LATENCY + 11025) * 1000000000LL / SAMPLE_RATE;
  }

  void sender_tick() {
    const int64_t now_remote = this->sender_ns(this->now_us);
    while (now_remote >= this->next_send_remote_ns) {
      if (!this->lost()) {
        this->deliver(this->now_us + this->net_delay_us(), UdpChannel::AUDIO,
                      rtp_packet(0x60, this->next_seq, this->next_rtp, marked_pcm(this->next_rtp)));
      }
      this->next_seq++;
      this->next_rtp += FRAMES_PER_PACKET;
      this->next_send_remote_ns += static_cast<int64_t>(FRAMES_PER_PACKET) * 1000000000LL / SAMPLE_RATE;
    }
    if (now_remote >= this->next_sync_remote_ns) {
      // rtp_now is the frame being sent now; it is due SENDER_LATENCY + 11025 frames later
      const uint32_t rtp_now =
          this->base_rtp + static_cast<uint32_t>((now_remote - this->base_ntp) * SAMPLE_RATE / 1000000000LL);
      std::vector<uint8_t> sync = {0x80, 0xd4, 0x00, 0x04};
      sync.resize(20);
      put_be32(&sync[4], rtp_now - SENDER_LATENCY);
      put_ntp(&sync[8], now_remote);
      put_be32(&sync[16], rtp_now);
      if (!this->lost() && this->syncs_sent >= this->sc.lost_first_syncs)
        this->deliver(this->now_us + this->net_delay_us(), UdpChannel::CONTROL, sync);
      this->syncs_sent++;
      this->next_sync_remote_ns += 1000000000LL;
    }
  }

  void output_tick(int64_t step_us) {
    if (this->output_start_us == 0 && !this->sink.queue.empty())
      this->output_start_us = this->now_us + static_cast<int64_t>(this->sc.output_start_delay_ms * 1000);
    if (this->output_start_us == 0 || this->now_us < this->output_start_us)
      return;
    this->output_phase += static_cast<double>(step_us) * 44100e-6 * (1 + this->sc.output_ppm * 1e-6);
    while (this->output_phase >= 1) {
      this->output_phase -= 1;
      std::pair<int16_t, int16_t> frame;
      if (!this->sink.play(&frame)) {
        if (this->last_heard_rtp != 0 && this->now_us >= this->measure_from_us)
          this->underrun_frames++;
        continue;
      }
      this->unreported++;
      if (this->now_us < this->measure_from_us)
        continue;
      this->frames_heard++;
      if (frame.first == 0 && frame.second == 0) {
        this->silence_heard++;
        continue;
      }
      const uint32_t full = marked_rtp(frame) | (RTP0 & ~0x1fffffffu);
      if (this->last_heard_rtp != 0) {
        const auto step = static_cast<int32_t>(full - this->last_heard_rtp);
        if (step == 0 || (step >= 2 && step <= 9)) {
          this->trims++;  // Frames repeated or dropped (up to 8 at once) to follow the sender's clock
        } else if (step != 1) {
          this->discontinuities++;
        }
      }
      this->last_heard_rtp = full;
      const double error_ms =
          static_cast<double>(this->now_us - this->local_us_for_sender(this->due_remote_ns(full))) / 1000.0;
      this->error_sum += error_ms;
      this->error_count++;
      this->max_abs_error = std::max(this->max_abs_error, std::fabs(error_ms));
    }
    if (this->sc.output_reports && this->unreported >= this->sc.report_chunk_frames) {
      this->receiver.notify_played(this->unreported, this->now_us);
      this->unreported = 0;
    }
  }

  void rtsp(const char *method, const std::string &headers = "", const std::string &body = "") {
    send_request(this->receiver, 0, rtsp_request(method, ++this->cseq, headers, body), this->now_us);
  }

  void seek() {
    // FLUSH, then the sender continues 30 s further on, 200 ms later
    this->next_seq += 10;
    this->rtsp("FLUSH", "RTP-Info: seq=" + std::to_string(this->next_seq) + ";rtptime=0\r\n");
    this->base_rtp = this->next_rtp + SAMPLE_RATE * 30;
    this->next_rtp = this->base_rtp;
    this->base_ntp = this->sender_ns(this->now_us) + 200000000;
    this->next_send_remote_ns = this->base_ntp;
    this->next_sync_remote_ns = this->base_ntp;
    this->last_heard_rtp = 0;
  }

  void run() {
    CHECK(this->receiver.begin());
    this->receiver.connection_opened(0, Endpoint{SENDER_IP, 50000}, Endpoint{ipv4(10, 0, 0, 1), 5000});
    this->rtsp("ANNOUNCE", "User-Agent: AirPlay/380.20\r\n", PCM_SDP);
    this->rtsp("SETUP", "Transport: RTP/AVP/UDP;unicast;mode=record;control_port=6001;timing_port=6002\r\n");
    this->base_ntp = this->sender_ns(this->now_us);
    this->next_send_remote_ns = this->base_ntp;
    this->next_sync_remote_ns = this->base_ntp;
    if (this->sc.sync_before_record) {
      std::vector<uint8_t> sync = {0x90, 0xd4, 0x00, 0x07};
      sync.resize(20);
      put_be32(&sync[4], RTP0 - SENDER_LATENCY);
      put_ntp(&sync[8], this->base_ntp);
      put_be32(&sync[16], RTP0);
      this->receiver.udp_packet(UdpChannel::CONTROL, sync.data(), sync.size(), Endpoint{SENDER_IP, 7000}, this->now_us);
      this->next_sync_remote_ns += 1000000000LL;
    }
    this->rtsp("RECORD",
               "RTP-Info: seq=" + std::to_string(this->next_seq) + ";rtptime=" + std::to_string(RTP0) + "\r\n");
    if (this->sc.flush_after_record)
      this->rtsp("FLUSH",
                 "RTP-Info: seq=" + std::to_string(this->next_seq) + ";rtptime=" + std::to_string(RTP0) + "\r\n");
    this->receiver.request_output_restart();

    this->measure_from_us = this->now_us + static_cast<int64_t>(this->sc.measure_from_s * 1e6);
    bool seeked = false;

    const int64_t start = this->now_us;
    const int64_t end = start + static_cast<int64_t>(this->sc.duration_s * 1e6);
    int64_t next_poll = this->now_us;
    while (this->now_us < end) {
      this->now_us += 250;
      this->output_tick(250);
      this->sender_tick();
      while (!this->events.empty() && this->events.begin()->first <= this->now_us) {
        auto fn = this->events.begin()->second;
        this->events.erase(this->events.begin());
        fn();
      }
      if (this->sc.seek_at_s > 0 && !seeked && this->now_us - start > this->sc.seek_at_s * 1e6) {
        seeked = true;
        this->seek();
        this->measure_from_us = this->now_us + 4000000;
      }
      if (this->now_us >= next_poll) {
        next_poll = this->now_us + 5000;
        this->receiver.poll(this->now_us);
      }
    }
  }

  void report_and_check() {
    const double mean = this->error_count > 0 ? this->error_sum / static_cast<double>(this->error_count) : 0;
    const double silence =
        this->frames_heard > 0 ? 100.0 * static_cast<double>(this->silence_heard) / this->frames_heard : 100;
    const ReceiverStats &stats = this->receiver.stats();
    std::printf("%-26s synced=%d mean=%7.2fms max|err|=%7.2fms silence=%5.2f%% trims=%llu discont=%llu "
                "underrun=%llu lost=%u late=%u resend=%u\n",
                this->sc.name, stats.synchronized, mean, this->max_abs_error, silence,
                static_cast<unsigned long long>(this->trims), static_cast<unsigned long long>(this->discontinuities),
                static_cast<unsigned long long>(this->underrun_frames), stats.lost_packets, stats.late_packets,
                stats.resend_requests);
    CHECK(stats.synchronized == this->sc.expect_synced);
    CHECK(this->frames_heard > 0);
    CHECK(silence <= this->sc.max_silence_percent);
    CHECK(this->discontinuities <= this->sc.max_discontinuities);
    CHECK(stats.late_packets <= this->sc.max_late_packets);
    if (this->sc.expect_synced) {
      CHECK(std::fabs(mean) <= this->sc.max_mean_error_ms);
      CHECK(this->max_abs_error <= this->sc.max_abs_error_ms);
    }
  }

  Scenario sc;
  std::mt19937 rng{1234};
  NoCrypto crypto;
  FakeSink sink;
  Receiver receiver;
  std::multimap<int64_t, std::function<void()>> events;
  int64_t now_us{1000000};
  int cseq{0};

  int64_t sender_offset_ns{123456789012345LL};  // Sender clock minus local clock, besides the NTP epoch
  int64_t base_ntp{0};
  uint32_t base_rtp{RTP0};
  uint16_t next_seq{500};
  uint32_t next_rtp{RTP0};
  int64_t next_send_remote_ns{0};
  int64_t next_sync_remote_ns{0};
  int syncs_sent{0};

  double output_phase{0};
  int64_t output_start_us{0};
  uint32_t unreported{0};
  int64_t measure_from_us{0};
  uint32_t last_heard_rtp{0};
  uint64_t frames_heard{0};
  uint64_t silence_heard{0};
  uint64_t trims{0};
  uint64_t discontinuities{0};
  uint64_t underrun_frames{0};
  double error_sum{0};
  uint64_t error_count{0};
  double max_abs_error{0};
};

int main(int argc, char **argv) {
  const bool long_runs = argc > 1 && std::strcmp(argv[1], "--long") == 0;
  std::vector<Scenario> scenarios;
  scenarios.push_back({.name = "ideal network"});
  scenarios.push_back({.name = "jitter, 1% loss", .loss = 0.01, .jitter_ms = 4});
  // Round trips of 10 to 40 ms as over Wi-Fi: the clock estimate must be good soon after the start, or playback
  // drifts while it improves
  scenarios.push_back({.name = "Wi-Fi round trips", .jitter_ms = 8, .duration_s = 40, .measure_from_s = 3});
  // An output that starts playing 20 ms after it got its first audio, as with I2S DMA buffers: the error is only
  // seen once the output reports, and must be corrected within a few seconds
  scenarios.push_back({.name = "output start delay",
                       .jitter_ms = 2,
                       .duration_s = 30,
                       .measure_from_s = 4,
                       .output_start_delay_ms = 20});
  scenarios.push_back({.name = "5% loss, stalls",
                       .loss = 0.05,
                       .jitter_ms = 4,
                       .stall_every_s = 10,
                       .stall_ms = 150,
                       .max_silence_percent = 1.0,
                       .max_discontinuities = 10});
  scenarios.push_back({.name = "large clock drift", .sender_ppm = 150, .output_ppm = -150, .max_mean_error_ms = 7.0});
  scenarios.push_back({.name = "seek", .loss = 0.01, .jitter_ms = 3, .seek_at_s = 30});
  // The sender's clock arrives only after 2 s, when the first packets are already due: those are dropped, the
  // rest plays in sync
  scenarios.push_back({.name = "early flush, syncs lost", .flush_after_record = true, .lost_first_syncs = 2});
  // Like pyatv: the first sync packet before RECORD is enough when the next ones are lost
  scenarios.push_back({.name = "sync before record",
                       .flush_after_record = true,
                       .sync_before_record = true,
                       .lost_first_syncs = 2,
                       .max_late_packets = 0});
  scenarios.push_back({.name = "coarse reports (46 ms)", .jitter_ms = 3, .report_chunk_frames = 2048});
  scenarios.push_back({.name = "small buffer (unsynced)",
                       .loss = 0.01,
                       .jitter_ms = 3,
                       .buffer_ms = 500,
                       .expect_synced = false,
                       .max_discontinuities = 5});
  scenarios.push_back({.name = "no output reports (unsynced)",
                       .jitter_ms = 2,
                       .output_reports = false,
                       .expect_synced = false,
                       .max_discontinuities = 5});
  if (long_runs) {
    scenarios.push_back({.name = "10 min, 2% loss, drift",
                         .sender_ppm = 60,
                         .output_ppm = -40,
                         .loss = 0.02,
                         .jitter_ms = 5,
                         .stall_every_s = 30,
                         .stall_ms = 300,
                         .duration_s = 600,
                         .max_silence_percent = 1.0,
                         .max_discontinuities = 50});
    scenarios.push_back({.name = "10 min unsynced, drift",
                         .sender_ppm = 60,
                         .output_ppm = -40,
                         .loss = 0.01,
                         .jitter_ms = 3,
                         .buffer_ms = 500,
                         .duration_s = 600,
                         .expect_synced = false,
                         .max_discontinuities = 50});
  }
  for (const Scenario &scenario : scenarios) {
    Sim sim(scenario);
    sim.run();
    sim.report_and_check();
  }
  return finish("test_sync");
}
