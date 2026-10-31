// AirPlay receiver for Linux and macOS that writes the audio as raw PCM (44.1 kHz, 16-bit, stereo) to stdout
// or a file. Play it live with:
//
//   ./airplay_receiver "My Speaker" | aplay -f cd
//   ./airplay_receiver "My Speaker" | ffplay -f s16le -ar 44100 -ch_layout stereo -nodisp -
//
// AIRPLAY_ARTWORK=<file> saves the cover art of the latest track to that file, AIRPLAY_PASSWORD=<password> makes
// senders ask for a password.
//
// Senders find the receiver through mDNS; the program prints the command that announces it (Avahi or dns-sd).
#include "airplay.h"

#ifndef AIRPLAY_HAS_MBEDTLS
#error "This example needs mbedTLS 2.28, 3.x or 4.x (Debian/Ubuntu: libmbedtls-dev, macOS: brew install mbedtls)"
#endif

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

static std::atomic<bool> g_running{true};

/// Plays at 44.1 kHz in real time from a small buffer, like a sound card would, and reports what it played
class PacedOutput : public airplay::AudioSink {
 public:
  PacedOutput(FILE *file, airplay::Receiver *&receiver) : file_(file), receiver_(receiver) {
    this->buffer_.resize(CAPACITY_FRAMES * 2);
  }

  size_t write(const int16_t *samples, size_t frames) override {
    std::lock_guard<std::mutex> lock(this->mutex_);
    const size_t accepted = std::min(frames, CAPACITY_FRAMES - this->count_);
    for (size_t i = 0; i < accepted; i++) {
      const size_t at = (this->head_ + this->count_ + i) % CAPACITY_FRAMES;
      this->buffer_[2 * at] = samples[2 * i];
      this->buffer_[2 * at + 1] = samples[2 * i + 1];
    }
    this->count_ += accepted;
    return accepted;
  }

  /// Output thread: takes 10 ms of audio every 10 ms; plays silence when there is none
  void run() {
    static constexpr size_t CHUNK = 441;
    std::vector<int16_t> chunk(CHUNK * 2);
    auto next = std::chrono::steady_clock::now();
    while (g_running) {
      next += std::chrono::milliseconds(10);
      std::this_thread::sleep_until(next);
      size_t frames;
      {
        std::lock_guard<std::mutex> lock(this->mutex_);
        frames = std::min(CHUNK, this->count_);
        for (size_t i = 0; i < frames; i++) {
          chunk[2 * i] = this->buffer_[2 * this->head_];
          chunk[2 * i + 1] = this->buffer_[2 * this->head_ + 1];
          this->head_ = (this->head_ + 1) % CAPACITY_FRAMES;
        }
        this->count_ -= frames;
      }
      std::fill(chunk.begin() + static_cast<std::ptrdiff_t>(frames * 2), chunk.end(), 0);
      std::fwrite(chunk.data(), sizeof(int16_t), chunk.size(), this->file_);
      std::fflush(this->file_);
      if (frames > 0 && this->receiver_ != nullptr)
        this->receiver_->notify_played(static_cast<uint32_t>(frames), airplay::SocketRunner::now_us());
    }
  }

 private:
  static constexpr size_t CAPACITY_FRAMES = airplay::SAMPLE_RATE / 5;  // 200 ms
  FILE *file_;
  airplay::Receiver *&receiver_;
  std::mutex mutex_;
  std::vector<int16_t> buffer_;
  size_t head_{0};
  size_t count_{0};
};

class PrintingListener : public airplay::Listener {
 public:
  void on_session_state(airplay::SessionState state) override {
    static const char *const NAMES[] = {"stopped", "playing", "paused"};
    std::fprintf(stderr, "Session: %s\n", NAMES[static_cast<int>(state)]);
  }
  void on_volume(float volume) override { std::fprintf(stderr, "Volume: %.0f%%\n", volume * 100); }
  void on_mute(bool muted) override { std::fprintf(stderr, "Muted: %s\n", muted ? "yes" : "no"); }
  void on_metadata(const airplay::Metadata &metadata) override {
    if (metadata.title[0] != '\0')
      std::fprintf(stderr, "Now playing: %s - %s (%s)\n", metadata.artist, metadata.title, metadata.album);
  }
  bool on_artwork_begin(airplay::ArtworkFormat format, size_t size) override {
    if (this->artwork_path == nullptr)
      return false;
    std::fprintf(stderr, "Cover art: %s, %zu bytes\n", format == airplay::ArtworkFormat::PNG ? "PNG" : "JPEG", size);
    this->artwork_file = std::fopen(this->artwork_path, "wb");
    return this->artwork_file != nullptr;
  }
  void on_artwork_data(const uint8_t *data, size_t length) override {
    std::fwrite(data, 1, length, this->artwork_file);
  }
  void on_artwork_end(bool /*complete*/) override {
    std::fclose(this->artwork_file);
    this->artwork_file = nullptr;
  }
  void on_progress(const airplay::Progress &progress) override {
    if (progress.duration_ms > 0) {
      std::fprintf(stderr, "Position: %u of %u s\n", static_cast<unsigned>(progress.position_ms / 1000),
                   static_cast<unsigned>(progress.duration_ms / 1000));
    }
  }
  void on_artwork_clear() override {
    if (this->artwork_path != nullptr)
      std::fprintf(stderr, "No cover art\n");
  }

  const char *artwork_path{nullptr};
  FILE *artwork_file{nullptr};
};

int main(int argc, char **argv) {
  const char *name = argc > 1 ? argv[1] : "airplay-cpp";
  FILE *output = stdout;
  if (argc > 2 && std::strcmp(argv[2], "-") != 0) {
    output = std::fopen(argv[2], "wb");
    if (output == nullptr) {
      std::perror(argv[2]);
      return 1;
    }
  }
  std::signal(SIGINT, [](int) { g_running = false; });
  std::signal(SIGPIPE, SIG_IGN);
  // AIRPLAY_DEBUG=1 shows the details of each session, AIRPLAY_DEBUG=2 every packet that is asked for again
  const char *debug = std::getenv("AIRPLAY_DEBUG");
  airplay::set_log_handler([](airplay::LogLevel, const char *message) { std::fprintf(stderr, "%s\n", message); },
                           debug != nullptr && debug[0] == '2'   ? airplay::LogLevel::LOG_LEVEL_VERBOSE
                           : debug != nullptr && debug[0] == '1' ? airplay::LogLevel::LOG_LEVEL_DEBUG
                                                                 : airplay::LogLevel::LOG_LEVEL_INFO);

  airplay::MbedtlsCrypto crypto;
  if (!crypto.init()) {
    std::fprintf(stderr, "Failed to load the key\n");
    return 1;
  }

  airplay::ReceiverConfig config;
  config.name = name;
  // Any stable, unique address works; real devices use their network interface's MAC address
  const uint8_t mac[6] = {0x02, 0x00, 0x00, 0xa1, 0xb2, 0xc3};
  std::memcpy(config.mac, mac, sizeof(mac));
  config.buffer_ms = 2500;  // Enough for synchronized playback
  config.metadata = true;
  const char *artwork_path = std::getenv("AIRPLAY_ARTWORK");
  config.artwork = artwork_path != nullptr;
  config.progress = true;
  const char *password = std::getenv("AIRPLAY_PASSWORD");
  config.password = password != nullptr && password[0] != '\0' ? password : nullptr;
  // AIRPLAY2=1 also offers AirPlay 2
  const char *airplay2 = std::getenv("AIRPLAY2");
  config.airplay2 = airplay2 != nullptr && airplay2[0] == '1';
  config.random = [](uint8_t *buffer, size_t length) {
    FILE *random = std::fopen("/dev/urandom", "rb");
    if (random == nullptr || std::fread(buffer, 1, length, random) != length) {
      std::fprintf(stderr, "Failed to read /dev/urandom\n");
      std::abort();
    }
    std::fclose(random);
  };

  airplay::Receiver *receiver_for_output = nullptr;
  PacedOutput sink(output, receiver_for_output);
  PrintingListener listener;
  listener.artwork_path = artwork_path;
  // AIRPLAY_PORT changes the RTSP port, e.g. on macOS, whose own AirPlay receiver uses 5000 and 7000
  uint16_t port = airplay::Receiver::DEFAULT_PORT;
  if (const char *port_text = std::getenv("AIRPLAY_PORT"))
    port = static_cast<uint16_t>(std::atoi(port_text));
  airplay::SocketRunner runner;
  // AIRPLAY_UDP_PORT=6000 uses UDP ports 6000-6002, e.g. to forward them from a container
  if (const char *udp_port = std::getenv("AIRPLAY_UDP_PORT"))
    runner.set_udp_base_port(static_cast<uint16_t>(std::atoi(udp_port)));
  airplay::Receiver receiver(config, crypto, runner, sink, &listener);
  if (!receiver.begin() || !runner.begin(receiver, port)) {
    std::fprintf(stderr, "Failed to start\n");
    return 1;
  }
  receiver_for_output = &receiver;
  std::thread output_thread([&sink]() { sink.run(); });

  char instance[128];
  receiver.service_instance_name(instance, sizeof(instance));
  size_t count = 0;
  const airplay::TxtRecord *records = receiver.txt_records(&count);
  std::fprintf(stderr, "Announce the receiver with:\n  Linux: avahi-publish-service '%s' _raop._tcp %u", instance,
               port);
  for (size_t i = 0; i < count; i++)
    std::fprintf(stderr, " %s=%s", records[i].key, records[i].value);
  std::fprintf(stderr, "\n  macOS: dns-sd -R '%s' _raop._tcp local %u", instance, port);
  for (size_t i = 0; i < count; i++)
    std::fprintf(stderr, " %s=%s", records[i].key, records[i].value);
  std::fprintf(stderr, "\n");
  const airplay::TxtRecord *airplay_records = receiver.airplay_txt_records(&count);
  if (count > 0) {
    std::fprintf(stderr, "  AirPlay 2, also: avahi-publish-service '%s' _airplay._tcp %u", name, port);
    for (size_t i = 0; i < count; i++)
      std::fprintf(stderr, " %s=%s", airplay_records[i].key, airplay_records[i].value);
    std::fprintf(stderr, "\n");
  }

  while (g_running)
    runner.run_once(100);

  runner.end();
  output_thread.join();
  return 0;
}
