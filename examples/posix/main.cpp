// AirPlay receiver for Linux and macOS that writes the audio as raw PCM (44.1 kHz, 16-bit, stereo) to stdout
// or a file. Play it live with:
//
//   ./airplay_receiver "My Speaker" | aplay -f cd
//   ./airplay_receiver "My Speaker" | ffplay -f s16le -ar 44100 -ch_layout stereo -nodisp -
//
// Senders find the receiver through mDNS; the program prints the command that announces it (Avahi or dns-sd).
#include "airplay.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
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
  airplay::set_log_handler([](airplay::LogLevel, const char *message) { std::fprintf(stderr, "%s\n", message); },
                           airplay::LogLevel::LOG_LEVEL_INFO);

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

  airplay::Receiver *receiver_for_output = nullptr;
  PacedOutput sink(output, receiver_for_output);
  PrintingListener listener;
  airplay::SocketRunner runner;
  airplay::Receiver receiver(config, crypto, runner, sink, &listener);
  if (!receiver.begin() || !runner.begin(receiver, airplay::Receiver::DEFAULT_PORT)) {
    std::fprintf(stderr, "Failed to start\n");
    return 1;
  }
  receiver_for_output = &receiver;
  std::thread output_thread([&sink]() { sink.run(); });

  char instance[128];
  receiver.service_instance_name(instance, sizeof(instance));
  size_t count = 0;
  const airplay::TxtRecord *records = receiver.txt_records(&count);
  std::fprintf(stderr, "Announce the receiver with:\n  avahi-publish-service '%s' _raop._tcp %u", instance,
               airplay::Receiver::DEFAULT_PORT);
  for (size_t i = 0; i < count; i++)
    std::fprintf(stderr, " %s=%s", records[i].key, records[i].value);
  std::fprintf(stderr, "\n  (macOS: dns-sd -R '%s' _raop._tcp local %u ...)\n", instance,
               airplay::Receiver::DEFAULT_PORT);

  while (g_running)
    runner.run_once(100);

  runner.end();
  output_thread.join();
  return 0;
}
