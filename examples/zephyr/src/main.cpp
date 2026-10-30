// AirPlay receiver on Zephyr. The audio goes to a null output that plays in real time and logs how much it
// played; replace it with your board's audio driver.
#include "airplay.h"

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include <algorithm>

/// Plays at 44.1 kHz from a 100 ms buffer, discarding the audio
class NullOutput : public airplay::AudioSink {
 public:
  size_t write(const int16_t *, size_t frames) override {
    const uint32_t queued = this->written_ - this->played_;
    const auto accepted =
        static_cast<uint32_t>(std::min<size_t>(frames, CAPACITY_FRAMES - std::min(queued, CAPACITY_FRAMES)));
    this->written_ += accepted;
    return accepted;
  }

  void report_played(airplay::Receiver &receiver) {
    const int64_t now = airplay::SocketRunner::now_us();
    if (this->last_us_ == 0)
      this->last_us_ = now;
    this->clock_ += (now - this->last_us_) * static_cast<int64_t>(airplay::SAMPLE_RATE);
    this->last_us_ = now;
    const auto elapsed = static_cast<uint32_t>(this->clock_ / 1000000);
    this->clock_ -= static_cast<int64_t>(elapsed) * 1000000;
    const uint32_t played = std::min(elapsed, this->written_ - this->played_);
    if (played > 0) {
      this->played_ += played;
      this->total_ += played;
      receiver.notify_played(played, now);
    }
  }

  uint64_t total() const { return this->total_; }

 private:
  static constexpr uint32_t CAPACITY_FRAMES = airplay::SAMPLE_RATE / 10;
  uint32_t written_{0};
  uint32_t played_{0};
  uint64_t total_{0};
  int64_t last_us_{0};
  int64_t clock_{0};
};

class PrintingListener : public airplay::Listener {
 public:
  explicit PrintingListener(NullOutput &output) : output_(output) {}
  void on_session_state(airplay::SessionState state) override {
    static const char *const NAMES[] = {"stopped", "playing", "paused"};
    printk("Session: %s (%u frames played)\n", NAMES[static_cast<int>(state)],
           static_cast<unsigned>(this->output_.total()));
  }
  void on_volume(float volume) override { printk("Volume: %d%%\n", static_cast<int>(volume * 100)); }
  void on_metadata(const airplay::Metadata &metadata) override {
    if (metadata.title[0] != '\0')
      printk("Now playing: %s - %s\n", metadata.artist, metadata.title);
  }

 private:
  NullOutput &output_;
};

static airplay::MbedtlsCrypto crypto;
static NullOutput output;
static PrintingListener listener(output);
static airplay::SocketRunner runner;

int main() {
  airplay::set_log_handler([](airplay::LogLevel, const char *message) { printk("%s\n", message); });

  airplay::ReceiverConfig config;
  config.name = "Zephyr Speaker";
  const uint8_t mac[6] = {0x02, 0x00, 0x5e, 0x10, 0x20, 0x30};  // Use the network interface's address
  std::copy(mac, mac + 6, config.mac);
  config.buffer_ms = 2500;
  config.metadata = true;

  static airplay::Receiver receiver(config, crypto, runner, output, &listener);
  if (!crypto.init() || !receiver.begin()) {
    printk("Setup failed\n");
    return 1;
  }
  while (!runner.begin(receiver))
    k_sleep(K_SECONDS(1));

  char instance[96];
  receiver.service_instance_name(instance, sizeof(instance));
  printk("AirPlay receiver %s on port %u\n", instance, airplay::Receiver::DEFAULT_PORT);
  while (true) {
    runner.run_once(100);
    output.report_played(receiver);
  }
  return 0;
}
