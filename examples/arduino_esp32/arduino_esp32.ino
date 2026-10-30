// AirPlay speaker for the Arduino ESP32 core (3.x): receives AirPlay audio and plays it through I2S.
//
// Wiring for a MAX98357A or PCM5102A: BCLK -> GPIO 26, LRCLK/WS -> GPIO 25, DIN -> GPIO 22.
#include <ESP_I2S.h>
#include <WiFi.h>
#include <airplay.h>
#include <mdns.h>

#include <algorithm>

static const char *const WIFI_SSID = "your-ssid";
static const char *const WIFI_PASSWORD = "your-password";
static const char *const NAME = "Arduino Speaker";

static constexpr int PIN_BCLK = 26;
static constexpr int PIN_WS = 25;
static constexpr int PIN_DOUT = 22;

static I2SClass i2s;

/// I2S output. The I2S clock runs all the time (silence when nothing is queued), so the played audio is
/// estimated from the elapsed time, limited to what was written.
class I2sOutput : public airplay::AudioSink {
 public:
  size_t write(const int16_t *samples, size_t frames) override {
    const size_t written = i2s.write(reinterpret_cast<const uint8_t *>(samples), frames * airplay::BYTES_PER_FRAME);
    const size_t written_frames = written / airplay::BYTES_PER_FRAME;
    this->written_ += written_frames;
    return written_frames;
  }

  void report_played(airplay::Receiver &receiver) {
    const int64_t now = airplay::SocketRunner::now_us();
    if (this->last_us_ == 0)
      this->last_us_ = now;
    this->clock_ += static_cast<double>(now - this->last_us_) * airplay::SAMPLE_RATE / 1e6;
    this->last_us_ = now;
    const auto elapsed = static_cast<uint32_t>(this->clock_);
    this->clock_ -= elapsed;
    const uint32_t played = std::min(elapsed, this->written_ - this->played_);
    if (played > 0) {
      this->played_ += played;
      receiver.notify_played(played, now);
    }
  }

 private:
  uint32_t written_{0};
  uint32_t played_{0};
  int64_t last_us_{0};
  double clock_{0};
};

class SerialListener : public airplay::Listener {
 public:
  void on_session_state(airplay::SessionState state) override {
    static const char *const NAMES[] = {"stopped", "playing", "paused"};
    Serial.printf("Session: %s\n", NAMES[static_cast<int>(state)]);
  }
  // Apply the volume to your amplifier or scale the samples
  void on_volume(float volume) override { Serial.printf("Volume: %d%%\n", static_cast<int>(volume * 100)); }
  void on_metadata(const airplay::Metadata &metadata) override {
    if (metadata.title[0] != '\0')
      Serial.printf("Now playing: %s - %s\n", metadata.artist, metadata.title);
  }
};

static airplay::MbedtlsCrypto crypto;
static I2sOutput output;
static SerialListener listener;
static airplay::SocketRunner runner;
static airplay::Receiver *receiver = nullptr;

static void airplay_task(void *) {
  while (!runner.begin(*receiver))
    delay(1000);
  while (true) {
    runner.run_once(100);
    output.report_played(*receiver);
  }
}

void setup() {
  Serial.begin(115200);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED)
    delay(250);
  WiFi.setSleep(false);  // Power saving delays packets by up to a beacon interval
  Serial.printf("Connected: %s\n", WiFi.localIP().toString().c_str());

  i2s.setPins(PIN_BCLK, PIN_WS, PIN_DOUT);
  i2s.setTimeout(0);  // Non-blocking writes
  if (!i2s.begin(I2S_MODE_STD, airplay::SAMPLE_RATE, I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_STEREO)) {
    Serial.println("I2S failed");
    return;
  }

  airplay::set_log_handler([](airplay::LogLevel, const char *message) { Serial.println(message); });

  static airplay::ReceiverConfig config;
  config.name = NAME;
  WiFi.macAddress(config.mac);
  // 2.5 s plays in sync with the sender but needs PSRAM; without it 500 ms plays unsynchronized
  config.buffer_ms = psramFound() ? 2500 : 500;
  config.allocate = [](size_t size) { return heap_caps_malloc_prefer(size, 2, MALLOC_CAP_SPIRAM, MALLOC_CAP_8BIT); };
  config.deallocate = heap_caps_free;
  config.metadata = true;
  static airplay::Receiver instance(config, crypto, runner, output, &listener);
  receiver = &instance;
  if (!crypto.init() || !receiver->begin()) {
    Serial.println("Setup failed");
    return;
  }

  // Announce the receiver with the ESP-IDF mDNS API, which allows the "<MAC>@<name>" instance name
  char name[96];
  receiver->service_instance_name(name, sizeof(name));
  size_t count = 0;
  const airplay::TxtRecord *records = receiver->txt_records(&count);
  mdns_txt_item_t txt[20];
  count = std::min(count, sizeof(txt) / sizeof(txt[0]));
  for (size_t i = 0; i < count; i++)
    txt[i] = mdns_txt_item_t{records[i].key, records[i].value};
  mdns_init();
  mdns_hostname_set("arduino-speaker");
  mdns_service_add(name, "_raop", "_tcp", airplay::Receiver::DEFAULT_PORT, txt, count);

  xTaskCreate(airplay_task, "airplay", 8192, nullptr, 10, nullptr);
}

void loop() { delay(1000); }
