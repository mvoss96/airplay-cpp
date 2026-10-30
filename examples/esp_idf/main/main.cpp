// AirPlay speaker: receives AirPlay audio and plays it through I2S.
//
// Wiring for a MAX98357A or PCM5102A on an ESP32: BCLK -> GPIO 26, LRCLK/WS -> GPIO 25, DIN -> GPIO 22
// (other chips: GPIO 4, 5 and 6).
// Set the Wi-Fi credentials with idf.py menuconfig -> Example Connection Configuration.
#include "airplay.h"

#include <driver/i2s_std.h>
#include <esp_log.h>
#include <esp_heap_caps.h>
#include <esp_mac.h>
#include <esp_netif.h>
#include <esp_timer.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <mdns.h>
#include <nvs_flash.h>
#include <protocol_examples_common.h>

#include <algorithm>
#include <atomic>

static const char *const TAG = "airplay_example";
static constexpr char NAME[] = "ESP32 Speaker";

#if CONFIG_IDF_TARGET_ESP32
static constexpr gpio_num_t I2S_BCLK = GPIO_NUM_26;
static constexpr gpio_num_t I2S_WS = GPIO_NUM_25;
static constexpr gpio_num_t I2S_DOUT = GPIO_NUM_22;
#else
static constexpr gpio_num_t I2S_BCLK = GPIO_NUM_4;
static constexpr gpio_num_t I2S_WS = GPIO_NUM_5;
static constexpr gpio_num_t I2S_DOUT = GPIO_NUM_6;
#endif
static constexpr uint32_t DMA_FRAMES = 240;
static constexpr uint32_t DMA_BUFFERS = 6;

/// I2S output. The DMA interrupt counts what was sent; report_played() turns that into played-audio reports.
class I2sOutput : public airplay::AudioSink {
 public:
  bool begin() {
    i2s_chan_config_t channel_config = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_AUTO, I2S_ROLE_MASTER);
    channel_config.dma_desc_num = DMA_BUFFERS;
    channel_config.dma_frame_num = DMA_FRAMES;
    channel_config.auto_clear = true;  // Silence when no audio is queued
    if (i2s_new_channel(&channel_config, &this->channel_, nullptr) != ESP_OK)
      return false;
    i2s_std_config_t config = {
        .clk_cfg = I2S_STD_CLK_DEFAULT_CONFIG(airplay::SAMPLE_RATE),
        .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_STEREO),
        .gpio_cfg =
            {
                .mclk = I2S_GPIO_UNUSED,
                .bclk = I2S_BCLK,
                .ws = I2S_WS,
                .dout = I2S_DOUT,
                .din = I2S_GPIO_UNUSED,
                .invert_flags = {},
            },
    };
    i2s_event_callbacks_t callbacks = {};
    callbacks.on_sent = I2sOutput::on_sent;
    return i2s_channel_init_std_mode(this->channel_, &config) == ESP_OK &&
           i2s_channel_register_event_callback(this->channel_, &callbacks, this) == ESP_OK &&
           i2s_channel_enable(this->channel_) == ESP_OK;
  }

  size_t write(const int16_t *samples, size_t frames) override {
    size_t written = 0;
    // Timeout 0: take what fits into the DMA buffers right now
    i2s_channel_write(this->channel_, samples, frames * airplay::BYTES_PER_FRAME, &written, 0);
    const size_t written_frames = written / airplay::BYTES_PER_FRAME;
    this->written_ += written_frames;
    return written_frames;
  }

  /// Reports the audio played since the last call. The DMA also sends silence when it runs dry, so the count
  /// is limited to the audio that was actually written.
  void report_played(airplay::Receiver &receiver) {
    const uint32_t sent = this->sent_frames_.load(std::memory_order_relaxed);
    const uint32_t played = std::min(sent - this->last_sent_, this->written_ - this->played_);
    this->last_sent_ = sent;
    if (played > 0) {
      this->played_ += played;
      receiver.notify_played(played, esp_timer_get_time());
    }
  }

 private:
  static bool IRAM_ATTR on_sent(i2s_chan_handle_t, i2s_event_data_t *event, void *context) {
    auto *self = static_cast<I2sOutput *>(context);
    self->sent_frames_.fetch_add(event->size / airplay::BYTES_PER_FRAME, std::memory_order_relaxed);
    return false;
  }

  i2s_chan_handle_t channel_{nullptr};
  std::atomic<uint32_t> sent_frames_{0};
  uint32_t last_sent_{0};
  uint32_t written_{0};
  uint32_t played_{0};
};

class LoggingListener : public airplay::Listener {
 public:
  void on_session_state(airplay::SessionState state) override {
    static const char *const NAMES[] = {"stopped", "playing", "paused"};
    ESP_LOGI(TAG, "Session: %s", NAMES[static_cast<int>(state)]);
  }
  // Apply the volume to your amplifier or scale the samples
  void on_volume(float volume) override { ESP_LOGI(TAG, "Volume: %d%%", static_cast<int>(volume * 100)); }
  void on_mute(bool muted) override { ESP_LOGI(TAG, "Muted: %s", muted ? "yes" : "no"); }
  void on_metadata(const airplay::Metadata &metadata) override {
    if (metadata.title[0] != '\0')
      ESP_LOGI(TAG, "Now playing: %s - %s", metadata.artist, metadata.title);
  }
};

static airplay::MbedtlsCrypto g_crypto;
static I2sOutput g_output;
static LoggingListener g_listener;
static airplay::SocketRunner g_runner;

static void register_mdns(const airplay::Receiver &receiver) {
  char instance[96];
  receiver.service_instance_name(instance, sizeof(instance));
  size_t count = 0;
  const airplay::TxtRecord *records = receiver.txt_records(&count);
  mdns_txt_item_t txt[20];
  count = std::min(count, sizeof(txt) / sizeof(txt[0]));
  for (size_t i = 0; i < count; i++)
    txt[i] = mdns_txt_item_t{records[i].key, records[i].value};
  ESP_ERROR_CHECK(mdns_init());
  ESP_ERROR_CHECK(mdns_hostname_set("esp32-speaker"));
  ESP_ERROR_CHECK(mdns_service_add(instance, "_raop", "_tcp", airplay::Receiver::DEFAULT_PORT, txt, count));
  ESP_LOGI(TAG, "Announced as %s", instance);
}

static void airplay_task(void *parameter) {
  auto *receiver = static_cast<airplay::Receiver *>(parameter);
  while (!g_runner.begin(*receiver))
    vTaskDelay(pdMS_TO_TICKS(1000));
  while (true) {
    g_runner.run_once(100);
    g_output.report_played(*receiver);
  }
}

extern "C" void app_main() {
  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  ESP_ERROR_CHECK(example_connect());
  esp_wifi_set_ps(WIFI_PS_NONE);  // Power saving delays packets by up to a beacon interval

  airplay::set_log_handler(
      [](airplay::LogLevel level, const char *message) {
        if (level <= airplay::LogLevel::LOG_LEVEL_WARN) {
          ESP_LOGW("airplay", "%s", message);
        } else {
          ESP_LOGI("airplay", "%s", message);
        }
      },
      airplay::LogLevel::LOG_LEVEL_INFO);

  static airplay::ReceiverConfig config;
  config.name = NAME;
  ESP_ERROR_CHECK(esp_read_mac(config.mac, ESP_MAC_WIFI_STA));
  // 2.5 s plays in sync with the sender (and other speakers) but needs about 460 KB: use PSRAM if available.
  // Without PSRAM use 500 ms; playback is then not synchronized.
  config.buffer_ms = heap_caps_get_free_size(MALLOC_CAP_SPIRAM) > 1024 * 1024 ? 2500 : 500;
  config.allocate = [](size_t size) { return heap_caps_malloc_prefer(size, 2, MALLOC_CAP_SPIRAM, MALLOC_CAP_8BIT); };
  config.deallocate = heap_caps_free;
  config.metadata = true;

  static airplay::Receiver receiver(config, g_crypto, g_runner, g_output, &g_listener);
  if (!g_crypto.init() || !receiver.begin() || !g_output.begin()) {
    ESP_LOGE(TAG, "Setup failed");
    return;
  }
  register_mdns(receiver);
  // The network stack runs at priority 18-23; audio needs to run soon after packets arrive
  xTaskCreate(airplay_task, "airplay", 8192, &receiver, 10, nullptr);
}
