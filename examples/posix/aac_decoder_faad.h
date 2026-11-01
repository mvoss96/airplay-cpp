#pragma once

// AAC decoder for the POSIX example, using FAAD2 (GPL; only built into the example when found)

#include "airplay.h"

#include <neaacdec.h>

#include <cstring>

class FaadDecoder : public airplay::AacDecoder {
 public:
  ~FaadDecoder() override { this->end(); }

  bool begin() override {
    this->end();
    this->decoder_ = NeAACDecOpen();
    if (this->decoder_ == nullptr)
      return false;
    NeAACDecConfigurationPtr config = NeAACDecGetCurrentConfiguration(this->decoder_);
    config->outputFormat = FAAD_FMT_16BIT;
    config->defObjectType = LC;
    NeAACDecSetConfiguration(this->decoder_, config);
    // AudioSpecificConfig: AAC-LC, 44.1 kHz, stereo
    unsigned char specific_config[] = {0x12, 0x10};
    unsigned long sample_rate = 0;
    unsigned char channels = 0;
    return NeAACDecInit2(this->decoder_, specific_config, sizeof(specific_config), &sample_rate, &channels) == 0;
  }

  size_t decode(const uint8_t *data, size_t length, int16_t *samples, size_t max_frames) override {
    if (this->decoder_ == nullptr)
      return 0;
    NeAACDecFrameInfo info{};
    void *output =
        NeAACDecDecode(this->decoder_, &info, const_cast<unsigned char *>(data), static_cast<unsigned long>(length));
    if (output == nullptr || info.error != 0 || info.channels != 2)
      return 0;
    const size_t frames = info.samples / 2;
    if (frames > max_frames)
      return 0;
    std::memcpy(samples, output, frames * 2 * sizeof(int16_t));
    // FAAD2 gives no audio for the first frame, which only primes the decoder
    if (frames == 0) {
      std::memset(samples, 0, airplay::AAC_FRAMES_PER_PACKET * 2 * sizeof(int16_t));
      return airplay::AAC_FRAMES_PER_PACKET;
    }
    return frames;
  }

  void end() override {
    if (this->decoder_ != nullptr)
      NeAACDecClose(this->decoder_);
    this->decoder_ = nullptr;
  }

 private:
  NeAACDecHandle decoder_{nullptr};
};
