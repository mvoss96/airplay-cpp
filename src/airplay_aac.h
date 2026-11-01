#pragma once

#include <cstddef>
#include <cstdint>

namespace airplay {

/// AAC-LC frames of AirPlay 2 buffered audio: 1024 frames of 44.1 kHz stereo each
inline constexpr uint32_t AAC_FRAMES_PER_PACKET = 1024;

/// AAC decoder for AirPlay 2 buffered audio, which iOS uses for most apps. Bring your own, e.g. Espressif's
/// esp_audio_codec; the receiver offers buffered audio only with one.
class AacDecoder {
 public:
  virtual ~AacDecoder() = default;
  /// @brief Prepares for raw AAC-LC frames (without ADTS headers) of 44.1 kHz stereo audio.
  virtual bool begin() = 0;
  /// @brief Decodes one frame into interleaved 16-bit stereo samples.
  /// @param max_frames Room in `samples`, at least AAC_FRAMES_PER_PACKET.
  /// @return the number of frames, or 0 if the frame could not be decoded.
  virtual size_t decode(const uint8_t *data, size_t length, int16_t *samples, size_t max_frames) = 0;
  /// @brief The stream ended; the decoder may free its memory.
  virtual void end() {}
};

}  // namespace airplay
