#pragma once

#include <cstddef>
#include <cstdint>

namespace airplay {

/// AirPlay 1 audio is always 44.1 kHz, 16-bit, stereo, in packets of 352 frames
inline constexpr uint32_t SAMPLE_RATE = 44100;
inline constexpr uint32_t NUM_CHANNELS = 2;
inline constexpr uint32_t FRAMES_PER_PACKET = 352;
inline constexpr size_t BYTES_PER_FRAME = NUM_CHANNELS * sizeof(int16_t);

/// IPv4 endpoint. The address is in network byte order (as in sockaddr_in), the port in host byte order.
struct Endpoint {
  uint32_t address{0};
  uint16_t port{0};
};

/// The three UDP sockets of a playback session
enum class UdpChannel : uint8_t {
  AUDIO = 0,
  CONTROL = 1,
  TIMING = 2,
};
inline constexpr size_t NUM_UDP_CHANNELS = 3;

enum class SessionState : uint8_t {
  NONE = 0,  // No sender is streaming
  PLAYING,
  PAUSED,
};

/// Track details sent by the sender
struct Metadata {
  static constexpr size_t FIELD_SIZE = 128;
  char title[FIELD_SIZE];
  char artist[FIELD_SIZE];
  char album[FIELD_SIZE];
  char album_artist[FIELD_SIZE];
  uint16_t year;   // 0 when unknown
  uint16_t track;  // Track number on the album; 0 when unknown
};

/// Playback position of the current track, as the sender reports it; duration 0 when no track plays
struct Progress {
  uint32_t position_ms;
  uint32_t duration_ms;
};

/// Image format of cover art
enum class ArtworkFormat : uint8_t {
  JPEG = 0,
  PNG,
};

/// What is needed to send remote control (DACP) commands to the sender
struct RemoteTarget {
  static constexpr size_t DACP_ID_SIZE = 17;
  static constexpr size_t ACTIVE_REMOTE_SIZE = 12;
  char dacp_id[DACP_ID_SIZE];              // Hex id; the sender announces iTunes_Ctrl_<id>._dacp._tcp
  char active_remote[ACTIVE_REMOTE_SIZE];  // Sent back in the Active-Remote header
  uint32_t address;                        // IPv4 of the sender, network byte order
};

/// mDNS TXT record of the _raop._tcp service
struct TxtRecord {
  const char *key;
  const char *value;
};

}  // namespace airplay
