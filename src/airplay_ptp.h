#pragma once

#include <cstddef>
#include <cstdint>

namespace airplay {

/// UDP ports of PTP (IEEE 1588): event messages (Sync) and general messages (Follow_Up, Announce)
inline constexpr uint16_t PTP_EVENT_PORT = 319;
inline constexpr uint16_t PTP_GENERAL_PORT = 320;

/// Follows the PTP clocks of AirPlay 2 senders that time their audio with PTP (macOS), as nqptp does for
/// shairport-sync: it only listens. Each clock's offset comes from its Sync and Follow_Up messages; the network
/// delay is not measured, so the sample with the least delay over a short window is used.
class PtpClocks {
 public:
  static constexpr size_t MAX_CLOCKS = 4;

  /// Handles a message received on PTP_EVENT_PORT (`general` false) or PTP_GENERAL_PORT, at local time `now_us`.
  void handle(bool general, const uint8_t *data, size_t length, uint32_t from_address, int64_t now_us);
  /// @brief Time of a clock minus local time (both in nanoseconds; local time as passed to handle()).
  /// @param clock Clock identity as AirPlay names timelines (networkTimeTimelineID); 0 for the grandmaster
  /// @return false while the clock has too few samples or none recently
  bool offset_ns(uint64_t clock, int64_t now_us, int64_t *offset) const;
  /// Clock identity of the grandmaster that announced itself last, or of the clock that last sent Sync; 0 if none
  uint64_t grandmaster() const { return this->grandmaster_; }
  /// Logs what the clocks look like, at most every few seconds
  void log_status(int64_t now_us);

 private:
  static constexpr size_t WINDOW = 16;
  struct Clock {
    uint64_t id;
    uint32_t address;
    int64_t last_seen_us;  // 0 for a free slot
    int64_t last_sample_us;
    int64_t samples[WINDOW];
    uint32_t count;  // Samples in total
    uint16_t sync_sequence;
    bool sync_pending;
    int64_t sync_received_ns;
    int64_t sync_correction_ns;
    uint32_t syncs;
    uint32_t follow_ups;
  };
  Clock *find_(uint64_t id, uint32_t address, int64_t now_us);
  void add_sample_(Clock &clock, int64_t sample, int64_t now_us);

  Clock clocks_[MAX_CLOCKS]{};
  uint64_t grandmaster_{0};
  int64_t last_log_us_{0};
};

}  // namespace airplay
