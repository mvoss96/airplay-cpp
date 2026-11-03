#pragma once

#include <cstddef>
#include <cstdint>

namespace airplay {

/// UDP ports of PTP (IEEE 1588): event messages (Sync) and general messages (Follow_Up, Announce)
inline constexpr uint16_t PTP_EVENT_PORT = 319;
inline constexpr uint16_t PTP_GENERAL_PORT = 320;

/// Follows the PTP clocks of AirPlay 2 senders that time their audio with PTP (macOS). Each clock's offset comes
/// from its Sync and Follow_Up messages, using the sample with the least network delay over a short window. While
/// a session uses PTP, the receiver also takes part as a clock that never becomes master: it announces itself and
/// measures the delay to the grandmaster with Delay_Req, which halves the error of the offset.
class PtpClocks {
 public:
  static constexpr size_t MAX_CLOCKS = 4;
  static constexpr size_t MAX_MESSAGE_SIZE = 64;

  /// The receiver's own clock identity, from its MAC address
  void set_identity(const uint8_t mac[6]);

  /// Handles a message received on PTP_EVENT_PORT (`general` false) or PTP_GENERAL_PORT, at local time `now_us`.
  void handle(bool general, const uint8_t *data, size_t length, uint32_t from_address, int64_t now_us);
  /// @brief Time of a clock minus local time (both in nanoseconds; local time as passed to handle()).
  /// @param clock Clock identity as AirPlay names timelines (networkTimeTimelineID); 0 for the grandmaster
  /// @return false while the clock has too few samples or none recently
  bool offset_ns(uint64_t clock, int64_t now_us, int64_t *offset) const;
  /// Clock identity of the grandmaster that announced itself last, or of the clock that last sent Sync; 0 if none
  uint64_t grandmaster() const { return this->grandmaster_; }
  /// The receiver's own clock identity (set_identity())
  uint64_t identity() const { return this->identity_; }
  /// Logs what the clocks look like, at most every few seconds
  void log_status(int64_t now_us);
  /// @brief A message the receiver sends now, if one is due: a Delay_Req to the grandmaster about every second, and
  /// an Announce every two seconds. Send it right away: the time of a Delay_Req is taken here.
  /// @return its length, 0 if none is due
  size_t next_message(uint8_t *buffer, int64_t now_us, uint32_t *to_address, bool *general);

 private:
  static constexpr size_t WINDOW = 16;
  struct Clock {
    uint64_t id;
    uint32_t address;
    uint8_t domain;
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
    // Delay_Resp: the grandmaster's receive time minus ours of sending, the offset plus the delay
    int64_t delay_samples[WINDOW];
    uint32_t delay_count;
    uint32_t delay_responses;
  };
  const Clock *active_(uint64_t id, int64_t now_us) const;
  void write_header_(uint8_t *buffer, uint8_t type, size_t length, uint8_t domain, uint16_t sequence, uint8_t control,
                     int8_t log_interval) const;
  Clock *find_(uint64_t id, uint32_t address, int64_t now_us);
  void add_sample_(Clock &clock, int64_t sample, int64_t now_us);

  Clock clocks_[MAX_CLOCKS]{};
  uint64_t grandmaster_{0};
  int64_t last_log_us_{0};
  uint64_t identity_{0};
  uint16_t delay_sequence_{0};
  bool delay_pending_{false};
  uint64_t delay_clock_{0};
  int64_t delay_sent_ns_{0};
  int64_t last_delay_request_us_{0};
  uint16_t announce_sequence_{0};
  int64_t last_announce_us_{0};
  // The grandmaster's part of its last Announce (priorities, quality, identity, steps, time source), passed on in
  // ours with one step more, as a clock that follows it does
  uint8_t grandmaster_announce_[17]{};
  bool have_grandmaster_announce_{false};
  // Messages seen per type (the low 4 bits of the first byte) since the last status line, and which were logged
  uint32_t type_counts_[16]{};
  uint32_t types_logged_{0};
};

}  // namespace airplay
