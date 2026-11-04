#pragma once

#include <cstddef>
#include <cstdint>

namespace airplay {

/// UDP ports of PTP (IEEE 1588): event messages (Sync) and general messages (Follow_Up, Announce)
inline constexpr uint16_t PTP_EVENT_PORT = 319;
inline constexpr uint16_t PTP_GENERAL_PORT = 320;

/// Follows the PTP clocks of AirPlay 2 senders that time their audio with PTP (macOS), as nqptp does for
/// shairport-sync. Each clock's offset comes from its Sync and Follow_Up messages, following the samples with the
/// least network delay. While a session uses PTP, the receiver announces itself as a clock that follows the
/// grandmaster and never becomes master, so that the grandmaster goes on sending it Sync messages. Apple's senders
/// answer no Delay_Req, so the delay to the receiver (a few ms) stays in the offset.
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
  /// @brief A message the receiver sends now, if one is due: an Announce to the clock it follows every two seconds.
  /// @param clock The clock the receiver follows (the session's timeline), 0 for the grandmaster
  /// @return its length, 0 if none is due
  size_t next_message(uint64_t clock, uint8_t *buffer, int64_t now_us, uint32_t *to_address, bool *general);

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
    // The offset less the least delay: rises with every better sample, falls only as fast as clocks drift apart,
    // so that samples taken late while the receiver was busy do not move it
    int64_t estimate;
    uint32_t below;        // Samples in a row far below the estimate: the clock was set back
    uint32_t above;        // Samples in a row far above it: a jump that counts once it is confirmed
    int64_t above_lowest;  // The lowest of those
    uint16_t sync_sequence;
    bool sync_pending;
    int64_t sync_received_ns;
    int64_t sync_correction_ns;
    uint32_t syncs;
    // The grandmaster part of its last Announce (priorities, quality, identity, steps, time source), passed on in
    // ours with one step more, as a clock that follows it does
    uint8_t announce[17];
    bool has_announce;
  };
  const Clock *active_(uint64_t id, int64_t now_us) const;
  void write_header_(uint8_t *buffer, uint8_t type, size_t length, uint8_t domain, uint16_t sequence, uint8_t control,
                     int8_t log_interval) const;
  Clock *find_(uint64_t id, uint32_t address, int64_t now_us);
  void add_sample_(Clock &clock, int64_t sample, int64_t now_us);
  static int64_t best_recent_(const Clock &clock, uint32_t samples);

  Clock clocks_[MAX_CLOCKS]{};
  uint64_t grandmaster_{0};
  int64_t last_log_us_{0};
  uint64_t identity_{0};
  uint16_t announce_sequence_{0};
  int64_t last_announce_us_{0};
  uint32_t types_logged_{0};  // Message types (on each port) logged when they first arrived
};

}  // namespace airplay
