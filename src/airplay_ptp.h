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
/// grandmaster and never becomes master, so that the grandmaster goes on sending it Sync messages. It also sends
/// Delay_Req: Music Assistant answers them, which gives the network delay, and counts them to see that the receiver
/// follows its clock. Apple's senders answer none, so they get no more after a few and the delay to the receiver (a
/// few ms) stays in their offset.
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
  /// @brief How often a clock's time jumped by more than a second, and by how much the last time.
  /// @return the number of jumps so far (0 for an unknown clock)
  uint32_t jumps(uint64_t clock, int64_t *last_jump_ns) const;
  /// The clock with an offset now that sends from address (a sender's own clock), 0 if none
  uint64_t clock_at(uint32_t address, int64_t now_us) const;
  /// Writes the identities of the clocks that have an offset now (offset_ns() succeeds) to ids, at most max
  size_t active_clocks(uint64_t *ids, size_t max, int64_t now_us) const;
  /// Clock identity of the grandmaster that announced itself last, or of the clock that last sent Sync; 0 if none
  uint64_t grandmaster() const { return this->grandmaster_; }
  /// The receiver's own clock identity (set_identity())
  uint64_t identity() const { return this->identity_; }
  /// Logs what the clocks look like, at most every few seconds
  void log_status(int64_t now_us);
  /// @brief A message the receiver sends now, if one is due: an Announce to the clock it follows every two seconds,
  /// a Delay_Req every second while the clock answers them.
  /// @param clock The clock the receiver follows (the session's timeline), 0 for the grandmaster
  /// @return its length, 0 if none is due
  size_t next_message(uint64_t clock, uint8_t *buffer, int64_t now_us, uint32_t *to_address, bool *general);

 private:
  static constexpr size_t WINDOW = 16;
  static constexpr size_t DELAY_WINDOW = 8;
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
    uint32_t below;  // Samples in a row far below the estimate: the clock was set back
    uint32_t above;  // Samples in a row far above it: a jump that counts once it is confirmed
    uint16_t sync_sequence;
    bool sync_pending;
    int64_t sync_received_ns;
    int64_t sync_correction_ns;
    uint32_t syncs;
    // The grandmaster part of its last Announce (priorities, quality, identity, steps, time source), passed on in
    // ours with one step more, as a clock that follows it does
    uint8_t announce[17];
    bool has_announce;
    // Delay_Req and the network delay from the answers (half the round trip, the least of the last few)
    bool delay_pending;
    uint8_t delay_unanswered;
    uint16_t delay_sequence;
    int64_t delay_sent_ns;
    int64_t last_delay_request_us;
    int32_t delays[DELAY_WINDOW];
    uint32_t delay_count;
    // Jumps of the estimate by more than a second: a sender that slept, or one that now follows another clock (a
    // group's new grandmaster) and sends its time
    uint32_t jumps;
    int64_t last_jump_ns;
  };
  const Clock *active_(uint64_t id, int64_t now_us) const;
  void write_header_(uint8_t *buffer, uint8_t type, size_t length, uint8_t domain, uint16_t sequence, uint8_t control,
                     int8_t log_interval) const;
  Clock *find_(uint64_t id, uint32_t address, int64_t now_us);
  void add_sample_(Clock &clock, int64_t sample, int64_t now_us);
  /// Whether another clock's latest sample is as far below its estimate as `change`: a delay in the receiver
  bool others_late_(const Clock &clock, int64_t change, int64_t now_us) const;
  static int64_t best_recent_(const Clock &clock, uint32_t samples);
  static int64_t middle_recent_(const Clock &clock);  // The middle of the last three samples
  static int64_t delay_ns_(const Clock &clock);
  static void set_estimate_(Clock &clock, int64_t estimate);

  Clock clocks_[MAX_CLOCKS]{};
  uint64_t grandmaster_{0};
  int64_t last_log_us_{0};
  uint64_t identity_{0};
  uint16_t announce_sequence_{0};
  uint16_t delay_sequence_{0};
  int64_t last_announce_us_{0};
  uint32_t types_logged_{0};  // Message types (on each port) logged when they first arrived
};

}  // namespace airplay
