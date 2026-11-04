#include "airplay_ptp.h"

#include "airplay_log.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>

namespace airplay {

static constexpr size_t HEADER_SIZE = 34;
static constexpr size_t TIMESTAMP_MESSAGE_SIZE = HEADER_SIZE + 10;
static constexpr size_t ANNOUNCE_SIZE = 64;
static constexpr uint8_t TYPE_SYNC = 0x0;
static constexpr uint8_t TYPE_FOLLOW_UP = 0x8;
static constexpr uint8_t TYPE_ANNOUNCE = 0xb;
static constexpr uint8_t FLAG_TWO_STEP = 0x02;  // In the first byte of the flags
/// Samples a clock needs before its offset is used
static constexpr uint32_t MIN_SAMPLES = 4;
/// A clock without samples for this long is not used, and its slot may go to another one
static constexpr int64_t CLOCK_TIMEOUT_US = 5000000;
static constexpr int64_t LOG_INTERVAL_US = 10000000;
static constexpr int64_t ANNOUNCE_INTERVAL_US = 2000000;
/// How fast two clocks may drift apart (quartz crystals stay within 50 ppm each)
static constexpr int64_t MAX_DRIFT_PPM = 100;
/// Samples this far below the estimate all the time mean the clock was set back
static constexpr int64_t STEP_NS = 20000000;
static constexpr uint32_t STEP_SAMPLES = 64;  // 8 s of Sync messages
/// Samples this far below are no delay but a clock that jumped (macOS stops its clock while it sleeps): a few
/// confirm it
static constexpr int64_t JUMP_NS = 1000000000;
static constexpr uint32_t JUMP_SAMPLES = 3;
/// After the first second, a sample more than this above the estimate counts only when the next ones confirm it
static constexpr int64_t RISE_NS = 2000000;
static constexpr uint32_t RISE_CONFIRMATIONS = 3;
static constexpr uint32_t SETTLE_SAMPLES = 8;

static uint64_t read_be(const uint8_t *data, size_t bytes) {
  uint64_t value = 0;
  for (size_t i = 0; i < bytes; i++)
    value = (value << 8) | data[i];
  return value;
}

/// Seconds (48 bits) and nanoseconds (32 bits) of a PTP timestamp
static int64_t read_timestamp_ns(const uint8_t *data) {
  return static_cast<int64_t>(read_be(data, 6)) * 1000000000LL + static_cast<int64_t>(read_be(data + 6, 4));
}

static void write_be(uint8_t *data, uint64_t value, size_t bytes) {
  for (size_t i = 0; i < bytes; i++)
    data[i] = static_cast<uint8_t>(value >> (8 * (bytes - 1 - i)));
}

static void format_address(uint32_t address, char *buffer, size_t size) {
  const auto *ip = reinterpret_cast<const uint8_t *>(&address);
  std::snprintf(buffer, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

void PtpClocks::handle(bool general, const uint8_t *data, size_t length, uint32_t from_address, int64_t now_us) {
  if (length < HEADER_SIZE || (data[1] & 0x0f) != 2)
    return;
  const uint8_t type = data[0] & 0x0f;
  const uint64_t id = read_be(data + 20, 8);
  const auto sequence = static_cast<uint16_t>(read_be(data + 30, 2));
  // The first message of every type and port, to see what a sender expects
  const uint32_t type_bit = 1u << (type + (general ? 16 : 0));
  if ((this->types_logged_ & type_bit) == 0) {
    this->types_logged_ |= type_bit;
    char address[16];
    format_address(from_address, address, sizeof(address));
    AIRPLAY_LOGV("PTP message type %u on port %u from %s (clock %016" PRIx64 ", %u bytes, flags %02x%02x, "
                 "interval %d)",
                 type, general ? 320 : 319, address, id, static_cast<unsigned>(length), data[6], data[7],
                 static_cast<int8_t>(data[33]));
  }
  // Nanoseconds times 2^16
  const int64_t correction_ns = static_cast<int64_t>(read_be(data + 8, 8)) / 65536;

  if (type == TYPE_ANNOUNCE && general && length >= ANNOUNCE_SIZE) {
    // Several senders may each be a grandmaster (an iPhone and a Mac that both had the receiver selected): each
    // clock keeps what it announces, and the receiver follows the one its session uses
    Clock *clock = this->find_(id, from_address, now_us);
    if (clock == nullptr)
      return;
    const uint64_t grandmaster = read_be(data + 53, 8);
    if (!clock->has_announce || grandmaster != read_be(clock->announce + 6, 8)) {
      char address[16];
      format_address(from_address, address, sizeof(address));
      AIRPLAY_LOGD("PTP grandmaster %016" PRIx64 " announced by %016" PRIx64 " (%s, domain %u, priority %u/%u, "
                   "class %u, %u steps)",
                   grandmaster, id, address, data[4], data[47], data[52], data[48],
                   static_cast<unsigned>(read_be(data + 61, 2)));
    }
    std::copy(data + 47, data + 64, clock->announce);
    clock->has_announce = true;
    clock->domain = data[4];
    this->grandmaster_ = grandmaster;
    return;
  }
  if (length < TIMESTAMP_MESSAGE_SIZE)
    return;
  if (type == TYPE_SYNC && !general) {
    Clock *clock = this->find_(id, from_address, now_us);
    if (clock == nullptr)
      return;
    clock->domain = data[4];
    clock->syncs++;
    if (this->grandmaster_ == 0)
      this->grandmaster_ = id;
    if ((data[6] & FLAG_TWO_STEP) != 0) {
      // The time it was sent follows in a Follow_Up
      clock->sync_pending = true;
      clock->sync_sequence = sequence;
      clock->sync_received_ns = now_us * 1000;
      clock->sync_correction_ns = correction_ns;
    } else {
      clock->sync_pending = false;
      this->add_sample_(*clock, read_timestamp_ns(data + 34) + correction_ns - now_us * 1000, now_us);
    }
  } else if (type == TYPE_FOLLOW_UP && general) {
    Clock *clock = this->find_(id, from_address, now_us);
    if (clock == nullptr)
      return;
    if (!clock->sync_pending || clock->sync_sequence != sequence)
      return;
    clock->sync_pending = false;
    // Sent at the precise origin time, received at sync_received_ns: the difference is the offset less the delay
    const int64_t sent_ns = read_timestamp_ns(data + 34) + correction_ns + clock->sync_correction_ns;
    if (clock->count == 0) {
      AIRPLAY_LOGV("PTP clock %016" PRIx64 ": sent at %" PRId64 ".%09" PRId64 " s (corrections %" PRId64 " and %" PRId64
                   " ns), received at %" PRId64 ".%06" PRId64 " s here",
                   clock->id, sent_ns / 1000000000, sent_ns % 1000000000, clock->sync_correction_ns, correction_ns,
                   clock->sync_received_ns / 1000000000, (clock->sync_received_ns / 1000) % 1000000);
    }
    this->add_sample_(*clock, sent_ns - clock->sync_received_ns, now_us);
  }
}

PtpClocks::Clock *PtpClocks::find_(uint64_t id, uint32_t address, int64_t now_us) {
  Clock *free = nullptr;
  for (Clock &clock : this->clocks_) {
    const bool in_use = clock.last_seen_us != 0 && now_us - clock.last_seen_us <= CLOCK_TIMEOUT_US;
    if (in_use && clock.id == id) {
      clock.last_seen_us = now_us;
      return &clock;
    }
    if (!in_use && free == nullptr)
      free = &clock;
  }
  if (free == nullptr)
    return nullptr;
  char text[16];
  format_address(address, text, sizeof(text));
  AIRPLAY_LOGD("PTP clock %016" PRIx64 " from %s", id, text);
  *free = Clock{};
  free->id = id;
  free->address = address;
  free->last_seen_us = now_us;
  return free;
}

void PtpClocks::add_sample_(Clock &clock, int64_t sample, int64_t now_us) {
  clock.samples[clock.count % WINDOW] = sample;
  if (clock.count == 0) {
    clock.estimate = sample;
  } else {
    const int64_t drifted = clock.estimate - (now_us - clock.last_sample_us) * MAX_DRIFT_PPM / 1000;
    if (sample > drifted + RISE_NS && clock.count >= SETTLE_SAMPLES) {
      // Far better than the estimate: a single one is an error (macOS sends a correction of 100 ms now and then),
      // several in a row show that the estimate was low
      clock.above_lowest = clock.above == 0 ? sample : std::min(clock.above_lowest, sample);
      clock.estimate = ++clock.above >= RISE_CONFIRMATIONS ? clock.above_lowest : drifted;
      if (clock.above >= RISE_CONFIRMATIONS)
        clock.above = 0;
    } else {
      clock.above = 0;
      clock.estimate = std::max(sample, drifted);
    }
    // A clock that was set back sends samples far below the estimate for longer than the receiver is ever busy, or
    // so far below that no delay explains them: start over from them
    if (sample < clock.estimate - STEP_NS) {
      clock.below++;
      if (clock.below >= STEP_SAMPLES || (clock.below >= JUMP_SAMPLES && sample < clock.estimate - JUMP_NS)) {
        AIRPLAY_LOGD("PTP clock %016" PRIx64 " jumped by %" PRId64 " ms", clock.id,
                     (best_recent_(clock, clock.below) - clock.estimate) / 1000000);
        clock.estimate = best_recent_(clock, clock.below);
        clock.below = 0;
      }
    } else {
      clock.below = 0;
    }
  }
  clock.count++;
  clock.last_sample_us = now_us;
}

int64_t PtpClocks::best_recent_(const Clock &clock, uint32_t samples) {
  // The sample just added is at clock.count % WINDOW
  int64_t best = clock.samples[clock.count % WINDOW];
  for (uint32_t i = 1; i < std::min<uint32_t>(samples, WINDOW); i++)
    best = std::max(best, clock.samples[(clock.count + WINDOW - i) % WINDOW]);
  return best;
}

const PtpClocks::Clock *PtpClocks::active_(uint64_t id, int64_t now_us) const {
  if (id == 0)
    id = this->grandmaster_;
  for (const Clock &clock : this->clocks_) {
    if (clock.id == id && clock.count >= MIN_SAMPLES && now_us - clock.last_sample_us <= CLOCK_TIMEOUT_US)
      return &clock;
  }
  return nullptr;
}

bool PtpClocks::offset_ns(uint64_t id, int64_t now_us, int64_t *offset) const {
  const Clock *clock = this->active_(id, now_us);
  if (clock == nullptr)
    return false;
  *offset = clock->estimate;
  return true;
}

void PtpClocks::set_identity(const uint8_t mac[6]) {
  // EUI-64 from the MAC address
  this->identity_ = (static_cast<uint64_t>(mac[0]) << 56) | (static_cast<uint64_t>(mac[1]) << 48) |
                    (static_cast<uint64_t>(mac[2]) << 40) | (0xfffeULL << 24) | (static_cast<uint64_t>(mac[3]) << 16) |
                    (static_cast<uint64_t>(mac[4]) << 8) | mac[5];
}

void PtpClocks::write_header_(uint8_t *buffer, uint8_t type, size_t length, uint8_t domain, uint16_t sequence,
                              uint8_t control, int8_t log_interval) const {
  std::fill(buffer, buffer + length, 0);
  buffer[0] = type;
  buffer[1] = 2;
  write_be(buffer + 2, length, 2);
  buffer[4] = domain;
  write_be(buffer + 20, this->identity_, 8);
  write_be(buffer + 28, 1, 2);  // Port number
  write_be(buffer + 30, sequence, 2);
  buffer[32] = control;
  buffer[33] = static_cast<uint8_t>(log_interval);
}

size_t PtpClocks::next_message(uint64_t clock, uint8_t *buffer, int64_t now_us, uint32_t *to_address, bool *general) {
  const Clock *master = this->active_(clock, now_us);
  if (master == nullptr && clock != 0)
    master = this->active_(0, now_us);
  if (master == nullptr || this->identity_ == 0)
    return 0;
  *to_address = master->address;
  if (now_us - this->last_announce_us_ >= ANNOUNCE_INTERVAL_US) {
    // A clock that loses every comparison (priority 255, class 255: slave only), so that the grandmaster knows
    // this receiver takes part
    this->last_announce_us_ = now_us;
    write_header_(buffer, TYPE_ANNOUNCE, ANNOUNCE_SIZE, master->domain, this->announce_sequence_++, 5, 1);
    write_be(buffer + 44, 37, 2);  // UTC offset
    if (master->has_announce) {
      // Follows the grandmaster: its details, one step further away, which never wins against it
      std::copy(master->announce, master->announce + 17, buffer + 47);
      write_be(buffer + 61, read_be(buffer + 61, 2) + 1, 2);
    } else {
      buffer[47] = 255;   // Priority 1
      buffer[48] = 255;   // Clock class: slave only
      buffer[49] = 0xfe;  // Accuracy unknown
      write_be(buffer + 50, 0xffff, 2);
      buffer[52] = 255;  // Priority 2
      write_be(buffer + 53, this->identity_, 8);
      buffer[63] = 0xa0;  // Internal oscillator
    }
    *general = true;
    return ANNOUNCE_SIZE;
  }
  return 0;
}

void PtpClocks::log_status(int64_t now_us) {
  if (detail::g_log_level < LogLevel::LOG_LEVEL_VERBOSE || now_us - this->last_log_us_ < LOG_INTERVAL_US)
    return;
  this->last_log_us_ = now_us;
  for (Clock &clock : this->clocks_) {
    if (clock.last_seen_us == 0 || now_us - clock.last_seen_us > CLOCK_TIMEOUT_US)
      continue;
    const size_t used = std::min<size_t>(clock.count, WINDOW);
    int64_t spread = 0;
    int64_t best = 0;
    if (used > 0) {
      const auto [low, high] = std::minmax_element(clock.samples, clock.samples + used);
      spread = *high - *low;
      best = clock.estimate;
    }
    AIRPLAY_LOGV("PTP clock %016" PRIx64 ": %" PRIu32 " Sync in %" PRId64 " s, offset %" PRId64 " ms, spread %" PRId64
                 " us",
                 clock.id, clock.syncs, LOG_INTERVAL_US / 1000000, best / 1000000, spread / 1000);
    clock.syncs = 0;
  }
}

}  // namespace airplay
