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
  // Nanoseconds times 2^16
  const int64_t correction_ns = static_cast<int64_t>(read_be(data + 8, 8)) / 65536;

  if (type == TYPE_ANNOUNCE && general && length >= ANNOUNCE_SIZE) {
    const uint64_t grandmaster = read_be(data + 53, 8);
    if (grandmaster != this->grandmaster_) {
      char address[16];
      format_address(from_address, address, sizeof(address));
      AIRPLAY_LOGD("PTP grandmaster %016" PRIx64 " announced by %016" PRIx64 " (%s, domain %u, priority %u/%u, "
                   "class %u, %u steps)",
                   grandmaster, id, address, data[4], data[47], data[52], data[48],
                   static_cast<unsigned>(read_be(data + 61, 2)));
      this->grandmaster_ = grandmaster;
    }
    return;
  }
  if (length < TIMESTAMP_MESSAGE_SIZE)
    return;
  if (type == TYPE_SYNC && !general) {
    Clock *clock = this->find_(id, from_address, now_us);
    if (clock == nullptr)
      return;
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
    clock->follow_ups++;
    if (!clock->sync_pending || clock->sync_sequence != sequence)
      return;
    clock->sync_pending = false;
    // Sent at the precise origin time, received at sync_received_ns: the difference is the offset less the delay
    const int64_t sent_ns = read_timestamp_ns(data + 34) + correction_ns + clock->sync_correction_ns;
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
  clock.count++;
  clock.last_sample_us = now_us;
}

bool PtpClocks::offset_ns(uint64_t id, int64_t now_us, int64_t *offset) const {
  if (id == 0)
    id = this->grandmaster_;
  for (const Clock &clock : this->clocks_) {
    if (clock.id != id || clock.count < MIN_SAMPLES || now_us - clock.last_sample_us > CLOCK_TIMEOUT_US)
      continue;
    // Every sample is the offset less the network delay: the largest has the least delay
    const size_t used = std::min<size_t>(clock.count, WINDOW);
    *offset = *std::max_element(clock.samples, clock.samples + used);
    return true;
  }
  return false;
}

void PtpClocks::log_status(int64_t now_us) {
  if (now_us - this->last_log_us_ < LOG_INTERVAL_US)
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
      best = *high;
    }
    AIRPLAY_LOGD("PTP clock %016" PRIx64 ": %" PRIu32 " Sync, %" PRIu32 " Follow_Up, offset %" PRId64
                 " ms, spread %" PRId64 " us",
                 clock.id, clock.syncs, clock.follow_ups, best / 1000000, spread / 1000);
    clock.syncs = 0;
    clock.follow_ups = 0;
  }
}

}  // namespace airplay
