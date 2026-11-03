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
static constexpr uint8_t TYPE_DELAY_REQ = 0x1;
static constexpr uint8_t TYPE_FOLLOW_UP = 0x8;
static constexpr uint8_t TYPE_DELAY_RESP = 0x9;
static constexpr uint8_t TYPE_ANNOUNCE = 0xb;
static constexpr size_t DELAY_RESP_SIZE = 54;
static constexpr uint8_t FLAG_TWO_STEP = 0x02;  // In the first byte of the flags
/// Samples a clock needs before its offset is used
static constexpr uint32_t MIN_SAMPLES = 4;
/// A clock without samples for this long is not used, and its slot may go to another one
static constexpr int64_t CLOCK_TIMEOUT_US = 5000000;
static constexpr int64_t LOG_INTERVAL_US = 10000000;
static constexpr int64_t DELAY_REQUEST_INTERVAL_US = 1000000;
static constexpr int64_t ANNOUNCE_INTERVAL_US = 2000000;
/// Delay measurements needed before they correct the offset
static constexpr uint32_t MIN_DELAY_SAMPLES = 2;

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
  if (type == TYPE_DELAY_RESP && general && length >= DELAY_RESP_SIZE) {
    // The grandmaster's receive time of our Delay_Req
    if (!this->delay_pending_ || id != this->delay_clock_ || sequence != this->delay_sequence_ ||
        read_be(data + 44, 8) != this->identity_)
      return;
    this->delay_pending_ = false;
    for (Clock &clock : this->clocks_) {
      if (clock.id != id || clock.last_seen_us == 0)
        continue;
      clock.delay_samples[clock.delay_count % WINDOW] =
          read_timestamp_ns(data + 34) - correction_ns - this->delay_sent_ns_;
      clock.delay_count++;
      clock.delay_responses++;
    }
    return;
  }
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
  // Every Sync sample is the offset less the delay to us, every Delay_Resp sample the offset plus the delay back:
  // the largest of the first and the smallest of the second have the least delay, and with a symmetric path their
  // mean is the offset
  const int64_t sync = *std::max_element(clock->samples, clock->samples + std::min<size_t>(clock->count, WINDOW));
  if (clock->delay_count < MIN_DELAY_SAMPLES) {
    *offset = sync;
    return true;
  }
  const int64_t delay =
      *std::min_element(clock->delay_samples, clock->delay_samples + std::min<size_t>(clock->delay_count, WINDOW));
  *offset = sync + (delay - sync) / 2;
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

size_t PtpClocks::next_message(uint8_t *buffer, int64_t now_us, uint32_t *to_address, bool *general) {
  const Clock *master = this->active_(0, now_us);
  if (master == nullptr || this->identity_ == 0)
    return 0;
  *to_address = master->address;
  if (now_us - this->last_announce_us_ >= ANNOUNCE_INTERVAL_US) {
    // A clock that loses every comparison (priority 255, class 255: slave only), so that the grandmaster knows
    // this receiver takes part
    this->last_announce_us_ = now_us;
    write_header_(buffer, TYPE_ANNOUNCE, ANNOUNCE_SIZE, master->domain, this->announce_sequence_++, 5, 1);
    write_be(buffer + 44, 37, 2);  // UTC offset
    buffer[47] = 255;              // Priority 1
    buffer[48] = 255;              // Clock class
    buffer[49] = 0xfe;             // Accuracy unknown
    write_be(buffer + 50, 0xffff, 2);
    buffer[52] = 255;  // Priority 2
    write_be(buffer + 53, this->identity_, 8);
    buffer[63] = 0xa0;  // Internal oscillator
    *general = true;
    return ANNOUNCE_SIZE;
  }
  if (now_us - this->last_delay_request_us_ >= DELAY_REQUEST_INTERVAL_US) {
    this->last_delay_request_us_ = now_us;
    this->delay_sequence_++;
    this->delay_pending_ = true;
    this->delay_clock_ = master->id;
    this->delay_sent_ns_ = now_us * 1000;
    write_header_(buffer, TYPE_DELAY_REQ, TIMESTAMP_MESSAGE_SIZE, master->domain, this->delay_sequence_, 1, 0x7f);
    *general = false;
    return TIMESTAMP_MESSAGE_SIZE;
  }
  return 0;
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
    int64_t delay = 0;
    if (clock.delay_count > 0) {
      const int64_t back =
          *std::min_element(clock.delay_samples, clock.delay_samples + std::min<size_t>(clock.delay_count, WINDOW));
      delay = (back - best) / 2;
    }
    AIRPLAY_LOGD("PTP clock %016" PRIx64 ": %" PRIu32 " Sync, %" PRIu32 " Follow_Up, %" PRIu32
                 " Delay_Resp, offset %" PRId64 " ms, spread %" PRId64 " us, delay %" PRId64 " us",
                 clock.id, clock.syncs, clock.follow_ups, clock.delay_responses, best / 1000000, spread / 1000,
                 delay / 1000);
    clock.syncs = 0;
    clock.follow_ups = 0;
    clock.delay_responses = 0;
  }
}

}  // namespace airplay
