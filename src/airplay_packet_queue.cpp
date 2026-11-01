#include "airplay_packet_queue.h"

#include <cstring>

namespace airplay {

// Packet header: length (2 bytes), RTP timestamp (4), sequence number (4), in host byte order

void PacketQueue::init(uint8_t *storage, size_t size) {
  this->data_ = storage;
  this->size_ = size;
  this->clear();
}

void PacketQueue::clear() {
  this->read_ = 0;
  this->write_ = 0;
  this->used_ = 0;
}

bool PacketQueue::push(uint32_t rtp, uint32_t seq, const uint8_t *data, uint16_t length) {
  const size_t needed = HEADER_SIZE + length;
  if (length == WRAP_MARKER || this->data_ == nullptr || needed > this->size_)
    return false;
  if (this->used_ == 0) {
    this->read_ = 0;
    this->write_ = 0;
  }
  if (this->used_ > 0 && this->write_ <= this->read_) {
    // Writing behind the read position: only the gap up to it is free
    if (this->read_ - this->write_ < needed)
      return false;
  } else if (this->size_ - this->write_ < needed) {
    // Not enough room at the end: continue at the start, if there is room before the read position
    if (this->read_ < needed && this->used_ > 0)
      return false;
    const size_t skipped = this->size_ - this->write_;
    if (skipped >= 2) {
      const uint16_t marker = WRAP_MARKER;
      std::memcpy(this->data_ + this->write_, &marker, sizeof(marker));
    }
    this->used_ += skipped;
    this->write_ = 0;
  }
  uint8_t *out = this->data_ + this->write_;
  std::memcpy(out, &length, 2);
  std::memcpy(out + 2, &rtp, 4);
  std::memcpy(out + 6, &seq, 4);
  if (length > 0)
    std::memcpy(out + HEADER_SIZE, data, length);
  this->write_ += needed;
  if (this->write_ == this->size_)
    this->write_ = 0;
  this->used_ += needed;
  return true;
}

void PacketQueue::skip_wrap_() {
  if (this->used_ == 0)
    return;
  uint16_t length = 0;
  const size_t left = this->size_ - this->read_;
  if (left >= 2)
    std::memcpy(&length, this->data_ + this->read_, 2);
  if (left < HEADER_SIZE || length == WRAP_MARKER) {
    this->used_ -= left;
    this->read_ = 0;
  }
}

bool PacketQueue::front(uint32_t *rtp, uint32_t *seq, const uint8_t **data, uint16_t *length) {
  this->skip_wrap_();
  if (this->used_ == 0)
    return false;
  const uint8_t *in = this->data_ + this->read_;
  std::memcpy(length, in, 2);
  std::memcpy(rtp, in + 2, 4);
  std::memcpy(seq, in + 6, 4);
  *data = in + HEADER_SIZE;
  return true;
}

void PacketQueue::pop() {
  this->skip_wrap_();
  if (this->used_ == 0)
    return;
  uint16_t length = 0;
  std::memcpy(&length, this->data_ + this->read_, 2);
  const size_t total = HEADER_SIZE + length;
  this->read_ += total;
  if (this->read_ == this->size_)
    this->read_ = 0;
  this->used_ -= total;
  if (this->used_ == 0) {
    this->read_ = 0;
    this->write_ = 0;
  }
}

}  // namespace airplay
