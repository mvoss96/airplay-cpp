#pragma once

#include <cstddef>
#include <cstdint>

namespace airplay {

/// First in, first out queue of variable length packets in a fixed buffer, for the compressed audio that AirPlay 2
/// senders send ahead. Each packet is kept in one piece.
class PacketQueue {
 public:
  static constexpr size_t HEADER_SIZE = 10;

  /// @brief Uses `storage` (not owned) for the packets.
  void init(uint8_t *storage, size_t size);
  /// @return false if the packet does not fit now
  bool push(uint32_t rtp, uint32_t seq, const uint8_t *data, uint16_t length);
  /// @brief The oldest packet. The data stays valid until pop() or clear().
  /// @return false if the queue is empty
  bool front(uint32_t *rtp, uint32_t *seq, const uint8_t **data, uint16_t *length);
  void pop();
  void clear();
  bool empty() const { return this->used_ == 0; }
  size_t size() const { return this->size_; }
  /// Bytes not in use; a packet of up to this size minus HEADER_SIZE and some waste at the end of the buffer fits
  size_t free_bytes() const { return this->size_ - this->used_; }

 private:
  static constexpr uint16_t WRAP_MARKER = 0xffff;
  /// Moves the read position past the unused end of the buffer
  void skip_wrap_();

  uint8_t *data_{nullptr};
  size_t size_{0};
  size_t read_{0};
  size_t write_{0};
  size_t used_{0};  // Bytes between read_ and write_, including what is skipped at the end
};

}  // namespace airplay
