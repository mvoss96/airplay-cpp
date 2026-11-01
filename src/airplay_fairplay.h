#pragma once

#include <cstddef>
#include <cstdint>

namespace airplay {

inline constexpr size_t FAIRPLAY_SETUP_REPLY_SIZE = 142;

/// @brief Answers a FairPlay setup message (POST /fp-setup). iOS asks for it before streaming to AirPlay 2
/// receivers that announce FairPlay (feature bit 14). AirPlay 2 audio keys arrive in SETUP, so only this handshake
/// is needed, not FairPlay decryption.
/// @param reply Receives up to FAIRPLAY_SETUP_REPLY_SIZE bytes.
/// @return the length of the reply, or 0 if the message is not one this receiver can answer.
size_t fairplay_setup_reply(const uint8_t *message, size_t length, uint8_t *reply, size_t size);

}  // namespace airplay
