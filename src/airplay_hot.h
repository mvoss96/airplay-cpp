#pragma once

// Placement of code that runs for every audio sample or packet (internal use).
//
// AIRPLAY_HOT: on the ESP32 in internal RAM, so that it does not wait for the flash cache, which the display and
// the network compete for; not inlined, because the caller stays in flash. AIRPLAY_INLINE: always inlined, for
// small helpers in such loops, where a call costs more than the work on the ESP32.

#if defined(ESP_PLATFORM)
#include <esp_attr.h>
#define AIRPLAY_HOT IRAM_ATTR __attribute__((noinline))
#elif defined(__GNUC__)
#define AIRPLAY_HOT __attribute__((noinline))
#else
#define AIRPLAY_HOT
#endif

#if defined(__GNUC__)
#define AIRPLAY_INLINE inline __attribute__((always_inline))
#else
#define AIRPLAY_INLINE inline
#endif
