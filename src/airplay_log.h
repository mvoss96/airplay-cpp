#pragma once

#include <cstdint>

namespace airplay {

enum class LogLevel : uint8_t {
  LOG_LEVEL_NONE = 0,
  LOG_LEVEL_ERROR,
  LOG_LEVEL_WARN,
  LOG_LEVEL_INFO,
  LOG_LEVEL_DEBUG,
  LOG_LEVEL_VERBOSE,
};

/// Receives formatted log messages (without a trailing newline)
using LogHandler = void (*)(LogLevel level, const char *message);

/// @brief Routes the library's log messages to a handler, up to a maximum level. Logging is off by default.
void set_log_handler(LogHandler handler, LogLevel max_level = LogLevel::LOG_LEVEL_INFO);

namespace detail {
extern LogLevel g_log_level;
void log(LogLevel level, const char *format, ...) __attribute__((format(printf, 2, 3)));
}  // namespace detail

}  // namespace airplay

#define AIRPLAY_LOG_(level, ...) \
  do { \
    if (static_cast<uint8_t>(level) <= static_cast<uint8_t>(::airplay::detail::g_log_level)) \
      ::airplay::detail::log(level, __VA_ARGS__); \
  } while (0)
#define AIRPLAY_LOGE(...) AIRPLAY_LOG_(::airplay::LogLevel::LOG_LEVEL_ERROR, __VA_ARGS__)
#define AIRPLAY_LOGW(...) AIRPLAY_LOG_(::airplay::LogLevel::LOG_LEVEL_WARN, __VA_ARGS__)
#define AIRPLAY_LOGI(...) AIRPLAY_LOG_(::airplay::LogLevel::LOG_LEVEL_INFO, __VA_ARGS__)
#define AIRPLAY_LOGD(...) AIRPLAY_LOG_(::airplay::LogLevel::LOG_LEVEL_DEBUG, __VA_ARGS__)
#define AIRPLAY_LOGV(...) AIRPLAY_LOG_(::airplay::LogLevel::LOG_LEVEL_VERBOSE, __VA_ARGS__)
