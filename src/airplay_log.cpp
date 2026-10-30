#include "airplay_log.h"

#include <cstdarg>
#include <cstdio>

namespace airplay {

namespace detail {
LogLevel g_log_level = LogLevel::LOG_LEVEL_NONE;
static LogHandler g_log_handler = nullptr;

void log(LogLevel level, const char *format, ...) {
  if (g_log_handler == nullptr)
    return;
  char message[192];
  va_list args;
  va_start(args, format);
  vsnprintf(message, sizeof(message), format, args);
  va_end(args);
  g_log_handler(level, message);
}
}  // namespace detail

void set_log_handler(LogHandler handler, LogLevel max_level) {
  detail::g_log_handler = handler;
  detail::g_log_level = handler != nullptr ? max_level : LogLevel::LOG_LEVEL_NONE;
}

}  // namespace airplay
