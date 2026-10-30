#include "airplay_dacp.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace airplay {

static char lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

bool dacp_instance_matches(const char *instance_name, const char *dacp_id) {
  const size_t id_length = std::strlen(dacp_id);
  if (id_length == 0)
    return false;
  for (const char *p = instance_name; *p != '\0'; p++) {
    size_t i = 0;
    while (i < id_length && p[i] != '\0' && lower(p[i]) == lower(dacp_id[i]))
      i++;
    if (i == id_length)
      return true;
  }
  return false;
}

size_t dacp_volume_command(float volume, char *buffer, size_t size) {
  // -30 to 0 dB, and -144 for silence
  static constexpr float MUTE_THRESHOLD = 0.005f;
  const float clamped = volume < 0.0f ? 0.0f : (volume > 1.0f ? 1.0f : volume);
  const float db = clamped < MUTE_THRESHOLD ? -144.0f : (clamped - 1.0f) * 30.0f;
  const int length = std::snprintf(buffer, size, "setproperty?dmcp.device-volume=%.6f", static_cast<double>(db));
  return length > 0 && static_cast<size_t>(length) < size ? static_cast<size_t>(length) : 0;
}

int dacp_volume_steps(float from, float to) {
  const float steps = (to - from) / DACP_VOLUME_STEP;
  return static_cast<int>(steps < 0.0f ? steps - 0.5f : steps + 0.5f);
}

size_t dacp_format_request(const RemoteTarget &target, uint16_t port, const char *command, char *buffer, size_t size) {
  const auto *ip = reinterpret_cast<const uint8_t *>(&target.address);
  const int length = std::snprintf(buffer, size,
                                   "GET /ctrl-int/1/%s HTTP/1.1\r\n"
                                   "Host: %u.%u.%u.%u:%u\r\n"
                                   "Active-Remote: %s\r\n"
                                   "Connection: close\r\n\r\n",
                                   command, ip[0], ip[1], ip[2], ip[3], port, target.active_remote);
  return length > 0 && static_cast<size_t>(length) < size ? static_cast<size_t>(length) : 0;
}

int dacp_parse_status(const char *reply, size_t length) {
  // "HTTP/1.1 204 No Content"
  if (length < 12 || std::strncmp(reply, "HTTP/", 5) != 0)
    return 0;
  const char *space = static_cast<const char *>(std::memchr(reply, ' ', length));
  if (space == nullptr || static_cast<size_t>(space - reply) + 4 > length)
    return 0;
  int status = 0;
  for (int i = 1; i <= 3; i++) {
    const char c = space[i];
    if (c < '0' || c > '9')
      return 0;
    status = status * 10 + (c - '0');
  }
  return status;
}

}  // namespace airplay
