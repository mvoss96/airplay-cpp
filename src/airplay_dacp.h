#pragma once

// Remote control of the sender (DACP): play, pause, next, previous and volume.
//
// The sender announces an mDNS service "_dacp._tcp" whose instance name contains RemoteTarget::dacp_id
// (usually "iTunes_Ctrl_<id>"). Find its port with your mDNS library, then send commands with
// send_dacp_command() (airplay_socket_runner.h) or with your own HTTP client using dacp_format_request().

#include "airplay_types.h"

#include <cstddef>
#include <cstdint>

namespace airplay {

inline constexpr char DACP_SERVICE_TYPE[] = "_dacp";
inline constexpr char DACP_SERVICE_PROTOCOL[] = "_tcp";

inline constexpr char DACP_PLAY[] = "play";
inline constexpr char DACP_PAUSE[] = "pause";
inline constexpr char DACP_PLAY_PAUSE[] = "playpause";
inline constexpr char DACP_NEXT[] = "nextitem";
inline constexpr char DACP_PREVIOUS[] = "previtem";
inline constexpr char DACP_VOLUME_UP[] = "volumeup";
inline constexpr char DACP_VOLUME_DOWN[] = "volumedown";

/// iPhone and iPad ignore dacp_volume_command(): their slider moves only with DACP_VOLUME_UP and
/// DACP_VOLUME_DOWN, by this much (0 to 1 scale) per command
inline constexpr float DACP_VOLUME_STEP = 1.0f / 16.0f;

/// @brief Whether an mDNS instance name of a "_dacp._tcp" service belongs to the target (case-insensitive).
bool dacp_instance_matches(const char *instance_name, const char *dacp_id);

/// @brief Formats the command that moves the sender's volume slider.
/// @param volume 0 to 1; 0 mutes.
/// @return Length of the command, or 0 if the buffer is too small.
size_t dacp_volume_command(float volume, char *buffer, size_t size);

/// @brief Number of DACP_VOLUME_STEP steps from one volume (0 to 1) to another, rounded to the nearest.
/// @return Positive for DACP_VOLUME_UP, negative for DACP_VOLUME_DOWN.
int dacp_volume_steps(float from, float to);

/// @brief Formats the HTTP request of a command, e.g. DACP_PLAY or the output of dacp_volume_command().
/// @return Length of the request, or 0 if the buffer is too small.
size_t dacp_format_request(const RemoteTarget &target, uint16_t port, const char *command, char *buffer, size_t size);

/// @brief Reads the HTTP status code from the start of a reply.
/// @return The status code, or 0 if the reply is not HTTP.
int dacp_parse_status(const char *reply, size_t length);

}  // namespace airplay
