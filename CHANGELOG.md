# Changelog

## v0.1.0

First release.

- AirPlay 1 (RAOP) receiver: RTSP, ALAC and PCM, RSA/AES encrypted streams
- Playback synchronized to the sender's clock with a position servo; unsynchronized playback with buffer level
  control for small buffers
- Retransmission of lost packets, silence for packets that never arrive
- Volume, mute, track details, cover art (passed on in pieces, without a large buffer) and remote control
  (DACP) helpers
- Sans-I/O core with a BSD socket runner for ESP-IDF, Arduino-ESP32, Zephyr, Linux and macOS
- mbedTLS 2.28 and 3.x crypto backend
- Examples for ESP-IDF, Arduino ESP32, Zephyr and POSIX
- `SocketRunner::set_udp_base_port()` for fixed UDP ports (NAT, containers)
