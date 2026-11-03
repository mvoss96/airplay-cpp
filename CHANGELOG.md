# Changelog

## v0.2.0

- PTP timing for AirPlay 2 (`ReceiverConfig::ptp`, `Transport::open_ptp()`), which macOS needs: the receiver
  follows the sender's PTP clock and takes part in PTP as a clock that never becomes master
- Buffered audio: overdue audio is dropped without decoding, and decoding speeds up while the jitter buffer is low
- The first packets after a start are lined up exactly when they are late
- Synchronized start waits until the output plays, so that an output that starts slowly does not play late
- `ReceiverConfig::output_queue_ms`; `Receiver::take_playback_timing()`
- Remote control details are reported in every session; silence does not keep a held sender playing
- Faster ALAC decoding and ChaCha20-Poly1305 on the ESP32 (internal RAM, no calls in the inner loops)

## v0.1.0

First release.

- AirPlay 1 (RAOP) receiver: RTSP, ALAC and PCM, RSA/AES encrypted streams
- Playback synchronized to the sender's clock with a position servo; unsynchronized playback with buffer level
  control for small buffers
- Retransmission of lost packets, silence for packets that never arrive
- Volume, mute, track details, cover art (passed on in pieces, without a large buffer), track position and
  remote control (DACP) helpers
- Optional password (RTSP Digest authentication)
- Sans-I/O core with a BSD socket runner for ESP-IDF, Arduino-ESP32, Zephyr, Linux and macOS
- mbedTLS crypto backend for 2.28, 3.x and 4.x (PSA crypto API, as in ESP-IDF 6)
- Examples for ESP-IDF, Arduino ESP32, Zephyr and POSIX
- `SocketRunner::set_udp_base_port()` for fixed UDP ports (NAT, containers)
