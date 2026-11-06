# Changelog

## v0.5.0

- The Home app's tile can control playback without Apple's MFi authentication, also on devices other than the
  sender (an iPad): the receiver relays remote control between a controller and the playing AirPlay 2 sender, as
  other AirPlay 2 speakers do. A controller sets up a remote control stream (type 130) while a session exists, also
  when it is paused. Its messages go to the sender's event connection and back, in any size.
- The _airplay TXT records as AirPlay 2 speakers announce them: without psi, vv, fex and igl, the status flags in
  lowercase hex, and isGroupLeader=0 while in a sender's group. `Listener::on_group()` has a third parameter for it
  (`in_group`). _raop has vs=366.0.
- Relay details are logged at verbose level

## v0.4.0

- HomeKit pairings can be kept across restarts: `Receiver::homekit_pairings()` and `set_homekit_pairings()`, with
  `Listener::on_homekit_pairings()` when they change. Access control ends with the last admin.
- The status flags in the TXT records (`flags`, `sf`) and /info carry HomeKit access control (0x400), with
  `Listener::on_status_flags()` when they change
- While a sender's session plays, its group (`groupUUID`, `groupContainsGroupLeader`) is announced as `gid` and
  `gcgl` with status flag 0x800, as other AirPlay 2 speakers do (`Listener::on_group()`); /info carries `gid`
- Feature bits 15-17 (cover art, progress and text in the AirPlay 1 way)
- `ReceiverConfig::homekit_identity`: a number other than 0 gives the receiver a new HomeKit key and pairing
  identifier, so that a home holding a broken setup of it can add it again (the device ID stays the MAC)
- The Home app's tile still shows "control not available", even with the same status signals as an MFi speaker;
  the remaining difference is Apple's MFi authentication

## v0.3.0

- HomeKit pairing: the Home app can add the receiver (pair-setup with the fixed PIN, pair-verify with the Home's
  keys, pair-add/remove/list, POST /configure). Like shairport-sync, pairings are kept in RAM only.
- A session that only controls playback (as the Home app sets up) may send RECORD
- PTP: when a second AirPlay 2 speaker joins an iPhone's session, the receiver follows the group's new grandmaster:
  the anchor moves with a clock jump while playing, and an anchor in another clock's time follows that clock
- PTP: before the sender names its timeline, the receiver follows the sender's own clock; after a jump, the middle
  of the three confirming samples
- Logs why a playing session gives no audio, and which PTP clock is used
- ESP-IDF example: the large single app partition

## v0.2.2

- Music Assistant: pause and resume play again (the audio held from before the pause no longer stops playback), and
  a flush (start, seek) drops the audio sent before it (Music Assistant counts packets in 16 bits)
- PTP: Delay_Req again, for masters that answer them (Music Assistant): the network delay is measured and added to
  the clock offset; masters that answer none (macOS) get no more after five
- The servo corrects timing errors from 2 ms on (was 5 ms), down to 0.5 ms

## v0.2.1

- Buffered ALAC, which Music Assistant sends when the receiver offers PTP: with v0.2.0 it could not play at all
- Buffered audio goes on decoding after playback filled in for audio that came late; before, decoding could stop
- Buffered audio is decoded by the amount of audio per poll, not by the number of packets
- A sender that does not answer on its event connection gets nothing more there after 2 s
- PTP: waits for a clock that went silent or jumped (a sender that slept) instead of playing on a wrong offset

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
