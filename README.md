# airplay-cpp

AirPlay 1 (RAOP) audio receiver in C++17. Turns an ESP32, a Zephyr board or a Linux machine into a speaker
that iPhone, iPad, Mac, iTunes and other AirPlay senders can stream to.

- **Audio**: ALAC (Apple Lossless) and uncompressed PCM, 44.1 kHz stereo, with or without encryption
- **Synchronized playback**: plays on the sender's timeline, so the sound stays in sync with video and with
  other AirPlay speakers in the same session; corrects clock drift by dropping or repeating single frames at
  the quietest point
- **Robust on Wi-Fi**: jitter buffer, retransmission of lost packets, silence for packets that never arrive
- **Control**: volume and mute from the sender, track title, artist and album, cover art, and remote control
  of the sender (play, pause, next, previous, volume) over DACP
- **Embedded friendly**: no exceptions, no RTTI, no heap allocation after `begin()`, buffers optionally in
  external RAM
- **Portable**: the protocol core does no I/O of its own. A socket runner covers ESP-IDF, Arduino-ESP32,
  Zephyr, Linux and macOS; for anything else implement a small `Transport` interface

Tested with Music.app on macOS 26 (encrypted ALAC, synchronized playback, volume, pause, seek and track
details), [pyatv](https://pyatv.dev) and PipeWire's RAOP sink.

AirPlay 2 is not supported: senders show the receiver as an AirPlay (1) speaker. Multi-room grouping of
several AirPlay 1 speakers from iTunes/Music on a Mac works; the Home app's AirPlay 2 groups do not.

## Quick start

```cpp
#include <airplay.h>

class MyOutput : public airplay::AudioSink {
 public:
  // Interleaved 16-bit stereo at 44.1 kHz. Take what fits without blocking and return the frame count.
  size_t write(const int16_t *samples, size_t frames) override;
};

airplay::MbedtlsCrypto crypto;
airplay::SocketRunner runner;
MyOutput output;

airplay::ReceiverConfig config;
config.name = "Kitchen";
std::memcpy(config.mac, my_mac_address, 6);
config.buffer_ms = 2500;  // Enough for synchronized playback

airplay::Receiver receiver(config, crypto, runner, output);
crypto.init();
receiver.begin();
runner.begin(receiver);  // Listens on port 5000

// Announce "_raop._tcp" on port 5000 with your mDNS library, using
// receiver.service_instance_name() and receiver.txt_records().

while (true) {
  runner.run_once();  // Network, timing and playback; call from one thread
  // Report what the output has actually played (see below)
}
```

Complete programs:

| Example | Platform |
|---|---|
| [`examples/esp_idf`](examples/esp_idf) | ESP-IDF 5.x, I2S amplifier or DAC, mDNS |
| [`examples/arduino_esp32`](examples/arduino_esp32) | Arduino ESP32 core 3.x, I2S |
| [`examples/zephyr`](examples/zephyr) | Zephyr (`native_sim`, adaptable to real boards) |
| [`examples/posix`](examples/posix) | Linux and macOS, writes PCM to stdout (`\| aplay -f cd`) |

## Installation

**ESP-IDF** (component manager), in your `main/idf_component.yml`:

```yaml
dependencies:
  mvoss96/airplay-cpp:
    git: https://github.com/mvoss96/airplay-cpp.git
    version: "v0.1.0"
```

**PlatformIO**: `lib_deps = https://github.com/mvoss96/airplay-cpp.git#v0.1.0`

**Arduino IDE**: download the repository as ZIP and use *Sketch → Include Library → Add .ZIP Library*.

**Zephyr**: add the repository to your west manifest (it is a Zephyr module) and set `CONFIG_AIRPLAY_CPP=y`;
see [`examples/zephyr/prj.conf`](examples/zephyr/prj.conf) for the network and mbedTLS options
(`CONFIG_ZVFS_POLL_MAX` must be at least 6).

**CMake**: `add_subdirectory(airplay-cpp)` and `target_link_libraries(app PRIVATE airplay)`. The mbedTLS
backend is built when `libmbedcrypto` 2.28 or 3.x is found (Debian/Ubuntu: `libmbedtls-dev`). mbedTLS 4 only
has the PSA crypto API and is not supported yet; on macOS, where Homebrew now installs mbedTLS 4, use
`brew install mbedtls@3` and configure with `-DCMAKE_PREFIX_PATH=$(brew --prefix mbedtls@3)`.

## Audio output

`AudioSink::write()` must not block: take as many frames as fit into the output's buffer and return how many
were taken; the rest is offered again later.

For synchronized playback the receiver needs to know when audio is actually heard. Call
`Receiver::notify_played(frames, timestamp_us)` whenever the output has played audio, with the time on the
clock of `SocketRunner::now_us()` (on ESP-IDF that is `esp_timer_get_time()`). Good sources are the I2S
driver's `on_sent` callback (see the ESP-IDF example) or the playback position of your audio pipeline.
`notify_played()` is thread-safe. Without these reports the receiver still plays, but not synchronized.

If the output pipeline is restarted and drops what it holds, call `request_output_restart()`.

## Network

The receiver listens on TCP port 5000 and opens three UDP ports per session (audio, control and timing).
By default the system picks free UDP ports. Behind NAT or in a container, fix them with
`runner.set_udp_base_port(6100)` (ports 6100-6102; the POSIX example reads `AIRPLAY_UDP_PORT`) and forward
the RTSP port and these UDP ports. Avoid 6000-6002 when the sender runs on the same machine: many senders use
6001/6002 themselves. On macOS the built-in AirPlay receiver occupies ports 5000 and 7000: pass another RTSP
port to `SocketRunner::begin()` (the POSIX example reads `AIRPLAY_PORT`), or turn off *AirPlay Receiver* in
System Settings. Docker Desktop on Windows and macOS does not work well, because its port forwarding
hides the sender's address; use host networking on Linux instead.

## Memory

| Buffer | Size |
|---|---|
| Jitter buffer | about 1.4 KB per 8 ms: 500 ms ≈ 100 KB, 2500 ms ≈ 460 KB |
| RTSP and packet buffers | about 7 KB |
| ALAC decoder | about 4 KB |
| Thread stack (RSA operations) | 8 KB recommended |

Synchronized playback needs `buffer_ms` of at least the sender's latency plus 250 ms, about 2250 ms for
current senders. On an ESP32 that means external RAM (PSRAM): pass `allocate`/`deallocate` in the config.
With a smaller buffer the receiver plays unsynchronized with three quarters of the buffer (at most 500 ms) of
delay, which is fine for music.

On ESP-IDF set `CONFIG_LWIP_UDP_RECVMBOX_SIZE=32` so that bursts of audio packets are not dropped, and turn
off Wi-Fi power saving (`esp_wifi_set_ps(WIFI_PS_NONE)`).

## Events and remote control

Pass a `Listener` to get the session state (playing, paused, stopped), volume (0 to 1), mute, track details
(when `config.metadata` is set) and the sender's remote control details. Listener calls happen on the thread
that drives the receiver.

With `config.artwork` set, the receiver also takes the cover art of each track (JPEG or PNG, usually 20 to
200 KB). It does not buffer the image: `on_artwork_begin(format, size)` announces it, and the bytes follow in
pieces through `on_artwork_data()` until `on_artwork_end()`. Return false from `on_artwork_begin()` to skip
an image, e.g. one larger than the memory you have for it. `on_artwork_clear()` means the track has no cover
or the session ended.

To control the sender, find the port of its `_dacp._tcp` mDNS service whose instance name contains
`RemoteTarget::dacp_id` (`dacp_instance_matches()`), then call
`send_dacp_command(target, port, airplay::DACP_PAUSE)` from a thread other than the receiver's; it blocks
for up to 1.5 s. For the volume, iTunes and Music on a Mac take an absolute value from `dacp_volume_command()`;
iPhone and iPad ignore it and only follow `DACP_VOLUME_UP` and `DACP_VOLUME_DOWN`, one `DACP_VOLUME_STEP` (1/16)
each (`dacp_volume_steps()` counts them). Senders report their new volume back through `Listener::on_volume()`.

`request_disconnect()` ends the current session, e.g. when another audio source takes over the speaker. Pause
the sender first with DACP, otherwise it may switch to its own speaker and keep playing there.

## Design

```
                 ┌─────────────────────────────── Receiver ───────────────────────────────┐
 TCP (RTSP) ───► │ RTSP: ANNOUNCE, SETUP, RECORD, FLUSH, TEARDOWN, SET/GET_PARAMETER, OPTIONS │
 UDP audio  ───► │ decrypt (Crypto) ─► decode (ALAC/PCM) ─► jitter buffer ─► playback ─────┼──► AudioSink
 UDP control ──► │ sync packets, retransmissions        ▲ resend requests                   │
 UDP timing  ◄─► │ clock exchange with the sender ───────┘ timeline                          │
                 └──────────────────────────────────────────────────────────────────────────┘
```

`Receiver` is a sans-I/O state machine: it gets connections, data, UDP packets and the time from outside and
sends through the `Transport` interface. `SocketRunner` implements `Transport` with BSD sockets and drives the
receiver with `select()`. `Crypto` is pluggable as well; `MbedtlsCrypto` works with mbedTLS 2.28 and 3.x.

## Testing

```sh
cmake -S . -B build -DAIRPLAY_BUILD_TESTS=ON -DAIRPLAY_BUILD_EXAMPLES=ON
cmake --build build && ctest --test-dir build --output-on-failure
```

- `test_alac`: ALAC streams encoded by ffmpeg, decoded bit-exact
- `test_session`: a whole session with real cryptography: Apple-Challenge signature, RSA-encrypted session
  key, AES-encrypted audio, retransmission, flush, volume, track details, take-over and teardown
- `test_sync`: simulation of a sender, a network with jitter, loss and stalls, and an output with its own
  clock; checks that playback stays within a few milliseconds of the sender's timeline
- `tests/interop`: streams a test signal to the POSIX example from two independent AirPlay senders,
  [pyatv](https://pyatv.dev) (unencrypted, with retransmission) and PipeWire's RAOP sink (RSA/AES-encrypted
  ALAC), and checks that every sample arrives in order and in sync. The same runs repeat with 5 % packet loss,
  2 % reordering and 1 % duplicates, injected into the receiver's UDP sockets by a small `LD_PRELOAD` shim

CI also builds the ESP-IDF, Arduino, PlatformIO and Zephyr examples and runs the Zephyr build against pyatv.

## ESPHome

An ESPHome media source component built on this library is in progress.

## Credits

The protocol handling follows [shairport-sync](https://github.com/mikebrady/shairport-sync), the position
servo [airplay-esp32](https://github.com/rbouteiller/airplay-esp32), and the ALAC decoder Apple's
[reference decoder](https://github.com/macosforge/alac). See [NOTICE](NOTICE).

## License

MIT, see [LICENSE](LICENSE).

AirPlay is a trademark of Apple Inc., registered in the U.S. and other countries. This project is not
affiliated with, authorized or endorsed by Apple Inc.
