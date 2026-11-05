# airplay-cpp

Native C++17 AirPlay 1 and 2 audio receiver library.

Targets:

- **ESP-IDF** (5, 6): ESP32 with Wi-Fi, runs on an ESP32-S3; also as an ESPHome component,
  [esphome-airplay](https://github.com/mvoss96/esphome-airplay)
- **Arduino ESP32** (core 3): example built in CI
- **Linux**: all interop tests run here
- **Zephyr**: built and streamed to in CI as `native_sim`, not yet on a real board
- **macOS**: POSIX example, not tested

Crypto through mbedTLS 2.28, 3.x or 4.x.

## What makes it different

It is written for microcontrollers first. There are no exceptions, no RTTI and no heap allocation after
`begin()`, and the large buffers can go to external RAM. The protocol core does no I/O of its own: a runner for
BSD sockets is included, and other platforms implement a small `Transport` interface.

Playback is synchronized to the sender's clock and corrects drift one frame at a time at the quietest point, so
sound stays in sync with video. Lost packets are requested again. Cover art is passed on in pieces as it
arrives, so a 200 KB image does not need 200 KB of RAM. A second sender can take over a session; the first one
is paused, stays connected and can take it back. The receiver can also control the sender: play, pause, next,
previous and volume.

## Usage

```cpp
airplay::Receiver receiver(config, crypto, runner, output);  // output: your airplay::AudioSink
crypto.init();
receiver.begin();
runner.begin(receiver);
while (true)
  runner.run_once();
```

[examples](examples) has complete programs for ESP-IDF, Arduino ESP32, Zephyr and POSIX. With the ESP-IDF
component manager:

```yaml
dependencies:
  mvoss96/airplay-cpp:
    git: https://github.com/mvoss96/airplay-cpp.git
```

## Memory

On the ESP32, synchronized playback buffers about 2.5 s of audio (460 KB), and AirPlay 2 adds 128 KB for AAC
audio, so both need PSRAM. Without PSRAM AirPlay 1 plays unsynchronized with a 500 ms buffer.

## Limitations

- 44.1 kHz, 16-bit stereo: no lossless high resolution, no video or screen mirroring
- macOS streams only with PTP timing, which needs `ReceiverConfig::ptp` and UDP ports 319 and 320 (not on Zephyr;
  root on Linux)
- The receiver can be added to the Home app. The application keeps the pairings (`Receiver::homekit_pairings()`,
  `Listener::on_homekit_pairings()`). Access is not restricted to the Home's members, and the Home app's tile shows
  "control not available", as for other receivers without Apple's MFi authentication
- A password works with AirPlay 1 only
- AirPlay 2 buffered audio needs an AAC decoder from the application (`AacDecoder`)

## Tests

```sh
cmake -S . -B build -DAIRPLAY_BUILD_TESTS=ON && cmake --build build && ctest --test-dir build
```

CI also streams to the POSIX example from pyatv, PipeWire and a buffered AAC sender, with and without packet
loss, and builds every example.

## Credits

Protocol handling follows [shairport-sync](https://github.com/mikebrady/shairport-sync), the position servo
[airplay-esp32](https://github.com/rbouteiller/airplay-esp32), and the ALAC decoder Apple's
[reference decoder](https://github.com/macosforge/alac). See [NOTICE](NOTICE).

MIT license. AirPlay is a trademark of Apple Inc.; this project is not affiliated with Apple.
