# airplay-cpp

AirPlay 1 and 2 audio receiver in C++17 for ESP32, Zephyr, Linux and macOS. No exceptions, no RTTI, no heap
allocation after `begin()`. For ESPHome see [esphome-airplay](https://github.com/mvoss96/esphome-airplay).

```cpp
airplay::Receiver receiver(config, crypto, runner, output);  // output: your airplay::AudioSink
crypto.init();
receiver.begin();
runner.begin(receiver);
while (true)
  runner.run_once();
```

Complete programs for ESP-IDF, Arduino ESP32, Zephyr and POSIX are in [examples](examples).

ESP-IDF component manager:

```yaml
dependencies:
  mvoss96/airplay-cpp:
    git: https://github.com/mvoss96/airplay-cpp.git
```

Tests: `cmake -S . -B build -DAIRPLAY_BUILD_TESTS=ON && cmake --build build && ctest --test-dir build`

## Credits

Protocol handling follows [shairport-sync](https://github.com/mikebrady/shairport-sync), the position servo
[airplay-esp32](https://github.com/rbouteiller/airplay-esp32), and the ALAC decoder Apple's
[reference decoder](https://github.com/macosforge/alac). See [NOTICE](NOTICE).

MIT license. AirPlay is a trademark of Apple Inc.; this project is not affiliated with Apple.
