# Zephyr example

Builds the receiver for `native_sim`, where Zephyr runs as a Linux program and uses the host's sockets. It
offers AirPlay 2 with PTP timing, which macOS needs; the PTP ports 319 and 320 need root:

```sh
west build -b native_sim/native/64 examples/zephyr
sudo ./build/zephyr/zephyr.exe
```

On real hardware, add a board overlay that enables the board's network interface, and replace the `NullOutput`
in `src/main.cpp` with the board's audio driver (for example the I2S API). Announce the receiver with Zephyr's
DNS-SD (`DNS_SD_REGISTER_TCP_SERVICE`) using the instance name and TXT records the receiver provides.
