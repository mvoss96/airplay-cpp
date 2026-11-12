# Raspberry Pi

Any Raspberry Pi from the 2 on, with Raspberry Pi OS (Bookworm or Trixie), turns
into an AirPlay 1 and 2 receiver: it shows up in the AirPlay list of iPhone,
iPad, Mac, the Home app and Music Assistant, keeps time with the sender (and
with other speakers in an AirPlay 2 group), and applies the volume the sender
sets.

The receiver itself is the [POSIX example](../examples/posix/main.cpp): it writes
44.1 kHz 16-bit stereo PCM to stdout and prints the mDNS command line for the
records of the running instance. Everything else a standalone device needs —
audio output, volume, service supervision, announcement — is in
[packaging/raspberry-pi](../packaging/raspberry-pi).

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/mvoss96/airplay-cpp/main/packaging/raspberry-pi/install.sh | sudo bash
```

The script installs the build dependencies, downloads and builds the source
(2–3 minutes on a Pi 4), installs the service and starts it. Options:

```sh
sudo ./install.sh --name Kitchen --output hdmi
sudo ./install.sh --ref v0.8.0          # build a tag instead of main
sudo ./install.sh --dry-run             # show what would happen
```

`--help` lists all of them, `packaging/raspberry-pi/README.md` the installed
files. Running the script again upgrades the binary and the unit and keeps
`/etc/default/airplay-receiver`.

### Without the script

```sh
sudo apt install cmake g++ libmbedtls-dev libfaad-dev alsa-utils avahi-utils python3
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAIRPLAY_BUILD_EXAMPLES=ON
cmake --build build --parallel

./build/airplay_receiver "My Speaker" | aplay -q -t raw -f cd -B 100000 -F 20000
```

Without the script the receiver stays announced only while it runs and there is
no restart on crash. The `-B 100000` matters, see [Multi-room](#multi-room-and-latency).

## Audio output

The installer offers three choices, `--output`:

| Value | ALSA device | Notes |
| --- | --- | --- |
| `jack` (default) | `airplay` | headphone jack, volume from the sender |
| `hdmi` | `plughw:CARD=vc4hdmi0,DEV=0` | no volume control |
| any ALSA name | as given, e.g. `plughw:CARD=Device,DEV=0` | USB sound card, DAC HAT |

For the jack the installer writes `/etc/alsa/conf.d/60-airplay-softvol.conf`:

```
pcm.airplay {
    type softvol
    slave.pcm "hw:CARD=Headphones,DEV=0"
    control { name "AirPlay" card 0 }
    min_dB -30.0
    max_dB 0.0
    resolution 100
}
```

The sender's volume therefore scales between −30 dB and 0 dB instead of jumping
to silence, and the mixer control `AirPlay` can be adjusted locally too:

```sh
amixer -c 0 sset AirPlay 60%
alsamixer -c 0     # F6 to pick the card, then "AirPlay"
```

On a USB card or HAT, use its ALSA name and set `AIRPLAY_VOLUME=0` — the volume
from the sender is then ignored, because the card has no control the receiver
knows.

## Configuration

`/etc/default/airplay-receiver`, read by the service:

| Setting | Default | Meaning |
| --- | --- | --- |
| `AIRPLAY_NAME` | hostname | name in the AirPlay list |
| `AIRPLAY_PASSWORD` | empty | fixed password; **turns AirPlay 2 off** |
| `AIRPLAY2` | `1` | offer AirPlay 2 |
| `AIRPLAY_PTP` | `1` | PTP timing, needed for macOS and for groups |
| `AIRPLAY_DEVICE` | `airplay` | ALSA device |
| `AIRPLAY_VOLUME` | `1` | apply the sender's volume |
| `AIRPLAY_MIXER_CARD` / `_CONTROL` | `0` / `AirPlay` | which control |
| `AIRPLAY_BUFFER_MS` / `_PERIOD_MS` | `100` / `20` | ALSA buffer, see below |
| `AIRPLAY_DEBUG` | `1` | `2` logs every packet |

After a change: `sudo systemctl restart airplay-receiver`.

A password in `AIRPLAY_PASSWORD` disables AirPlay 2 (a limitation of the
library). AirPlay 2 senders use the password set in the Home app instead, and
those pairings live in RAM: after a restart the Home app pairs again.

## Multi-room and latency

Inside an AirPlay 2 group the sender gives one timeline for all speakers, on a
PTP clock. Each receiver schedules its audio on that timeline, and its position
servo trims single samples to stay on it — that is what keeps the Pi within a
few milliseconds of the others.

One thing a receiver cannot see: the latency of its own audio output. The POSIX
example pipes PCM into `aplay`, and `aplay` fills a 500 ms ALSA buffer by
default. Those 500 ms are played late, uniformly, and no amount of PTP fixes
them — in a group the Pi then trails the other speakers by about half a second.

The wrapper therefore starts `aplay` with `-B 100000 -F 20000` (100 ms buffer,
20 ms periods). Measured on a Pi 4 against an ESP32-S3 receiver in the same
group, that removed the audible offset; `AIRPLAY_BUFFER_MS=50` also ran without
dropouts. Lower means tighter, but leaves less margin against a busy system:

```sh
AIRPLAY_BUFFER_MS=100
AIRPLAY_PERIOD_MS=20
```

The receiver's own 2.5 s jitter buffer is unaffected: that one is for network
jitter and does not delay playback relative to the timeline.

## The service

```sh
systemctl status airplay-receiver
sudo systemctl restart airplay-receiver
journalctl -u airplay-receiver -f          # live log
journalctl -u airplay-receiver -b -o cat | grep -E "Synchronized|failed"
```

A healthy session looks like this:

```
Stream: AAC, AirPlay 2 buffered
PTP grandmaster 10da639d90dd0008 announced by 10da639d90dd0008 (192.168.0.83, domain 0)
Clock locked to PTP clock 10da639d90dd0008
Synchronized: buffered 2562 ms, output 190 ms, servo -92 us; lost 0, late 0,
  resend requests 0, trimmed frames 0, silence 208 ms, underruns 0
```

`servo` should stay within a few hundred microseconds, `lost`, `resend
requests` and `underruns` at 0. `late` counts packets that arrived too late to
play; a burst right after joining a group is normal, a growing counter is not.

The unit runs the receiver as the installing user with
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, because PTP listens on UDP 319 and
320. Without that capability the receiver logs `PTP is not available` and macOS
senders refuse to start.

## Troubleshooting

**The device does not appear in the AirPlay list.** Check that `avahi-daemon` is
running and that the receiver found the network:
`journalctl -u airplay-receiver -n 30`. The service needs a network with
multicast; a guest network or an isolated VLAN does not work.

**The iPhone says "Unable to connect".** Usually pairing or PTP. The log then
shows `pair-verify failed`, `Pairing failed` or `SETUP before pairing`. Restarting
the service during playback also produces it, because the session ends.

**The name appears as `name-2` or `name-3`.** Avahi found a stale record for the
name, typically the address a previous network interface had. Restart Avahi
(`sudo systemctl restart avahi-daemon`) and clear the caches of the devices that
still answer with the old address; a router that keeps handing out an old DHCP
name for the host keeps the conflict alive.

**No sound, but the log is synchronized.** Wrong ALSA device, or the softvol
control sits at 0 %: `amixer -c 0 sget AirPlay`. On HDMI check
`aplay -l` for the card name.

**Crackling or `underruns` counting up.** Raise `AIRPLAY_BUFFER_MS` to 150,
check the load (`uptime`), and for Wi-Fi use 5 GHz. On the Pi 4 the on-board
Wi-Fi power save adds latency spikes; `iw dev wlan0 set power_save off` (or the
NetworkManager setting) helps.

**Multi-room is off by a fixed amount.** Compare `AIRPLAY_BUFFER_MS` on both
devices — a device with a bigger output buffer plays later. Nothing else in the
grouping needs adjusting; PTP does the rest.

## What was verified

On a Raspberry Pi 4 (Debian 13, kernel 6.18, wired Ethernet) with `main` at
v0.8.0:

- AirPlay 1 from pyatv, AirPlay 2 buffered (AAC) from an iPhone 16 and from
  pyatv, macOS-style PTP
- streaming with `lost 0`, `resend requests 0` and `underruns 0`, servo within
  ±0.5 ms; metadata, cover and volume arriving
- two speakers in one AirPlay 2 group, in sync after the buffer change above
- restart of the process (`kill -9`) and of the service: mDNS re-announced,
  playback recovers on the next connect
- headphone jack with the softvol control, sender volume applied

Not covered yet: a multi-hour soak and a reboot of the Pi. The service is
enabled at boot; the first boot is checked by hand.
