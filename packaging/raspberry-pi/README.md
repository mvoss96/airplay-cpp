# Raspberry Pi packaging

Turns a Raspberry Pi into a standalone AirPlay 1/2 receiver: builds the POSIX
example, installs it as a systemd service, applies the sender's volume to the
headphone jack and announces the receiver over mDNS.

Full guide, including the multi-room latency details: [docs/raspberry-pi.md](../../docs/raspberry-pi.md).

## Install

From a checkout:

```sh
sudo ./packaging/raspberry-pi/install.sh
```

Piped, no checkout needed:

```sh
curl -fsSL https://raw.githubusercontent.com/mvoss96/airplay-cpp/main/packaging/raspberry-pi/install.sh | sudo bash
```

Options: `--name` (name in the AirPlay list), `--output jack|hdmi|<ALSA device>`,
`--ref` (branch or tag to build when downloading), `--prefix`, `--skip-build`,
`--no-restart`, `--dry-run`. `--help` lists them all.

Running it again upgrades the binary and the unit; `/etc/default/airplay-receiver`
is kept, so local edits survive.

## What gets installed

| Path | Purpose |
| --- | --- |
| `/usr/local/lib/airplay-cpp/airplay_receiver` | the POSIX example |
| `/usr/local/bin/airplay-receiver-run` | starts the receiver, pipes PCM into `aplay`, announces it, applies the sender's volume |
| `/etc/systemd/system/airplay-receiver.service` | service, restarts on crash, PTP ports 319/320 |
| `/etc/default/airplay-receiver` | configuration, written once |
| `/etc/alsa/conf.d/60-airplay-softvol.conf` | `softvol` control `AirPlay` on the headphone jack (jack only) |
| `/opt/airplay-cpp/src` | source, when the script downloads it |

## Remove

```sh
sudo ./uninstall.sh          # keeps the configuration
sudo ./uninstall.sh --purge  # removes it and the downloaded source
```

## Notes

- The service runs as `$SUDO_USER` with `CAP_NET_BIND_SERVICE`, so PTP works
  without running the receiver as root.
- `AIRPLAY_BUFFER_MS` (default 100) is the one latency the receiver cannot see.
  With `aplay`'s default of 500 ms the speaker plays half a second behind other
  speakers in an AirPlay 2 group.
- A password in `AIRPLAY_PASSWORD` turns AirPlay 2 off; AirPlay 2 uses the Home
  app's password.
