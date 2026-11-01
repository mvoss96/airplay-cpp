#!/bin/bash
# Streams a test signal from an independent AirPlay sender to a receiver on 127.0.0.1:5000 and checks what
# arrives.
#
#   tests/interop/run.sh posix  build/airplay_receiver [pyatv|pipewire]  # checks every sample of the output
#   tests/interop/run.sh zephyr build/zephyr/zephyr.exe [pyatv]          # checks the log of the Zephyr example
#
# pyatv: Python sender; sends track details, cover art, progress and volume, unencrypted. With PASSWORD=<password>
#   the receiver asks for it and pyatv logs in. With AIRPLAY2=1 pyatv uses AirPlay 2: transient pairing, an
#   encrypted RTSP connection and ChaCha20-Poly1305 encrypted audio.
#   RECORD_FIRST=1 makes it send RECORD before setting up the audio stream, as iOS does. AUDIO_KEY=none, zero or
#   earlier leaves the key out of the stream setup, as iOS does for realtime streams, and sends the audio
#   unencrypted, encrypted with a zero key or, as iOS does, with the key of a turned down buffered stream.
# buffered: AirPlay 2 buffered audio (AAC over TCP), as iOS streams most apps; the receiver needs an AAC decoder
#   (the POSIX example with FAAD2). Its output is compared with ffmpeg's decoding of the same file. PAUSE=1 pauses
#   in the middle; REMOTE_CONTROL=1 opens a second session only for remote control, as iOS does.
# pipewire: PipeWire's RAOP sink; RSA-encrypted session key and AES-encrypted audio. Needs pipewire,
#   wireplumber and dbus-run-session.
#
# IMPAIR_SO=path/to/impair.so (built from impair.c) makes the receiver lose, reorder and duplicate UDP packets
# at the rates in IMPAIR_LOSS, IMPAIR_REORDER and IMPAIR_DUPLICATE; the stream must still arrive complete
# thanks to retransmission.
set -e
MODE=$1
RECEIVER=$(realpath "$2")
SENDER=${3:-pyatv}
HERE=$(dirname "$(realpath "$0")")

if [ "$SENDER" = pipewire ] && [ -z "$DBUS_SESSION_BUS_ADDRESS" ]; then
  exec dbus-run-session -- "$0" "$@"  # WirePlumber needs a D-Bus session
fi

WORK=${WORK:-$(mktemp -d)}
cd "$WORK"
IMPAIR_SO=${IMPAIR_SO:+$(realpath "$OLDPWD/$IMPAIR_SO" 2> /dev/null || realpath "$IMPAIR_SO")}
FRAMES=264600  # 6 s
if [ "$SENDER" = buffered ]; then
  AIRPLAY2=1
  python3 "$HERE/make_signal.py" signal.wav 6
  ffmpeg -loglevel error -y -i signal.wav -c:a aac -b:a 256k -f adts signal.aac
  ffmpeg -loglevel error -y -i signal.aac -f s16le -ac 2 -ar 44100 reference.pcm
else
  python3 "$HERE/make_wav.py" ramp.wav $FRAMES
fi

PRELOAD=""
if [ -n "$IMPAIR_SO" ]; then
  PRELOAD=$(realpath "$IMPAIR_SO")
  echo "Impaired network: loss=${IMPAIR_LOSS:-0} reorder=${IMPAIR_REORDER:-0} duplicate=${IMPAIR_DUPLICATE:-0}"
fi
if [ "$MODE" = posix ]; then
  AIRPLAY_DEBUG=${AIRPLAY_DEBUG:-1} AIRPLAY_ARTWORK=cover.bin AIRPLAY_PASSWORD=$PASSWORD AIRPLAY2=$AIRPLAY2 \
    LD_PRELOAD=$PRELOAD \
    "$RECEIVER" Interop out.pcm \
    2> receiver.log &
else
  LD_PRELOAD=$PRELOAD "$RECEIVER" > receiver.log 2>&1 &
fi
RECEIVER_PID=$!
sleep 2

if [ "$SENDER" = buffered ]; then
  python3 "$HERE/send_buffered.py" 127.0.0.1 5000 signal.aac $([ "$PAUSE" = 1 ] && echo --pause) \
    $([ "$REMOTE_CONTROL" = 1 ] && echo --remote-control) ||
    echo "The sender failed"
  sleep 1
elif [ "$SENDER" = pyatv ]; then
  TXT="txtvers=1 ch=2 cn=0,1 et=0,1 ek=1 sv=false da=true sr=44100 ss=16 pw=$([ -n "$PASSWORD" ] && echo true || echo false) tp=UDP vn=65537 vs=105.1 sf=0x4 md=0,1,2"
  if [ "$AIRPLAY2" = 1 ]; then
    TXT="$TXT $(sed -n 's/.*_airplay._tcp.* \(features=[^ ]*\).*/\1/p' receiver.log | sed 's/features=/ft=/')"
  fi
  AIRPLAY_PASSWORD=$PASSWORD RECORD_FIRST=$RECORD_FIRST AUDIO_KEY=$AUDIO_KEY python3 "$HERE/send.py" ramp.wav 020000A1B2C3@Interop $TXT || echo "The sender failed"
  sleep 2
else
  export XDG_RUNTIME_DIR="$WORK/run" XDG_CONFIG_HOME="$WORK/config"
  mkdir -p -m 700 "$XDG_RUNTIME_DIR"
  mkdir -p "$XDG_CONFIG_HOME/pipewire/pipewire.conf.d"
  cp "$HERE"/pipewire/*.conf "$XDG_CONFIG_HOME/pipewire/pipewire.conf.d/"
  pipewire > pipewire.log 2>&1 &
  PIPEWIRE_PID=$!
  sleep 1
  wireplumber > wireplumber.log 2>&1 &
  WIREPLUMBER_PID=$!
  for _ in $(seq 50); do
    pw-cli ls Node 2> /dev/null | grep -q '"raop_sink"' && break
    sleep 0.2
  done
  timeout 30 pw-play --target raop_sink ramp.wav
  sleep 3  # The sender holds its latency (1.5 s) of audio
  kill $WIREPLUMBER_PID $PIPEWIRE_PID 2> /dev/null || true
  sleep 1
fi

kill -INT $RECEIVER_PID 2> /dev/null || true
sleep 1
kill -KILL $RECEIVER_PID 2> /dev/null || true
cat receiver.log

grep -q "Playback synchronized to the sender" receiver.log
if [ "$SENDER" = buffered ]; then
  grep -q "Stream: AAC, AirPlay 2 buffered" receiver.log
  python3 "$HERE/check_lossy.py" out.pcm reference.pcm $([ "$PAUSE" = 1 ] && echo --pause)
  exit 0
fi
if [ "$SENDER" = pyatv ]; then
  grep -q "Now playing: pyatv - Ramp" receiver.log
  if [ "$AIRPLAY2" = 1 ] && [ -z "$PASSWORD" ]; then  # Not offered with a password
    grep -q "Paired" receiver.log
    grep -q "Stream: .*, AirPlay 2" receiver.log
  fi
  if [ "$MODE" = posix ]; then
    cmp artwork.bin cover.bin  # Cover art arrived complete
    grep -q "Position: 0 of 6 s" receiver.log
  fi
  MAX_SKIPPED=0
else
  grep -q "Stream: .*, encrypted" receiver.log
  MAX_SKIPPED=2000  # PipeWire drops a few short runs of samples itself
fi

CHECK_OPTIONS="--max-skipped $MAX_SKIPPED"
if [ -n "$IMPAIR_SO" ]; then
  # Lost sync packets can delay the start by up to a second
  CHECK_OPTIONS="$CHECK_OPTIONS --max-start 44100"
  if [ "$SENDER" = pipewire ]; then
    CHECK_OPTIONS="$CHECK_OPTIONS --allow-lost-packets"  # PipeWire does not answer retransmission requests
  fi
fi
if [ "$MODE" = posix ]; then
  python3 "$HERE/check.py" out.pcm $FRAMES $CHECK_OPTIONS
else
  # The null output counts what it played: the whole stream minus what the sender cut off at the end
  PLAYED=$(sed -n 's/^Session: stopped (\([0-9]*\) frames played)$/\1/p' receiver.log | tail -1)
  echo "played=$PLAYED"
  test -n "$PLAYED" && test "$PLAYED" -gt $((FRAMES - 8820)) && test "$PLAYED" -lt $((FRAMES + 4410))
  echo "INTEROP OK"
fi
