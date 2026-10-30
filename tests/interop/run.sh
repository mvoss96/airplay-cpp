#!/bin/sh
# Streams a test signal with pyatv (an independent AirPlay sender) to a receiver on 127.0.0.1:5000 and checks
# what arrives.
#
#   tests/interop/run.sh posix  build/airplay_receiver   # checks every sample of the PCM output
#   tests/interop/run.sh zephyr build/zephyr/zephyr.exe  # checks the log of the Zephyr example
set -e
MODE=$1
RECEIVER=$(realpath "$2")
HERE=$(dirname "$(realpath "$0")")
WORK=$(mktemp -d)
cd "$WORK"
TXT="txtvers=1 ch=2 cn=0,1 et=0,1 ek=1 sv=false da=true sr=44100 ss=16 pw=false sm=false tp=UDP vn=3 vs=105.1 md=0"
FRAMES=264600  # 6 s

python3 "$HERE/make_wav.py" ramp.wav $FRAMES
if [ "$MODE" = posix ]; then
  "$RECEIVER" Interop out.pcm 2> receiver.log &
else
  "$RECEIVER" > receiver.log 2>&1 &
fi
PID=$!
sleep 2
python3 "$HERE/send.py" ramp.wav 020000A1B2C3@Interop $TXT
sleep 2
kill -INT $PID 2> /dev/null || true
sleep 1
kill -KILL $PID 2> /dev/null || true
cat receiver.log

grep -q "Playback synchronized to the sender" receiver.log
grep -q "Now playing: pyatv - Ramp" receiver.log
if [ "$MODE" = posix ]; then
  python3 "$HERE/check.py" out.pcm $FRAMES
else
  # The null output counts what it played: the whole stream minus what the sender cut off at the end
  PLAYED=$(sed -n 's/^Session: stopped (\([0-9]*\) frames played)$/\1/p' receiver.log | tail -1)
  echo "played=$PLAYED"
  test -n "$PLAYED" && test "$PLAYED" -gt $((FRAMES - 8820)) && test "$PLAYED" -lt $((FRAMES + 4410))
fi
echo "INTEROP OK"
