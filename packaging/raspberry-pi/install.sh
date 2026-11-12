#!/usr/bin/env bash
# Install airplay-cpp as an AirPlay 1/2 receiver service on a Raspberry Pi.
#
#   curl -fsSL https://raw.githubusercontent.com/mvoss96/airplay-cpp/main/packaging/raspberry-pi/install.sh | sudo bash
#   sudo ./packaging/raspberry-pi/install.sh --name Kitchen --output hdmi
#
# Builds from the checkout this script lives in, or downloads the repository
# when it is piped in. Existing configuration is kept, so running it again
# upgrades the binary and the unit.
set -euo pipefail

REPO_URL="https://github.com/mvoss96/airplay-cpp"
REF="main"
NAME=""
OUTPUT="jack"
RUN_USER=""
PREFIX="/usr/local"
SOURCE_DIR=""
BUILD_DIR=""
DESTDIR=""
SKIP_BUILD=0
NO_RESTART=0
DRY_RUN=0

CONF=/etc/default/airplay-receiver
UNIT=/etc/systemd/system/airplay-receiver.service
ALSA_CONF=/etc/alsa/conf.d/60-airplay-softvol.conf

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die()  { printf 'Error: %s\n' "$*" >&2; exit 1; }
run()  {
  if [ "$DRY_RUN" = 1 ]; then
    printf '   [dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

usage() {
  cat <<'EOF'
Usage: install.sh [options]

  --name NAME        name in the AirPlay list (default: hostname)
  --output OUTPUT    jack (default), hdmi, or an ALSA device such as
                     plughw:CARD=Device,DEV=0
  --user USER        user the service runs as (default: $SUDO_USER)
  --ref REF          git ref to build when the script downloads the source
                     (default: main)
  --source DIR       build from this checkout instead of downloading
  --prefix DIR       installation prefix (default: /usr/local)
  --destdir DIR      write all files below DIR, change no service (packaging)
  --skip-build       use the binary that is already installed
  --no-restart       do not restart the service at the end
  --dry-run          print what would happen
  -h, --help         this text
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --name)        NAME="${2:?--name needs a value}"; shift 2 ;;
    --output)      OUTPUT="${2:?--output needs a value}"; shift 2 ;;
    --user)        RUN_USER="${2:?--user needs a value}"; shift 2 ;;
    --ref)         REF="${2:?--ref needs a value}"; shift 2 ;;
    --source)      SOURCE_DIR="${2:?--source needs a value}"; shift 2 ;;
    --prefix)      PREFIX="${2:?--prefix needs a value}"; shift 2 ;;
    --destdir)     DESTDIR="${2:?--destdir needs a value}"; shift 2 ;;
    --build-dir)   BUILD_DIR="${2:?--build-dir needs a value}"; shift 2 ;;
    --skip-build)  SKIP_BUILD=1; shift ;;
    --no-restart)  NO_RESTART=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             die "unknown option: $1 (see --help)" ;;
  esac
done

# --- environment ------------------------------------------------------------
[ "$(id -u)" = 0 ] || die "run this as root: sudo $0"

if [ -z "$RUN_USER" ]; then
  RUN_USER="${SUDO_USER:-}"
  if [ -z "$RUN_USER" ] || [ "$RUN_USER" = root ]; then
    for candidate in pi debian ubuntu; do
      if id "$candidate" >/dev/null 2>&1; then RUN_USER="$candidate"; break; fi
    done
  fi
fi
[ -n "$RUN_USER" ] && id "$RUN_USER" >/dev/null 2>&1 || die "no service user found, pass --user"
RUN_GROUP="$(id -gn "$RUN_USER")"
[ -n "$NAME" ] || NAME="$(hostname)"

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
if [ -z "$SOURCE_DIR" ] && [ -n "$SCRIPT_DIR" ] &&
   [ -f "$SCRIPT_DIR/../../CMakeLists.txt" ] && [ -d "$SCRIPT_DIR/../../src" ]; then
  SOURCE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
fi

# Piped in through curl there is no script directory next to the assets: fetch
# them from the same ref as the source.
TMP_ASSETS=""
cleanup() { [ -n "$TMP_ASSETS" ] && rm -rf "$TMP_ASSETS"; }
trap cleanup EXIT
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/airplay-receiver-run" ]; then
  ASSET_DIR="$SCRIPT_DIR"
else
  ASSET_DIR="$(mktemp -d)"
  TMP_ASSETS="$ASSET_DIR"
  step "Files from $REPO_URL/$REF"
  for asset in airplay-receiver-run airplay-receiver.service \
               airplay-receiver.default 60-airplay-softvol.conf; do
    curl -fsSL "$REPO_URL/raw/$REF/packaging/raspberry-pi/$asset" -o "$ASSET_DIR/$asset" ||
      die "cannot download $asset from $REPO_URL ($REF)"
  done
  say "downloaded 4 files into $ASSET_DIR"
fi

if command -v apt-get >/dev/null 2>&1; then
  PKGS="build-essential cmake libmbedtls-dev libfaad-dev alsa-utils avahi-daemon avahi-utils python3 curl"
else
  PKGS=""
fi

say "airplay-cpp installer"
say "  name       : $NAME"
say "  output     : $OUTPUT"
say "  service    : $RUN_USER:$RUN_GROUP"
say "  prefix     : $PREFIX"
say "  source     : ${SOURCE_DIR:-download $REPO_URL ($REF)}"
[ -n "$DESTDIR" ] && say "  destdir    : $DESTDIR (no service changes)"

# --- packages ---------------------------------------------------------------
if [ -z "$DESTDIR" ] && [ -n "$PKGS" ]; then
  step "Packages"
  missing=""
  for pkg in $PKGS; do
    dpkg -s "$pkg" >/dev/null 2>&1 || missing="$missing $pkg"
  done
  if [ -n "$missing" ]; then
    say "installing:$missing"
    run apt-get update -qq
    # shellcheck disable=SC2086
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $missing
  else
    say "all present"
  fi
fi

# --- source ----------------------------------------------------------------
if [ "$SKIP_BUILD" = 0 ]; then
  step "Source"
  if [ -z "$SOURCE_DIR" ]; then
    SOURCE_DIR=/opt/airplay-cpp/src
    say "downloading $REPO_URL at $REF into $SOURCE_DIR"
    run mkdir -p "$(dirname "$SOURCE_DIR")"
    if [ "$DRY_RUN" = 0 ]; then
      tmp="$(mktemp -d)"
      curl -fsSL "$REPO_URL/archive/$REF.tar.gz" -o "$tmp/src.tar.gz" ||
        die "cannot download $REPO_URL/archive/$REF.tar.gz"
      tar -xzf "$tmp/src.tar.gz" -C "$tmp"
      rm -rf "$SOURCE_DIR"
      mv "$tmp"/*/ "$SOURCE_DIR"
      rm -rf "$tmp"
    fi
  else
    say "using checkout $SOURCE_DIR"
  fi

  step "Build"
  [ -n "$BUILD_DIR" ] || BUILD_DIR="$SOURCE_DIR/build"
  run cmake -S "$SOURCE_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DAIRPLAY_BUILD_EXAMPLES=ON
  run cmake --build "$BUILD_DIR" --parallel "$(nproc)"
  BINARY_SRC="$BUILD_DIR/airplay_receiver"
  [ "$DRY_RUN" = 1 ] || [ -x "$BINARY_SRC" ] || die "build did not produce $BINARY_SRC"
else
  BINARY_SRC=""
  say "skipping the build"
fi

# --- output device ---------------------------------------------------------
case "$OUTPUT" in
  jack)
    DEVICE="airplay"
    VOLUME=1
    MIXER_CARD=0
    MIXER_CONTROL=AirPlay
    WANT_SOFTVOL=1
    ;;
  hdmi)
    DEVICE="plughw:CARD=vc4hdmi0,DEV=0"
    VOLUME=0
    MIXER_CARD=0
    MIXER_CONTROL=AirPlay
    WANT_SOFTVOL=0
    ;;
  *)
    DEVICE="$OUTPUT"
    VOLUME=0
    MIXER_CARD=0
    MIXER_CONTROL=AirPlay
    WANT_SOFTVOL=0
    ;;
esac

# --- files -----------------------------------------------------------------
BIN_DIR="$DESTDIR$PREFIX/lib/airplay-cpp"
BIN="$PREFIX/lib/airplay-cpp/airplay_receiver"
WRAPPER="$DESTDIR$PREFIX/bin/airplay-receiver-run"

step "Files"
run install -d -m 0755 "$BIN_DIR" "$DESTDIR$PREFIX/bin" "$DESTDIR/etc/default" \
                          "$DESTDIR/etc/systemd/system" "$DESTDIR/etc/alsa/conf.d"

place() {  # place MODE SOURCE TARGET
  if [ "$DRY_RUN" = 1 ]; then
    say "   [dry-run] install -m $1 $2 $3"
  else
    install -m "$1" "$2" "$3"
  fi
}

if [ "$SKIP_BUILD" = 0 ]; then
  place 0755 "$BINARY_SRC" "$DESTDIR$BIN"
fi
place 0755 "$ASSET_DIR/airplay-receiver-run" "$WRAPPER"
say "  $DESTDIR$BIN"
say "  $DESTDIR$WRAPPER"

if [ "$WANT_SOFTVOL" = 1 ]; then
  place 0644 "$ASSET_DIR/60-airplay-softvol.conf" "$DESTDIR$ALSA_CONF"
  say "  $DESTDIR$ALSA_CONF"
fi

# The unit is generated: user, paths and the service user differ per machine.
if [ "$DRY_RUN" = 0 ]; then
  sed -e "s|@USER@|$RUN_USER|g" \
      -e "s|@GROUP@|$RUN_GROUP|g" \
      -e "s|@EXECUTABLE@|$PREFIX/bin/airplay-receiver-run|g" \
      "$ASSET_DIR/airplay-receiver.service" > "$DESTDIR$UNIT.tmp"
  install -m 0644 "$DESTDIR$UNIT.tmp" "$DESTDIR$UNIT"
  rm -f "$DESTDIR$UNIT.tmp"
else
  say "   [dry-run] write $UNIT (User=$RUN_USER)"
fi
say "  $DESTDIR$UNIT"

if [ -f "$DESTDIR$CONF" ]; then
  say "  $DESTDIR$CONF kept (edit it to change the configuration)"
elif [ "$DRY_RUN" = 1 ]; then
  say "   [dry-run] write $CONF (name=$NAME, device=$DEVICE)"
else
  sed -e "s|@NAME@|$NAME|g" \
      -e "s|@DEVICE@|$DEVICE|g" \
      -e "s|@VOLUME@|$VOLUME|g" \
      -e "s|@MIXER_CARD@|$MIXER_CARD|g" \
      -e "s|@MIXER_CONTROL@|$MIXER_CONTROL|g" \
      -e "s|@BINARY@|$BIN|g" \
      "$ASSET_DIR/airplay-receiver.default" > "$DESTDIR$CONF"
  chmod 0644 "$DESTDIR$CONF"
  say "  $DESTDIR$CONF"
fi

# --- service ---------------------------------------------------------------
if [ -z "$DESTDIR" ]; then
  step "Service"
  if [ "$WANT_SOFTVOL" = 1 ] && ! aplay -L 2>/dev/null | grep -q 'hw:CARD=Headphones'; then
    say "warning: no headphone jack card found; check the device in $CONF"
  fi
  run systemctl daemon-reload
  run systemctl enable airplay-receiver.service
  if [ "$NO_RESTART" = 1 ]; then
    say "not restarting (--no-restart): sudo systemctl restart airplay-receiver"
  else
    run systemctl restart airplay-receiver.service
    sleep 2
    if systemctl is-active --quiet airplay-receiver.service; then
      say "service is running"
    else
      say "service did not start; see: journalctl -u airplay-receiver -n 50"
    fi
  fi
else
  say ""
  say "files written below $DESTDIR, no service changed"
fi

cat <<EOF

Done. The receiver announces itself as "$NAME" once a sender looks for it.

  status   : systemctl status airplay-receiver
  log      : journalctl -u airplay-receiver -f
  config   : $CONF
  restart  : sudo systemctl restart airplay-receiver

In an AirPlay 2 group this speaker matches the others because PTP and the
sender's timeline are used. The ALSA buffer (AIRPLAY_BUFFER_MS) is the one
latency the receiver cannot see: keep it small.
EOF
