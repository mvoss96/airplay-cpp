#!/usr/bin/env bash
# Remove the airplay-cpp receiver installed by install.sh.
#   sudo ./uninstall.sh            keep /etc/default/airplay-receiver
#   sudo ./uninstall.sh --purge    remove it as well
set -euo pipefail

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" = 0 ] || { echo "run this as root: sudo $0" >&2; exit 1; }

systemctl disable --now airplay-receiver.service 2>/dev/null || true
rm -f /etc/systemd/system/airplay-receiver.service
systemctl daemon-reload

rm -f /usr/local/bin/airplay-receiver-run
rm -f /usr/local/lib/airplay-cpp/airplay_receiver
rmdir /usr/local/lib/airplay-cpp 2>/dev/null || true
rm -f /etc/alsa/conf.d/60-airplay-softvol.conf

if [ "$PURGE" = 1 ]; then
  rm -f /etc/default/airplay-receiver
  rm -rf /opt/airplay-cpp
  echo "removed configuration and source"
else
  echo "kept /etc/default/airplay-receiver and /opt/airplay-cpp (--purge removes them)"
fi

echo "done"
