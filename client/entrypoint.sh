#!/bin/sh
set -eu

source_config=${WG_CONFIG:-/config/wg0.conf}
runtime_dir=/run/frontlane
runtime_config=$runtime_dir/wg0.conf
interface=wg0
up=0

if [ ! -f "$source_config" ]; then
  printf 'Configuration not found: %s\n' "$source_config" >&2
  printf 'Save the Frontlane server peer config as config/wg0.conf.\n' >&2
  exit 1
fi

if ip link show "$interface" >/dev/null 2>&1; then
  printf 'Interface %s already exists; stop the other WireGuard interface first.\n' "$interface" >&2
  exit 1
fi

mkdir -p "$runtime_dir"
chmod 0700 "$runtime_dir"
# A container cannot change the host resolver; WireGuard routing remains unchanged.
sed '/^[[:space:]]*DNS[[:space:]]*=/d' "$source_config" > "$runtime_config"
chmod 0600 "$runtime_config"

cleanup() {
  if [ "$up" -eq 1 ]; then
    wg-quick down "$runtime_config"
  fi
}
trap cleanup EXIT
trap 'exit 0' HUP INT TERM

wg-quick up "$runtime_config"
up=1
printf 'Frontlane client active on %s (%s).\n' "$interface" "$(ip -4 -o address show dev "$interface" | awk '{print $4}')"

while :; do
  sleep 3600 &
  wait "$!"
done
