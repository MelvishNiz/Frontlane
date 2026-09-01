#!/bin/sh
set -eu

source_config=${WG_CONFIG:-/config/wg0.conf}
runtime_dir=/run/privatewg
runtime_config=$runtime_dir/wg0.conf
interface=wg0
up=0

if [ ! -f "$source_config" ]; then
  printf 'Konfigurasi tidak ditemukan: %s\n' "$source_config" >&2
  printf 'Simpan config peer Server dari PrivateWG sebagai config/wg0.conf.\n' >&2
  exit 1
fi

if ip link show "$interface" >/dev/null 2>&1; then
  printf 'Interface %s sudah ada; hentikan WireGuard lain terlebih dahulu.\n' "$interface" >&2
  exit 1
fi

mkdir -p "$runtime_dir"
chmod 0700 "$runtime_dir"
# DNS container tidak dapat mengganti resolver host; routing WireGuard tetap identik dengan instalasi native.
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
printf 'PrivateWG client aktif pada %s (%s).\n' "$interface" "$(ip -4 -o address show dev "$interface" | awk '{print $4}')"

while :; do
  sleep 3600 &
  wait "$!"
done
