#!/usr/bin/env sh
set -eu

command -v nft >/dev/null 2>&1 || { echo "nftables belum terpasang" >&2; exit 1; }

cat >/etc/nftables.d/privatewg.nft <<'RULES'
table inet privatewg {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iifname "lo" accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept
    tcp dport 22 accept
    udp dport 51820 accept
    tcp dport { 80, 443 } accept
    iifname "wg0" udp dport 53 accept
    iifname "wg0" tcp dport { 53, 8080 } accept
  }
}
RULES

nft -c -f /etc/nftables.d/privatewg.nft
nft list table inet privatewg >/dev/null 2>&1 && nft delete table inet privatewg || true
nft -f /etc/nftables.d/privatewg.nft
printf '%s\n' 'Firewall PrivateWG aktif: UDP 51820 + TCP 80/443 publik; DNS dan port panel internal hanya wg0.'
