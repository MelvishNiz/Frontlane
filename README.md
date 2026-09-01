# PrivateWG

Panel WireGuard ringan untuk aplikasi web privat. Go + SQLite mengelola peer dan domain; Caddy menyediakan Let's Encrypt; CoreDNS memberi DNS hanya untuk klien VPN.

## Prasyarat

- VPS Ubuntu 24.04/Debian 12 dengan IPv4 publik.
- Docker Engine + Compose plugin.
- Kernel WireGuard dan `nftables` pada host.
- Domain dengan DNS provider apa pun.
- Record DNS publik `A` untuk `panel.example.com` dan setiap domain aplikasi menuju IP VPS hub.
- Port publik: UDP `51820`, TCP `80/443`. Panel tersedia publik melalui HTTPS; domain aplikasi tetap ditolak tanpa IP WireGuard.

## Instalasi

```bash
cp .env.example .env
chmod 600 .env
# Edit seluruh nilai .env; gunakan password acak minimum 20 karakter.
docker compose build
docker compose up -d
```

Startup pertama membuat peer `bootstrap-admin`. Ambil profil sekali:

```bash
sudo cp data/privatewg/bootstrap.conf ~/privatewg-bootstrap.conf
sudo chown "$USER":"$USER" ~/privatewg-bootstrap.conf
sudo rm data/privatewg/bootstrap.conf
```

Buka `https://panel.example.com` langsung tanpa WireGuard. Import profil bootstrap hanya untuk mengakses aplikasi privat, lalu hapus peer bootstrap setelah peer pengganti dibuat.

Peer baru dapat dibuka kembali dari menu Peer. Halaman detail menyediakan QR, salin config, download `.conf`, dan toggle akses; config disimpan terenkripsi. Peer yang dibuat oleh versi lama tidak memiliki private key tersimpan dan harus dibuat ulang.

Menu Domain menerima subdomain `PWG_BASE_DOMAIN` maupun domain external. Untuk domain external, buat record DNS publik `A`/`AAAA` menuju VPS hub sebelum mengaktifkan rute. Toggle domain menghapus atau memasang kembali route Caddy/CoreDNS tanpa menghapus datanya.

Aktifkan firewall setelah memastikan SSH berjalan pada TCP `22`. Script memakai default-deny dan mengizinkan SSH `22`; edit script dahulu bila port SSH berbeda:

```bash
sudo install -d -m 755 /etc/nftables.d
sudo sh scripts/firewall-nftables.sh
```

Agar persisten, include `/etc/nftables.d/*.nft` dari `/etc/nftables.conf`, lalu aktifkan `nftables`:

```bash
sudo systemctl enable --now nftables
```

## Laravel pada VPS hub

Expose web server Laravel hanya ke loopback, contoh Compose Laravel:

```yaml
ports:
  - "127.0.0.1:8081:80"
```

Buat record DNS publik `app.example.com` menuju IP hub. Panel Domain: domain `app.example.com`, target `127.0.0.1:8081`.

Container Laravel 12 contoh opsional:

```bash
docker compose --profile example up -d
```

Startup pertama mengunduh Laravel melalui Composer ke volume `laravel_example`. Target panel: `127.0.0.1:8081`. Mode `artisan serve` hanya demo; aplikasi produksi tetap gunakan Nginx/FrankenPHP.

## Laravel pada VPS lain

1. Buat peer jenis Server dari panel.
2. Import konfigurasi pada VPS aplikasi sebagai `wg0`.
3. Bind web server ke IP peer, misalnya `10.77.0.20:80`.
4. Izinkan port aplikasi hanya dari interface `wg0` pada firewall VPS tersebut.
5. Buat record DNS publik domain menuju IP VPS hub, bukan VPS aplikasi.
6. Tambahkan domain di panel dengan target `10.77.0.20:80`.

Traffic browser berhenti di Caddy hub. Caddy meneruskan request ke VPS aplikasi melalui WireGuard.

## Operasi

```bash
docker compose logs -f privatewg
docker compose logs -f caddy
docker compose restart coredns
sudo wg show wg0
docker compose config
```

Backup minimum:

```bash
tar czf privatewg-backup.tgz data/privatewg data/wireguard data/caddy data/coredns
```

Backup berisi server private key. Simpan terenkripsi dan batasi akses.

## Batas V1

- Satu admin; password awal tidak otomatis berubah saat `.env` berubah.
- Config peer baru disimpan terenkripsi AES-256-GCM agar QR dan download tetap tersedia. Peer lama harus dibuat ulang.
- Key enkripsi diturunkan dari server private key; mengganti `data/wireguard/server.key` membuat config tersimpan tidak dapat dibuka.
- Session berada di memori; restart meminta login ulang.
- Subnet tetap `10.77.0.0/24`; split tunnel tetap.
- Sertifikat HTTP-01 memerlukan record `A` publik per domain dan TCP `80` publik.
- Panel publik mengandalkan HTTPS, password kuat, rate limit, CSRF, dan audit log; V1 belum menyediakan MFA.
- Target proxy dibatasi ke loopback atau `10.77.0.0/24` untuk mencegah SSRF.
