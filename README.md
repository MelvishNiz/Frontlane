# PrivateWG

Panel WireGuard ringan untuk aplikasi web privat. Go + SQLite mengelola peer dan domain; Traefik menyediakan Let's Encrypt; CoreDNS memberi DNS hanya untuk klien VPN.

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
chmod 700 data/traefik/letsencrypt
# Edit seluruh nilai .env; gunakan password acak minimum 20 karakter.
docker compose build
docker compose up -d --remove-orphans
```

Startup pertama membuat peer `bootstrap-admin`. Ambil profil sekali:

```bash
sudo cp data/privatewg/bootstrap.conf ~/privatewg-bootstrap.conf
sudo chown "$USER":"$USER" ~/privatewg-bootstrap.conf
sudo rm data/privatewg/bootstrap.conf
```

Buka `https://panel.example.com` langsung tanpa WireGuard. Dashboard Traefik tersedia di `https://panel.example.com/traefik/dashboard/` dan memakai sesi login panel yang sama. Import profil bootstrap hanya untuk mengakses aplikasi privat, lalu hapus peer bootstrap setelah peer pengganti dibuat.

Migrasi dari rilis Caddy: verifikasi seluruh DNS A/AAAA dan TCP `80` lebih dahulu, jalankan cutover sekali untuk menghindari rate limit Let's Encrypt, hentikan stack lama dengan `docker compose down`, lalu jalankan `docker compose up -d --build --remove-orphans`. Sertifikat Caddy tidak kompatibel dengan penyimpanan Traefik; Traefik menerbitkan ulang sertifikat. Verifikasi `data/traefik/letsencrypt/acme.json` terisi dan seluruh HTTPS berhasil. Simpan `data/caddy` sementara untuk rollback.

Peer baru dapat dibuka kembali dari menu Peer. Halaman detail menyediakan QR, salin config, download `.conf`, dan toggle akses; config disimpan terenkripsi. Peer yang dibuat oleh versi lama tidak memiliki private key tersimpan dan harus dibuat ulang.

Menu Domain menerima subdomain `PWG_BASE_DOMAIN` maupun domain external. Untuk domain external, buat record DNS publik `A`/`AAAA` menuju VPS hub sebelum mengaktifkan rute. Toggle domain menghapus atau memasang kembali upstream tanpa menghapus datanya. Domain tetap menampilkan halaman status saat rute dijeda, upstream/VPS tidak terjangkau, atau pengunjung belum terhubung ke VPN.

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

1. Buat peer jenis Server dari panel, lalu download konfigurasinya.
2. Simpan konfigurasi tersebut sebagai `client/config/wg0.conf` pada VPS aplikasi.
3. Jalankan client WireGuard:

```bash
chmod 600 client/config/wg0.conf
docker compose -f client/compose.yaml up -d
docker compose -f client/compose.yaml logs -f
```

Container memakai network namespace host. Interface `wg0` dan rute `10.77.0.0/24` muncul langsung pada VPS, sama seperti instalasi WireGuard native. Kernel host tetap harus mendukung WireGuard; bila pembuatan interface gagal, jalankan `sudo modprobe wireguard` pada host.

4. Bind web server ke IP peer, misalnya `10.77.0.20:80`, atau `0.0.0.0:80` dengan firewall yang membatasi akses. Layanan yang hanya bind ke `127.0.0.1` tidak dapat dicapai melalui IP peer.
5. Izinkan port aplikasi hanya dari interface `wg0` pada firewall VPS tersebut.
6. Buat record DNS publik domain menuju IP VPS hub, bukan VPS aplikasi.
7. Tambahkan domain di panel dengan target `10.77.0.20:80`.

Verifikasi pada VPS aplikasi:

```bash
ip address show wg0
sudo wg show wg0
ping -c 3 10.77.0.1
```

Traffic browser berhenti di Traefik hub. Traefik meneruskan request ke VPS aplikasi melalui WireGuard. File `client/config/wg0.conf` berisi private key, diabaikan oleh Git dan Docker build context.

## Operasi

```bash
docker compose logs -f privatewg
docker compose logs -f traefik
docker compose restart coredns
sudo wg show wg0
docker compose config
```

Backup minimum:

```bash
tar czf privatewg-backup.tgz data/privatewg data/wireguard data/traefik data/coredns
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
