# PrivateWG

PrivateWG is a lightweight control panel for private web applications. It manages WireGuard peers and domains with Go and SQLite, uses Traefik for HTTPS, and provides private DNS through CoreDNS.

## Requirements

- Linux server with a public IPv4 address, Docker Engine, and Docker Compose
- WireGuard kernel support
- A free `wg0` interface and `10.77.0.0/24` subnet
- Public UDP `51820` and TCP `80/443`
- Public DNS A records for `panel.example.com` and each application domain pointing to the hub server

## Install the Server

```bash
cp .env.example .env
chmod 600 .env
chmod 700 data/traefik/letsencrypt
```

Edit `.env`:

```dotenv
PWG_PUBLIC_ENDPOINT=203.0.113.10:51820
PWG_BASE_DOMAIN=example.com
PWG_ACME_EMAIL=admin@example.com
PWG_ADMIN_USER=admin
PWG_ADMIN_PASSWORD=replace-with-at-least-20-random-characters
```

Start the server stack:

```bash
docker compose config --quiet
docker compose up -d --build --remove-orphans
```

The first startup creates a `bootstrap-admin` peer. Copy its configuration, then remove the server copy:

```bash
sudo cp data/privatewg/bootstrap.conf ~/privatewg-bootstrap.conf
sudo chown "$USER":"$USER" ~/privatewg-bootstrap.conf
sudo rm data/privatewg/bootstrap.conf
```

Open `https://panel.example.com`. Import `privatewg-bootstrap.conf` into WireGuard to access private application domains. Create a replacement peer, then delete `bootstrap-admin`.

## Publish an Application

For an application on the hub server, expose its HTTP port only on loopback:

```yaml
ports:
  - "127.0.0.1:8081:80"
```

Add the domain in PrivateWG with target `127.0.0.1:8081`. A generic Nginx example is available:

```bash
docker compose --profile example up -d app-example
```

For every application domain, point its public DNS A record to the hub server. PrivateWG accepts HTTP upstreams on loopback or `10.77.0.0/24`; Traefik provides public TLS termination and limits application access to VPN peers.

## Install the Client on Another Server

Create a peer with type `Server` in PrivateWG. Download its configuration and save it as `client/config/wg0.conf` on the application server.

Build and start the tunnel client:

```bash
chmod 600 client/config/wg0.conf
docker compose -f client/compose.yaml up -d --build
docker compose -f client/compose.yaml logs -f
```

The container creates `wg0` directly on the host. Bind the application to its peer IP, such as `10.77.0.20:80`, then add that address as the domain target in PrivateWG. Allow the application port only through `wg0`.

Verify the tunnel:

```bash
ip address show wg0
sudo wg show wg0
ping -c 3 10.77.0.1
```

The Docker client removes `DNS =` from its runtime configuration because a container cannot change the host resolver. Configure host DNS separately if the application server must resolve PrivateWG domains.

## Firewall

The included script allows SSH on TCP `22`, WireGuard on UDP `51820`, and HTTP/HTTPS on TCP `80/443`, then applies a default-deny policy. Review it first if your SSH port or firewall setup differs.

```bash
sudo install -d -m 755 /etc/nftables.d
sudo sh scripts/firewall-nftables.sh
```

## Operations

```bash
docker compose logs -f privatewg
docker compose logs -f traefik
docker compose restart coredns
sudo wg show wg0
```

Create a consistent backup while the stack is stopped:

```bash
docker compose stop
tar czf privatewg-backup.tgz .env data/privatewg data/wireguard data/traefik data/coredns
docker compose start
```

The backup contains passwords, private keys, peer configurations, and certificates. Store it encrypted with restricted permissions.

## Limits

- One administrator; changing `.env` does not update an existing account
- Fixed `wg0`, UDP `51820`, and `10.77.0.0/24`
- HTTP upstreams only; Traefik handles HTTPS
- In-memory sessions require sign-in after restart
- No MFA
