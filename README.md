# Frontlane

Frontlane is a lightweight, self-hosted application gateway. It publishes public or private HTTPS routes, connects remote application servers through WireGuard, manages private peer access with roles, and stores its control-plane state in SQLite.

The project retains the `privatewg` binary, container names, data paths, and `PWG_*` environment variables for deployment compatibility.

## Requirements

- Linux server with a public IPv4 address, Docker Engine, and Docker Compose
- WireGuard kernel support
- A free `wg0` interface and `10.77.0.0/24` subnet
- Public UDP `51820` and TCP `80/443`
- Public DNS A records for `panel.example.com` and each application domain pointing to the gateway

## Install the Gateway

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

Start the stack:

```bash
docker compose config --quiet
docker compose up -d --build --remove-orphans
```

The first startup creates a `bootstrap-admin` peer. Copy its configuration, then remove the server copy:

```bash
sudo cp data/privatewg/bootstrap.conf ~/frontlane-bootstrap.conf
sudo chown "$USER":"$USER" ~/frontlane-bootstrap.conf
sudo rm data/privatewg/bootstrap.conf
```

Open `https://panel.example.com`. Import the bootstrap configuration into WireGuard, create a replacement peer, then delete `bootstrap-admin`.

## Publish an Application

For an application on the gateway host, expose its HTTP port only on loopback:

```yaml
ports:
  - "127.0.0.1:8081:80"
```

Add a route in Frontlane with target `127.0.0.1:8081`. A generic Nginx example is available:

```bash
docker compose --profile example up -d app-example
```

Point the route's public DNS A record to the gateway. Traefik terminates TLS automatically.

Choose one visibility mode:

- `Private`: only enabled WireGuard peers sharing a role with the route can connect. This is the default.
- `Public`: anyone on the Internet can reach the upstream. Frontlane does not add login or application authentication.

Changing a private route to public exposes its upstream immediately. Ensure the application supplies any required authentication, authorization, request limits, and security headers before enabling public access. Role assignments remain stored while a route is public and apply again if it returns to private.

## Connect a Remote Application Server

Create a peer with type `Server` in Frontlane. Download its configuration and save it as `client/config/wg0.conf` on the application server.

```bash
chmod 600 client/config/wg0.conf
docker compose -f client/compose.yaml up -d --build
docker compose -f client/compose.yaml logs -f
```

The container creates `wg0` directly on the host. Bind the application to its peer IP, such as `10.77.0.20:80`, then use that address as the route target. Allow the application port only through `wg0`.

Verify the tunnel:

```bash
ip address show wg0
sudo wg show wg0
ping -c 3 10.77.0.1
```

The Docker client removes `DNS =` from its runtime configuration because a container cannot change the host resolver. Configure host DNS separately if the application server must resolve Frontlane routes.

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
tar czf frontlane-backup.tgz .env data/privatewg data/wireguard data/traefik data/coredns
docker compose start
```

The backup contains passwords, private keys, peer configurations, and certificates. Store it encrypted with restricted permissions.

## Limits

- One administrator; changing `.env` does not update an existing account
- Fixed `wg0`, UDP `51820`, and `10.77.0.0/24`
- HTTP upstreams only; Traefik handles public HTTPS
- Public routes rely on upstream applications for authentication
- In-memory sessions require sign-in after restart
- No MFA, OIDC, WAF, or high availability
