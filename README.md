# Tunler

A lightweight, self-hosted tunnel inspired by [ngrok](https://ngrok.com).
Give any local port a public HTTPS URL on your own domain, useful for testing
OAuth callbacks, receiving webhooks, or sharing a local demo.

Run the server on a box you control, install the client, and `tunler 8000`
turns `localhost:8000` into `https://my-app.tunler.example.com`.

Features:

- Stable subdomains on your own domain.
- Automatic Let's Encrypt certificates.
- Local web request inspector.
- Per-user domain ownership.
- No traffic logging on the server.
- Single static Go binary for client and server.

## Quickstart

**1. Run a server** (on a box with a public IP and a wildcard DNS record;
see [Running a server](#running-a-server) for the details):

```sh
docker run -d --name tunler -p 80:80 -p 443:443 \
  -e TUNLER_PASSWORD=<master password> \
  -v tunler-data:/var/lib/tunler \
  ghcr.io/jessegall/tunler:latest --domain tunler.example.com --email you@example.com
```

**2. Install the client** from your server (it binds to that server, so you
never need `--host`):

```sh
curl -fsSL https://tunler.example.com/install | sh
```

**3. Log in once, then tunnel:**

```sh
tunler login you@example.com            # prompts for the master password
tunler 8000                             # → https://<random>.tunler.example.com
tunler 8000 --domain=my-app             # → https://my-app.tunler.example.com
```

The first user to use a subdomain owns it; nobody else can tunnel on it.

## Running a server

You need a Linux server with a public IP, a (sub)domain, and ports 80/443
open. Certificates come from Let's Encrypt automatically.

### 1. DNS

Point two A records at your server (AAAA too if you have IPv6):

```
tunler.example.com      A   <your-server-ip>
*.tunler.example.com    A   <your-server-ip>
```

The wildcard is what lets `my-app.tunler.example.com` resolve without ever
touching DNS again. Verify: `dig +short anything.tunler.example.com`.

### 2. Run it (Docker Compose)

Create `.env`:

```sh
TUNLER_DOMAIN=tunler.example.com
TUNLER_EMAIL=you@example.com
TUNLER_PASSWORD=$(openssl rand -hex 16)
```

Use [`deploy/docker-compose.yml`](deploy/docker-compose.yml) and start it:

```sh
docker compose up -d
curl https://tunler.example.com/healthz   # -> ok
```

The image bundles the client binaries, so `https://tunler.example.com/install`
works immediately.

### Build it yourself

Don't want to pull a prebuilt image? Build from source:

```sh
git clone https://github.com/jessegall/tunler
cd tunler
docker build -t tunler:latest .
```

Then point `deploy/docker-compose.yml` at `tunler:latest` instead of
`ghcr.io/jessegall/tunler:latest`. The image bundles the client binaries, so
`/install` still works.

To build just the binaries without Docker: `make build` for this machine, or
`make release` to cross-compile every platform into `./dist`.

### Configuration

Everything can be set with flags, environment variables, or a JSON config
file (`--config`), in that order of precedence. A config file lets you tune
the server's posture:

```jsonc
{
  "domain": "tunler.example.com",
  "downloads": { "require_auth": true },      // gate /install + /dl/ behind the password
  "limits": {
    "max_body_bytes": 0,                       // 0 = unlimited
    "max_conns_per_tunnel": 64,
    "response_header_timeout": "30s",
    "data_conn_idle_timeout": "5m"
  },
  "lockout": { "enabled": true, "threshold": 5, "max_backoff": "15m" },
  "registration": { "mode": "allowlist", "allowlist": ["you@example.com"] }
}
```

### Without Docker

The same binary runs standalone. Grab `tunler-server-<os>-<arch>` from the
[releases](https://github.com/jessegall/tunler/releases) and run
`tunler-server --domain tunler.example.com --data /var/lib/tunler` (e.g. under
systemd with `EnvironmentFile` for `TUNLER_PASSWORD`).

### Behind an existing reverse proxy

If another proxy already owns 80/443, pass raw TLS through by SNI so tunler
still terminates TLS itself. For Traefik v2, mount its dynamic-config
directory into the container and add `--traefik-file=/path/tunler.yml`;
tunler regenerates the passthrough rules per claimed domain (v2 has no
wildcard `HostSNI`). For nginx, use `ngx_stream_ssl_preread`.

### Notes

- The first request to a new subdomain triggers on-demand certificate
  issuance (a few seconds); certs are cached in the data volume afterwards.
- Back up `/var/lib/tunler`; it holds users, domains, and certificates.

## Using the client

```sh
tunler 8000 --domain=my-app        # foreground tunnel with a live request log
tunler 8000 --domain=my-app -d     # …in the background instead
tunler 8000 --auth=user:pass       # visitors must pass HTTP basic auth
tunler list                        # running tunnels
tunler disconnect [domain]         # stop a background tunnel (--all for all)
tunler logs my-app -f              # follow a background tunnel's output
tunler status                      # logged in where/as whom, does auth work
tunler domains                     # subdomains you own
tunler release my-app              # give up a subdomain (--all for all)
tunler update                      # self-update from the server
tunler logout                      # forget this machine's login
```

Foreground tunnels print a live request log and serve a **web inspector** on
`http://127.0.0.1:4646`, showing every request/response with full headers and
bodies (`--inspect=0` to disable). This runs on your own machine over your
own traffic; the server never sees it.

The target can be a port (`8000`) or `host:port`. The original `Host` header
and `X-Forwarded-*` are preserved, so OAuth redirect URIs work as-is.

**CI / scripts**: everything works one-shot with flags, no prompts, no saved
state:

```sh
tunler connect 8000 --host=tunler.example.com --domain=my-app --secret=$TUNLER_SECRET
tunler login ci@example.com --host=... --password=... --no-save   # prints the secret
tunler list --json / tunler status --json                          # machine-readable
```

Env vars: `TUNLER_HOST`, `TUNLER_SECRET`, `TUNLER_PASSWORD`.

## Security & privacy

- The server logs no traffic, only login and tunnel events.
- One master password per server, required to log in. Optional allowlist to
  restrict who can register.
- Logins get a random 256-bit secret; the server stores only its hash.
- Subdomains are owned by the first user to claim them.
- Certificates are only issued for claimed subdomains.
- Downloads and `tunler update` trust the server over TLS; the SHA-256 is a
  corruption check, not a signature.

## How it works

The client keeps a long-lived outbound control connection to the server
(HTTP Upgrade, like WebSocket), which is why it works behind NAT/firewalls.
When a visitor hits `my-app.tunler.example.com`, the server asks the client to
dial back a data connection and reverse-proxies through it. TLS certificates
are issued per subdomain on demand via Let's Encrypt TLS-ALPN.

## Development

Build from source and run the whole thing locally, with no TLS or real
domain, to hack on it. `--no-tls` serves plain HTTP on a single port and
routes by the `Host` header, so a tunnel is reachable at
`http://<name>.localhost:8080`.

```sh
make test    # go vet + race tests
make build   # build ./bin/tunler and ./bin/tunler-server

# start a local server, a dummy app on :9000, and a tunnel to it
./bin/tunler-server --domain localhost --password test --no-tls --listen :8080 &
python3 -m http.server 9000 &
./bin/tunler connect 9000 --host=localhost:8080 --domain=my-app --email=me@example.com --password=test --insecure &

# reach the tunnel through the server
curl -H "Host: my-app.localhost" http://localhost:8080/
```

## License

[MIT](LICENSE)
