# VulnDockCustomized (self-hosted web)

Operations guide for the web fork. Product overview: [README.md](../README.md) (English), [README.ja.md](README.ja.md) (日本語).

## Docker (release image)

Tagged releases publish `ghcr.io/<owner>/vulndock-customized` (linux/amd64). Example:

```sh
docker run --rm -p 8080:8080 -v vulndock-data:/data ghcr.io/<owner>/vulndock-customized:latest
```

Complete the setup wizard at `http://localhost:8080` on first run. Set `VULNDOCK_SETUP_TOKEN` or read `.setup-token` inside the data volume (`docker exec` / `cat /data/.setup-token`). Required by default even when browsing via `localhost` on the host (loopback trust does not apply through published ports with proxy headers).

## Build

```sh
make install
make build
```

Binary: `build/bin/vulndock-customized`

## Run

```sh
export VULNDOCK_DATA_DIR="$HOME/.local/share/vulndock-customized"
./build/bin/vulndock-customized
# Optional dev override: export VULNDOCK_STATIC_DIR="$PWD/frontend/dist"
```

Open `http://127.0.0.1:8080` (or your host IP on Tailscale/LAN).

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `VULNDOCK_BIND` | `0.0.0.0:8080` | Listen address |
| `VULNDOCK_DATA_DIR` | `~/.local/share/vulndock-customized` | SQLite DB directory |
| `VULNDOCK_STATIC_DIR` | `frontend/dist` (if present) | Built SPA files |
| `VULNDOCK_SETUP_TOKEN` | auto-generated if unset | First-time setup wizard |
| `VULNDOCK_TRUST_LOOPBACK_SETUP` | `false` | Dev-only: allow setup without token from loopback clients |
| `VULNDOCK_SECURE_COOKIES` | `false` | Set `true` behind HTTPS reverse proxy |

## Migrate from desktop VulnDock

```sh
./build/bin/vulndock-customized migrate --from-json
# or explicit path:
./build/bin/vulndock-customized migrate --from-json ~/.config/VulnDock/reports.json
```

Use `--force` to import when the database already has reports.

## Development

Terminal 1:

```sh
make build && VULNDOCK_BIND=127.0.0.1:8080 ./build/bin/vulndock-customized
```

Terminal 2:

```sh
make frontend-dev
```

Vite proxies `/api` to port 8080.

## systemd

See `deploy/vulndock-customized.service`. Adjust paths and user, then:

```sh
sudo cp deploy/vulndock-customized.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vulndock-customized
```

## Security notes

- Intended for **Tailscale / private LAN**. Default bind is all interfaces; restrict with host firewall if needed.
- Do not store production secrets in reports or PoC attachments.
- Encrypted backup uses the same **vulndock.encrypted-backup.v1** format as desktop VulnDock.
