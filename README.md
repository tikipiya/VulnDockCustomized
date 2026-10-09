# VulnDockCustomized

**Self-hosted web edition** of [VulnDock](https://github.com/Saku0512/VulnDock) — a private workspace for vulnerability report metadata, PoC attachments, and CVSS vectors.  
日本語の概要は [docs/README.ja.md](docs/README.ja.md) を参照してください。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

This fork replaces the original **Wails desktop app** with a **Go HTTP server** and **Svelte** SPA you run on your own machine (LAN or Tailscale). It is not wire-compatible with upstream releases.

## Features

- Create, edit, search, and soft-delete vulnerability reports (5-day retention before purge).
- Track program, target asset, status, dates, rewards, tags, conversation logs, and report URLs.
- Store PoC files in **SQLite** (BLOB, 50 MB per file).
- **CVSS 3.1 / 4.0** scoring from vector strings (client-side).
- Filter by status, CVSS rating, and next-action windows.
- **Single-user** access: setup wizard, session cookie (72 h sliding), password change, CSRF on mutating API calls.
- Import legacy desktop data: `vulndock-customized migrate --from-json`.
- **Saved prompts**: reusable text templates in the sidebar (copy, edit, included in encrypted backups).

**v1.2.1:** backup restore deadlock fix, session/setup/proxy-rate-limit and safer PoC preview tweaks.

**v1.2.0:** saved prompts, stability fixes (SQLite loading, CSRF after reload), and security hardening for self-hosted deployment.

**v1.1.0:** encrypted ZIP backup export/restore (desktop-compatible format) via UI and `/api/backup/*`.

## Requirements

- **Go** 1.26.4+
- **Node.js** 22+ and **npm** (to build the frontend)

No Wails or WebKit build dependencies.

## Quick start

```sh
git clone <your-repo-url>
cd VulnDock
make install
make build
./build/bin/vulndock-customized
```

Open `http://127.0.0.1:8080`, complete the **initial setup** (admin password), then use the app.

Default paths:

| Item | Location |
|------|----------|
| SQLite database | `~/.local/share/vulndock-customized/vulndock-customized.db` |
| Static UI (dev) | `frontend/dist` via `VULNDOCK_STATIC_DIR` |
| Legacy import source | `~/.config/VulnDock/reports.json` (+ `attachments/`) |

See [docs/WEB_SELF_HOST.md](docs/WEB_SELF_HOST.md) for environment variables, **systemd**, migration, and security notes.

## Development

**API server** (terminal 1):

```sh
make build
VULNDOCK_BIND=127.0.0.1:8080 ./build/bin/vulndock-customized
```

**Frontend with hot reload** (terminal 2; proxies `/api` to port 8080):

```sh
make frontend-dev
```

## Testing and checks

```sh
make check    # go test + npm check + npm test
make test     # go test + npm test
go test ./...
```

Individual targets: `make go-test`, `make frontend-check`, `make frontend-test`, `make frontend-build`.

## Building

```sh
make build
```

Produces:

- `build/bin/vulndock-customized` — server binary  
- `frontend/dist/` — copied into the binary at build time (`make build` embeds the UI). Override with `VULNDOCK_STATIC_DIR` for development.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `VULNDOCK_BIND` | `127.0.0.1:8080` | Listen address |
| `VULNDOCK_DATA_DIR` | `~/.local/share/vulndock-customized` | Data directory (SQLite) |
| `VULNDOCK_STATIC_DIR` | `frontend/dist` if present | Path to built SPA |
| `VULNDOCK_SETUP_TOKEN` | (auto-generated, written to `.setup-token` in data dir) | First-time setup (required unless direct loopback trust is enabled) |
| `VULNDOCK_TRUST_LOOPBACK_SETUP` | `false` | If `true`, skip setup token for **direct** loopback clients without proxy headers (dev only) |
| `VULNDOCK_TRUST_PROXY_IP` | `false` | If `true`, use `X-Real-IP` / `X-Forwarded-For` for login rate limits (enable only behind a trusted reverse proxy) |
| `VULNDOCK_SECURE_COOKIES` | `false` | Set `true` when the app is served only over HTTPS (session cookie `Secure` flag) |

First-time setup always requires the setup token unless you set `VULNDOCK_TRUST_LOOPBACK_SETUP=true` **and** connect directly to loopback (no `X-Forwarded-For` / `Forwarded` headers—reverse proxies always need the token).

## Migrate from desktop VulnDock

```sh
./build/bin/vulndock-customized migrate --from-json
# explicit path:
./build/bin/vulndock-customized migrate --from-json ~/.config/VulnDock/reports.json
```

Use `--force` if the database already contains reports. Use `--data-dir` to target a non-default data directory.

## Releasing

Push a version tag to run the release workflow (Linux archives + container image):

```sh
git tag v1.0.0
git push origin v1.0.0
```

Release assets are named `VulnDockCustomized_<os>_<arch>.tar.gz` (binary + `frontend/dist`).  
Checksums and Sigstore bundles are attached when the publish job runs.

## Project layout

| Path | Purpose |
|------|---------|
| `cmd/vulndock-customized/` | Server CLI (`serve`, `migrate`) |
| `internal/domain/` | Report model and normalization |
| `internal/store/sqlite/` | SQLite persistence |
| `internal/httpapi/` | REST API and SPA static handler |
| `internal/auth/` | Password hash and sessions |
| `internal/service/` | Report business logic |
| `internal/migrate/` | JSON import from desktop layout |
| `app.go` | Legacy file-based store (used by `go test` for backup/crypto behavior) |
| `frontend/src/App.svelte` | Main UI |
| `frontend/src/api/client.ts` | HTTP API client |
| `deploy/vulndock-customized.service` | Example systemd unit |
| `.github/workflows/ci.yml` | CI |
| `.github/workflows/release.yml` | Tag releases |

## Documentation

- [Self-hosted guide](docs/WEB_SELF_HOST.md) — operations (EN).
- [日本語 README](docs/README.ja.md).
- [Contributing](CONTRIBUTING.md).
- [Security policy](SECURITY.md).
- [User guide (legacy desktop)](docs/USER_GUIDE.md) — upstream-oriented; storage paths differ in this fork.

## CI

On pushes to `main` and on pull requests, GitHub Actions runs:

- `gofmt` and `go mod tidy` cleanliness  
- `go test ./...`  
- `go build ./cmd/vulndock-customized`  
- Frontend `npm run check`, `npm test`, and `npm run build`

OpenSSF Scorecard runs on `main` (see badge workflows in upstream; adjust if you fork the repo).

## Upstream and license

Derived from [Saku0512/VulnDock](https://github.com/Saku0512/VulnDock) (MIT). Desktop installers, Homebrew, and WinGet flows in upstream **do not apply** to this fork unless you reintroduce them.

See [LICENSE](LICENSE).
