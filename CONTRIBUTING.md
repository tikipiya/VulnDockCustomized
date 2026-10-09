# Contributing to VulnDockCustomized

Thank you for considering a contribution. This fork is a **self-hosted web application** (Go + Svelte). The upstream Wails desktop flow no longer applies.

## Reporting bugs and enhancements

Use GitHub Issues with:

- Expected vs actual behavior
- Steps to reproduce
- Server OS, browser, and how you deploy (binary, systemd, Docker)
- Relevant logs (no secrets, PoC payloads, or report contents)

Do **not** report security vulnerabilities in public issues. See [SECURITY.md](SECURITY.md).

## Development setup

Requirements: Go 1.26.4+, Node.js 22+, npm.

```sh
make install
```

Run the API server:

```sh
make build
VULNDOCK_BIND=127.0.0.1:8080 VULNDOCK_TRUST_LOOPBACK_SETUP=true ./build/bin/vulndock-customized
```

Run the frontend dev server (proxies `/api` to port 8080):

```sh
make frontend-dev
```

## Required checks

Before opening a pull request:

```sh
make check
```

This runs `go test ./...`, `npm run check`, and `npm test` under `frontend/`.

Focused commands:

```sh
go test ./...
go build ./cmd/vulndock-customized
npm test --prefix frontend
npm run check --prefix frontend
npm run build --prefix frontend
```

If you change Go modules:

```sh
go mod tidy
```

Ensure `gofmt` is clean (`gofmt -l .` should print nothing).

## Contribution guidelines

- Keep pull requests focused.
- Update [README.md](README.md) or [docs/WEB_SELF_HOST.md](docs/WEB_SELF_HOST.md) for user-visible behavior changes.
- Add tests when fixing bugs or changing domain logic (`app.go` tests cover legacy backup/crypto; prefer tests for new `internal/` code when practical).
- Do not commit credentials, local databases, or real vulnerability data.
- For auth, sessions, attachment storage, or CI permission changes, include a short security note in the PR.

## License

Contributions are released under the MIT license.
