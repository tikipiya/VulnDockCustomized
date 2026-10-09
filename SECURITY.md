# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `main`  | Yes |
| Latest release tag (e.g. `v1.1.0`) | Yes, same fixes as `main` when applicable |
| Older tags | Best effort only |

Security fixes land on `main` first, then release tags as needed.

## Reporting a vulnerability

**Do not** open a public GitHub issue for a suspected security vulnerability.

Report privately to this fork:

**https://github.com/tikipiya/VulnDockCustomized/security/advisories/new**

If GitHub private reporting is unavailable, contact the maintainer through another private channel before disclosing details publicly.

Include:

- Clear description and impact (who can exploit it, what data or access is at risk).
- Steps to reproduce on **VulnDockCustomized** (version or commit, OS, deployment: binary, Docker, reverse proxy).
- Affected routes or components (e.g. `/api/auth/setup`, backup restore).
- CVSS vector if you have one.
- Minimal proof-of-concept; do **not** attach real customer data, live exploits against third parties, or unrelated secrets.

### Upstream overlap

This project is derived from [Saku0512/VulnDock](https://github.com/Saku0512/VulnDock) (MIT). Issues that apply only to the **desktop Wails app** or upstream installers should be reported to upstream. Issues in **shared formats** (e.g. encrypted backup ZIP `vulndock.encrypted-backup.v1`) may affect both; you may report to either project or both—please say so in the report.

## Handling expectations

Maintainers will try to:

- Acknowledge receipt in a reasonable time (best effort).
- Confirm reproducibility.
- Ship a fix before broad public disclosure when appropriate.
- Credit reporters on request when practical.

This is a volunteer / best-effort project; response times are not guaranteed.

## Security notes for operators

VulnDockCustomized is a **single-user, self-hosted** web application. You are responsible for network exposure and host security.

### Data at rest

- SQLite database and sessions: default directory `~/.local/share/vulndock-customized/` (override with `VULNDOCK_DATA_DIR`).
- Permissions: data directory `0700`, database file `0600` when created by the server.
- Content includes report text, **PoC BLOBs**, password hashes, and session identifiers. Treat the data directory as **highly sensitive**.

### Network and authentication

- Default bind is `0.0.0.0:8080`. Restrict with firewall, Tailscale, or bind to `127.0.0.1` when appropriate.
- **Initial setup** requires `VULNDOCK_SETUP_TOKEN` (or the token printed at startup) unless `VULNDOCK_TRUST_LOOPBACK_SETUP=true` and the server sees a loopback client. Do **not** expose an uninitialized instance to the internet.
- Behind nginx/Caddy, do not rely on loopback trust; always set a strong setup token and use HTTPS with `VULNDOCK_SECURE_COOKIES=true`.
- Session cookies are HttpOnly, SameSite=Lax; mutating API calls require CSRF. There is no multi-tenant isolation—anyone who can authenticate is the sole administrator.

### Backups

- Encrypted ZIP backups use Argon2id + AES-256-GCM (desktop-compatible payload). Protect backup files and passwords; lost passwords cannot be recovered.
- Restore **replaces** all reports and saved prompts in the database. Test restores on a copy before using production data.

### What not to put in reports to us

When filing **security advisories** or support issues, redact:

- Your production `VULNDOCK_SETUP_TOKEN`, session cookies, and admin passwords.
- Full PoC exploit code against real targets unless required for reproduction.
- Third-party credentials or personal data from real programs.

## Secure development

See [CONTRIBUTING.md](CONTRIBUTING.md). Run `make check` before submitting changes that touch auth, backup, or storage.
