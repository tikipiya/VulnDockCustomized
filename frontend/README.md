# VulnDockCustomized frontend

Svelte 5 + TypeScript + Vite SPA for the self-hosted server.

## Commands

```sh
npm ci
npm run dev      # dev server; proxies /api → http://127.0.0.1:8080 (see vite.config.ts)
npm run check    # svelte-check
npm test
npm run build    # output to dist/ (served by vulndock-customized)
```

Run the Go server from the repository root before using `npm run dev`.

## Layout

- `src/App.svelte` — main UI
- `src/AuthShell.svelte` — login / setup gate
- `src/api/client.ts` — REST client (cookies + CSRF)

Wails bindings under `wailsjs/` are **legacy** and unused by the web build.
