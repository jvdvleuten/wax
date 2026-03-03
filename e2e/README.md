# Wax Browser E2E

This folder contains browser-level WebAuthn tests that use Chromium virtual
authenticators against a tiny Elixir harness server.

## Run locally

Terminal 1:

```bash
cd e2e/harness
mix deps.get
MIX_ENV=test mix e2e.server --host 127.0.0.1 --port 4100
```

Terminal 2:

```bash
cd e2e
npm ci
npx playwright install chromium
BASE_URL=http://localhost:4100 npm test
```
