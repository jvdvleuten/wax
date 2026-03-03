# FIDO Alliance Conformance

This document describes a practical workflow to validate a `wax` fork for
passkey/WebAuthn behavior.

## 1. Fork setup

Work in your own fork repository, for example:

```bash
git remote -v
# origin https://github.com/<your-user>/wax.git
```

## 2. Local build baseline

From the `wax` repo:

```bash
mix deps.get
mix test
```

On OTP 28, this repo should compile and run tests with:

- `19 tests, 0 failures`

## 3. Unofficial conformance regression

This repository includes CI checks in:

- `.github/workflows/ci.yml`

The `unofficial-conformance` job runs:

- `mix test --only conformance`
- `mix test --exclude conformance`
- a workspace hygiene check to ensure tests do not leave generated tracked files
- browser E2E passkey flows using Playwright virtual authenticators

Run the same checks locally:

```bash
mix test --only conformance
mix test --exclude conformance
```

Run browser E2E locally:

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

Suggested companion tools for debugging failures:

- Chrome DevTools WebAuthn panel (Virtual Authenticator):
  `https://developer.chrome.com/docs/devtools/webauthn/`
- passkeys.dev tools (feature checks, response decoding):
  `https://tools.passkeys.dev/`
- SimpleWebAuthn debugger for payload inspection:
  `https://debugger.simplewebauthn.dev/`

## 4. Test server for official suite

The official FIDO Alliance conformance tool is private and must be obtained
through FIDO Alliance certification access.

The test harness used by this project is:

- `https://github.com/tanguilp/wax_fido_test_suite_server`

Clone and run it separately, then point the conformance tool to that server URL.

## 5. Required conformance-specific configuration

Some TPM conformance tests use a fake manufacturer ID (`id:FFFFF1D0`).
Wax can now enable this through configuration instead of source edits:

```elixir
config :wax_,
  tpm_allow_conformance_fake_manufacturer: true
```

Recommended conformance-related settings in the test server:

```elixir
config :wax_,
  origin: "http://localhost:4000",
  rp_id: :auto,
  metadata_dir: :wax_fido_test_suite_server,
  tpm_allow_conformance_fake_manufacturer: true
```

## 6. Run the official suite

In the FIDO conformance tool UI:

1. Open `FIDO2 Tests`.
2. Download/import server metadata and place it in the server's configured metadata directory.
3. Set `Server URL` to your running server endpoint.
4. Run server tests (typically excluding metadata tests unless your scenario requires them).

## 7. Evidence of pass/fail

To claim conformance, keep artifacts from the official tool run:

- total test count
- pass/fail summary
- exported report/log from the tool
- tested `wax` commit SHA

Without these artifacts, conformance status should be considered unverified.
