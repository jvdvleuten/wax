# FIDO2 Conformance Port Status (ExUnit)

This document tracks best-effort migration of the FIDO2 Server conformance tool tests
into local ExUnit tests for the `wax` library.

Source suite inspected from a local, licensed installation of the official
FIDO Alliance conformance tooling (FIDO2 server module test definitions and
associated helper scripts).

## Source Test Surface

Server-side FIDO2 suite files:

- `tests/Server/MakeCredential/*` (121 `it(...)` cases)
- `tests/Server/GetAssertion/*` (54 `it(...)` cases)
- `tests/Server/MDS/mds-1.js` (6 `it(...)` cases)
- Total in tool: **181** cases

Core server API flow in tool (`js/serverAPI.js`):

- `POST /attestation/options`
- `POST /attestation/result`
- `POST /assertion/options`
- `POST /assertion/result`
- `POST https://mds3.fido.tools/getTestMetadata` (MDS helper)

## Ported Coverage In `wax` ExUnit

Implemented now:

- `test/wax/client_data_conformance_test.exs`
  - 17 negative CollectClientData cases ported for registration flow
  - 17 negative CollectClientData cases ported for assertion flow
  - Source parity: `Resp-2` groups in MakeCredential and GetAssertion
- `test/wax/register_attestation_object_conformance_test.exs`
  - 20 registration attestation-object cases ported from MakeCredential `Resp-3` and packed-self checks
  - Covers malformed/missing CBOR members, AT flag/data consistency, leftover bytes, unknown fmt,
    and packed attStmt validation branches (`alg`, `sig`, mismatch)
- `test/wax/assertion_authenticator_data_conformance_test.exs`
  - 11 assertion authenticatorData cases ported from GetAssertion `Resp-3`
  - Covers UV policy behavior (`required`/`preferred`/`discouraged`), extension-data success path,
    and negatives for leftover bytes, rpId hash mismatch, and signature mismatch
- `test/wax/conformance_regression_test.exs`
  - UV-required rejection on registration when UV flag is false
  - UV-required rejection on authentication when UV flag is false
- `test/wax/metadata_test.exs`
  - MDS status rejection coverage for:
    - `USER_VERIFICATION_BYPASS`
    - `ATTESTATION_KEY_COMPROMISE`
    - `USER_KEY_REMOTE_COMPROMISE`
    - `USER_KEY_PHYSICAL_COMPROMISE`
  - Plus existing revoked/update/date ordering logic
- `test/wax_test.exs`
  - Existing vectors covering packed/u2f/tpm/apple/basic auth paths and failures

## Remaining Gaps (Best-Effort Backlog)

Not yet ported to dedicated ExUnit cases:

1. Wrapper/API contract tests from tool (`status/errorMessage` envelope shape and field typing at HTTP boundary).
2. Full MakeCredential response-structure negative matrix (`Resp-1`) at HTTP payload shape level (`id/type/response` missing/invalid).
3. Full Assertion response-structure negative matrix (`Resp-1`) at HTTP payload shape level (`id/type/response` missing/invalid).
4. Remaining attestation-format exhaustive permutations from tool files:
   - packed full/self/none/u2f/tpm/android-key/android-safetynet/apple
5. Optional algorithm matrix parity checks (tool optional blocks).
6. Assertion sign-counter replay checks (`counter is not increased`) require app-level persisted counter state (outside current `Wax.authenticate/5` contract).
7. End-to-end session/cookie behavior expected by tool wrapper (library itself is stateless).

## Notes

- Some tool assertions are wrapper-specific and map better to `wax_fido_test_suite_server`
  endpoint tests than to low-level `wax` library unit tests.
- Goal here is to maximize deterministic CI-friendly coverage in ExUnit while keeping
  tests stable and meaningful for the public `wax` library API.
