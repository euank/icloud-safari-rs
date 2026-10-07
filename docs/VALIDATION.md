# Validation and remaining limits

Last exercised: 2026-09-06 (America/Los_Angeles).

| Area | Evidence |
| --- | --- |
| Login / refresh / escrow discovery | Actual CLI against the test account |
| Existing-key recovery | Live, 44 authenticated PCS identities |
| CLI Safari reads | Live tabs/bookmarks/history and offline fixture read; all encrypted fields authenticated |
| New-peer join and resume | Live using an existing trusted peer; same peer retained |
| CLI enrollment resume | Live already-joined resume retained identical identity/key material and created no escrow attempt marker |
| Bookmark and tab CRUD | Current replacement PCS writer, exact authenticated readback, deletion independently confirmed |
| Password CRUD | New random password, exact decrypted create/update checks, deletion independently confirmed |
| CLI CRUD | Actual CLI bookmark/tab/password creation, update, exact JSON readback, and independently confirmed deletion |
| Fresh passcode recovery | **Unresolved:** one HTTP 409 rejection; no automatic retry |
| Offline / read-only builds | Tests enforce no enrollment/recovery mutation and fixture-only commands |
| Failure paths | Mock tests cover bad proofs, stale/revoked trust, incomplete pagination, failed delete verification, edited plans, redirects and secret redaction |
| Local state | Tests cover atomic/private files, symlinks/traversal, process locks, and account/peer binding |
| Toolchains | Default and read-only Clippy/tests, plus Rust 1.88 all-target compile checks |

Live tests are ignored by default and require explicit environment confirmation.
Never run them against an account without authority. `tests/live_crud.rs`
creates only uniquely marked records, keeps a private journal, and cleans them
up with ownership checks. `tests/live_cli_crud.rs` separately exercises actual
CLI commands with private password files and captured output; optional
`ICLOUD_CLI_CRUD_RESUME=1` also checks an already-joined sponsored checkpoint.
Both live CRUD runs removed all three of their disposable records (six total).

The library does not establish/reset an empty trust circle, publish a new
escrow bottle, or provide Apple device attestation. Preserve the enrolled state
and its recovery identities: deletion is not recoverable from a newly published
bottle. Native Safari UI display has not been rechecked on an Apple device;
the live tests exercise CloudKit and authenticated Rust readback.

On non-macOS platforms the first-use Apple library download remains required,
as documented in README. Password reads are online-only. A command refreshes
tokens while it runs; no daemon remains after it exits. These are explicit
limitations, not silently simulated functionality.
