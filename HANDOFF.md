# Rust implementation handoff

## Goal

Build an independent Rust client that can authenticate to iCloud, fetch Safari
tabs/bookmarks/history and website passwords directly from Apple's CloudKit
servers, recover the applicable keys through Octagon/CKKS, decrypt
PCS/CKKS-protected values, export them, and perform explicitly confirmed writes.

The implementation must be derived from [`docs/PROTOCOL.md`](docs/PROTOCOL.md),
not from an existing implementation in another language. That document is the
confirmed read-protocol contract. [`docs/WRITE-PROTOCOL.md`](docs/WRITE-PROTOCOL.md)
contains separate, confidence-labelled Safari write research. Bookmark/tab
creation, existing-record update/delete, and password CRUD are production-E2E
tested.

## Included material

```text
docs/PROTOCOL.md
    Complete wire-level and cryptographic read specification.

docs/WRITE-PROTOCOL.md
    Confirmed save endpoint and field encryption, full record metadata,
    provisional save envelope, unknowns, and native-capture acceptance gate.

fixtures/public/protocol-vectors.json
    Non-secret known-answer vectors. These should become Rust unit tests.

fixtures/private/safari-cloudkit/{tabs,bookmarks,history}.json
    Saved raw CloudKit responses plus normalized records for offline tests.

fixtures/private/pcs-identities/{safari,cloud-tabs,history}.der
    The minimum initial P-256 identities needed to open the saved Safari PCS
    object graphs. Child record identities must be recovered from zone objects,
    not supplied as fixtures.

fixtures/private/keychain/all-views.json
    Archived raw CKKS records from synchronized views. Live password reads use
    the saved Octagon identity to request recoverable TLKShares; plaintext
    passwords are never persisted in this fixture.

fixtures/private/live/device.json
    Stable emulated device identifiers. Reuse them; do not regenerate them.

fixtures/private/live/session.json
    Reduced live state: DSIDs, CloudKit/MME tokens, container user IDs,
    KeychainSync URL, and persistent Octagon peer/sponsor state. It deliberately
    excludes passwords, PETs, unrelated app tokens, and decrypted keychain
    dumps. Bearer tokens may expire and then require account reauthentication.

fixtures/private/expected.json
    Hashes and offline acceptance counts for this exact fixture bundle.
```

Everything under `fixtures/private` is ignored by Git and mode-restricted. It
contains private browsing data, bearer credentials, and private keys. Do not
print secrets in test output, commit the directory, or send it to another
service.

## Implementation order

1. Implement generic protobuf-wire and DER readers that retain unknown fields.
2. Pass every public vector.
3. Implement the offline PCS graph and Safari value decoders. Meet all counts
   in `fixtures/private/expected.json` without network access.
4. Implement CloudKit fetching as an explicitly selected live operation. New
   responses must feed the same offline pipeline.
5. Implement CKKS item recovery, then Octagon enrollment/recovery. Escrow
   recovery must remain behind an explicit confirmation because attempts are
   limited.
6. Implement Apple Account bootstrap last. Anisette needs provisioned Apple
   components; do not attempt to manufacture its credentials.

The original Anisette convention was a `GET` of `http://127.0.0.1:6969/`,
returning the documented JSON header map. The Rust implementation retains that
configurable compatibility interface but now provisions Anisette locally by
default. On non-macOS systems it downloads Apple's official Apple Music APK on
first use and extracts its two required native libraries. Those proprietary
binaries cannot be redistributed, so this one-time download remains a runtime
bootstrap limitation.

Keep fixture loading and live I/O separate. Ordinary list/export commands
fetch current data by default; `--offline` and `--fixture-dir` select cached or
fixture-only operation.

## Minimum commands

The final CLI should provide equivalents of:

```text
list-tabs [--json] [--offline]
list-devices [--json] [--offline]
list-bookmarks [--json] [--offline]
list-history [--json] [--offline]
passwords list [--json] [--show-passwords]
passwords create|update|delete
write create|update|delete|apply-update|apply-delete
verify-fixtures
```

An offline command must report how many PCS objects were discovered/unwrapped
and how many encrypted fields authenticated. Authentication failure must never
fall back to displaying unauthenticated plaintext.

## Completion criteria

- Every public known-answer vector passes, including corruption rejection.
- All 10 private PCS objects unwrap and all 19 encrypted fields authenticate.
- The per-dataset object, record, field, and codec counts match `expected.json`.
- The three selected initial identities are sufficient; no account-specific
  master key or recovered child scalar is hard-coded.
- A changed key, header, IV, tag, ciphertext, or AAD is rejected.
- Truncated four-byte key-ID collisions are reported as ambiguous.
- Live fetch is the default for list/export and performs no record mutation.
- `--offline` never performs network I/O.
- Tokens, private keys, and decrypted browsing data are redacted from normal
  logs and error messages.

Safari bookmark/tab creation, field updates/deletes, and website-password CRUD
are live operations guarded by explicit confirmation, fresh-state conflict
checks, and authenticated post-write verification. New Safari records receive
a fresh PCS key and signed protection object which is reopened through the
ordinary read key graph before use. A read-only binary can be built with
`--no-default-features`.
