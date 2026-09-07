# icloud-safari

`icloud-safari` is a Rust library and CLI for interacting with Safari tabs,
bookmarks, history, and login passwords stored in iCloud.

```console
cargo run -- list-tabs --json
cargo run -- passwords list --json
cargo run -- export --output safari.json
```

List and export commands fetch current iCloud data by default. Pass `--offline`
to use the local cache; selecting `--fixture-dir` is also implicitly offline.

## Login and local state

Run `cargo run -- login` and enter your Apple Account password and, when
requested, its two-factor code.

If the account's trusted Apple devices are unavailable, use `cargo run --
login --sms` to request the code from its trusted phone instead.

The client includes Apple's [publicly distributed legacy Apple Root CA](https://www.apple.com/certificateauthority/) because
the GrandSlam endpoint still serves that private-PKI chain. TLS verification is
never disabled.

On Linux and other non-macOS platforms, the first command that needs Anisette
downloads Apple's official Apple Music Android APK (currently about 136 MiB)
from `apps.mzstatic.com`, extracts `libstoreservicescore.so` and
`libCoreADI.so`, then deletes the APK. The extracted Apple libraries remain in
private local state and are required to generate Anisette headers locally.
This is the current self-contained bootstrap limitation: the repository cannot
redistribute Apple's proprietary binaries, so first use requires network
access and depends on Apple continuing to publish a compatible APK at that
URL.

An existing HTTP Anisette provider remains available as an explicit
compatibility override with `--anisette-url URL`.

## Passwords

Password records are recovered from the iCloud Keychain CKKS `Passwords` view
using the saved Octagon identity. Normal output redacts the secret:

```console
cargo run -- passwords list
cargo run -- passwords list --show-passwords --json
```

Create, update, and delete require an explicit write confirmation. Passwords
are read from a hidden terminal prompt by default so they do not appear in the
process list or shell history. Automation may use a mode-restricted file:

```console
cargo run -- passwords create --domain example.com --username alice \
  --confirm-write-to-icloud
cargo run -- passwords update --record UUID --confirm-write-to-icloud
cargo run -- passwords delete --record UUID --confirm-record UUID \
  --confirm-write-to-icloud
```

The local `keychain/all-views.json` cache contains encrypted CKKS records, not
plaintext passwords. Plaintext is emitted only when explicitly requested or
returned to a library caller.

The wire format, Apple source references, supported item class, and live test
contract are documented in
[`docs/KEYCHAIN-PASSWORDS.md`](docs/KEYCHAIN-PASSWORDS.md).

## Bookmarks and tabs

Create a bookmark in Safari's top-level bookmarks folder, or a tab owned by the
first synchronized Safari device:

```console
cargo run -- write create --dataset bookmarks --title "Rust" \
  --url https://www.rust-lang.org/ --confirm-write-to-icloud
cargo run -- write create --dataset tabs --title "Rust" \
  --url https://www.rust-lang.org/ --confirm-write-to-icloud
```

Use `--parent-id RECORD_ID` or `--owning-device-id RECORD_ID` to select those
relationships explicitly. Creation first fetches current state, creates and
self-checks a fresh PCS record-protection object, uses fail-if-exists semantics,
then fetches and authenticates the returned encrypted fields.

## Writes and safety

Safari creation, field updates, and deletes use authenticated encryption and
fresh-state conflict checks. Creation generates a new PCS object; updates
preserve unknown record metadata and include the fetched etag. Password CRUD
similarly refetches and authenticates its result. Every live mutation requires
`--confirm-write-to-icloud`; deletes also require the record UUID twice.

To compile a read-only build with all mutation commands removed, use:

```console
cargo build --no-default-features
```

Protocol-source provenance and retained third-party notices are documented in
[`docs/PROVENANCE.md`](docs/PROVENANCE.md) and
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
