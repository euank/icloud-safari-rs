# Protocol provenance

This project implements undocumented Apple protocols. Protocol facts and source
code are different things: the links below identify the independent material
used to validate behavior, while this repository contains its own Rust types,
control flow, error handling, and tests.

## Protected Cloud Storage

The fresh-protection encoder was replaced with a fixed-profile DER writer
using the protocol descriptions below. The read path was cross-checked against
these sources; it was not rewritten as part of that replacement.

The sources reviewed were:

- the MIT-licensed [OpenTagViewer clean-room Find My export
  specification](https://github.com/parawanderer/OpenTagViewer/tree/main/docs/findmy-export),
  particularly its field-by-field PCS ASN.1 and signature/HMAC descriptions;
- the MIT-licensed [FindMy.py PCS
  implementation](https://github.com/parawanderer/FindMy.py/blob/feat/icloud-keychain-export/findmy/cloudkit/pcs.py)
  and its independently written [synthetic PCS
  tests](https://github.com/parawanderer/FindMy.py/blob/feat/icloud-keychain-export/tests/test_pcs.py);
- Apple's open-source [`SOSECWrapUnwrap.c`](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/SecureObjectSync/SOSECWrapUnwrap.c)
  for the RFC 6637 P-256/SHA-256/AES-128 wrapping profile; and
- the older MIT-licensed [InflatableDonkey](https://github.com/horrorho/InflatableDonkey)
  PCS reader as historical, independent corroboration of the DER and unwrap
  formats.

The fixed construction vectors in `src/crypto.rs` and `src/pcs.rs` were
calculated independently with Python `hashlib` and `cryptography`, then pinned
as Rust tests. They cover the RFC 6637 output, master signing scalar and public
key, HMAC KDF, key identifier, both protection signatures, protection HMAC,
recipient unwrap, and parser round trip.

Earlier development consulted OpenBubbles/rustpush. The current encoder was
written after that exposure, so this project does not claim a formally isolated
clean-room development process. The former general ASN.1 model and constructor
were removed; the replacement implements only single-recipient version-5
protection from the above wire-format descriptions.

Reviewed revisions: OpenTagViewer `76f7a058256735474483226dbd445c46c3e91e5a`
and FindMy.py `ddc7f2342fc9f32ebe315b85c22a4554ce419f6d`.

The prior writer passed the disposable production E2E described in
`WRITE-PROTOCOL.md`. The replacement passes offline private-fixture creation,
cryptographic vectors, and signature/HMAC verification; it has not had a new
production E2E run.

## CloudKit and Safari records

CloudKit protobuf layouts are derived from this project's preserved wire
fixtures, generated Apple model names, and the independently implemented
MIT-licensed [FindMy.py CloudKit
schema](https://github.com/parawanderer/FindMy.py/blob/feat/icloud-keychain-export/findmy/cloudkit/proto/cloudkit.proto).
The minimum save/delete requests were then checked against disposable records
in production. Safari record field meanings and plaintext encodings come from
the repository's authenticated fixtures and before/after tests.

## Publication note

The publication history starts from a fresh root commit containing the reviewed
source tree. Old development history is retained only in a separate private
recovery archive. Removing history does not change the provenance of code in
the current tree.

License notices for referenced MIT implementations are retained in
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
