# Safari iCloud write protocol: current evidence and capture contract

Last updated: 2026-09-05

## Status

This is a write-path research specification, not an authorization to mutate an
account. It distinguishes byte-level facts from hypotheses so an implementation
does not silently turn a plausible field number into a destructive request.

The current evidence is sufficient to implement outbound field encryption,
existing-record update/delete, and fresh PCS-protected bookmark/tab creation.
Live update and delete passed disposable production E2E tests. On 2026-09-05,
bookmark and tab creation each passed a complete production create, ordinary
key-graph reopen/decrypt, exact title/URL match, delete, and independent absence
check. A one-byte RFC 6637 KDF encoding defect found during the initial bookmark
probe was corrected and is covered by independent unwrap and full key-graph
recovery checks.

Confidence labels used below:

- **confirmed** — observed in a captured protobuf, authenticated fixture, or
  the preserved Apple framework;
- **derived** — the exact inverse of a confirmed and tested read primitive;
- **inferred** — strongly suggested by generated Apple class/field names or the
  numbering adjacent to the confirmed read operation;
- **unknown** — must be measured before a write-capable release.

A live Rust-client test was repeated against a disposable bookmark on
2026-09-05. A uniquely marked title was saved, fetched, decrypted, and
authenticated; a second compare-and-swap save restored the original title, and
a final independent fetch confirmed that the marker was absent. The test does
not replace the required native Safari capture.

## Implemented safe subset

The Rust library exposes `WriteWorkspace`; the CLI exposes `write create`,
`write update`, and `write delete`. The creation path:

- generates an OS-random 128-bit record master key;
- RFC-6637-wraps it to the recovered zone child identity;
- DER-encodes encrypted PCS identities, self-signature, outer zone-child
  signature, HMAC, key hint, and SHA-1 protection tag;
- re-encrypts a current record-type template under the new key while replacing
  title, URL, date, parent/owner, and uniqueness fields;
- reopens the generated object through a fresh ordinary PCS key graph before
  allowing a request to be sent;
- saves with merge and fail-if-exists semantics plus the freshly fetched zone
  protection tag, then fetches and authenticates the returned record.

The update/delete path:

- locate the complete fetched record in the archived protobuf response;
- retain the record identifier, type, etag, PCS object, PCS tag, and every
  unknown field;
- authenticate the old encrypted field and select its record master key;
- retain the observed legacy or record-context AAD convention;
- encode string or caller-supplied canonical plaintext bytes;
- encrypt with a fresh OS-random IV and self-decrypt before use;
- replace only `RecordFieldValue` fields 1, 2, and 13;
- emit a mode-0600 prepared-update or prepared-delete artifact.

Untouched protobuf fields reuse their original wire bytes instead of being
normalized. Preparation commands have no HTTP transport. Live application is
compiled in by default but can be removed with `--no-default-features`. Every
mutation still requires an explicit runtime confirmation.

## Evidence

The local primary evidence is:

- full `CKDPRecord` values preserved as `ck-encryption-record.bin` and
  `ck-migration-record.bin` in the private research archive;
- authenticated encrypted fields from tabs, bookmarks, and history;
- macOS 15.7.9 (24G830) `CloudKitDaemon.framework` and
  `ProtectedCloudStorage.framework` from the preserved Mac image;
- the confirmed `RecordRetrieveChanges` request/response used by the CLI.

The operation values and save-semantics mapping are additionally corroborated
by the [generated CloudKitDaemon implementation from an iOS 18.2 image](https://github.com/EthanArbuckle/iPhone17-1_18.2_22C152_Restore/blob/main/System/Library/PrivateFrameworks/CloudKitDaemon.framework/CKDPRecordSaveRequest.m),
the MIT-licensed [FindMy.py CloudKit schema](https://github.com/parawanderer/FindMy.py/blob/feat/icloud-keychain-export/findmy/cloudkit/proto/cloudkit.proto),
and [Laky-64's record-save encoder](https://github.com/Laky-64/appleservices/blob/master/cloudkit/recordsave.go).
The live test confirms that a full-record save using fields 1, 4, 6, and 8,
operation/field 210, semantics 1, and an unchanged record PCS object is accepted
by the production service.

The CloudKitDaemon binary contains the endpoint and generated-model names:

```text
/api/client/record/save
recordSaveType
recordSaveRequest
recordSaveResponse
fieldsToDeleteIfExistOnMerge
conflictLoserUpdate
saveSemantics
recordProtectionInfoTag
conflictLosersToResolve
```

It also contains relevant result names including `atomicFailure`,
`staleRecordUpdate`, `recordProtectionInfoTagMismatch`, and
`zoneProtectionInfoTagMismatch`. These strings prove that the private protocol
has these concepts, but do not by themselves prove protobuf field numbers or
enum values.

Apple's public API documentation supplies the semantic guardrails: the default
save policy compares the fetched record change tag, changed-keys and all-keys
policies bypass that comparison, and atomicity is scoped per record zone. See
[savePolicy](https://developer.apple.com/documentation/cloudkit/ckmodifyrecordsoperation/savepolicy),
[recordChangeTag](https://developer.apple.com/documentation/cloudkit/ckrecord/recordchangetag),
and [isAtomic](https://developer.apple.com/documentation/cloudkit/ckmodifyrecordsoperation/isatomic).

## Transport envelope

The save endpoint is **confirmed** as the path:

```text
POST https://gateway.icloud.com/ckdatabase/api/client/record/save
```

Use the same CloudKit authentication, headers, gzip compression, ULEB128
message delimiting, `RequestOperation.Header`, container, bundle identifier,
database scope, and response-result checking specified in `PROTOCOL.md` for
record reads. A save is a different operation and endpoint; it is not a
`RecordRetrieveChanges` request sent to `/record/sync`.

The following envelope assignment is **confirmed by Apple's generated operation
enum and independently implemented CloudKit protobuf schemas**:

```text
RequestOperation.operation.type = 210
RequestOperation.field[210]      = RecordSaveRequest
ResponseOperation.field[210]     = RecordSaveResponse
```

The corresponding delete operation is type and field `214`. These values are
also consistent with the confirmed record-changes value `213`. The initial
research incorrectly treated the operation sequence as one-based relative to
record retrieve; the first live probe exposed that off-by-one error as HTTP
503, and a read-back proved that no mutation occurred.

## Full record wire shape observed on reads

The compact reader currently consumes only fields 2, 3, and 7, but a writer
must retain the complete fetched record. Generic protobuf decoding of two full
Apple records produced this layout:

```proto
message Record {                         // observed CKDPRecord
  optional string etag = 1;              // ASCII server change tag
  optional RecordIdentifier id = 2;
  optional Identifier type = 3;
  optional Identifier created_by = 4;
  optional TimeStatistics times = 5;     // creation and modification dates
  repeated RecordField fields = 7;
  optional Identifier modified_by = 9;
  optional string modified_by_device = 11;
  optional ProtectionInfo protection = 13;
  // Other generated CKDPRecord properties exist. Preserve unknown fields.
}

message ProtectionInfo {                 // observed in Record field 13
  optional bytes protection_info = 1;    // DER PCS record object
  optional string protection_info_tag = 2; // observed 40 ASCII bytes
}
```

This is a partial schema, not permission to discard fields absent from the
example. The observed records also contain empty fields 21 and 22 and scalar
field 28. A clean-room writer should use an unknown-field-preserving protobuf
representation, or reconstruct a minimal request only after a native capture
shows which system fields Apple actually sends.

Identifiers and values retain the read-protocol definitions:

```proto
message Identifier {
  string name = 1;
  uint64 type = 2;
}

message RecordIdentifier {
  Identifier record = 1;                 // identifier type 1
  RecordZoneIdentifier zone = 2;
}

message RecordZoneIdentifier {
  Identifier zone = 1;                   // identifier type 6
  Identifier owner = 2;                  // identifier type 7
  uint64 database = 3;                   // observed 1 for private database
}

message RecordField {
  Identifier identifier = 1;
  RecordFieldValue value = 2;
}
```

For an existing-record compare-and-swap update, preserve at least the record
identifier, type, current `etag`, record PCS object, and its
`protection_info_tag`. Fetch immediately before constructing the update. Never
invent, hash, or locally increment the etag or PCS tag; both are server-issued
opaque values.

## Encrypting one field

This section is **derived** from the Apple encrypt routine and verified by the
inverse operation against every current encrypted fixture.

### Serialize the plaintext first

The input to PCS encryption is the exact CloudKit/Safari wire value, not its
displayed JSON or text form. `PROTOCOL.md` specifies the currently observed
UTF-8, protobuf string/date, binary plist/keyed archive, and compressed-history
encodings. A writer must reproduce the native encoding for that specific
record type and field. Do not encrypt normalized JSON.

Unknown value types are read-only until a native before/after capture fixes
their canonical encoding.

### Select the record key and AAD

Use the current record PCS master key recovered from `Record.protection_info`.
The four-byte key hint embedded in the encrypted blob is the first four bytes
of the full v3 master-key ID:

```text
t    = SP800-108-HMAC-SHA256(M, "master key id labell", empty, 16)
id   = HMAC-SHA256(t, "M key input data 2 u")
hint = id[0:4]
```

Use the AAD mode already observed for that record/field family:

```text
legacy:  UTF8(fieldName)
context: UTF8(zoneName + "-" + recordName + "-" + fieldName)
```

The context form is CloudKit encrypted-field context type 1. The components
are concatenated with literal ASCII hyphens and no NUL or length prefix.

### Construct an FP v3 ciphertext

Given record master key `M`, serialized plaintext `P`, and field AAD `A`:

```text
K      = SP800-108-HMAC-SHA256(M, "encryption key key m", empty, 16)
header = 03 || id[0:2] || 02 || id[2:4]
iv     = 12 cryptographically random bytes
(C,T)  = AES-128-GCM-ENCRYPT(K, iv, P, AAD = header || A)
blob   = header || iv || T[0:12] || C
```

The GCM authentication tag is truncated to 12 bytes. Store `blob` as
`RecordFieldValue.bytesValue` (field 2), set its explicit value type to 20
(observed encrypted bytes), and set `RecordFieldValue.isEncrypted` (field 13)
to true. Never reuse an IV with the same derived key.

Before allowing serialization into a network request, the implementation must
decrypt its own result with the read path and compare the raw plaintext bytes.
It must also reject a one-bit change to the header, IV, tag, ciphertext, or AAD.
The tracked `fixtures/public/protocol-vectors.json` `fp_v3` entry is already a
deterministic bidirectional vector: its IV is `blob[6:18]`, and encryption with
that IV must reproduce the complete `blob` exactly.

## Reusing versus rotating record PCS

For a field-only update, the leading hypothesis is to resend the fetched
record PCS object and `protection_info_tag` unchanged while producing fresh
field IVs. This is plausible because the PCS object supplies the record master
key and is independent of an individual field ciphertext.

It is still **unconfirmed**. A native Safari before/after capture must establish
whether an ordinary field edit changes:

- `Record.protection_info.protection_info`;
- `Record.protection_info.protection_info_tag`;
- the PCS object's standalone 32-byte value;
- optional `[3]` signature material; or
- parent/zone protection tags.

Creation uses a fresh record PCS object. The implementation follows the
MIT-licensed [OpenTagViewer clean-room PCS
specification](https://github.com/parawanderer/OpenTagViewer/blob/main/docs/findmy-export/05-pcs-decryption.md)
and [FindMy.py's independently written PCS implementation and
tests](https://github.com/parawanderer/FindMy.py/blob/feat/icloud-keychain-export/tests/test_pcs.py),
with RFC 6637 behavior checked against Apple's open-source
[`SOSECWrapUnwrap.c`](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/SecureObjectSync/SOSECWrapUnwrap.c).
It derives a P-256 self-signing key with PBKDF2, adds an outer signature by the
zone child key, and wraps the record master key with RFC 6637. Deterministic
vectors pin each construction primitive. The generated object must parse and
reopen through this repository's existing read implementation before it is
eligible for transport. See [`PROVENANCE.md`](PROVENANCE.md).

## Generated save and delete layouts

The iOS 15.8.8 (19H422) Apple OTA's `CloudKitDaemon.framework` generated class
layout orders the `CKDPRecordSaveRequest` ivar-offset symbols as follows. This
is **derived from Apple's binary, not yet confirmed by a captured request**:

```proto
message RecordSaveRequest {
  optional Record record = 1;
  optional bool merge = 2;
  repeated RecordFieldIdentifier fields_to_delete_if_exist_on_merge = 3;
  optional string etag = 4;
  optional ConflictLoserUpdate conflict_loser_update = 5;
  optional SaveSemantics save_semantics = 6;
  optional string zone_protection_info_tag = 7;
  optional string record_protection_info_tag = 8;
  repeated ConflictLoserResolve conflict_losers_to_resolve = 9;
  optional string share_etag = 10;
  optional ShareIdUpdate share_id_update = 11;
  optional string parent_chain_protection_info_tag = 12;
  optional RequestedFields requested_fields = 13;
}

enum SaveSemantics {
  FAIL_IF_OUTDATED = 1;
  FAIL_IF_EXISTS = 2;
  OVERRIDE = 3;
}

message RecordDeleteRequest {
  optional RecordIdentifier record_identifier = 1;
  optional string etag = 2;
  repeated RecordField plugin_fields = 3;
  optional bool participant_key_lost = 4;
  repeated bytes public_keys = 5;
}
```

The save response ivar order is `etag = 1`, `timeStatistics = 2`,
`serverFields = 3`, and `expirationTime = 4`; the generated delete response has
no instance fields. Apple's generated `StringAsSaveSemantics:` implementation
maps `failIfOutdated`, `failIfExists`, and `override` to 1, 2, and 3.

The Rust encoder uses save fields 1, 4, 6, and 8 for an existing-record
compare-and-swap update, and delete fields 1 and 2. Creation uses fields 1
(record), 2 (merge=true), 6 (fail-if-exists), and 7 (zone protection tag).
Those minimum layouts are backed by this project's disposable-record E2E
results and independently corroborated by the FindMy.py CloudKit schema. The
encoder does not guess values for the remaining optional features.

The safest first mutation is a single-field update to one purpose-created
record, with the server-unchanged/compare-and-swap behavior and atomic mode.
Changed-keys or all-keys semantics should not be used to bypass a stale etag.

## Remaining native-capture research

A native Safari capture remains useful for comparing optional fields and exact
client conventions even though the minimal requests are accepted by CloudKit.

For an update capture:

1. Save the complete pre-edit `RecordRetrieveChanges` response and local Safari
   representation.
2. Change exactly one non-structural field, such as the title of a disposable
   bookmark; do not move it or modify parents in the same test.
3. Capture the gzipped, length-delimited request to `/api/client/record/save`
   and its response. Preserve raw bytes before decoding.
4. Fetch changes again and preserve the returned record.
5. Produce a generic protobuf tree for request and response, including wire
   type, field number, byte length, and nested-message boundaries.
6. Diff record metadata, PCS DER, encrypted blob header/AAD mode, etag, and PCS
   tag. Redact tokens and plaintext only after storing an encrypted private
   research copy.
7. Repeat with a deliberately stale pre-edit record to identify the exact
   conflict result without overwriting the newer value.

The capture is accepted only when it confirms:

- endpoint, operation type, and top-level request/response field;
- every `RecordSaveRequest` field number and save-semantics value used;
- whether the request contains a full record or only changed fields;
- how field deletion is represented;
- etag and `recordProtectionInfoTag` placement;
- whether field-only edits reuse PCS bytes;
- the response's returned record/change tag and error envelope.

## Runtime safety gate

Live write support is isolated in the `experimental-live-writes` Cargo feature.
It is enabled in the default CLI build and can be compiled out with
`--no-default-features`. The synthetic encryption round-trip is already
covered. The write path requires all of the following at runtime:

- an explicit write subcommand; reads and backups can never invoke it;
- a purpose-created disposable marker during live E2E development;
- a fresh source-record hash check for updates/deletes, or a fresh zone-tag and
  name-absence check for creation;
- exactly one record per request;
- separate offline preparation for update/delete requests;
- an authenticated post-save plaintext-hash match or post-delete absence;
- no automatic retry on stale-record, PCS-tag, zone-tag, or atomic failures.

Key rotation of an existing record, parent moves, sharing, field deletion, and
multi-record writes remain disabled. Bookmark/tab creation is enabled with
fail-if-exists and zone-tag protection and an authenticated post-write fetch.

## Open questions

1. Which extra optional save fields does native Safari send?
2. Does native Safari send a complete record or only changed fields?
3. How are parent moves, field tombstones, and multi-record transactions encoded?
4. Which outbound keyed-archive encodings are canonical for less common Safari fields?

The write path remains an undocumented-protocol implementation and should be
treated as compatibility-sensitive even after successful production E2E tests.
