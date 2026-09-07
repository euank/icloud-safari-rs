# Safari iCloud protocol and cryptography

Last updated: 2026-09-04

## Scope and confidence

This document specifies the protocol implemented by this repository to fetch
and decrypt Safari tabs, bookmarks, and history from iCloud on a non-Apple
platform. Together with a fixture bundle satisfying the contract in section
14, it is intended to be sufficient for an experienced implementer to rebuild
the **read-only path in a fresh repository and another language**, without
reading or copying this project's source.

The following have been verified against live Apple services and the saved
fixtures:

- native Apple authentication can obtain the tokens used by CloudKit;
- CloudKit's private-database change operation returns Safari records;
- an enrolled Octagon peer can recover CKKS keys and PCS identities;
- the complete PCS zone-to-record key chain can be opened;
- every encrypted value in the current tabs, bookmarks, and history fixtures
  authenticates and decodes.

Sections 11–13 give the exact Apple Account, escrow, and Octagon bootstrap used
by the working client. Anisette machine attestation uses provisioned Apple
components: the client can generate it locally with the installed macOS
framework or with native libraries extracted from Apple's Android APK on
Linux. A byte-level HTTP provider remains an optional compatibility boundary.

The read protocol is implementation-ready. Outbound FP v3 field encryption is
also understood, but the CloudKit save submessage has not yet been captured.
[`WRITE-PROTOCOL.md`](WRITE-PROTOCOL.md) records the confirmed write-path
evidence, exact encryption construction, inferred operation envelope, missing
wire fields, and the native disposable-record capture required before writes
can be enabled. Do not use the current material to write to a valuable account.

## Notation

| Expression | Meaning |
| --- | --- |
| `BE16(x)`, `BE32(x)` | unsigned big-endian integer |
| `LE64(x)` | low 64 bits of an integer, little-endian |
| `HMAC(k, x)` | HMAC-SHA-256 |
| `SHA256(x)` | SHA-256 |
| `P256`, `P384` | NIST prime elliptic curves |
| `x(P)` | fixed-width big-endian x coordinate of point `P` |
| `‖` | byte concatenation |
| `DER(T)` | DER encoding of ASN.1 value `T` |
| `FP` | the PCS “file protection” object/key format used here |
| `PCS` | Apple Protected Cloud Storage |
| `CKKS` | CloudKit Keychain Sync |

Unless noted otherwise, strings used in cryptographic operations are their
exact ASCII/UTF-8 bytes, without a trailing NUL.

## End-to-end model

The data and key paths are independent until local decryption:

```text
Apple login + Anisette
  -> mmeAuthToken + CloudKit token
  -> ckAppInit for each Safari container
  -> container-scoped CloudKit user ID
  -> private-zone RecordRetrieveChanges
  -> records, encrypted fields, and embedded PCS objects

Octagon trust enrollment
  -> recoverable CKKS top-level keys (TLKs)
  -> CKKS class keys
  -> decrypted Manatee PCS identity item
  -> unwrap zone PCS object
  -> zone FP master key
  -> decrypt zone [0] private export
  -> child/record private identity
  -> unwrap record PCS object(s)
  -> record FP master key(s)
  -> decrypt authenticated CloudKit fields
  -> Safari values
```

Tokens authorize downloading ciphertext. The CKKS/PCS key chain authorizes
decrypting it; a CloudKit bearer token alone is insufficient.

## 1. Authentication inputs

The working client uses Apple's GrandSlam SRP login with Anisette metadata and
a stable emulated device identity. The resulting MME account response supplies:

- the numeric account `dsid`;
- an `mmeAuthToken`, used only to initialize CloudKit containers; and
- a `cloudKitToken`, used as the database bearer token.

Use the same stable device UUID, serial number, hardware/software description,
and Anisette identity for later requests. The exact token and two-factor flows
are specified in section 12.

For key recovery, create and persist an Octagon peer, recover a sponsor from an
escrow bottle using a freshly minted PET, join the trust circle, and call the
Cuttlefish recoverable-TLK operation. Enrollment can consume rate-limited
escrow attempts; it is persistent account state, not part of a routine backup.

## 2. CloudKit transport

### Containers and zones

All three datasets use bundle ID `com.apple.Safari`, production environment,
and the private database:

| Dataset | Container | Zone |
| --- | --- | --- |
| Tabs | `com.apple.SafariShared.CloudTabs` | `CloudTabs` |
| Bookmarks | `com.apple.SafariShared.WBSCloudBookmarksStore` | `Bookmarks` |
| History | `com.apple.SafariShared.History` | `History` |

### Container initialization

For each container, send:

```text
POST https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit?container=<container>
Authorization: Basic base64(UTF8(dsid ":" mmeAuthToken))
x-cloudkit-containerid: <container>
x-cloudkit-bundleid: com.apple.Safari
x-cloudkit-databasescope: Private
x-cloudkit-environment: Production
<the remaining common CloudKit headers listed below>
<the Anisette headers from section 12>
```

The response JSON contains `cloudKitUserId`. Cache it per container. It is an
opaque identifier and is neither the DSID nor necessarily reusable across
containers.

### Record-change request

Send the private-zone change request to:

```text
POST https://gateway.icloud.com/ckdatabase/api/client/record/sync
x-cloudkit-userid: <container-scoped cloudKitUserId>
x-cloudkit-authtoken: <cloudKitToken>
content-encoding: gzip
content-type: <the exact application/x-protobuf value below>
```

Also send the container, bundle, database-scope, production-environment,
device, request UUID, operation ID, and Anisette headers used for `ckAppInit`.
The complete common non-Anisette header block used by the working client is:

```text
accept: application/x-protobuf
accept-encoding: gzip
accept-language: en-US,en;q=0.9
cache-control: no-transform
content-encoding: gzip
content-type: application/x-protobuf; desc="https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc"; messageType=RequestOperation; delimited=true
user-agent: CloudKit/1970 (19H384)
x-apple-c2-metric-triggers: 0
x-apple-operation-group-id: fresh uppercase 16-hex-character value
x-apple-operation-id: fresh uppercase 16-hex-character value
x-apple-request-uuid: fresh uppercase UUID
x-cloudkit-bundleid: <bundle>
x-cloudkit-containerid: <container>
x-cloudkit-databasescope: Private
x-cloudkit-duetpreclearedmode: None
x-cloudkit-environment: Production
x-mme-client-info: <MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)>
```

Use this block for `ckAppInit` too, adding its Basic authorization and
Anisette headers; its request body is empty despite the advertised content
encoding. Database operations add `x-cloudkit-userid` and
`x-cloudkit-authtoken`. CKCode operations additionally add the routing hint
specified in section 13. The database HTTP body is:

```text
gzip(ULEB128(length(RequestOperation)) ‖ RequestOperation)
```

The protobuf schemas below use `field:type`; omitted optional fields are not
encoded. “message” means a length-delimited nested protobuf.

```text
Identifier {
  1:string name
  2:uint64 type
}

RecordZoneIdentifier {
  1:message Identifier(zoneName, type=6)
  2:message Identifier(cloudKitUserId, type=7)
}

RecordRetrieveChangesRequest {
  1:bytes continuationToken       // omit on first page
  2:message RecordZoneIdentifier
  4:uint64 maxChanges             // 500 works
}

Operation {
  1:string uppercaseUUID
  2:uint64 type = 213
  4:bool   true
}

RequestOperation {
  1:message Header
  2:message Operation
  213:message RecordRetrieveChangesRequest
}
```

The observed `Header` is:

```text
 2:string containerID
 3:string bundleID
 7:message Identifier(deviceUUID, type=2)
 8:string softwareVersion
 9:string hardwareVersion
10:string "com.apple.cloudkit.CloudKitDaemon"
11:string "1970"
18:string "5.0"
19:uint64 1                     // production environment
21:string deviceDisplayName
22:string deviceUUID
23:uint64 1                     // private database
25:uint64 1                     // zone isolation
29:uint64 0
32:string lowercaseHex(SHA1(UTF8(deviceUUID)))
33:string deviceSerial
34:uint64 0
35:uint64 1
```

The response may be gzip-compressed and is again a stream of ULEB128-framed
protobuf messages. In `ResponseOperation`, field 3 is a result message. Its
field 1 is the result code (`1` is success); on error, result field 2 contains
an error whose field 4 is the description. The operation-specific response is
field 213:

```text
RecordRetrieveChangesResponse {
  1:message Change repeated       // Change field 5 is a Record
  2:bytes continuationToken
  4:uint64 status                 // 1 = fetch another page; 3 = final
}

Record {
  2:message recordIdentifier
  3:message recordTypeIdentifier
  7:message Field repeated
}

Field {
  1:message fieldNameIdentifier
  2:message Value
}
```

An identifier's string is nested in its field 1. The observed `Value` union is:

| Field | Wire type | Meaning |
| --- | --- | --- |
| 2 | length-delimited | bytes |
| 4 | varint | signed/integer value |
| 5 | fixed64 | little-endian IEEE-754 double |
| 6 | message | date; nested field 1 is a fixed64 double |
| 7 | length-delimited | UTF-8 string |
| 9 | message | reference; descend through field 2 identifiers to the record name |

Follow pages while status is `1` and a continuation token is present. Preserve
unknown record fields and raw bytes; Apple can add value variants.

## 3. Recovering the initial PCS identities from CKKS

An Octagon-enrolled client calls the Cuttlefish recoverable-TLK operation and
syncs CKKS zones. The Safari container identities currently reside in Manatee
items labelled like:

```text
PCS com.apple.SafariShared.CloudTabs - ...
PCS com.apple.SafariShared.History - ...
```

Bookmarks use the applicable general Safari PCS identity. Select identities by
matching their public x coordinate to the recipient ID in the PCS object; do
not make labels the cryptographic lookup key.

The CKKS decryption pipeline is:

```text
Octagon peer P-384 private encryption key
  -> decrypt TLKShare
TLK (64-byte AES-SIV key)
  -> unwrap synckey/class key
class key (64-byte AES-SIV key)
  -> unwrap per-item key
item key (64-byte AES-SIV key)
  -> decrypt item data with authenticated metadata
binary plist
  -> v_Data PCS identity DER
```

### TLKShare ECIES

Base64-decode the share's `wrappedkey` and unarchive its NSKeyedArchive. It
contains an ephemeral sender public key, ciphertext, and authentication code.
SecurityFoundation ciphertexts observed here append 113 unused bytes
(`97 + 16`); remove them before decryption.

Resolve NSKeyedArchiver UIDs through `$objects`, starting at `$top.root`.
Foundation `NSData`, `NSString`, and collection wrappers expose `NS.data`,
`NS.string`, and `NS.objects` respectively. The resulting dictionary uses
these exact keys (including Apple's `ExternaRepresentation` spelling):

```text
SFEphemeralSenderPublicKeyExternaRepresentation -> P-384 X9.63 public bytes
SFCiphertext                                     -> ciphertext plus 113-byte suffix
SFIESAuthenticationCode                         -> GCM tag
```

With the peer's P-384 private key:

```text
Z       = P384-ECDH(peerPrivate, ephemeralPublic)
derived = X9.63-KDF-SHA256(Z, sharedInfo=ephemeralPublicEncoding, L=48)
key     = derived[0:32]
iv      = derived[32:48]
plain   = AES-256-GCM-decrypt(key, iv, ciphertext, tag, AAD=empty)
```

Here X9.63 KDF is:

```text
SHA256(Z ‖ BE32(1) ‖ sharedInfo) ‖
SHA256(Z ‖ BE32(2) ‖ sharedInfo) ‖ ...
```

truncated to the requested length. The plaintext is:

```text
CuttlefishSerializedKey {
  1:string uuid
  2:string zoneName
  3:uint64 keyClass
  4:bytes  key
}
```

### CKKS AES-SIV layers

AES-SIV ciphertexts use the 64-byte parent key directly. A `synckey` record's
base64 `wrappedkey` decrypts under its `parentkeyref` TLK with no associated
data. An `item` record's base64 `wrappedkey` similarly decrypts under its class
key to yield the item key.

Item `data` has this layout:

```text
randomIV[16] ‖ AES-SIV(tag ‖ ciphertext)
```

Decrypt it with the item key and this ordered list of associated-data strings:

```text
[ randomIV ] + [ value for each metadata key in lexicographic key order ]
```

For CKKS item encryption version 2, construct the metadata map as follows:

```text
"UUID"              -> UTF8(record name)
"encver"            -> LE64(encver; default 2)
"gen"               -> LE64(gen; default 0)
"wrappedkey"        -> UTF8(parentkeyref record name)
"pcsservice"        -> LE64(value), if present
"pcspublicidentity" -> raw bytes, if present
"pcspublickey"      -> raw bytes, if present
```

Add all other record fields except names beginning `server_` and:

```text
gen pcspublickey UUID data pcsservice pcspublicidentity parentkeyref
uploadver wrappedkey encver
```

Encode added values as UTF-8 for strings, unchanged for bytes, LE64 for
integers/booleans, and UTC `YYYY-MM-DDTHH:MM:SSZ` for dates. After AES-SIV
authentication, remove ISO-7816-4 padding (`80 00...00`) and parse the binary
plist. The PCS identity is its `v_Data` byte value.

### PCS identity private export

The recovered DER contains a 64-byte OCTET STRING:

```text
publicX[32] ‖ privateScalar[32]
```

Both are P-256 values. Reject it unless `0 < privateScalar < n(P256)` and
`x(privateScalar * G) == publicX`. Never select or accept a private scalar based
only on a byte offset.

## 4. PCS object envelope

PCS protection objects are DER `APPLICATION[1]` values (`0x61`) containing a
sequence with this observed grammar:

```asn1
PCSObject ::= [APPLICATION 1] EXPLICIT SEQUENCE {
  recipients       SEQUENCE {
    version          INTEGER,                 -- observed 0
    entries          SET OF Recipient
  },
  encryptedPrivate [0] EXPLICIT OCTET STRING,
  publicIdentity   [1] EXPLICIT SEQUENCE {
    version          INTEGER,                 -- observed 5
    export           OCTET STRING
  },
  digestOrIntegrity OCTET STRING,             -- 32 bytes, purpose unknown
  masterKeyHint    [2] EXPLICIT OCTET STRING, -- 4 bytes
  signature        [3] EXPLICIT SEQUENCE {    -- optional
    publicX          OCTET STRING,            -- 32 bytes
    version          INTEGER,                 -- observed 1
    ecdsaDER         OCTET STRING
  } OPTIONAL
}

Recipient ::= SEQUENCE {
  identity SEQUENCE {
    version INTEGER,                          -- observed 3
    publicX OCTET STRING                      -- 32-byte compact P-256 x
  },
  wrappedMasterKey OCTET STRING
}
```

Some objects omit `[3]`. For the read path, use the recipient entries,
`encryptedPrivate`, `publicIdentity`, and `masterKeyHint`. The standalone
32-byte value is not the v3 master-key ID. Its semantics and the signature
construction must be understood before implementing writes.

Compact P-256 encodings contain x only. Either possible y root may be used for
ECDH because negating the input point negates the shared point but leaves its x
coordinate unchanged.

## 5. PCS cryptographic primitives

### NIST SP 800-108 counter KDF

All PCS labels below use HMAC-SHA-256 counter mode:

```text
KDF(k, label, context, L) = first L bytes of K(1) ‖ K(2) ‖ ...
K(i) = HMAC(k,
            BE32(i) ‖ label ‖ 00 ‖ context ‖ BE32(L * 8))
```

### FP master-key identifier

For an FP master key `M`:

```text
t     = KDF(M, "master key id labell", empty, 16)
id    = HMAC(t, "M key input data 2 u")          // 32 bytes
hint  = id[0:4]
```

The misspelling and spaces in both 20-byte labels are significant. Always
compute and retain the full ID; a four-byte hint is only an index. If two
different full IDs have the same hint, report ambiguity rather than choosing a
key.

A compact identity's separate 20-byte identity key ID, where needed, is:

```text
SHA256(publicX)[0:20]
```

PCS object recipient IDs in the objects studied here are instead the complete
32-byte compact `publicX`.

### RFC 6637-style P-256 key unwrap

The recipient's wrapped master key is:

```text
BE16(ephemeralPublicLengthInBits)
‖ ephemeralPublic
‖ U8(wrappedLength)
‖ wrapped
```

Observed compact P-256 values use `ephemeralPublicLengthInBits = 0x0100`, a
32-byte x coordinate, and `wrappedLength = 48`. Uncompressed points may appear
as `04 ‖ x[32] ‖ y[32]` with bit length `0x0208`.

Reconstruct the ephemeral point, then compute:

```text
Z = x(P256-ECDH(recipientPrivate, ephemeralPublic))    // 32 bytes

params = 09 2A8648CE3D030107 12 03 01 08 07
         ^  ^ P-256 OID       ^        ^  ^
         |                    ECDH=18  SHA256=8, AES128=7
         DER-OID byte length

fingerprint = "fingerprint" ‖ 00*9                    // 20 bytes
sender      = "Anonymous Sender    "                  // 20 bytes
KEK = SHA256(BE32(1) ‖ Z ‖ params ‖ sender ‖ fingerprint)[0:16]
```

RFC 3394 AES key-unwrap `wrapped` using `KEK`. The result is exactly 40 bytes:

```text
algorithm[1] ‖ key[N] ‖ BE16(sum(key bytes) mod 65536) ‖ padding[P]
```

Each padding byte equals `P`, and `N = 40 - P - 3`. Validate the RFC 3394
integrity value, padding, and additive checksum. Current PCS master keys are
16 bytes. A successful unwrap is not enough: compute the v3 ID and require
that it begins with the object's four-byte `masterKeyHint`.

### FP encrypted blobs

Version 3 field/private blobs are:

```text
03 ‖ id[0:2] ‖ 02 ‖ id[2:4] ‖ IV[12] ‖ TAG[12] ‖ ciphertext
\___________________________/
         header[6]
```

Thus the lookup hint is `blob[1:3] ‖ blob[4:6]`. To decrypt under master key
`M`:

```text
K         = KDF(M, "encryption key key m", empty, 16)
AAD       = header ‖ extraAAD
plaintext = AES-128-GCM-decrypt(K, IV, ciphertext, TAG, AAD)
```

The GCM tag is 12 bytes. Use an API that accepts truncated tags; many
high-level AES-GCM interfaces require 16 bytes. Supply the tag once, and do
not include an enclosing DER OCTET STRING tag/length in the blob.

Versions 2 and 4 have been seen by the PCS routine and use header lengths 3
and 5 respectively, but their complete header semantics have not been
validated in Safari fixtures. Treat version 3 as the specified format.

## 6. Walking the PCS key graph

PCS objects occur inside the zone metadata and records returned by CloudKit.
Parse them structurally from their containing protobuf fields where possible;
the research CLI can also locate DER `APPLICATION[1]` objects in raw responses.

For each dataset:

1. Parse all PCS objects and index available CKKS identities by their exact
   32-byte public x coordinate.
2. Find an object recipient matching an available identity.
3. RFC 6637-unwrap its FP master key and verify the v3 hint.
4. Decrypt the object's `[0]` value with empty `extraAAD`.
5. Parse the authenticated plaintext for a 64-byte
   `childPublicX ‖ childPrivateScalar` identity.
6. Parse the object's `[1]` public export and choose its final curve-valid
   32-byte OCTET STRING as the expected child public x.
7. Verify both `x(childPrivateScalar * G) == childPublicX` and
   `childPublicX == expectedChildPublicX`.
8. Add the child identity to the identity index and repeat until no new object
   can be unwrapped.
9. Index all verified object master keys by their four-byte v3 hints and use
   those hints to select keys for encrypted record fields.

The initial object is the zone object. Its `[0]` ciphertext is 165 bytes in
the current fixtures and decrypts to a 135-byte DER child private export. The
child identity opens the record PCS objects. A record object's 41-byte `[0]`
value decrypts to an 11-byte DER marker, not another identity, so graph
expansion naturally stops there.

Tabs and history currently each use one record key; bookmarks use multiple
record keys. Do not encode those counts as protocol invariants.

## 7. Decrypting CloudKit record fields

An encrypted byte field begins with an FP header. Reconstruct its four-byte
hint, select an unambiguous verified record master key, then try the applicable
CloudKit field context as `extraAAD`:

```text
legacy context: UTF8(fieldName)
context type 1: UTF8(zoneName "-" recordName "-" fieldName)
```

Tabs and history fixtures use the newer zone/record/field form; bookmark
fixtures include the legacy field-name form. The hyphens are literal and there
is no NUL terminator. If metadata does not expose the context type, attempting
both is safe because GCM authentication is the oracle. Never accept output
based on plausible plaintext.

Authenticate the ciphertext before parsing, decompressing, or displaying it.
An authentication failure means the key, AAD, or bytes are wrong; it is not an
unknown plaintext codec.

## 8. Safari plaintext codecs

After successful GCM authentication, decode in this order while preserving
unknown values as bytes:

1. If the payload is a valid zlib stream, decompress it.
2. If it begins `bplist00`, parse it as a binary plist.
3. If it is an `NSKeyedArchiver`, resolve `$top.root` UID references through
   `$objects`. An object with `NS.time` is seconds since Apple's epoch.
4. Recognize encrypted CKDP scalar wrappers:

   ```text
   string = 32 ‖ ULEB128(length) ‖ UTF8(value)  // protobuf field 6
   date   = 2A 09 09 ‖ IEEE754-LE64(seconds)    // field 5, Date.field 1
   ```

   Current strings are short enough that the length is one byte; implement a
   general varint decoder.
5. Otherwise accept valid printable UTF-8.
6. Preserve anything else losslessly, for example as base64 in JSON output.

The Apple absolute-time epoch is `2001-01-01T00:00:00Z`; convert to Unix time
by adding `978307200`. History payloads observed here are zlib-compressed
binary plists containing keys such as `Visits` and `ClientVersion`, with visit
times using the Apple epoch. Bookmark titles and URLs may be raw UTF-8, while
other bookmark values use keyed plists or the CKDP date wrapper.

Some byte-valued fields are unencrypted application data (for example zlib
JSON position values) or opaque hashes. Only treat a value as PCS-encrypted
after validating its FP header and authenticating it.

## 9. Required validation and failure behavior

A conforming read implementation should enforce these invariants:

- reject malformed protobuf lengths, DER lengths, points, and scalar ranges;
- validate every AES-KW, AES-SIV, and AES-GCM integrity check;
- validate the RFC 6637 padding and additive checksum;
- verify a PCS master key's full v3 ID before indexing its hint;
- reject truncated-ID collisions as ambiguous;
- verify every recovered private scalar against both embedded public values;
- use authenticated GCM success, never plaintext appearance, to select AAD;
- retain unknown records, fields, protobuf variants, and plaintext encodings;
- never print or persist private scalars, master keys, tokens, or decrypted
  data by default;
- make all backup acquisition operations read-only.

Useful implementation tests include a generated 12-byte-tag FP round trip;
single-byte corruption of each key/header/IV/tag/ciphertext/AAD component;
RFC 6637 known-answer tests; malformed DER/protobuf cases; pagination; and an
artificial collision between two full v3 IDs sharing a four-byte hint.

## 10. Known gaps

The read path does not require these answers, but a safe write implementation
does:

- semantics and calculation of the PCS object's standalone 32-byte field;
- exact `[3]` signature input and when the signature is mandatory;
- complete versions 2 and 4 FP blob formats;
- all Safari record/value schemas and canonical outbound serialization;
- record creation, change tags, deletes, conflicts, atomicity, and key rotation;
- behavior under shared zones, multiple owners, and identity rotation;
- whether additional encrypted-field context types exist.

Write-path research has narrowed this list: the private save endpoint, model
names, full fetched-record metadata, and outbound v3 field encryption are now
known. The blocking gap is a raw native save request/response proving the save
submessage tags, semantics enum, PCS-tag handling, and whether field-only edits
reuse PCS bytes. See [`WRITE-PROTOCOL.md`](WRITE-PROTOCOL.md); inferred values
there are deliberately not part of this document's conformance contract.

## 11. Clean-room implementation order

Implement and test the system in layers. This avoids spending authentication
or escrow attempts while debugging local parsers.

### Stage A: offline Safari decryptor

Inputs:

- the three normalized Safari dump JSON files described in section 14; and
- a directory of recovered PCS identity DER files.

Implement protobuf parsing, PCS-object extraction, DER parsing, RFC 6637
unwrap, FP decryption, graph walking, field AAD, and plaintext codecs. This
stage requires no Apple credentials or network access. It is complete when all
three fixture datasets meet the conformance counts in section 14.

### Stage B: CKKS identity recovery

Inputs:

- archived CKKS `item` and `synckey` records;
- recoverable TLKShare records; and
- the applicable P-384 Octagon encryption private key.

Implement the ECIES and AES-SIV pipeline in section 3. Its output is the PCS
identity DER directory consumed by Stage A. No live join is required when
these fixtures are supplied.

### Stage C: live CloudKit acquisition

Inputs:

- a saved `mmeAuthToken`, `cloudKitToken`, device identity, and Anisette
  provider.

Implement `ckAppInit` and `RecordRetrieveChanges`. Save raw response bytes as
well as parsed fields, then feed the result to Stage A. This stage is read-only.

### Stage D: account bootstrap and Octagon enrollment

Inputs:

- Apple Account credentials and interactive 2FA;
- an Anisette provider;
- the login/escrow secret for a recoverable bottle; and
- explicit user consent immediately before escrow recovery.

Implement sections 12 and 13 last. Persist the device and peer keypairs before
any escrow call, and reuse them on retry. A failed recovery can consume one of
the account's limited attempts.

The implementation should expose these layers as separate commands or library
interfaces. In particular, parsing a fixture must never silently initiate a
live request.

## 12. Apple Account and MME bootstrap

### Stable device and Anisette provider

Generate once and persist:

```text
deviceUUID    = uppercase UUID
serial        = stable 12-character Mac-like serial
localUserUUID = uppercase UUID
```

The fallback machine headers are:

```text
X-Apple-I-Client-Time: UTC RFC3339 seconds, e.g. 2026-09-04T12:34:56Z
X-Apple-I-TimeZone: UTC
loc: system locale, normally en_US
X-Apple-Locale: same locale
X-Apple-I-MD-RINFO: 17106176
X-Apple-I-MD-LU: base64(UTF8(uppercase localUserUUID))
X-Mme-Device-Id: uppercase deviceUUID
X-Apple-I-SRL-NO: serial
```

For every authenticated Apple request, fetch a fresh JSON object from a
compatible Anisette provider and overlay these allowed keys onto the fallback
headers:

```text
X-Apple-I-MD
X-Apple-I-MD-M
X-Apple-I-MD-RINFO
X-Apple-I-MD-LU
X-Apple-I-SRL-NO
X-Mme-Device-Id
X-Apple-I-Client-Time
X-Apple-I-TimeZone
X-Apple-Locale
```

`X-Apple-I-MD` and `X-Apple-I-MD-M` are mandatory. This client provisions and
generates Anisette locally: macOS uses the installed Apple framework, while
Linux extracts the required proprietary native libraries from Apple's official
Apple Music Android APK on first use. Because those libraries cannot be
redistributed here, first use on Linux requires that download. An explicit
compatibility provider can instead be selected; its contract is an HTTP `GET`
whose JSON response maps the allowed header names to strings.

### GrandSlam SRP login

Endpoint and fixed headers:

```text
POST https://gsa.apple.com/grandslam/GsService2
Content-Type: text/x-xml-plist
Accept: */*
User-Agent: akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0
X-MMe-Client-Info: <MacBookPro13,2> <Mac OS X;10.15.2;19C57> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>
```

Add the stable device/Anisette headers. Requests and responses are Apple XML
plists. Every request has this envelope:

```text
{
  "Header": {"Version": "1.0.1"},
  "Request": {
    "cpd": {
      "bootstrap": true,
      "icscrec": true,
      "pbe": false,
      "prkgen": true,
      "svct": "iCloud",
      ...the stable device/Anisette headers as plist keys...
    },
    ...operation parameters...
  }
}
```

Use SRP-6a, SHA-256, the RFC 5054 2048-bit group, `g = 2`, and a fresh
256-byte random client exponent with its high bit set. The modulus is the
`srp_2048_modulus` in
[`../fixtures/public/protocol-vectors.json`](../fixtures/public/protocol-vectors.json).
Integers are unsigned big-endian. `PAD(x)` left-pads to 256 bytes and
`MIN(x)` is the minimal non-empty encoding.

Send the initialization operation:

```text
{
  "A2k": MIN(A),
  "ps": ["s2k", "s2k_fo"],
  "u": username,
  "o": "init"
}
```

where `A = g^a mod N`. The response selects `sp`, and supplies salt `s`,
iteration count `i`, challenge `B`, and continuation value `c`. Derive the
password material exactly as follows:

```text
p0 = SHA256(UTF8(password))
p1 = p0                         if sp == "s2k"
p1 = lowercaseHex(p0) as ASCII if sp == "s2k_fo"
p  = PBKDF2-HMAC-SHA256(password=p1, salt=s, iterations=i, length=32)

x = INT(SHA256(s ‖ SHA256(":" ‖ p)))
k = INT(SHA256(PAD(N) ‖ PAD(g)))
u = INT(SHA256(PAD(A) ‖ PAD(B)))
S = (B - k * g^x mod N)^(a + u*x) mod N
K = SHA256(MIN(S))

M1 = SHA256(
       (SHA256(MIN(N)) XOR SHA256(PAD(g))) ‖
       SHA256(UTF8(username)) ‖ s ‖ MIN(A) ‖ MIN(B) ‖ K)
M2 = SHA256(MIN(A) ‖ M1 ‖ K)
```

Send completion using the same envelope:

```text
{"c": c, "M1": M1, "u": username, "o": "complete"}
```

Require the returned `M2` to equal the locally calculated value. Derive:

```text
spdKey = HMAC-SHA256(K, "extra data key:")
spdIV  = HMAC-SHA256(K, "extra data iv:")[0:16]
```

AES-CBC-decrypt response field `spd` with `spdKey` and `spdIV`, remove PKCS#7
padding, and parse the XML plist. The account identifier is `adsid` or
`DsPrsId`. The short-lived PET is:

```text
spd["t"]["com.apple.gs.idms.pet"]["token"]
```

### Two-factor authentication

If completion status field `au` is `trustedDeviceSecondaryAuth`, obtain `dsid`
and `GsIdmsToken` (also observed as `GsIdMS`) from `spd`. Construct:

```text
X-Apple-Identity-Token: base64(UTF8(dsid ":" GsIdmsToken))
Content-Type: text/x-xml-plist
User-Agent: Xcode
Accept: text/x-xml-plist
Accept-Language: en-us
X-Apple-App-Info: com.apple.gs.xcode.auth
X-Xcode-Version: 11.2 (11B41)
X-Mme-Client-Info: <the GrandSlam client-info above>
```

Add device/Anisette headers, then:

```text
GET https://gsa.apple.com/auth/verify/trusteddevice       // trigger
GET https://gsa.apple.com/grandslam/GsService2/validate  // submit
security-code: <six-digit code>                          // submit header
```

For `secondaryAuth` (SMS), use the same headers:

```text
PUT  https://gsa.apple.com/auth/verify/phone/
     JSON {"phoneNumber":{"id":1},"mode":"sms"}

POST https://gsa.apple.com/auth/verify/phone/securitycode
     JSON {"phoneNumber":{"id":1},"mode":"sms",
           "securityCode":{"code":"<code>"}}
```

After a successful code, perform the complete GrandSlam SRP login again. It
must return without another `au` challenge.

### Exchange PET for MME tokens

Send an XML-plist request:

```text
POST https://setup.icloud.com/setup/iosbuddy/loginDelegates
Authorization: Basic base64(UTF8(username ":" PET))
X-Apple-ADSID: <adsid>
User-Agent: com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0
X-Mme-Client-Info: <MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>
Accept: */*
```

Add device/Anisette headers. The plist body is:

```text
{
  "apple-id": username,
  "delegates": {"com.apple.mobileme": {}},
  "password": PET,
  "client-id": localUserUUID
}
```

Require `delegates.com.apple.mobileme.status == 0`. Persist the response DSID,
`service-data.tokens.mmeAuthToken`, and other `service-data.tokens`.

Refresh account-specific service URLs and the CloudKit token with:

```text
POST https://setup.icloud.com/setup/get_account_settings
Authorization: Basic base64(UTF8(dsid ":" mmeAuthToken))
X-Mme-Client-Info: <the AOSKit client-info above>
User-Agent: <the iCloudHelper user-agent above>
Accept: */*
body: empty
```

Add device/Anisette headers and parse the returned plist. Persist
`tokens.cloudKitToken` and the `webservices` map. KeychainSync's endpoint may
be named by `escrowProxyUrl`; other services commonly use `url`, `configURL`,
or `wsUrl`. Never persist the password or transient PET in a plaintext fixture.

## 13. Octagon enrollment and recoverable keys

This section is necessary only when a fixture bundle does not already include
PCS identity DER files or the Stage-B CKKS inputs. It mutates Octagon trust and
uses a rate-limited escrow recovery.

### CKCode function invocation

Use container `com.apple.security.keychain`, bundle
`com.apple.security.cuttlefish`, and the CloudKit transport in section 2. POST
to:

```text
https://gateway.icloud.com/ckcoderouter/api/client/code/invoke
x-cloudkit-functionroutinghint: Cuttlefish/<functionName>
```

The operation type and RequestOperation field are both `1101`. That field is:

```text
FunctionInvokeRequest {
  1:string service = "Cuttlefish"
  2:string functionName
  3:bytes  parameters
}
```

In a successful ResponseOperation, field `1101` is the function response and
its field 1 is the serialized result protobuf.

### Generate and sign an Octagon peer

Generate independent P-384 signing and encryption keypairs. Public external
form is `04 ‖ X[48] ‖ Y[48]`; private external form appends scalar `D[48]`.
Public keys embedded in permanent info are standard DER SubjectPublicKeyInfo.

Encode protobuf fields in ascending field order. Sign with randomized
ECDSA-P384-SHA384 over `UTF8(domain) ‖ protobufData`. A signed blob is:

```text
SignedInfo { 1:bytes data, 2:bytes DER_ECDSA_signature }
```

Permanent info uses domain `TPPB.PeerPermanentInfo`:

```text
PeerPermanentInfo {
  1:uint64 epoch = 1
  2:bytes  signingPublicSPKI
  3:bytes  encryptionPublicSPKI
  4:string machineID = deviceUUID
  5:string modelID = "MacBookPro18,3"
  6:uint64 creationTime = Unix seconds
}

peerID = "SHA256:" ‖ base64(SHA256(permanentData ‖ permanentSignature))
```

Stable info uses domain `TPPB.PeerStableInfo`:

```text
PeerStableInfo {
   1:uint64 clock
   2:uint64 frozenPolicyVersion
   3:string frozenPolicyHash
   5:string osVersion
   6:string deviceName
   9:string serialNumber
  10:uint64 flexiblePolicyVersion
  11:string flexiblePolicyHash
  12:uint64 userControllableViews = 1
  19:bool   supportsRepudiation = true
}
```

The policy values verified by this project are:

```text
frozen version  = 5
frozen hash     = SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo=
flexible version = 20
flexible hash    = SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY=
osVersion        = macOS 13.4.1 (22F8)
```

These are server policy identifiers, not timeless protocol constants. If the
server rejects them, call its policy-document operation and update both values
as a pair rather than guessing.

Dynamic info uses domain `TPPB.PeerDynamicInfo`:

```text
PeerDynamicInfo {
  1:uint64 clock
  2:string includedPeerID repeated
  3:string excludedPeerID repeated
  5:string preapprovalHash repeated
}
```

Persist both P-384 private keys, peer ID, permanent data/signature, and the
latest stable/dynamic data/signatures before attempting recovery.

### Discover and recover an escrow bottle

Call Cuttlefish `fetchViableBottles` with parameters:

```text
FetchViableBottlesRequest { 1:uint64 1, 2:bytes empty }
```

The result repeats field 1 escrow records. Within each, field 1 is the bottle
ID; field 2 is a bottle message whose field 2 is `OTBottle` bytes. The
KeychainSync escrow service's non-destructive `GETRECORDS` operation can add
human-readable device metadata.

Escrow HTTP calls use Basic authentication `(username, freshly minted PET)`,
Anisette headers, and:

```text
POST <keychainSyncHost>/escrowproxy/api/<command>
Content-Type: application/x-apple-plst
User-Agent: com.apple.sbd/638.100.48 com.apple.iCloudHelper/282
X-Mme-Client-Info: <MacBookPro18,3> <macOS;13.4.1;22F8> <com.apple.AuthKit/1 (com.apple.sbd/638.100.48)>
Accept: */*
Accept-Language: en-US,en;q=0.9
X-Apple-I-Locale: en_US
x-apple-i-device-type: 1
```

The body is an XML plist:

```text
{
  "command": "GETRECORDS" | "SRP_INIT" | "RECOVER",
  "label": bottleID,
  "transactionUUID": uppercaseUUID,
  "userActionLabel": "com.apple.sbd: escrow recovery",
  "version": 1,
  ...command fields...
}
```

The URL slugs are lowercase `get_records`, `srp_init`, and `recover`; their
body command values are the uppercase forms shown above.

`GETRECORDS` normally uses label `com.apple.securebackup.record` and returns
base64 plist metadata in `metadataList`. It spends no passcode attempt.

Recovery uses the RFC 5054 group from section 12 but a distinct SRP encoding.
It is irreversible and must require explicit confirmation. Send `SRP_INIT`
with `blob = base64(MIN(A))`. Decode `respBlob` as a KeyVault message:

```text
BE32(totalLength) ‖ fixedHeader ‖ BE32(sectionOffset)*(count+1) ‖ body

body section at offset = BE32(dataLength) ‖ data [‖ zero padding]
```

For `SRP_INIT`, header length is 24 and section count is 3: identifier, salt,
and server `B`. With username equal to the returned DSID and password bytes
equal to the escrow secret:

```text
k  = INT(SHA256(PAD(N) ‖ PAD(g)))
x  = INT(SHA256(salt ‖ SHA256(username ‖ ":" ‖ password)))
u  = INT(SHA256(MIN(A) ‖ MIN(B)))
S  = (B - k*g^x mod N)^(a + u*x) mod N
K  = SHA256(MIN(S))
M1 = SHA256((SHA256(PAD(N)) XOR SHA256(PAD(g))) ‖ SHA256(username)
            ‖ salt ‖ MIN(A) ‖ MIN(B) ‖ K)
M2 = SHA256(MIN(A) ‖ M1 ‖ K)
```

For `RECOVER`, copy the initialization header, replace bytes 0:4 with BE32(165)
and bytes 4:8 with BE32(2 when `clubTypeID == 1`, otherwise 0). Pack the
identifier into a 20-byte section and `M1` into the next section. Send this as
the base64 `blob`, with the same label and transaction UUID.

Decode the recovery `respBlob` with header length 40 for club type 1, otherwise
24, and three sections. Require section 0 to equal `M2`. Header bytes 4:8 give
the version:

- version 0: AES-CBC-decrypt section 1 using key `K` and IV section 2, then
  remove PKCS#7 padding;
- version 2: AES-GCM-decrypt section 2 using key `K`, IV section 1, and empty
  AAD; section 2 contains ciphertext concatenated with its tag.

Decode the result as another KeyVault message with 16-byte header and six
sections. Header bytes 8:12 are the PBKDF2 iteration count. Derive
`PBKDF2-HMAC-SHA256(escrowSecret, section1, rounds, 16)`, then AES-128-CBC
decrypt section 3 using `section1[0:16]` as IV and remove PKCS#7 padding. Parse
the resulting plist and take `BottledPeerEntropy`.

### Open the OTBottle and join

Parse the viable `OTBottle` protobuf:

```text
OTBottle {
   1:string peerID
   2:string bottleID
   8:bytes  escrowedSigningPublicSPKI
   9:bytes  escrowedEncryptionPublicSPKI
  12:message AuthenticatedCiphertext
}

AuthenticatedCiphertext {
  1:bytes ciphertext
  2:bytes GCMTag
  3:bytes IV
}
```

Let `adsid` be the GUID-like account identifier returned by GrandSlam, not the
numeric MME DSID. Derive with RFC 5869 HKDF-SHA384, salt `UTF8(adsid)`:

```text
bottleKey = HKDF(entropy, info="Escrow Symmetric Key", L=32)
```

AES-256-GCM decrypt the OTBottle with empty AAD. Its plaintext is:

```text
OTInternalBottle {
  3:message OTPrivateKey
  4:message OTPrivateKey
}
OTPrivateKey { 1:uint64 keyType, 2:bytes privateX963 }
```

Field 3 is the sponsor signing key and field 4 the sponsor encryption key.
Verify their public keys against OTBottle fields 8 and 9 before using them.
The working read path uses those stored private keys. For implementations that
need to derive/check the escrowed keys independently, use HKDF-SHA384 with the
same entropy and ADSID salt, `L=56`, and info strings `Escrow Signing Private
Key` and `Escrow Encryption Private Key`; turn each output into a P-384 scalar
as `(INT(output) mod (n-1)) + 1`.

Create a voucher protobuf and sign it with the recovered sponsor signing key,
domain `TPPB.Voucher`:

```text
Voucher {
  1:uint64 reason = 1
  2:string beneficiaryPeerID = new peer
  3:string sponsorPeerID = recovered peer
}
```

Call `fetchChanges` with parameters `{1:string syncToken}` (omit the field for
the first fetch). The result's field 1 is a Changes message: field 1 is the
restore/sync token and repeated field 2 changes contain added peer at field 3.
An added peer is:

```text
CuttlefishPeer {
  1:string peerID
  2:message permanent SignedInfo
  3:message stable SignedInfo
  4:message dynamic SignedInfo
  5:message voucher SignedInfo
}
```

Parse all stable clocks and the sponsor's included peer IDs/dynamic clock.
Rebuild the joining peer's stable info at `max(stable clocks)+1`. Rebuild its
dynamic info at `sponsor dynamic clock+1`, including the sponsor's included
peers plus the new peer itself. Attach the voucher and call
`joinWithVoucher`:

```text
JoinWithVoucherRequest {
  1:string restorePoint = fetchChanges sync token
  2:message joining CuttlefishPeer
  3:bytes bottle optional
  4:message TLKShare repeated optional
  5:message ViewKeys repeated optional
}
```

An empty successful result completes the join. Persist `joined=true` and the
recovered sponsor encryption private key.

### Fetch recoverable TLKs

Invoke `fetchRecoverableTLKShares` with `{1:string forPeerID}` twice: once for
the new peer, using its encryption key, and once for the recovered sponsor,
using the sponsor encryption key. The sponsor call is essential for
user-controllable views such as Manatee.

The result repeats field 1 groups. In each group:

- field 3 is a CuttlefishRecord whose field 2 is a CKKS TLKShare Record;
- field 2 is a view-key group whose fields 1, 2, and 3 are CuttlefishRecords
  containing TLK/class-A/class-C `synckey` Records.

Parse those inner Records using section 2, union results from both peers, and
run the CKKS pipeline in section 3. Also sync at least `Manatee` and
`ProtectedCloudStorage`; syncing all known CKKS zones is more robust.

## 14. PCS extraction, Safari schemas, and fixture contract

### Exact PCS object locations

Do not scan arbitrary ciphertext for `0x61` in production. In a
`RecordRetrieveChangesResponse`, the zone protection path is:

```text
response.field12
  -> field1
    -> field3
      -> field1 = zone PCS object DER
```

Tabs and history also carry their record protection object at:

```text
response.field12 -> field1 -> field6 -> field1 = record PCS object DER
```

Bookmarks carry per-record PCS objects in the changed Record itself:

```text
response.field1 Change -> field5 Record -> field13 -> field1 = PCS object DER
```

The bookmark `MigrationState` record does not contain a valid PCS object at
that path. Validate the full DER length and grammar before accepting a value.
Preserve response field 12 and Record field 13 even if the generic record
model does not otherwise understand them.

### Observed Safari record schemas

The following field names are sufficient to reproduce the current backup
projection. Unknown fields must still be retained.

```text
CloudTabDevice:
  DeviceName(bytes/PCS), DeviceTypeIdentifier(bytes/PCS), LastModified(date)

CloudTab:
  DateLastViewed(bytes/PCS), OwningDevice(string record name),
  Position(bytes), Title(bytes/PCS), URL(bytes/PCS)

BookmarkList:
  IdentityHash(bytes), MinimumAPIVersion(integer), ParentFolder(string),
  Position(bytes), Title(bytes/PCS), and *_deviceIdentifier/*_generation
  conflict metadata

BookmarkLeaf:
  DateAdded(bytes/PCS), IdentityHash(bytes), MinimumAPIVersion(integer),
  ParentFolder(string), Position(bytes), PreviewText(bytes/PCS optional),
  Title(bytes/PCS), URL(bytes/PCS), and paired conflict metadata

EncryptionInfo:
  Key(bytes/PCS in the fixture), KeyID(bytes)

MigrationState:
  MigrationState(integer), MigratorDeviceIdentifier(string)

Visits:
  EncryptedData(bytes/PCS), UUID(string), Version(integer)
```

Group `CloudTab` records by `OwningDevice`, which equals a `CloudTabDevice`
record name. Sort tabs by the first sort value decoded from `Position`.
Bookmark roots currently have `ParentFolder == "com.apple.Safari.TopBookmark"`;
attach leaves by matching their `ParentFolder` to a `BookmarkList` record name.
These are presentation rules, not cryptographic invariants.

### Portable fixture bundle

A fixture bundle passed to a clean-room implementer should have this shape:

```text
fixture/
  safari-cloudkit/
    tabs.json
    bookmarks.json
    history.json
  pcs-identities/
    *.der
  expected.json
```

Each dataset JSON is:

```text
{
  "container": string,
  "zone": string,
  "database": "private",
  "fetched_at": RFC3339 string,
  "pages": [{
    "raw_response_base64": base64 RecordRetrieveChangesResponse bytes,
    "status": integer,
    "records": [{
      "name": string,
      "record_type": string,
      "fields": {
        fieldName: scalar
                 | {"type":"bytes", "base64":string}
                 | {"type":"date", "unix_seconds":number}
      }
    }]
  }]
}
```

For the existing private bundle, `unix_seconds` actually carries the raw Apple
absolute-time value despite its historical name; add `978307200` when
rendering it. A future fixture format should rename it `apple_seconds`.

`expected.json` should contain no plaintext secrets. It should record the
SHA-256 of every input, record/page counts, PCS-object counts, number of
successfully unwrapped objects and authenticated fields, and plaintext codec
class per record/field. The current bundle's conformance values are:

| Dataset | Pages | Records | PCS objects | Unwrapped | Authenticated fields |
| --- | ---: | ---: | ---: | ---: | ---: |
| Tabs | 1 | 3 | 2 | 2 | 8 |
| Bookmarks | 1 | 6 | 6 | 6 | 10 |
| History | 1 | 1 | 2 | 2 | 1 |

Expected codec counts are:

```text
tabs:      bplist 5, ckdp-date 2, ckdp-string 1
bookmarks: utf-8 6, bplist 3, bytes 1
history:   zlib-bplist 1
```

The per-field expectations are:

```text
tabs CloudTabDevice.DeviceName              bplist
tabs CloudTabDevice.DeviceTypeIdentifier    ckdp-string
tabs CloudTab.DateLastViewed                ckdp-date       (each record)
tabs CloudTab.Title                         bplist          (each record)
tabs CloudTab.URL                           bplist          (each record)

bookmarks BookmarkList.Title                utf-8           (each record)
bookmarks BookmarkLeaf.Title                utf-8           (each record)
bookmarks BookmarkLeaf.URL                  utf-8           (each record)
bookmarks BookmarkLeaf.DateAdded            bplist          (each record)
bookmarks BookmarkLeaf.PreviewText           bplist          (when present)
bookmarks EncryptionInfo.Key                bytes

history Visits.EncryptedData                zlib-bplist
```

The private fixture JSON hashes at the time of this document are:

```text
tabs.json      862addac2c0352396a37647566d78c7877ee2b46f7d7099061923c801b0aef89
bookmarks.json c1201673a2c372a8db176ef975a9ea5df32b1f417f37d7abdbeef91860cd250e
history.json   3497c52e70c5945b4056d7afb1177a93546279e72860fab6cb425cdff33f5cfa
```

The bundle contains private browsing data and private keys. Transfer it only
through an approved secret channel, keep it out of version control, and delete
working copies when they are no longer needed.

### Public known-answer vectors

[`../fixtures/public/protocol-vectors.json`](../fixtures/public/protocol-vectors.json) is a
non-secret, tracked conformance file. It includes:

- the exact RFC 5054 group used by both SRP flows;
- a PCS v3 KDF/key-ID result;
- a deterministic FP version-3 encryption/decryption blob with a 12-byte GCM
  tag (`IV = blob[6:18]`);
- an AES-SIV vector with ordered associated-data elements;
- a deterministic P-384/X9.63/AES-GCM ECIES vector; and
- plain and diversified RFC 6637 unwrap vectors.

An independent implementation should pass those vectors before touching the
private bundle. Completion means: public vectors pass; every private fixture
object unwraps and every expected field authenticates; altering any protected
byte causes failure; and a live fetch, when explicitly requested, produces a
new offline-decryptable bundle without making a CloudKit mutation.
