# iCloud Keychain password protocol

Last updated: 2026-09-05

## Scope and evidence

The client reads CKKS records from the private
`com.apple.security.keychain` CloudKit container, obtains recoverable TLKShares
through Cuttlefish using the saved Octagon identity, unwraps the Passwords view
key hierarchy, and authenticates each item before parsing its binary plist.

The write implementation follows Apple's open-source Security implementation,
principally `CKKSItemEncrypter.m`, `CKKSItem.m`,
`CKKSOutgoingQueueEntry.m`, and `CKKSOutgoingQueueOperation.m`:

<https://github.com/apple-oss-distributions/Security>

The CloudKit save/delete operation numbers and envelopes are the same generated
CloudKitDaemon protocol used by the Safari write path.

## Item encryption

For a new Passwords item the client:

1. selects the current class-C key from the Passwords `currentkey` record;
2. generates a random 64-byte item key;
3. wraps that key with AES-256-SIV under the class key, with no AAD;
4. serializes the keychain attributes as a binary plist;
5. adds ISO/IEC 7816-4 padding to a 20-byte boundary, including Apple's extra
   block for password data shorter than 20 bytes;
6. generates a random 16-byte IV and encrypts with AES-256-SIV;
7. authenticates the IV followed by CKKS metadata in lexical key order:
   `UUID`, `encver`, `gen`, and the parent key UUID in `wrappedkey`;
8. saves an `item` CKRecord with `FailIfExists` semantics.

Updates decrypt and authenticate the existing item, replace only `v_Data`, use
a fresh item key and IV, preserve the fetched CKRecord's unknown/server fields,
and save with its etag and `FailIfOutdated` semantics. Deletes send the fetched
record identifier and etag. No mutation is automatically retried after a
conflict.

The supported projection is a synchronized Safari website login: an `inet`
keychain item in access group `com.apple.cfnetwork`, with `srvr`, `acct`,
`v_Data`, and `labl`. Passkeys, verification codes, credit cards, Wi-Fi keys,
and arbitrary application keychain entries are intentionally outside this API.

## Live acceptance test

On 2026-09-05, the Rust client performed this production E2E sequence against
the test account:

1. create a uniquely named disposable website login;
2. refetch the Passwords zone and authenticate/decrypt every field exactly;
3. update the secret, refetch, and authenticate/decrypt the replacement;
4. delete the record, refetch, and confirm its absence.

The same run repeated the Safari bookmark update test and restored the original
title. No disposable password record or Safari marker was left in the account.

## Secret handling

The CLI redacts password values unless `--show-passwords` is supplied. Mutation
commands obtain secrets from a hidden terminal prompt or an explicitly selected
file rather than command-line arguments. The persisted CKKS snapshot remains
encrypted. Library callers receive plaintext strings and are responsible for
their lifetime and storage.
