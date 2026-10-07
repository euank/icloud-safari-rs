//! Joining an existing Octagon trust circle and recovering Safari keys.
//!
//! Wire contracts: docs/PROTOCOL.md section 13 and the MIT FindMy.py
//! keychain/{bottle,join,peers}.py implementation (see docs/PROVENANCE.md).
//! There is deliberately no operation for establishing/resetting a trust circle.

pub mod escrow;

use crate::{
    Error, Result,
    cloudkit::{AnisetteProvider, DeviceState, HttpTransport},
    keychain::KeychainClient,
    wire::{self, Message, Value},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use p384::{
    SecretKey,
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bottle {
    pub label: String,
    pub bottle_id: String,
    pub peer_id: String,
    raw: Vec<u8>,
}

pub async fn list_bottles<T: HttpTransport, A: AnisetteProvider>(
    client: &KeychainClient<T, A>,
) -> Result<Vec<Bottle>> {
    let response = client.invoke("fetchViableBottles", &[8, 1, 18, 0]).await?;
    let mut bottles = Vec::new();
    for entry in messages(&Message::parse(&response)?, 1)? {
        let raw = required(&entry, 2)?;
        let bottle = Message::parse(raw)?;
        let contents = Message::parse(required(&bottle, 2)?)?;
        bottles.push(Bottle {
            label: text(&entry, 1)?,
            bottle_id: text(&contents, 2)?,
            peer_id: text(&contents, 1)?,
            raw: raw.to_vec(),
        });
    }
    Ok(bottles)
}

#[derive(Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PeerKeys {
    pub signing_priv_x963: String,
    pub encryption_priv_x963: String,
}
impl std::fmt::Debug for PeerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerKeys(<redacted>)")
    }
}
#[derive(Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Sponsor {
    pub peer_id: String,
    pub signing_priv_x963: String,
    pub encryption_priv_x963: String,
}
impl std::fmt::Debug for Sponsor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sponsor(<redacted>)")
    }
}
#[derive(Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct RecoveryIdentity {
    pub peer_id: String,
    pub encryption_priv_x963: String,
}
impl std::fmt::Debug for RecoveryIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryIdentity(<redacted>)")
    }
}
#[derive(Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Enrollment {
    pub peer_id: String,
    pub keys: PeerKeys,
    pub sponsor: Sponsor,
    /// Additional authenticated trusted identities used only to recover TLKs;
    /// they do not sign the new peer's voucher or replace its permanent keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_identities: Vec<RecoveryIdentity>,
    pub joined: bool,
    // Exact signed peer bytes are retained across retries; never mint a second
    // peer just because a network response was lost.
    pub peer_base64: String,
}
impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrollment")
            .field("peer_id", &self.peer_id)
            .field("joined", &self.joined)
            .finish_non_exhaustive()
    }
}

struct Peer {
    permanent: Message,
    stable: Message,
    dynamic: Message,
    voucher: Option<Message>,
}
pub struct Directory {
    token: String,
    peers: BTreeMap<String, Peer>,
}

pub async fn fetch_directory<T: HttpTransport, A: AnisetteProvider>(
    client: &KeychainClient<T, A>,
) -> Result<Directory> {
    let mut directory = Directory {
        token: String::new(),
        peers: BTreeMap::new(),
    };
    let mut seen = BTreeSet::new();
    for _ in 0..100 {
        let mut request = Vec::new();
        if !directory.token.is_empty() {
            wire::encode_string(1, &directory.token, &mut request);
        }
        let response = client.invoke("fetchChanges", &request).await?;
        let count = apply_directory_page(&response, &mut directory)?;
        if count == 0 {
            if directory.peers.is_empty() {
                return Err(Error::Authentication(
                    "no existing Octagon trust circle was returned".into(),
                ));
            }
            return Ok(directory);
        }
        if directory.token.is_empty() || !seen.insert(directory.token.clone()) {
            return Err(Error::Authentication(
                "Octagon directory pagination did not advance".into(),
            ));
        }
    }
    Err(Error::Authentication(
        "Octagon directory exceeded the pagination limit; no join was attempted".into(),
    ))
}

#[cfg(test)]
fn parse_directory(response: &[u8]) -> Result<Directory> {
    let mut directory = Directory {
        token: String::new(),
        peers: BTreeMap::new(),
    };
    apply_directory_page(response, &mut directory)?;
    Ok(directory)
}

fn apply_directory_page(response: &[u8], directory: &mut Directory) -> Result<usize> {
    let response = Message::parse(response)?;
    let changes = Message::parse(required(&response, 1)?)?;
    let entries = messages(&changes, 2)?;
    let count = entries.len();
    for change in entries {
        let Some(raw) = change.first_bytes(3) else {
            // The independent protocol defines only add(3) as a peer update.
            // Other change kinds are metadata, not termination or peer data.
            continue;
        };
        let peer = Message::parse(raw)?;
        let id = text(&peer, 1)?;
        let permanent = Message::parse(required(&peer, 2)?)?;
        let body = Message::parse(required(&permanent, 1)?)?;
        let public =
            VerifyingKey::from_public_key_der(required(&body, 2)?).map_err(|_| Error::Integrity)?;
        verify_signed(&permanent, &public, b"TPPB.PeerPermanentInfo")?;
        let expected_id = format!(
            "SHA256:{}",
            STANDARD.encode(Sha256::digest(
                [required(&permanent, 1)?, required(&permanent, 2)?].concat()
            ))
        );
        if id != expected_id {
            return Err(Error::Integrity);
        }
        let stable = Message::parse(required(&peer, 3)?)?;
        let dynamic = Message::parse(required(&peer, 4)?)?;
        verify_signed(&stable, &public, b"TPPB.PeerStableInfo")?;
        verify_signed(&dynamic, &public, b"TPPB.PeerDynamicInfo")?;
        directory.peers.insert(
            id,
            Peer {
                permanent: body,
                stable: Message::parse(required(&stable, 1)?)?,
                dynamic: Message::parse(required(&dynamic, 1)?)?,
                voucher: peer.first_bytes(5).map(Message::parse).transpose()?,
            },
        );
    }
    if changes.first_bytes(1).is_some() {
        directory.token = text(&changes, 1)?;
    }
    Ok(count)
}

/// Build a new peer offline after authenticating the recovered bottle. The
/// caller must persist this value before sending a join request.
pub fn prepare_enrollment(
    bottle: &Bottle,
    entropy: &[u8],
    adsid: &str,
    device: &DeviceState,
    directory: &Directory,
) -> Result<Enrollment> {
    let sponsor = open_bottle(bottle, entropy, adsid, directory)?;
    prepare_enrollment_from_sponsor(sponsor, device, directory)
}

/// Create a new peer using previously recovered sponsor keys, without another
/// escrow attempt. The current directory must authenticate and trust the sponsor.
/// Persist the returned draft before calling `join`.
pub fn prepare_enrollment_from_sponsor(
    sponsor: Sponsor,
    device: &DeviceState,
    directory: &Directory,
) -> Result<Enrollment> {
    let peer = directory.peers.get(&sponsor.peer_id).ok_or_else(|| {
        Error::Authentication("saved sponsor is absent from the current trust circle".into())
    })?;
    current_trust(directory, &sponsor.peer_id)?;
    for (field, secret) in [
        (2, &sponsor.signing_priv_x963),
        (3, &sponsor.encryption_priv_x963),
    ] {
        let secret = Zeroizing::new(hex::decode(secret).map_err(|_| Error::Integrity)?);
        let public = private_key(&secret)?
            .public_key()
            .to_public_key_der()
            .map_err(|_| Error::Integrity)?;
        if required(&peer.permanent, field)? != public.as_bytes() {
            return Err(Error::Integrity);
        }
    }
    let signing = SecretKey::random(&mut rand::rngs::OsRng);
    let encryption = SecretKey::random(&mut rand::rngs::OsRng);
    let signer = SigningKey::from(&signing);
    let mut permanent = Vec::new();
    wire::encode_uint(1, 1, &mut permanent);
    wire::encode_bytes(
        2,
        signing
            .public_key()
            .to_public_key_der()
            .map_err(|_| Error::Integrity)?
            .as_bytes(),
        &mut permanent,
    );
    wire::encode_bytes(
        3,
        encryption
            .public_key()
            .to_public_key_der()
            .map_err(|_| Error::Integrity)?
            .as_bytes(),
        &mut permanent,
    );
    wire::encode_string(4, &device.device_uuid, &mut permanent);
    wire::encode_string(5, "MacBookPro18,3", &mut permanent);
    wire::encode_uint(6, chrono::Utc::now().timestamp() as u64, &mut permanent);
    let permanent = sign(&signer, b"TPPB.PeerPermanentInfo", &permanent);
    let parsed = Message::parse(&permanent)?;
    let peer_id = format!(
        "SHA256:{}",
        STANDARD.encode(Sha256::digest(
            [required(&parsed, 1)?, required(&parsed, 2)?].concat()
        ))
    );
    let seed = directory
        .peers
        .get(&sponsor.peer_id)
        .ok_or(Error::Integrity)?;
    let (clock, mut included, excluded) = current_trust(directory, &sponsor.peer_id)?;
    included.insert(peer_id.clone());
    let mut dynamic = Vec::new();
    wire::encode_uint(
        1,
        clock.checked_add(1).ok_or(Error::Integrity)?,
        &mut dynamic,
    );
    for id in included {
        wire::encode_string(2, &id, &mut dynamic);
    }
    for id in excluded {
        wire::encode_string(3, &id, &mut dynamic);
    }
    let stable_clock = directory
        .peers
        .values()
        .filter_map(|peer| peer.stable.first_varint(1))
        .max()
        .ok_or(Error::Integrity)?;
    let mut stable = Vec::new();
    wire::encode_uint(
        1,
        stable_clock.checked_add(1).ok_or(Error::Integrity)?,
        &mut stable,
    );
    // Adopt the authenticated sponsor's policy identifiers as a pair.
    for number in [2, 3, 10, 11] {
        let field = seed
            .stable
            .fields
            .iter()
            .find(|field| field.number == number)
            .ok_or(Error::Unsupported(
                "sponsor omitted required policy identifiers",
            ))?;
        stable.extend_from_slice(&field.raw);
    }
    wire::encode_string(5, "macOS 13.4.1 (22F8)", &mut stable);
    wire::encode_string(6, "icloud-safari Rust client", &mut stable);
    wire::encode_string(9, &device.serial, &mut stable);
    wire::encode_uint(12, 1, &mut stable);
    wire::encode_uint(19, 1, &mut stable);
    let mut voucher = Vec::new();
    wire::encode_uint(1, 1, &mut voucher);
    wire::encode_string(2, &peer_id, &mut voucher);
    wire::encode_string(3, &sponsor.peer_id, &mut voucher);
    let sponsor_key =
        private_key(&hex::decode(&sponsor.signing_priv_x963).map_err(|_| Error::Integrity)?)?;
    let mut peer = Vec::new();
    wire::encode_string(1, &peer_id, &mut peer);
    wire::encode_bytes(2, &permanent, &mut peer);
    wire::encode_bytes(
        3,
        &sign(&signer, b"TPPB.PeerStableInfo", &stable),
        &mut peer,
    );
    wire::encode_bytes(
        4,
        &sign(&signer, b"TPPB.PeerDynamicInfo", &dynamic),
        &mut peer,
    );
    wire::encode_bytes(
        5,
        &sign(&SigningKey::from(&sponsor_key), b"TPPB.Voucher", &voucher),
        &mut peer,
    );
    Ok(Enrollment {
        peer_id,
        keys: PeerKeys {
            signing_priv_x963: hex::encode(export(&signing)),
            encryption_priv_x963: hex::encode(export(&encryption)),
        },
        sponsor,
        recovery_identities: Vec::new(),
        joined: false,
        peer_base64: STANDARD.encode(peer),
    })
}

/// Retain an existing trusted peer's encryption identity for TLK recovery.
/// The identity must bind to the authenticated directory and current trust.
/// This changes no signed peer bytes. Persist the draft and session afterward.
pub fn add_recovery_identity(
    enrollment: &mut Enrollment,
    identity: RecoveryIdentity,
    directory: &Directory,
) -> Result<()> {
    validate_draft(enrollment, directory)?;
    validate_recovery_identity(&identity, &enrollment.sponsor.peer_id, directory)?;
    if identity.peer_id == enrollment.peer_id
        || identity.peer_id == enrollment.sponsor.peer_id
        || enrollment
            .recovery_identities
            .iter()
            .any(|existing| existing.peer_id == identity.peer_id)
    {
        return Ok(());
    }
    enrollment.recovery_identities.push(identity);
    Ok(())
}

fn validate_recovery_identity(
    identity: &RecoveryIdentity,
    sponsor: &str,
    directory: &Directory,
) -> Result<()> {
    let (_, included, excluded) = current_trust(directory, sponsor)?;
    if !included.contains(&identity.peer_id) || excluded.contains(&identity.peer_id) {
        return Err(Error::Authentication(
            "saved recovery identity is not currently trusted".into(),
        ));
    }
    let peer = directory
        .peers
        .get(&identity.peer_id)
        .ok_or(Error::Integrity)?;
    let private =
        Zeroizing::new(hex::decode(&identity.encryption_priv_x963).map_err(|_| Error::Integrity)?);
    let public = private_key(&private)?
        .public_key()
        .to_public_key_der()
        .map_err(|_| Error::Integrity)?;
    if required(&peer.permanent, 3)? != public.as_bytes() {
        return Err(Error::Integrity);
    }
    Ok(())
}

/// Explicitly refresh a pending peer's mutable trust and policy statements.
///
/// This performs no network requests, retains the exact permanent info and
/// voucher, and never changes the peer identifier or private keys. The caller
/// must persist the updated enrollment (including the client's session copy)
/// before calling [`join`]. A rejected refresh leaves `enrollment` unchanged.
/// Already-admitted peers must be reconciled with `join`, not refreshed here.
pub fn refresh_enrollment(enrollment: &mut Enrollment, directory: &Directory) -> Result<()> {
    let raw = validate_draft(enrollment, directory)?;
    let (clock, mut included, excluded) = current_trust(directory, &enrollment.sponsor.peer_id)?;
    if excluded.contains(&enrollment.peer_id) {
        return Err(Error::Authentication(
            "saved pending peer has been excluded; no trust refresh was performed".into(),
        ));
    }
    if enrollment.joined || directory.peers.contains_key(&enrollment.peer_id) {
        return Err(Error::Authentication(
            "peer is already enrolled; resume without refreshing trust to reconcile membership"
                .into(),
        ));
    }
    included.insert(enrollment.peer_id.clone());
    let peer = Message::parse(&raw)?;
    let stable = Message::parse(required(&peer, 3)?)?;
    let stable = Message::parse(required(&stable, 1)?)?;
    let dynamic = Message::parse(required(&peer, 4)?)?;
    let dynamic = Message::parse(required(&dynamic, 1)?)?;
    let stable_clock = directory
        .peers
        .values()
        .filter_map(|peer| peer.stable.first_varint(1))
        .max()
        .ok_or(Error::Integrity)?;
    let sponsor = directory
        .peers
        .get(&enrollment.sponsor.peer_id)
        .ok_or(Error::Integrity)?;
    let mut new_stable = Vec::new();
    wire::encode_uint(
        1,
        stable_clock.checked_add(1).ok_or(Error::Integrity)?,
        &mut new_stable,
    );
    for number in [2, 3, 10, 11] {
        let field = sponsor
            .stable
            .fields
            .iter()
            .find(|field| field.number == number)
            .ok_or(Error::Unsupported(
                "sponsor omitted required policy identifiers",
            ))?;
        new_stable.extend_from_slice(&field.raw);
    }
    for field in &stable.fields {
        if ![1, 2, 3, 10, 11].contains(&field.number) {
            new_stable.extend_from_slice(&field.raw);
        }
    }
    let mut new_dynamic = Vec::new();
    wire::encode_uint(
        1,
        clock.checked_add(1).ok_or(Error::Integrity)?,
        &mut new_dynamic,
    );
    for id in included {
        wire::encode_string(2, &id, &mut new_dynamic);
    }
    for id in excluded {
        wire::encode_string(3, &id, &mut new_dynamic);
    }
    for field in &dynamic.fields {
        if ![1, 2, 3].contains(&field.number) {
            new_dynamic.extend_from_slice(&field.raw);
        }
    }
    let private = Zeroizing::new(
        hex::decode(&enrollment.keys.signing_priv_x963).map_err(|_| Error::Integrity)?,
    );
    let signer = SigningKey::from(&private_key(&private)?);
    let mut refreshed = Vec::new();
    for field in &peer.fields {
        match field.number {
            3 => wire::encode_bytes(
                3,
                &sign(&signer, b"TPPB.PeerStableInfo", &new_stable),
                &mut refreshed,
            ),
            4 => wire::encode_bytes(
                4,
                &sign(&signer, b"TPPB.PeerDynamicInfo", &new_dynamic),
                &mut refreshed,
            ),
            _ => refreshed.extend_from_slice(&field.raw),
        }
    }
    validate_current_trust(&refreshed, enrollment, directory)?;
    enrollment.peer_base64 = STANDARD.encode(refreshed);
    Ok(())
}

type Trust = (u64, BTreeSet<String>, BTreeSet<String>);
fn current_trust(directory: &Directory, sponsor: &str) -> Result<Trust> {
    let seed = directory.peers.get(sponsor).ok_or(Error::Integrity)?;
    let mut included = strings(&seed.dynamic, 2)?;
    let mut excluded = strings(&seed.dynamic, 3)?;
    included.retain(|id| !excluded.contains(id));
    let mut clock = seed.dynamic.first_varint(1).ok_or(Error::Integrity)?;
    let mut ahead: Vec<_> = directory
        .peers
        .iter()
        .filter(|(_, peer)| peer.dynamic.first_varint(1).unwrap_or(0) > clock)
        .collect();
    ahead.sort_by_key(|(_, peer)| peer.dynamic.first_varint(1).unwrap_or(0));
    for (id, peer) in ahead {
        if excluded.contains(id)
            || (!included.contains(id)
                && !voucher_admits(id, peer, &included, &excluded, directory))
        {
            continue;
        }
        included.extend(strings(&peer.dynamic, 2)?);
        excluded.extend(strings(&peer.dynamic, 3)?);
        included.retain(|id| !excluded.contains(id));
        clock = peer.dynamic.first_varint(1).ok_or(Error::Integrity)?;
    }
    if excluded.contains(sponsor) || !included.contains(sponsor) {
        return Err(Error::Authentication(
            "bottle sponsor is no longer trusted; no join was attempted".into(),
        ));
    }
    Ok((clock, included, excluded))
}

fn voucher_admits(
    id: &str,
    peer: &Peer,
    included: &BTreeSet<String>,
    excluded: &BTreeSet<String>,
    directory: &Directory,
) -> bool {
    let validate = || -> Result<()> {
        let voucher = peer.voucher.as_ref().ok_or(Error::Integrity)?;
        let body = Message::parse(required(voucher, 1)?)?;
        let sponsor_id = text(&body, 3)?;
        if text(&body, 2)? != id
            || !included.contains(&sponsor_id)
            || excluded.contains(&sponsor_id)
        {
            return Err(Error::Integrity);
        }
        let sponsor = directory.peers.get(&sponsor_id).ok_or(Error::Integrity)?;
        let public = VerifyingKey::from_public_key_der(required(&sponsor.permanent, 2)?)
            .map_err(|_| Error::Integrity)?;
        verify_signed(voucher, &public, b"TPPB.Voucher")
    };
    validate().is_ok()
}

/// Join once, checking the current directory first to reconcile a lost response.
/// The caller persists `joined` after success. There is no automatic network retry.
pub async fn join<T: HttpTransport, A: AnisetteProvider>(
    client: &KeychainClient<T, A>,
    enrollment: &mut Enrollment,
) -> Result<()> {
    if !cfg!(feature = "experimental-live-writes") {
        return Err(Error::Unsupported(
            "live enrollment is disabled in this build",
        ));
    }
    let saved: Enrollment =
        serde_json::from_value(client.session().extra.get("octagon").cloned().ok_or(
            Error::Authentication("persist the pending enrollment before joining".into()),
        )?)?;
    if serde_json::to_value(&saved)? != serde_json::to_value(&*enrollment)? {
        return Err(Error::Integrity);
    }
    let directory = fetch_directory(client).await?;
    let peer = validate_draft(enrollment, &directory)?;
    if directory.peers.contains_key(&enrollment.peer_id) {
        enrollment.joined = true;
        return Ok(());
    }
    if enrollment.joined {
        return Err(Error::Authentication(
            "saved peer is absent from the trust circle".into(),
        ));
    }
    validate_current_trust(&peer, enrollment, &directory)?;
    // Confirm the recovered identity can actually obtain keys before adding a peer.
    client.fetch_recoverable_keys().await?;
    let mut request = Vec::new();
    wire::encode_string(1, &directory.token, &mut request);
    wire::encode_bytes(2, &peer, &mut request);
    client.invoke("joinWithVoucher", &request).await?;
    let after = fetch_directory(client).await?;
    if !after.peers.contains_key(&enrollment.peer_id) {
        return Err(Error::Authentication(
            "join result not yet visible; rerun enrollment to reconcile the saved peer".into(),
        ));
    }
    enrollment.joined = true;
    Ok(())
}

fn validate_draft(enrollment: &Enrollment, directory: &Directory) -> Result<Vec<u8>> {
    let peer = STANDARD
        .decode(&enrollment.peer_base64)
        .map_err(|_| Error::Integrity)?;
    let parsed = Message::parse(&peer)?;
    if text(&parsed, 1)? != enrollment.peer_id {
        return Err(Error::Integrity);
    }
    let key = private_key(
        &hex::decode(&enrollment.keys.signing_priv_x963).map_err(|_| Error::Integrity)?,
    )?;
    for (field, domain) in [
        (2, b"TPPB.PeerPermanentInfo".as_slice()),
        (3, b"TPPB.PeerStableInfo"),
        (4, b"TPPB.PeerDynamicInfo"),
    ] {
        verify_signed(
            &Message::parse(required(&parsed, field)?)?,
            SigningKey::from(&key).verifying_key(),
            domain,
        )?;
    }
    let permanent = Message::parse(required(&parsed, 2)?)?;
    let expected_id = format!(
        "SHA256:{}",
        STANDARD.encode(Sha256::digest(
            [required(&permanent, 1)?, required(&permanent, 2)?].concat()
        ))
    );
    if expected_id != enrollment.peer_id {
        return Err(Error::Integrity);
    }
    let body = Message::parse(required(&permanent, 1)?)?;
    for (field, private) in [
        (2, &enrollment.keys.signing_priv_x963),
        (3, &enrollment.keys.encryption_priv_x963),
    ] {
        let private = Zeroizing::new(hex::decode(private).map_err(|_| Error::Integrity)?);
        let public = private_key(&private)?
            .public_key()
            .to_public_key_der()
            .map_err(|_| Error::Integrity)?;
        if required(&body, field)? != public.as_bytes() {
            return Err(Error::Integrity);
        }
    }
    let voucher = Message::parse(required(&parsed, 5)?)?;
    let sponsor = directory
        .peers
        .get(&enrollment.sponsor.peer_id)
        .ok_or(Error::Integrity)?;
    for (field, private) in [
        (2, &enrollment.sponsor.signing_priv_x963),
        (3, &enrollment.sponsor.encryption_priv_x963),
    ] {
        let bytes = Zeroizing::new(hex::decode(private).map_err(|_| Error::Integrity)?);
        let public = private_key(&bytes)?
            .public_key()
            .to_public_key_der()
            .map_err(|_| Error::Integrity)?;
        if required(&sponsor.permanent, field)? != public.as_bytes() {
            return Err(Error::Integrity);
        }
    }
    let public = VerifyingKey::from_public_key_der(required(&sponsor.permanent, 2)?)
        .map_err(|_| Error::Integrity)?;
    verify_signed(&voucher, &public, b"TPPB.Voucher")?;
    let voucher_body = Message::parse(required(&voucher, 1)?)?;
    if voucher_body.first_varint(1) != Some(1)
        || text(&voucher_body, 2)? != enrollment.peer_id
        || text(&voucher_body, 3)? != enrollment.sponsor.peer_id
    {
        return Err(Error::Integrity);
    }
    let mut seen = BTreeSet::new();
    for identity in &enrollment.recovery_identities {
        if !seen.insert(&identity.peer_id) {
            return Err(Error::Integrity);
        }
        validate_recovery_identity(identity, &enrollment.sponsor.peer_id, directory)?;
    }
    Ok(peer)
}

fn validate_current_trust(
    peer: &[u8],
    enrollment: &Enrollment,
    directory: &Directory,
) -> Result<()> {
    let peer = Message::parse(peer)?;
    let dynamic = Message::parse(required(&peer, 4)?)?;
    let dynamic = Message::parse(required(&dynamic, 1)?)?;
    let stable = Message::parse(required(&peer, 3)?)?;
    let stable = Message::parse(required(&stable, 1)?)?;
    let (clock, mut included, excluded) = current_trust(directory, &enrollment.sponsor.peer_id)?;
    included.insert(enrollment.peer_id.clone());
    let stable_clock = directory
        .peers
        .values()
        .filter_map(|peer| peer.stable.first_varint(1))
        .max()
        .ok_or(Error::Integrity)?;
    let sponsor = directory
        .peers
        .get(&enrollment.sponsor.peer_id)
        .ok_or(Error::Integrity)?;
    let policy_unchanged = [2, 3, 10, 11]
        .into_iter()
        .all(|number| stable.values(number).eq(sponsor.stable.values(number)));
    if excluded.contains(&enrollment.peer_id)
        || dynamic.first_varint(1) != clock.checked_add(1)
        || strings(&dynamic, 2)? != included
        || strings(&dynamic, 3)? != excluded
        || stable.first_varint(1) != stable_clock.checked_add(1)
        || !policy_unchanged
    {
        return Err(Error::Authentication("pending enrollment trust or policy is stale; preserve the saved recovery checkpoint and refresh the draft before joining (do not repeat escrow recovery)".into()));
    }
    Ok(())
}

fn open_bottle(
    bottle: &Bottle,
    entropy: &[u8],
    adsid: &str,
    directory: &Directory,
) -> Result<Sponsor> {
    let wrapper = Message::parse(&bottle.raw)?;
    let raw = required(&wrapper, 2)?;
    let contents = Message::parse(raw)?;
    if text(&contents, 1)? != bottle.peer_id || text(&contents, 2)? != bottle.bottle_id {
        return Err(Error::Integrity);
    }
    let sponsor = directory
        .peers
        .get(&bottle.peer_id)
        .ok_or(Error::Authentication(
            "bottle sponsor is not in the current circle".into(),
        ))?;
    for (field, public) in [
        (8, required(&contents, 8)?),
        (10, required(&sponsor.permanent, 2)?),
    ] {
        let key = VerifyingKey::from_public_key_der(public).map_err(|_| Error::Integrity)?;
        let sig_field = if field == 8 { 4 } else { 5 };
        key.verify(
            raw,
            &Signature::from_der(required(&wrapper, sig_field)?).map_err(|_| Error::Integrity)?,
        )
        .map_err(|_| Error::Integrity)?;
    }
    if entropy.is_empty() || adsid.is_empty() {
        return Err(Error::Integrity);
    }
    let hkdf = hkdf::Hkdf::<Sha384>::new(Some(adsid.as_bytes()), entropy);
    let order = num_bigint::BigUint::parse_bytes(b"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",16).ok_or(Error::Integrity)?;
    for (field, info) in [
        (8, b"Escrow Signing Private Key".as_slice()),
        (9, b"Escrow Encryption Private Key"),
    ] {
        let mut material = Zeroizing::new([0u8; 56]);
        hkdf.expand(info, &mut *material)
            .map_err(|_| Error::Integrity)?;
        let value = num_bigint::BigUint::from_bytes_be(&material[..])
            % (&order - num_bigint::BigUint::from(1u8))
            + num_bigint::BigUint::from(1u8);
        let bytes = Zeroizing::new(value.to_bytes_be());
        let mut scalar = Zeroizing::new([0u8; 48]);
        scalar[48 - bytes.len()..].copy_from_slice(&bytes);
        let derived = SecretKey::from_slice(&scalar[..]).map_err(|_| Error::Integrity)?;
        if derived
            .public_key()
            .to_public_key_der()
            .map_err(|_| Error::Integrity)?
            .as_bytes()
            != required(&contents, field)?
        {
            return Err(Error::Integrity);
        }
    }
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha384>::new(Some(adsid.as_bytes()), entropy)
        .expand(b"Escrow Symmetric Key", &mut *key)
        .map_err(|_| Error::Integrity)?;
    let ciphertext = Message::parse(required(&contents, 12)?)?;
    let plaintext = escrow::gcm_decrypt(
        &key[..],
        required(&ciphertext, 3)?,
        required(&ciphertext, 1)?,
        required(&ciphertext, 2)?,
    )?;
    let internal = Message::parse(&plaintext)?;
    let signing = Message::parse(required(&internal, 3)?)?;
    let encryption = Message::parse(required(&internal, 4)?)?;
    if signing.first_varint(1) != Some(1) || encryption.first_varint(1) != Some(1) {
        return Err(Error::Integrity);
    }
    let signing_bytes = required(&signing, 2)?;
    let encryption_bytes = required(&encryption, 2)?;
    for (bytes, expected) in [
        (signing_bytes, required(&sponsor.permanent, 2)?),
        (encryption_bytes, required(&sponsor.permanent, 3)?),
    ] {
        let key = private_key(bytes)?;
        if key
            .public_key()
            .to_public_key_der()
            .map_err(|_| Error::Integrity)?
            .as_bytes()
            != expected
        {
            return Err(Error::Integrity);
        }
    }
    Ok(Sponsor {
        peer_id: bottle.peer_id.clone(),
        signing_priv_x963: hex::encode(signing_bytes),
        encryption_priv_x963: hex::encode(encryption_bytes),
    })
}

fn private_key(bytes: &[u8]) -> Result<SecretKey> {
    if bytes.len() != 145 {
        return Err(Error::Integrity);
    }
    let key = SecretKey::from_slice(&bytes[97..]).map_err(|_| Error::Integrity)?;
    if key.public_key().to_encoded_point(false).as_bytes() != &bytes[..97] {
        return Err(Error::Integrity);
    }
    Ok(key)
}
fn export(key: &SecretKey) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        [
            key.public_key().to_encoded_point(false).as_bytes(),
            key.to_bytes().as_slice(),
        ]
        .concat(),
    )
}
fn sign(key: &SigningKey, domain: &[u8], data: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(&[domain, data].concat());
    let mut result = Vec::new();
    wire::encode_bytes(1, data, &mut result);
    wire::encode_bytes(2, signature.to_der().as_bytes(), &mut result);
    result
}
fn verify_signed(message: &Message, key: &VerifyingKey, domain: &[u8]) -> Result<()> {
    key.verify(
        &[domain, required(message, 1)?].concat(),
        &Signature::from_der(required(message, 2)?).map_err(|_| Error::Integrity)?,
    )
    .map_err(|_| Error::Integrity)
}
fn required(message: &Message, field: u32) -> Result<&[u8]> {
    message
        .first_bytes(field)
        .ok_or(Error::Protobuf("missing enrollment field"))
}
fn text(message: &Message, field: u32) -> Result<String> {
    String::from_utf8(required(message, field)?.to_vec()).map_err(|_| Error::Integrity)
}
fn messages(message: &Message, field: u32) -> Result<Vec<Message>> {
    message
        .values(field)
        .map(|value| match value {
            Value::Bytes(bytes) => Message::parse(bytes),
            _ => Err(Error::Integrity),
        })
        .collect()
}
fn strings(message: &Message, field: u32) -> Result<BTreeSet<String>> {
    message
        .values(field)
        .map(|value| match value {
            Value::Bytes(bytes) => String::from_utf8(bytes.clone()).map_err(|_| Error::Integrity),
            _ => Err(Error::Integrity),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudkit::{HttpRequest, HttpResponse, SessionState};
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    type Replies = VecDeque<(&'static str, Vec<u8>)>;
    #[derive(Clone)]
    struct Script(Arc<Mutex<Replies>>);
    #[async_trait::async_trait]
    impl HttpTransport for Script {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
            let (method, payload) = self
                .0
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected request (possibly a write)");
            assert!(request.headers.contains(&(
                "x-cloudkit-functionroutinghint".into(),
                format!("Cuttlefish/{method}")
            )));
            let mut function = Vec::new();
            wire::encode_bytes(1, &payload, &mut function);
            let mut operation = Vec::new();
            wire::encode_bytes(1101, &function, &mut operation);
            let mut body = Vec::new();
            wire::encode_varint(operation.len() as u64, &mut body);
            body.extend(operation);
            Ok(HttpResponse {
                status: 200,
                headers: vec![],
                body,
            })
        }
    }
    struct Anisette;
    #[async_trait::async_trait]
    impl AnisetteProvider for Anisette {
        async fn headers(&self) -> Result<BTreeMap<String, String>> {
            Ok(BTreeMap::from([
                ("X-Apple-I-MD".into(), "synthetic".into()),
                ("X-Apple-I-MD-M".into(), "synthetic".into()),
            ]))
        }
    }
    fn client(script: Script, enrollment: Option<&Enrollment>) -> KeychainClient<Script, Anisette> {
        let mut session: SessionState = serde_json::from_value(serde_json::json!({
            "username": "test@example.invalid", "dsid": "123",
            "mme": {"dsid": "123", "mmeAuthToken": "synthetic", "tokens": {"cloudKitToken": "synthetic"}, "cloudKitUserId": "synthetic"}
        })).unwrap();
        if let Some(enrollment) = enrollment {
            session
                .extra
                .insert("octagon".into(), serde_json::to_value(enrollment).unwrap());
        }
        KeychainClient::new(script, Anisette, DeviceState::generate(), session).unwrap()
    }
    fn page(token: &str, peers: &[Vec<u8>]) -> Vec<u8> {
        let mut changes = Vec::new();
        wire::encode_string(1, token, &mut changes);
        for peer in peers {
            let mut change = Vec::new();
            wire::encode_bytes(3, peer, &mut change);
            wire::encode_bytes(2, &change, &mut changes);
        }
        let mut response = Vec::new();
        wire::encode_bytes(1, &changes, &mut response);
        response
    }
    fn fixture_page() -> Vec<u8> {
        let value: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/public/enrollment-vectors.json"))
                .unwrap();
        hex::decode(value["directory"].as_str().unwrap()).unwrap()
    }
    fn prepared() -> Enrollment {
        let (bottle, entropy, adsid, directory) = fixture();
        prepare_enrollment(
            &bottle,
            &entropy,
            &adsid,
            &DeviceState::generate(),
            &directory,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn directory_paginates_through_metadata_and_rejects_token_cycles() {
        let mut metadata = Vec::new();
        wire::encode_string(1, "metadata", &mut metadata);
        wire::encode_bytes(2, &[8, 1], &mut metadata);
        let mut first = Vec::new();
        wire::encode_bytes(1, &metadata, &mut first);
        let script = Script(Arc::new(Mutex::new(VecDeque::from([
            ("fetchChanges", first),
            ("fetchChanges", fixture_page()),
            ("fetchChanges", page("end", &[])),
        ]))));
        assert_eq!(
            fetch_directory(&client(script.clone(), None))
                .await
                .unwrap()
                .peers
                .len(),
            1
        );
        assert!(script.0.lock().unwrap().is_empty());
        let script = Script(Arc::new(Mutex::new(VecDeque::from([
            ("fetchChanges", fixture_page()),
            ("fetchChanges", fixture_page()),
        ]))));
        assert!(
            fetch_directory(&client(script.clone(), None))
                .await
                .is_err()
        );
        assert!(script.0.lock().unwrap().is_empty());
    }

    #[cfg(feature = "experimental-live-writes")]
    #[tokio::test]
    async fn resume_authenticates_draft_and_never_rejoins_existing_peer() {
        let mut enrollment = prepared();
        let peer = STANDARD.decode(&enrollment.peer_base64).unwrap();
        let script = Script(Arc::new(Mutex::new(VecDeque::from([
            ("fetchChanges", fixture_page()),
            ("fetchChanges", page("joined", std::slice::from_ref(&peer))),
            ("fetchChanges", page("end", &[])),
        ]))));
        join(&client(script.clone(), Some(&enrollment)), &mut enrollment)
            .await
            .unwrap();
        assert!(enrollment.joined);
        assert!(script.0.lock().unwrap().is_empty());
        enrollment.keys.encryption_priv_x963 = enrollment.keys.signing_priv_x963.clone();
        let script = Script(Arc::new(Mutex::new(VecDeque::from([
            ("fetchChanges", fixture_page()),
            ("fetchChanges", page("joined", &[peer])),
            ("fetchChanges", page("end", &[])),
        ]))));
        assert!(
            join(&client(script.clone(), Some(&enrollment)), &mut enrollment)
                .await
                .is_err()
        );
        assert!(script.0.lock().unwrap().is_empty());
    }

    #[cfg(feature = "experimental-live-writes")]
    #[tokio::test]
    async fn no_shares_means_no_join_mutation() {
        let mut enrollment = prepared();
        let script = Script(Arc::new(Mutex::new(VecDeque::from([
            ("fetchChanges", fixture_page()),
            ("fetchChanges", page("end", &[])),
            ("fetchRecoverableTLKShares", vec![]),
            ("fetchRecoverableTLKShares", vec![]),
        ]))));
        assert!(
            join(&client(script.clone(), Some(&enrollment)), &mut enrollment)
                .await
                .is_err()
        );
        assert!(!enrollment.joined);
        assert!(script.0.lock().unwrap().is_empty());
    }

    #[test]
    fn stale_or_excluded_sponsor_cannot_join() {
        let enrollment = prepared();
        let (_, _, _, mut directory) = fixture();
        let peer = validate_draft(&enrollment, &directory).unwrap();
        validate_current_trust(&peer, &enrollment, &directory).unwrap();
        let sponsor = directory
            .peers
            .get_mut(&enrollment.sponsor.peer_id)
            .unwrap();
        let mut dynamic = Vec::new();
        wire::encode_uint(1, 8, &mut dynamic);
        wire::encode_string(2, &enrollment.sponsor.peer_id, &mut dynamic);
        sponsor.dynamic = Message::parse(&dynamic).unwrap();
        assert!(validate_current_trust(&peer, &enrollment, &directory).is_err());
        wire::encode_string(3, &enrollment.sponsor.peer_id, &mut dynamic);
        directory
            .peers
            .get_mut(&enrollment.sponsor.peer_id)
            .unwrap()
            .dynamic = Message::parse(&dynamic).unwrap();
        assert!(validate_current_trust(&peer, &enrollment, &directory).is_err());
    }

    #[test]
    fn newer_peer_requires_authenticated_voucher_to_extend_trust() {
        let enrollment = prepared();
        let (_, _, _, mut directory) = fixture();
        let peer = STANDARD.decode(&enrollment.peer_base64).unwrap();
        apply_directory_page(&page("next", &[peer]), &mut directory).unwrap();
        let (clock, included, _) = current_trust(&directory, &enrollment.sponsor.peer_id).unwrap();
        assert_eq!(clock, 8);
        assert!(included.contains(&enrollment.peer_id));
        directory
            .peers
            .get_mut(&enrollment.peer_id)
            .unwrap()
            .voucher = None;
        let (clock, included, _) = current_trust(&directory, &enrollment.sponsor.peer_id).unwrap();
        assert_eq!(clock, 7);
        assert!(!included.contains(&enrollment.peer_id));
    }

    #[test]
    fn refresh_retains_identity_and_voucher_while_updating_mutable_trust() {
        let mut enrollment = prepared();
        let before = enrollment.clone();
        let (_, _, _, mut directory) = fixture();
        let sponsor = directory
            .peers
            .get_mut(&enrollment.sponsor.peer_id)
            .unwrap();
        let mut dynamic = Vec::new();
        wire::encode_uint(1, 20, &mut dynamic);
        wire::encode_string(2, &enrollment.sponsor.peer_id, &mut dynamic);
        wire::encode_string(3, "newly-excluded", &mut dynamic);
        sponsor.dynamic = Message::parse(&dynamic).unwrap();
        let mut stable: Vec<u8> = sponsor
            .stable
            .fields
            .iter()
            .filter(|field| ![1, 10, 11].contains(&field.number))
            .flat_map(|field| field.raw.clone())
            .collect();
        wire::encode_uint(1, 30, &mut stable);
        wire::encode_uint(10, 21, &mut stable);
        wire::encode_string(11, "updated-policy-hash", &mut stable);
        sponsor.stable = Message::parse(&stable).unwrap();
        assert!(
            validate_current_trust(
                &STANDARD.decode(&enrollment.peer_base64).unwrap(),
                &enrollment,
                &directory
            )
            .is_err()
        );
        refresh_enrollment(&mut enrollment, &directory).unwrap();
        assert_eq!(enrollment.peer_id, before.peer_id);
        assert_eq!(
            enrollment.keys.signing_priv_x963,
            before.keys.signing_priv_x963
        );
        assert_eq!(
            enrollment.keys.encryption_priv_x963,
            before.keys.encryption_priv_x963
        );
        assert_eq!(
            enrollment.sponsor.signing_priv_x963,
            before.sponsor.signing_priv_x963
        );
        assert_eq!(
            enrollment.sponsor.encryption_priv_x963,
            before.sponsor.encryption_priv_x963
        );
        let old = Message::parse(&STANDARD.decode(&before.peer_base64).unwrap()).unwrap();
        let new = Message::parse(&STANDARD.decode(&enrollment.peer_base64).unwrap()).unwrap();
        for field in [1, 2, 5] {
            assert_eq!(
                required(&old, field).unwrap(),
                required(&new, field).unwrap()
            );
        }
        let raw = validate_draft(&enrollment, &directory).unwrap();
        validate_current_trust(&raw, &enrollment, &directory).unwrap();
        let dynamic = Message::parse(required(&new, 4).unwrap()).unwrap();
        let dynamic = Message::parse(required(&dynamic, 1).unwrap()).unwrap();
        assert_eq!(dynamic.first_varint(1), Some(21));
        assert_eq!(
            strings(&dynamic, 3).unwrap(),
            BTreeSet::from(["newly-excluded".into()])
        );
    }

    #[test]
    fn rejected_refresh_leaves_saved_identity_unchanged() {
        let mut enrollment = prepared();
        let before = serde_json::to_value(&enrollment).unwrap();
        let (_, _, _, mut directory) = fixture();
        let sponsor = directory
            .peers
            .get_mut(&enrollment.sponsor.peer_id)
            .unwrap();
        let mut dynamic = Vec::new();
        wire::encode_uint(1, 8, &mut dynamic);
        wire::encode_string(2, &enrollment.sponsor.peer_id, &mut dynamic);
        wire::encode_string(3, &enrollment.sponsor.peer_id, &mut dynamic);
        sponsor.dynamic = Message::parse(&dynamic).unwrap();
        assert!(refresh_enrollment(&mut enrollment, &directory).is_err());
        assert_eq!(serde_json::to_value(&enrollment).unwrap(), before);
        let (_, _, _, mut directory) = fixture();
        let peer = STANDARD.decode(&enrollment.peer_base64).unwrap();
        apply_directory_page(&page("joined", &[peer]), &mut directory).unwrap();
        assert!(refresh_enrollment(&mut enrollment, &directory).is_err());
        assert_eq!(serde_json::to_value(&enrollment).unwrap(), before);
    }

    #[test]
    fn recovery_identities_require_trusted_key_binding_and_are_deduplicated() {
        let old = prepared();
        let (bottle, entropy, adsid, mut directory) = fixture();
        apply_directory_page(
            &page("old-peer", &[STANDARD.decode(&old.peer_base64).unwrap()]),
            &mut directory,
        )
        .unwrap();
        let mut new = prepare_enrollment(
            &bottle,
            &entropy,
            &adsid,
            &DeviceState::generate(),
            &directory,
        )
        .unwrap();
        let signed_before = new.peer_base64.clone();
        let recovery = RecoveryIdentity {
            peer_id: old.peer_id.clone(),
            encryption_priv_x963: old.keys.encryption_priv_x963.clone(),
        };
        assert!(!format!("{recovery:?}").contains(&recovery.encryption_priv_x963));
        add_recovery_identity(&mut new, recovery.clone(), &directory).unwrap();
        add_recovery_identity(&mut new, recovery.clone(), &directory).unwrap();
        assert_eq!(new.recovery_identities.len(), 1);
        assert_eq!(new.peer_base64, signed_before);
        validate_draft(&new, &directory).unwrap();
        let wrong = RecoveryIdentity {
            encryption_priv_x963: old.keys.signing_priv_x963.clone(),
            peer_id: recovery.peer_id.clone(),
        };
        assert!(add_recovery_identity(&mut new, wrong, &directory).is_err());
        let unknown = RecoveryIdentity {
            peer_id: "unknown-peer".into(),
            encryption_priv_x963: recovery.encryption_priv_x963.clone(),
        };
        assert!(add_recovery_identity(&mut new, unknown, &directory).is_err());
        let mut revoked = Vec::new();
        wire::encode_uint(1, 100, &mut revoked);
        wire::encode_string(2, &new.sponsor.peer_id, &mut revoked);
        wire::encode_string(3, &old.peer_id, &mut revoked);
        directory
            .peers
            .get_mut(&new.sponsor.peer_id)
            .unwrap()
            .dynamic = Message::parse(&revoked).unwrap();
        assert!(validate_draft(&new, &directory).is_err());
        assert!(add_recovery_identity(&mut new, recovery, &directory).is_err());
        assert_eq!(new.recovery_identities.len(), 1);
    }

    #[test]
    fn old_enrollment_json_defaults_to_no_recovery_identities() {
        let enrollment = prepared();
        let value = serde_json::to_value(&enrollment).unwrap();
        assert!(value.get("recovery_identities").is_none());
        let parsed: Enrollment = serde_json::from_value(value).unwrap();
        assert!(parsed.recovery_identities.is_empty());
    }

    fn fixture() -> (Bottle, Vec<u8>, String, Directory) {
        let value: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/public/enrollment-vectors.json"))
                .unwrap();
        let bottle = Bottle {
            label: "test-label".into(),
            bottle_id: value["bottle_id"].as_str().unwrap().into(),
            peer_id: value["peer_id"].as_str().unwrap().into(),
            raw: hex::decode(value["bottle"].as_str().unwrap()).unwrap(),
        };
        let directory =
            parse_directory(&hex::decode(value["directory"].as_str().unwrap()).unwrap()).unwrap();
        (
            bottle,
            hex::decode(value["entropy"].as_str().unwrap()).unwrap(),
            value["adsid"].as_str().unwrap().into(),
            directory,
        )
    }

    #[test]
    fn independent_bottle_and_peer_signatures_authenticate() {
        let (bottle, entropy, adsid, directory) = fixture();
        let sponsor = open_bottle(&bottle, &entropy, &adsid, &directory).unwrap();
        let raw = hex::decode(&sponsor.signing_priv_x963).unwrap();
        assert_eq!(&raw[97..144], &[0u8; 47]);
        assert_eq!(raw[144], 2);
        let raw = hex::decode(&sponsor.encryption_priv_x963).unwrap();
        assert_eq!(raw[144], 3);
        assert!(!format!("{sponsor:?}").contains(&sponsor.signing_priv_x963));
        assert!(open_bottle(&bottle, &entropy, "wrong-account", &directory).is_err());
        let mut wrong = entropy.clone();
        wrong[0] ^= 1;
        assert!(open_bottle(&bottle, &wrong, &adsid, &directory).is_err());
        let mut tampered = bottle.clone();
        tampered.raw[100] ^= 1;
        assert!(open_bottle(&tampered, &entropy, &adsid, &directory).is_err());
    }

    #[test]
    fn prepared_peer_preserves_trust_and_all_signatures_verify() {
        let (bottle, entropy, adsid, directory) = fixture();
        let result = prepare_enrollment(
            &bottle,
            &entropy,
            &adsid,
            &DeviceState::generate(),
            &directory,
        )
        .unwrap();
        assert!(!result.joined);
        let raw = STANDARD.decode(&result.peer_base64).unwrap();
        let peer = Message::parse(&raw).unwrap();
        let key = private_key(&hex::decode(&result.keys.signing_priv_x963).unwrap()).unwrap();
        for (field, domain) in [
            (2, b"TPPB.PeerPermanentInfo".as_slice()),
            (3, b"TPPB.PeerStableInfo"),
            (4, b"TPPB.PeerDynamicInfo"),
        ] {
            verify_signed(
                &Message::parse(required(&peer, field).unwrap()).unwrap(),
                SigningKey::from(&key).verifying_key(),
                domain,
            )
            .unwrap();
        }
        let sponsor =
            private_key(&hex::decode(&result.sponsor.signing_priv_x963).unwrap()).unwrap();
        verify_signed(
            &Message::parse(required(&peer, 5).unwrap()).unwrap(),
            SigningKey::from(&sponsor).verifying_key(),
            b"TPPB.Voucher",
        )
        .unwrap();
        let dynamic = Message::parse(required(&peer, 4).unwrap()).unwrap();
        let dynamic = Message::parse(required(&dynamic, 1).unwrap()).unwrap();
        assert_eq!(dynamic.first_varint(1), Some(8));
        assert_eq!(
            strings(&dynamic, 2).unwrap(),
            BTreeSet::from([result.peer_id.clone(), bottle.peer_id.clone()])
        );
        assert_eq!(
            strings(&dynamic, 3).unwrap(),
            BTreeSet::from(["excluded-peer".into()])
        );
        let stable = Message::parse(required(&peer, 3).unwrap()).unwrap();
        let stable = Message::parse(required(&stable, 1).unwrap()).unwrap();
        assert_eq!(stable.first_varint(1), Some(5));
        assert_eq!(text(&stable, 11).unwrap(), "flexible-test-policy");
    }

    #[test]
    fn rejects_mismatched_private_export() {
        let key = SecretKey::random(&mut rand::rngs::OsRng);
        let mut bytes = export(&key);
        bytes[1] ^= 1;
        assert!(private_key(&bytes).is_err());
        assert!(private_key(&[0; 48]).is_err());
    }
}
