//! Explicitly opted-in new-peer join using already recovered same-account keys.
//! This never contacts escrow and does not validate fresh passcode recovery.
//! Use a durable copy of current state with no Octagon identity; preserve it.
//! ICLOUD_SPONSORED_CONFIRM=join-existing-circle
//! ICLOUD_LIVE_STATE_DIR=/private/durable/copy
//! ICLOUD_LIVE_ENROLLMENT_SESSION=/private/older/same-account/session.json
#![cfg(feature = "experimental-live-writes")]

use icloud_safari::{
    anisette::LocalOrHttpAnisette,
    cloudkit::{DeviceState, ReqwestTransport, SessionState},
    enrollment::{self, Enrollment, Sponsor},
    keychain::KeychainClient,
    state::FileStateStore,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[tokio::test]
#[ignore = "adds a peer using existing sponsor keys; requires explicit environment confirmation"]
async fn join_and_resume_with_existing_sponsor_without_escrow()
-> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("ICLOUD_SPONSORED_CONFIRM").as_deref() != Ok("join-existing-circle") {
        return Err("explicit sponsored join confirmation required".into());
    }
    let store = FileStateStore::new(std::env::var("ICLOUD_LIVE_STATE_DIR")?);
    let _lock = store.try_lock()?;
    let mut session: SessionState = store.read_json("live/session.json")?;
    let device: DeviceState = store.read_json("live/device.json")?;
    let provider = LocalOrHttpAnisette::open(store.root(), None).await?;
    let client = KeychainClient::initialize(
        ReqwestTransport::default(),
        provider.clone(),
        device.clone(),
        session.clone(),
    )
    .await?;
    session = client.session().clone();
    let mut draft: Enrollment = if store
        .root()
        .join("enrollment/sponsored-pending.json")
        .try_exists()?
    {
        store.read_json("enrollment/sponsored-pending.json")?
    } else {
        if session.extra.contains_key("octagon") {
            return Err("target already has enrollment".into());
        }
        let source = std::env::var("ICLOUD_LIVE_ENROLLMENT_SESSION")?;
        let source = Zeroizing::new(std::fs::read(source)?);
        let source: SessionState = serde_json::from_slice(&source)?;
        if source.mme.dsid != session.mme.dsid || source.username != session.username {
            return Err("sponsor account mismatch".into());
        }
        let existing = source
            .extra
            .get("octagon")
            .ok_or("source has no Octagon peer")?;
        let keys: enrollment::PeerKeys = serde_json::from_value(
            existing
                .get("keys")
                .ok_or("source has no peer keys")?
                .clone(),
        )?;
        let sponsor = Sponsor {
            peer_id: existing
                .get("peer_id")
                .and_then(serde_json::Value::as_str)
                .ok_or("source has no peer ID")?
                .into(),
            signing_priv_x963: keys.signing_priv_x963.clone(),
            encryption_priv_x963: keys.encryption_priv_x963.clone(),
        };
        let directory = enrollment::fetch_directory(&client).await?;
        let draft = enrollment::prepare_enrollment_from_sponsor(sponsor, &device, &directory)?;
        store.write_json("enrollment/sponsored-pending.json", &draft)?;
        draft
    };
    // Keep the original Mac's recovery-only key: the old joined peer may never
    // have received its own CKKS shares after that Mac was decommissioned.
    let source = Zeroizing::new(std::fs::read(std::env::var(
        "ICLOUD_LIVE_ENROLLMENT_SESSION",
    )?)?);
    let source: SessionState = serde_json::from_slice(&source)?;
    if source.mme.dsid != session.mme.dsid || source.username != session.username {
        return Err("recovery identity account mismatch".into());
    }
    let recovery: enrollment::RecoveryIdentity = serde_json::from_value(
        source
            .extra
            .get("octagon")
            .and_then(|value| value.get("sponsor"))
            .ok_or("source has no recovery identity")?
            .clone(),
    )?;
    let directory = enrollment::fetch_directory(&client).await?;
    enrollment::add_recovery_identity(&mut draft, recovery, &directory)?;
    store.write_json("enrollment/sponsored-pending.json", &draft)?;
    session
        .extra
        .insert("octagon".into(), serde_json::to_value(&draft)?);
    store.write_json("live/session.json", &session)?;
    let client = KeychainClient::new(
        ReqwestTransport::default(),
        provider.clone(),
        device.clone(),
        session.clone(),
    )?;
    enrollment::join(&client, &mut draft).await?;
    store.write_json("enrollment/sponsored-pending.json", &draft)?;
    session
        .extra
        .insert("octagon".into(), serde_json::to_value(&draft)?);
    store.write_json("live/session.json", &session)?;
    let client = KeychainClient::new(ReqwestTransport::default(), provider, device, session)?;
    let identities = client.recover_pcs_identities().await?;
    for identity in &identities {
        store.write_bytes(
            format!(
                "pcs-identities/{}.der",
                hex::encode(Sha256::digest(&**identity))
            ),
            identity,
        )?;
    }
    let peer_id = draft.peer_id.clone();
    enrollment::join(&client, &mut draft).await?;
    assert!(draft.joined && peer_id == draft.peer_id);
    let (_, passwords) = client.fetch_and_decrypt_passwords().await?;
    eprintln!(
        "New peer joined and resume confirmed; {} PCS identities and {} password records recovered (contents withheld).",
        identities.len(),
        passwords.len()
    );
    Ok(())
}
