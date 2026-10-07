//! Opt-in read-only smoke test. Never runs during ordinary cargo test/CI.
use icloud_safari::{
    anisette::LocalOrHttpAnisette,
    cloudkit::{DeviceState, ReqwestTransport, SessionState},
    enrollment,
    keychain::KeychainClient,
    state::FileStateStore,
};

#[tokio::test]
#[ignore = "requires explicit private state and contacts Apple"]
async fn discovers_bottles_and_recovers_existing_keys() {
    let root = std::env::var("ICLOUD_LIVE_STATE_DIR").expect("set ICLOUD_LIVE_STATE_DIR");
    let store = FileStateStore::new(root);
    let mut session: SessionState = store.read_json("live/session.json").unwrap();
    // An optional older same-account session can supply enrollment without
    // replacing the current tokens. This merge exists only in memory.
    if let Ok(path) = std::env::var("ICLOUD_LIVE_ENROLLMENT_SESSION") {
        let old: SessionState = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(
            old.mme.dsid == session.mme.dsid && old.username == session.username,
            "enrollment account mismatch"
        );
        session
            .extra
            .insert("octagon".into(), old.extra["octagon"].clone());
    }
    let device: DeviceState = store.read_json("live/device.json").unwrap();
    let anisette = LocalOrHttpAnisette::open(store.root(), None).await.unwrap();
    let client = KeychainClient::initialize(ReqwestTransport::default(), anisette, device, session)
        .await
        .unwrap();
    let bottles = enrollment::list_bottles(&client).await.unwrap();
    assert!(!bottles.is_empty());
    enrollment::fetch_directory(&client).await.unwrap();
    let identities = client.recover_pcs_identities().await.unwrap();
    assert!(!identities.is_empty());
    eprintln!(
        "Live check: {} viable bottles; {} validated PCS identities",
        bottles.len(),
        identities.len()
    );
}
