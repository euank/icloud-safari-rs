use std::path::PathBuf;

use icloud_safari::OfflineReader;

#[test]
fn private_fixture_contract() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/private");
    if !root.join("expected.json").is_file() {
        return;
    }
    let report = OfflineReader::open(root)
        .unwrap()
        .verify_expected()
        .unwrap();
    assert_eq!(report.pcs_objects, 10);
    assert_eq!(report.unwrapped_objects, 10);
    assert_eq!(report.authenticated_fields, 19);
}
