use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use icloud_safari::{Dataset, NewBookmark, NewTab, WriteWorkspace, wire::Message};

fn private_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/private")
}

#[test]
fn prepares_fresh_pcs_records_for_bookmarks_and_tabs() {
    let root = private_root();
    if !root.join("expected.json").is_file() {
        return;
    }
    let writer = WriteWorkspace::open(root).unwrap();
    let plans = [
        writer
            .prepare_bookmark_create(NewBookmark {
                title: "Disposable bookmark",
                url: "https://example.invalid/bookmark",
                parent_id: None,
            })
            .unwrap(),
        writer
            .prepare_tab_create(NewTab {
                title: "Disposable tab",
                url: "https://example.invalid/tab",
                owning_device_id: None,
            })
            .unwrap(),
    ];
    for plan in plans {
        assert_eq!(plan.record_name.len(), 36);
        assert_eq!(plan.record_protection_info_tag.len(), 40);
        assert_eq!(plan.zone_protection_info_tag.len(), 40);
        assert!(!format!("{plan:?}").contains(&plan.record_base64));
        let save = Message::parse(&plan.encode_record_save_request().unwrap()).unwrap();
        assert!(save.first_bytes(1).is_some());
        assert_eq!(save.first_varint(2), Some(1));
        assert_eq!(save.first_varint(6), Some(2));
        assert_eq!(
            save.first_bytes(7),
            Some(plan.zone_protection_info_tag.as_bytes())
        );
    }
}

#[test]
fn prepares_lossless_encrypted_update_and_delete() {
    let root = private_root();
    if !root.join("expected.json").is_file() {
        return;
    }
    let writer = WriteWorkspace::open(root).unwrap();
    let first = writer
        .prepare_string_update(
            Dataset::Bookmarks,
            "Favorites Bar",
            "Title",
            "Write conformance title",
        )
        .unwrap();
    let second = writer
        .prepare_string_update(
            Dataset::Bookmarks,
            "Favorites Bar",
            "Title",
            "Write conformance title",
        )
        .unwrap();

    assert_eq!(first.metadata.record_name, "Favorites Bar");
    assert_eq!(first.metadata.record_type, "BookmarkList");
    assert!(!first.metadata.etag.is_empty());
    assert_eq!(first.metadata.protection_info_tag.len(), 40);
    assert_ne!(first.original_record_sha256, first.updated_record_sha256);
    // Fresh AES-GCM IVs make otherwise identical updates distinct.
    assert_ne!(first.updated_record_sha256, second.updated_record_sha256);
    let updated = STANDARD.decode(&first.updated_record_base64).unwrap();
    Message::parse(&updated).unwrap();
    // The source is recovered from the plan's known fixture hash internally by
    // the live path; here, a changed plan hash is rejected before encoding.
    let mut corrupted = first.clone();
    corrupted.updated_record_sha256.replace_range(..2, "00");
    assert!(corrupted.encode_record_save_request().is_err());
    let save = Message::parse(&first.encode_record_save_request().unwrap()).unwrap();
    assert_eq!(save.first_bytes(1), Some(updated.as_slice()));
    assert_eq!(save.first_bytes(4), Some(first.metadata.etag.as_bytes()));
    assert_eq!(save.first_varint(6), Some(1));
    assert_eq!(
        save.first_bytes(8),
        Some(first.metadata.protection_info_tag.as_bytes())
    );

    let delete = writer
        .prepare_delete(Dataset::Bookmarks, "Favorites Bar")
        .unwrap();
    assert_eq!(delete.metadata.etag, first.metadata.etag);
    assert!(!delete.record_identifier_base64.is_empty());
    let delete_request = Message::parse(&delete.encode_record_delete_request().unwrap()).unwrap();
    assert!(delete_request.first_bytes(1).is_some());
    assert_eq!(
        delete_request.first_bytes(2),
        Some(delete.metadata.etag.as_bytes())
    );
}
