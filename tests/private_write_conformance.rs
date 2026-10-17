use std::{
    collections::BTreeMap,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use icloud_safari::{
    Dataset, NewBookmark, NewTab, WriteWorkspace,
    wire::{Message, Value},
};

fn private_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/private")
}

/// A private copy of the fixtures: creating a bookmark saves the writer's
/// device identifier in the workspace, which must not land in the fixtures.
fn private_copy() -> tempfile::TempDir {
    fn copy(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o700)).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).unwrap();
            }
        }
    }
    let copy_root = tempfile::tempdir().unwrap();
    copy(&private_root(), copy_root.path());
    copy_root
}

#[test]
fn prepares_fresh_pcs_records_for_bookmarks_and_tabs() {
    if !private_root().join("expected.json").is_file() {
        return;
    }
    let root = private_copy();
    let writer = WriteWorkspace::open(root.path()).unwrap();
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

fn field_name(field: &Message) -> String {
    let identifier = Message::parse(field.first_bytes(1).unwrap()).unwrap();
    String::from_utf8(identifier.first_bytes(1).unwrap().to_vec()).unwrap()
}

/// Field name -> CloudKit value message of one record.
fn record_fields(record: &Message) -> BTreeMap<String, Message> {
    let mut fields = BTreeMap::new();
    for field in record.values(7) {
        let Value::Bytes(field) = field else { continue };
        let field = Message::parse(field).unwrap();
        let value = Message::parse(field.first_bytes(2).unwrap()).unwrap();
        assert!(
            fields.insert(field_name(&field), value).is_none(),
            "repeated field"
        );
    }
    fields
}

fn record_type(record: &Message) -> String {
    let identifier = Message::parse(record.first_bytes(3).unwrap()).unwrap();
    String::from_utf8(identifier.first_bytes(1).unwrap().to_vec()).unwrap()
}

fn parent(value: &Message) -> String {
    let reference = Message::parse(value.first_bytes(9).unwrap()).unwrap();
    let record_id = Message::parse(reference.first_bytes(2).unwrap()).unwrap();
    let identifier = Message::parse(record_id.first_bytes(1).unwrap()).unwrap();
    String::from_utf8(identifier.first_bytes(1).unwrap().to_vec()).unwrap()
}

fn position_json(value: &Message) -> serde_json::Value {
    let mut json = Vec::new();
    flate2::read::ZlibDecoder::new(value.first_bytes(2).unwrap())
        .read_to_end(&mut json)
        .unwrap();
    serde_json::from_slice(&json).unwrap()
}

fn sort_value(json: &serde_json::Value) -> i64 {
    json.pointer("/default/sortValues/0/sortValue")
        .and_then(serde_json::Value::as_i64)
        .unwrap()
}

/// Every Safari-written bookmark record in the cached fetch.
fn cached_bookmarks(root: &Path) -> Vec<Message> {
    let stored: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.join("safari-cloudkit/bookmarks.json")).unwrap(),
    )
    .unwrap();
    let mut records = Vec::new();
    for page in stored["pages"].as_array().unwrap() {
        let raw = STANDARD
            .decode(page["raw_response_base64"].as_str().unwrap())
            .unwrap();
        for change in Message::parse(&raw).unwrap().values(1) {
            let Value::Bytes(change) = change else {
                continue;
            };
            let change = Message::parse(change).unwrap();
            let Some(record) = change.first_bytes(5) else {
                continue;
            };
            let record = Message::parse(record).unwrap();
            if record_type(&record).starts_with("Bookmark") {
                records.push(record);
            }
        }
    }
    records
}

#[test]
fn new_bookmark_takes_only_the_encoding_from_its_template() {
    if !private_root().join("expected.json").is_file() {
        return;
    }
    let root = private_copy();
    let existing = cached_bookmarks(root.path());
    let leaves: Vec<_> = existing
        .iter()
        .filter(|record| record_type(record) == "BookmarkLeaf")
        .map(record_fields)
        .collect();
    assert!(!leaves.is_empty());
    let folder = parent(&leaves[0]["ParentFolder"]);
    let last_sibling = existing
        .iter()
        .map(record_fields)
        .filter(|fields| fields.get("ParentFolder").map(parent).as_deref() == Some(&folder))
        .filter_map(|fields| {
            fields
                .get("Position")
                .map(position_json)
                .filter(|json| json.pointer("/default/sortValues/0").is_some())
                .map(|json| sort_value(&json))
        })
        .max()
        .unwrap();

    let plan = WriteWorkspace::open(root.path())
        .unwrap()
        .prepare_bookmark_create(NewBookmark {
            title: "Disposable bookmark",
            url: "https://example.invalid/bookmark",
            parent_id: Some(&folder),
        })
        .unwrap();
    let created = Message::parse(&STANDARD.decode(&plan.record_base64).unwrap()).unwrap();
    let fields = record_fields(&created);

    // Exactly the known schema: no preview text (or its stamps), nothing else.
    let names: Vec<_> = fields.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "DateAdded",
            "DateAdded_deviceIdentifier",
            "DateAdded_generation",
            "IdentityHash",
            "MinimumAPIVersion",
            "MinimumAPIVersion_deviceIdentifier",
            "MinimumAPIVersion_generation",
            "ParentAndPosition_deviceIdentifier",
            "ParentAndPosition_generation",
            "ParentFolder",
            "Position",
            "Title",
            "TitleURLAndIdentityHash_deviceIdentifier",
            "TitleURLAndIdentityHash_generation",
            "URL",
        ]
    );
    for name in ["Title", "URL", "DateAdded"] {
        assert_eq!(
            fields[name].first_varint(13),
            Some(1),
            "{name} is encrypted"
        );
    }
    assert_eq!(parent(&fields["ParentFolder"]), folder);

    // A fresh identity: random body, Safari's shared four-byte suffix.
    let identity = fields["IdentityHash"].first_bytes(2).unwrap();
    for leaf in &leaves {
        let theirs = leaf["IdentityHash"].first_bytes(2).unwrap();
        assert_ne!(identity, theirs);
        assert_eq!(identity.len(), theirs.len());
        assert_eq!(identity[identity.len() - 4..], theirs[theirs.len() - 4..]);
    }

    // Appended after the folder's last child, with its own sort entry.
    let position = position_json(&fields["Position"]);
    assert_eq!(sort_value(&position), last_sibling + 1000);
    let entry = position["default"]["sortValues"][0]["deviceIdentifier"]
        .as_str()
        .unwrap();
    for leaf in &leaves {
        assert_ne!(
            position_json(&leaf["Position"])["default"]["sortValues"][0]["deviceIdentifier"],
            entry
        );
    }

    // Every group stamp names this writer, at generation 1.
    let device: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.path().join("safari-writer-device.json")).unwrap(),
    )
    .unwrap();
    let device = device["device_identifier"].as_str().unwrap();
    for (name, value) in &fields {
        if name.ends_with("_deviceIdentifier") {
            assert_eq!(value.first_bytes(7), Some(device.as_bytes()), "{name}");
            for leaf in &leaves {
                assert_ne!(leaf[name].first_bytes(7), Some(device.as_bytes()));
            }
        }
        if name.ends_with("_generation") {
            assert_eq!(value.first_varint(4), Some(1), "{name}");
        }
    }
    assert_eq!(
        fields["MinimumAPIVersion"].first_varint(4),
        leaves[0]["MinimumAPIVersion"].first_varint(4)
    );

    // The device identifier is reused by the next create.
    let again = WriteWorkspace::open(root.path())
        .unwrap()
        .prepare_bookmark_create(NewBookmark {
            title: "Second",
            url: "https://example.invalid/second",
            parent_id: Some(&folder),
        })
        .unwrap();
    let again =
        record_fields(&Message::parse(&STANDARD.decode(&again.record_base64).unwrap()).unwrap());
    assert_eq!(
        again["DateAdded_deviceIdentifier"].first_bytes(7),
        Some(device.as_bytes())
    );
}
