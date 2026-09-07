//! Lossless, offline write preparation for existing Safari records.
//!
//! Preparation is available in the default build. Network application lives
//! behind the separate `experimental-live-writes` feature.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    Error, Result,
    model::Dataset,
    pcs::{FieldAadMode, Identity, KeyGraph, create_record_protection, extract_objects},
    wire::{self, Message, Value},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlaintextCodec {
    Utf8,
    CkdpString,
    RawBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AadMode {
    LegacyFieldName,
    RecordContext,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecordMetadata {
    pub dataset: Dataset,
    pub zone: String,
    pub record_name: String,
    pub record_type: String,
    pub etag: String,
    pub protection_info_tag: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedFieldUpdate {
    pub format: String,
    pub metadata: RecordMetadata,
    pub field_name: String,
    pub plaintext_codec: PlaintextCodec,
    pub aad_mode: AadMode,
    pub original_record_sha256: String,
    pub updated_record_sha256: String,
    pub plaintext_sha256: String,
    pub updated_record_base64: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedDelete {
    pub format: String,
    pub metadata: RecordMetadata,
    pub record_identifier_base64: String,
    pub source_record_sha256: String,
}

#[derive(Clone, Debug)]
pub struct NewBookmark<'a> {
    pub title: &'a str,
    pub url: &'a str,
    pub parent_id: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct NewTab<'a> {
    pub title: &'a str,
    pub url: &'a str,
    pub owning_device_id: Option<&'a str>,
}

#[derive(Clone)]
pub struct PreparedCreate {
    pub dataset: Dataset,
    pub zone: String,
    pub record_name: String,
    pub record_type: String,
    pub record_base64: String,
    pub record_sha256: String,
    pub zone_protection_info_tag: String,
    pub record_protection_info_tag: String,
    #[cfg_attr(not(feature = "experimental-live-writes"), allow(dead_code))]
    pub(crate) expected_fields: BTreeMap<String, zeroize::Zeroizing<Vec<u8>>>,
    #[cfg_attr(not(feature = "experimental-live-writes"), allow(dead_code))]
    pub(crate) master_key: zeroize::Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for PreparedCreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedCreate")
            .field("dataset", &self.dataset)
            .field("zone", &self.zone)
            .field("record_name", &self.record_name)
            .field("record_type", &self.record_type)
            .field("record", &"<encrypted>")
            .field("master_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SaveSemantics {
    FailIfOutdated,
    FailIfExists,
    Override,
}

impl SaveSemantics {
    fn wire_value(self) -> u64 {
        match self {
            Self::FailIfOutdated => 1,
            Self::FailIfExists => 2,
            Self::Override => 3,
        }
    }
}

impl PreparedFieldUpdate {
    /// Encode Apple's `CKDPRecordSaveRequest` for a compare-and-swap update.
    /// The returned bytes are the operation-specific message, not an HTTP
    /// request or a `RequestOperation` envelope.
    pub fn encode_record_save_request(&self) -> Result<Vec<u8>> {
        let record = STANDARD
            .decode(&self.updated_record_base64)
            .map_err(|_| Error::Fixture("prepared record is not valid base64".into()))?;
        if hex::encode(Sha256::digest(&record)) != self.updated_record_sha256 {
            return Err(Error::Integrity);
        }
        Message::parse(&record)?;
        let mut request = Vec::new();
        wire::encode_bytes(1, &record, &mut request);
        wire::encode_string(4, &self.metadata.etag, &mut request);
        wire::encode_uint(6, SaveSemantics::FailIfOutdated.wire_value(), &mut request);
        wire::encode_string(8, &self.metadata.protection_info_tag, &mut request);
        Ok(request)
    }

    /// Ensure a serialized plan still describes a one-field-only change from
    /// the freshly fetched source record. This rejects hand-edited plans that
    /// alter metadata or any second field.
    pub fn validate_against_source(&self, source: &[u8]) -> Result<()> {
        if hex::encode(Sha256::digest(source)) != self.original_record_sha256 {
            return Err(Error::Integrity);
        }
        let updated = STANDARD
            .decode(&self.updated_record_base64)
            .map_err(|_| Error::Fixture("prepared record is not valid base64".into()))?;
        if hex::encode(Sha256::digest(&updated)) != self.updated_record_sha256 {
            return Err(Error::Integrity);
        }
        let original = Message::parse(source)?;
        let changed = Message::parse(&updated)?;
        if metadata(self.metadata.dataset, &self.metadata.zone, &original)? != self.metadata
            || metadata(self.metadata.dataset, &self.metadata.zone, &changed)? != self.metadata
            || original.fields.len() != changed.fields.len()
        {
            return Err(Error::Integrity);
        }
        let mut differences = 0;
        for (before, after) in original.fields.iter().zip(&changed.fields) {
            if before.raw == after.raw {
                continue;
            }
            if before.number != 7 || after.number != 7 {
                return Err(Error::Integrity);
            }
            validate_changed_record_field(before, after, &self.field_name)?;
            differences += 1;
        }
        if differences != 1 {
            return Err(Error::Integrity);
        }
        Ok(())
    }
}

impl PreparedDelete {
    /// Encode Apple's `CKDPRecordDeleteRequest` with the fetched etag so the
    /// server can reject a stale delete.
    pub fn encode_record_delete_request(&self) -> Result<Vec<u8>> {
        let identifier = STANDARD
            .decode(&self.record_identifier_base64)
            .map_err(|_| Error::Fixture("prepared identifier is not valid base64".into()))?;
        Message::parse(&identifier)?;
        let mut request = Vec::new();
        wire::encode_bytes(1, &identifier, &mut request);
        wire::encode_string(2, &self.metadata.etag, &mut request);
        Ok(request)
    }
}

impl PreparedCreate {
    pub fn encode_record_save_request(&self) -> Result<Vec<u8>> {
        let record = STANDARD
            .decode(&self.record_base64)
            .map_err(|_| Error::Fixture("prepared record is not valid base64".into()))?;
        if hex::encode(Sha256::digest(&record)) != self.record_sha256 {
            return Err(Error::Integrity);
        }
        Message::parse(&record)?;
        let mut request = Vec::new();
        wire::encode_bytes(1, &record, &mut request);
        wire::encode_uint(2, 1, &mut request);
        wire::encode_uint(6, SaveSemantics::FailIfExists.wire_value(), &mut request);
        wire::encode_string(7, &self.zone_protection_info_tag, &mut request);
        Ok(request)
    }
}

#[derive(Clone, Debug)]
pub struct WriteWorkspace {
    root: PathBuf,
}

#[derive(Deserialize)]
struct StoredDataset {
    zone: String,
    pages: Vec<StoredPage>,
}

#[derive(Deserialize)]
struct StoredPage {
    raw_response_base64: String,
}

impl WriteWorkspace {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.is_dir() {
            return Err(Error::Fixture(format!(
                "write workspace not found: {}",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    pub fn prepare_bookmark_create(&self, value: NewBookmark<'_>) -> Result<PreparedCreate> {
        if value.title.is_empty() || value.url.is_empty() {
            return Err(Error::Fixture(
                "bookmark title and URL must not be empty".into(),
            ));
        }
        self.prepare_create(
            Dataset::Bookmarks,
            "BookmarkLeaf",
            BTreeMap::from([
                ("Title".into(), value.title.as_bytes().to_vec()),
                ("URL".into(), value.url.as_bytes().to_vec()),
                ("DateAdded".into(), keyed_date_now()?),
            ]),
            BTreeMap::from([(
                "ParentFolder".into(),
                value
                    .parent_id
                    .unwrap_or("com.apple.Safari.TopBookmark")
                    .to_owned(),
            )]),
        )
    }

    pub fn prepare_tab_create(&self, value: NewTab<'_>) -> Result<PreparedCreate> {
        if value.title.is_empty() || value.url.is_empty() {
            return Err(Error::Fixture("tab title and URL must not be empty".into()));
        }
        let owner = value
            .owning_device_id
            .map(str::to_owned)
            .or_else(|| {
                self.first_record_name(Dataset::Tabs, "CloudTabDevice")
                    .ok()
                    .flatten()
            })
            .ok_or_else(|| {
                Error::Fixture("no CloudTabDevice is available for the new tab".into())
            })?;
        self.prepare_create(
            Dataset::Tabs,
            "CloudTab",
            BTreeMap::from([
                ("Title".into(), keyed_string(value.title)?),
                ("URL".into(), keyed_string(value.url)?),
                ("DateLastViewed".into(), ckdp_date_now()),
            ]),
            BTreeMap::from([("OwningDevice".into(), owner)]),
        )
    }

    /// Prepare an update while retaining the fetched record's unknown fields,
    /// etag, identifier, PCS object, and protection-info tag.
    pub fn prepare_string_update(
        &self,
        dataset: Dataset,
        record_name: &str,
        field_name: &str,
        new_value: &str,
    ) -> Result<PreparedFieldUpdate> {
        let loaded = self.load(dataset, record_name)?;
        let old_blob = encrypted_field(&loaded.record, field_name)?;
        let old_plaintext = loaded
            .graph
            .decrypt_field(&loaded.zone, record_name, field_name, &old_blob)?
            .ok_or(Error::Integrity)?;
        let codec = detect_string_codec(&old_plaintext)?;
        let plaintext = match codec {
            PlaintextCodec::Utf8 => new_value.as_bytes().to_vec(),
            PlaintextCodec::CkdpString => encode_ckdp_string(new_value),
            PlaintextCodec::RawBytes => {
                return Err(Error::Unsupported(
                    "the existing field is not a recognized string encoding",
                ));
            }
        };
        self.finish_update(loaded, field_name, &old_blob, plaintext, codec)
    }

    /// Prepare a byte-for-byte plaintext replacement. This is intended for
    /// callers that already implement the record type's canonical codec.
    pub fn prepare_bytes_update(
        &self,
        dataset: Dataset,
        record_name: &str,
        field_name: &str,
        plaintext: &[u8],
    ) -> Result<PreparedFieldUpdate> {
        let loaded = self.load(dataset, record_name)?;
        let old_blob = encrypted_field(&loaded.record, field_name)?;
        self.finish_update(
            loaded,
            field_name,
            &old_blob,
            plaintext.to_vec(),
            PlaintextCodec::RawBytes,
        )
    }

    pub fn prepare_delete(&self, dataset: Dataset, record_name: &str) -> Result<PreparedDelete> {
        // A delete only needs the server identifier, etag, and protection tag.
        // Deliberately avoid recovering the whole PCS graph here so a corrupt
        // unrelated record cannot prevent removal of the offending record.
        let stored = self.read_dataset(dataset)?;
        let mut record_bytes = None;
        for page in &stored.pages {
            if record_bytes.is_none() {
                record_bytes = find_record(&decode_page(page)?, record_name)?;
            }
        }
        let record_bytes = record_bytes.ok_or_else(|| {
            Error::Fixture(format!(
                "record {record_name:?} was not found in {}",
                dataset.as_str()
            ))
        })?;
        let record = Message::parse(&record_bytes)?;
        let record_identifier = record
            .first_bytes(2)
            .ok_or(Error::Protobuf("record omitted identifier"))?;
        Ok(PreparedDelete {
            format: "icloud-safari-prepared-delete-v1".into(),
            metadata: metadata(dataset, &stored.zone, &record)?,
            record_identifier_base64: STANDARD.encode(record_identifier),
            source_record_sha256: hex::encode(Sha256::digest(&record_bytes)),
        })
    }

    fn finish_update(
        &self,
        mut loaded: LoadedRecord,
        field_name: &str,
        old_blob: &[u8],
        plaintext: Vec<u8>,
        codec: PlaintextCodec,
    ) -> Result<PreparedFieldUpdate> {
        let (new_blob, aad) = loaded.graph.reencrypt_field(
            &loaded.zone,
            &identifier_name(
                loaded
                    .record
                    .first_bytes(2)
                    .ok_or(Error::Protobuf("record omitted identifier"))?,
                true,
            )?,
            field_name,
            old_blob,
            &plaintext,
        )?;
        replace_encrypted_field(&mut loaded.record, field_name, &new_blob)?;
        let updated = loaded.record.encode();
        // Parsing the result here catches malformed nesting before it can be
        // persisted or handed to a future transport implementation.
        Message::parse(&updated)?;
        let metadata = metadata(loaded.dataset, &loaded.zone, &loaded.record)?;
        Ok(PreparedFieldUpdate {
            format: "icloud-safari-prepared-field-update-v1".into(),
            metadata,
            field_name: field_name.into(),
            plaintext_codec: codec,
            aad_mode: match aad {
                FieldAadMode::Legacy => AadMode::LegacyFieldName,
                FieldAadMode::Context => AadMode::RecordContext,
            },
            original_record_sha256: hex::encode(Sha256::digest(&loaded.record_bytes)),
            updated_record_sha256: hex::encode(Sha256::digest(&updated)),
            plaintext_sha256: hex::encode(Sha256::digest(&plaintext)),
            updated_record_base64: STANDARD.encode(updated),
        })
    }

    /// Verify that the currently cached server record decrypts to the exact
    /// plaintext committed to by a prepared update.
    pub fn verify_applied_update(&self, plan: &PreparedFieldUpdate) -> Result<()> {
        let loaded = self.load(plan.metadata.dataset, &plan.metadata.record_name)?;
        let blob = encrypted_field(&loaded.record, &plan.field_name)?;
        let plaintext = loaded
            .graph
            .decrypt_field(
                &loaded.zone,
                &plan.metadata.record_name,
                &plan.field_name,
                &blob,
            )?
            .ok_or(Error::Integrity)?;
        if hex::encode(Sha256::digest(plaintext)) != plan.plaintext_sha256 {
            return Err(Error::Integrity);
        }
        Ok(())
    }

    fn first_record_name(&self, dataset: Dataset, record_type: &str) -> Result<Option<String>> {
        let stored = self.read_dataset(dataset)?;
        for page in stored.pages {
            let raw = decode_page(&page)?;
            if let Some((name, _)) = find_record_type(&raw, record_type)? {
                return Ok(Some(name));
            }
        }
        Ok(None)
    }

    fn prepare_create(
        &self,
        dataset: Dataset,
        record_type: &str,
        encrypted_replacements: BTreeMap<String, Vec<u8>>,
        string_replacements: BTreeMap<String, String>,
    ) -> Result<PreparedCreate> {
        let stored = self.read_dataset(dataset)?;
        let mut objects = Vec::new();
        let mut template = None;
        let mut zone_tag = None;
        for page in &stored.pages {
            let raw = decode_page(page)?;
            objects.extend(extract_objects(&raw)?);
            zone_tag = zone_tag.or_else(|| zone_protection_tag(&raw).ok());
            if template.is_none() {
                template = find_record_type(&raw, record_type)?.map(|value| value.1);
            }
        }
        let template = template.ok_or_else(|| {
            Error::Fixture(format!(
                "no {record_type} record is available as a schema template"
            ))
        })?;
        let template = Message::parse(&template)?;
        let template_name = identifier_name(
            template
                .first_bytes(2)
                .ok_or(Error::Protobuf("template omitted identifier"))?,
            true,
        )?;
        let identities = load_identities(&self.root)?;
        let graph = KeyGraph::recover(&objects, identities)?;
        let protection = create_record_protection(&objects, &graph)?;
        let record_name = uuid::Uuid::new_v4().to_string().to_uppercase();
        let mut output = Vec::new();
        let identifier = rename_record_identifier(
            template
                .first_bytes(2)
                .ok_or(Error::Protobuf("template omitted identifier"))?,
            &record_name,
        )?;
        wire::encode_bytes(2, &identifier, &mut output);
        wire::encode_bytes(
            3,
            template
                .first_bytes(3)
                .ok_or(Error::Protobuf("template omitted type"))?,
            &mut output,
        );
        let mut seen_encrypted = BTreeMap::new();
        let mut seen_strings = BTreeMap::new();
        for raw_field in template.values(7) {
            let Value::Bytes(raw_field) = raw_field else {
                continue;
            };
            let mut field = Message::parse(raw_field)?;
            let name = identifier_name(
                field
                    .first_bytes(1)
                    .ok_or(Error::Protobuf("record field omitted identifier"))?,
                false,
            )?;
            if dataset == Dataset::Bookmarks && name == "PreviewText" {
                continue;
            }
            if let Some(replacement) = string_replacements.get(&name) {
                let replacement = replace_string_or_reference_value(
                    field
                        .first_bytes(2)
                        .ok_or(Error::Protobuf("record field omitted value"))?,
                    replacement,
                )?;
                if !field.replace_first_bytes(2, &replacement) {
                    return Err(Error::Protobuf("record field omitted value"));
                }
                seen_strings.insert(name.clone(), ());
                wire::encode_bytes(7, &field.encode(), &mut output);
                continue;
            }
            let value = Message::parse(
                field
                    .first_bytes(2)
                    .ok_or(Error::Protobuf("record field omitted value"))?,
            )?;
            if value.first_varint(13) == Some(1) && value.first_bytes(2).is_some() {
                let old_blob = value
                    .first_bytes(2)
                    .ok_or(Error::Protobuf("encrypted field omitted bytes"))?;
                let (old_plaintext, mode) = graph
                    .decrypt_field_with_mode(&stored.zone, &template_name, &name, old_blob)?
                    .ok_or(Error::Integrity)?;
                let plaintext = if let Some(replacement) = encrypted_replacements.get(&name) {
                    seen_encrypted.insert(name.clone(), ());
                    replacement.clone()
                } else if dataset == Dataset::Bookmarks && name == "IdentityHash" {
                    fresh_identity_hash(&old_plaintext)
                } else {
                    old_plaintext
                };
                let aad = match mode {
                    FieldAadMode::Legacy => name.clone(),
                    FieldAadMode::Context => {
                        format!("{}-{record_name}-{name}", stored.zone)
                    }
                };
                let blob = crate::crypto::fp_v3_encrypt(
                    &protection.master_key,
                    aad.as_bytes(),
                    &plaintext,
                )?;
                let mut value = value;
                if !value.replace_first_bytes(2, &blob) {
                    return Err(Error::Protobuf("encrypted field omitted bytes"));
                }
                if !field.replace_first_bytes(2, &value.encode()) {
                    return Err(Error::Protobuf("record field omitted value"));
                }
            }
            wire::encode_bytes(7, &field.encode(), &mut output);
        }
        let missing: Vec<_> = encrypted_replacements
            .keys()
            .filter(|key| !seen_encrypted.contains_key(*key))
            .chain(
                string_replacements
                    .keys()
                    .filter(|key| !seen_strings.contains_key(*key)),
            )
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(Error::Fixture(format!(
                "schema template omitted creation fields: {}",
                missing.join(", ")
            )));
        }
        let mut protection_info = Vec::new();
        wire::encode_bytes(1, &protection.der, &mut protection_info);
        wire::encode_string(2, &protection.tag, &mut protection_info);
        wire::encode_bytes(13, &protection_info, &mut output);
        let created_record = Message::parse(&output)?;

        // Reopen the new object through a fresh graph, using only the persisted
        // and recovered identities available to a future read. This is
        // intentionally independent of the in-memory master key used above.
        let mut verification_objects = objects;
        verification_objects.push(crate::pcs::Object::parse(&protection.der)?);
        let verification_graph =
            KeyGraph::recover(&verification_objects, graph.recovered_identities())?;
        for (name, expected) in &encrypted_replacements {
            let blob = encrypted_field(&created_record, name)?;
            let plaintext = verification_graph
                .decrypt_field(&stored.zone, &record_name, name, &blob)?
                .ok_or(Error::Integrity)?;
            if plaintext != *expected {
                return Err(Error::Integrity);
            }
        }
        Ok(PreparedCreate {
            dataset,
            zone: stored.zone,
            record_name,
            record_type: record_type.into(),
            record_sha256: hex::encode(Sha256::digest(&output)),
            record_base64: STANDARD.encode(output),
            zone_protection_info_tag: zone_tag.ok_or(Error::Protobuf(
                "record changes omitted zone protection tag",
            ))?,
            record_protection_info_tag: protection.tag,
            expected_fields: encrypted_replacements
                .into_iter()
                .map(|(name, value)| (name, zeroize::Zeroizing::new(value)))
                .collect(),
            master_key: protection.master_key,
        })
    }

    fn read_dataset(&self, dataset: Dataset) -> Result<StoredDataset> {
        let path = self
            .root
            .join("safari-cloudkit")
            .join(format!("{}.json", dataset.as_str()));
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }

    fn load(&self, dataset: Dataset, wanted: &str) -> Result<LoadedRecord> {
        let stored = self.read_dataset(dataset)?;
        let mut objects = Vec::new();
        let mut found = None;
        for page in stored.pages {
            let raw = STANDARD
                .decode(page.raw_response_base64)
                .map_err(|_| Error::Fixture("invalid base64 response".into()))?;
            objects.extend(extract_objects(&raw)?);
            if found.is_none() {
                found = find_record(&raw, wanted)?;
            }
        }
        let record_bytes = found.ok_or_else(|| {
            Error::Fixture(format!(
                "record {wanted:?} was not found in {}",
                dataset.as_str()
            ))
        })?;
        let identities = load_identities(&self.root)?;
        let graph = KeyGraph::recover(&objects, identities)?;
        let record = Message::parse(&record_bytes)?;
        Ok(LoadedRecord {
            dataset,
            zone: stored.zone,
            record,
            record_bytes,
            graph,
        })
    }
}

struct LoadedRecord {
    dataset: Dataset,
    zone: String,
    record: Message,
    record_bytes: Vec<u8>,
    graph: KeyGraph,
}

fn load_identities(root: &Path) -> Result<Vec<Identity>> {
    let mut entries =
        fs::read_dir(root.join("pcs-identities"))?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.path());
    entries
        .into_iter()
        .filter(|entry| entry.path().extension().is_some_and(|value| value == "der"))
        .map(|entry| Identity::from_der(&fs::read(entry.path())?))
        .collect()
}

fn decode_page(page: &StoredPage) -> Result<Vec<u8>> {
    STANDARD
        .decode(&page.raw_response_base64)
        .map_err(|_| Error::Fixture("invalid base64 response".into()))
}

fn find_record_type(response: &[u8], wanted_type: &str) -> Result<Option<(String, Vec<u8>)>> {
    let response = Message::parse(response)?;
    for change in response.values(1) {
        let Value::Bytes(change) = change else {
            continue;
        };
        let change = Message::parse(change)?;
        let Some(record) = change.first_bytes(5) else {
            continue;
        };
        let parsed = Message::parse(record)?;
        let Some(record_type) = parsed.first_bytes(3) else {
            continue;
        };
        if identifier_name(record_type, false)? == wanted_type {
            let name = identifier_name(
                parsed
                    .first_bytes(2)
                    .ok_or(Error::Protobuf("record omitted identifier"))?,
                true,
            )?;
            return Ok(Some((name, record.to_vec())));
        }
    }
    Ok(None)
}

pub(crate) fn zone_protection_tag(response: &[u8]) -> Result<String> {
    let response = Message::parse(response)?;
    let metadata = Message::parse(
        response
            .first_bytes(12)
            .ok_or(Error::Protobuf("response omitted zone metadata"))?,
    )?;
    let zone = Message::parse(
        metadata
            .first_bytes(1)
            .ok_or(Error::Protobuf("metadata omitted zone"))?,
    )?;
    let protection = Message::parse(
        zone.first_bytes(3)
            .ok_or(Error::Protobuf("zone omitted protection info"))?,
    )?;
    std::str::from_utf8(
        protection
            .first_bytes(2)
            .ok_or(Error::Protobuf("zone protection omitted tag"))?,
    )
    .map(str::to_owned)
    .map_err(|_| Error::Protobuf("zone protection tag is not UTF-8"))
}

fn rename_record_identifier(raw: &[u8], name: &str) -> Result<Vec<u8>> {
    let mut record_id = Message::parse(raw)?;
    let mut identifier = Message::parse(
        record_id
            .first_bytes(1)
            .ok_or(Error::Protobuf("record identifier omitted value"))?,
    )?;
    if !identifier.replace_first_bytes(1, name.as_bytes())
        || !record_id.replace_first_bytes(1, &identifier.encode())
    {
        return Err(Error::Protobuf("record identifier omitted name"));
    }
    Ok(record_id.encode())
}

fn ck_value_string(value: &str) -> Vec<u8> {
    let mut output = Vec::new();
    wire::encode_uint(1, 3, &mut output);
    wire::encode_string(7, value, &mut output);
    output
}

fn replace_string_or_reference_value(source: &[u8], replacement: &str) -> Result<Vec<u8>> {
    let mut value = Message::parse(source)?;
    if value.first_varint(1) != Some(5) {
        return Ok(ck_value_string(replacement));
    }
    let mut reference = Message::parse(
        value
            .first_bytes(9)
            .ok_or(Error::Protobuf("reference value omitted reference"))?,
    )?;
    let identifier = rename_record_identifier(
        reference
            .first_bytes(2)
            .ok_or(Error::Protobuf("reference omitted record identifier"))?,
        replacement,
    )?;
    if !reference.replace_first_bytes(2, &identifier)
        || !value.replace_first_bytes(9, &reference.encode())
    {
        return Err(Error::Protobuf("reference value is malformed"));
    }
    Ok(value.encode())
}

fn keyed_string(value: &str) -> Result<Vec<u8>> {
    let mut top = plist::Dictionary::new();
    top.insert("root".into(), plist::Value::Uid(plist::Uid::new(1)));
    let mut archive = plist::Dictionary::new();
    archive.insert("$version".into(), plist::Value::Integer(100000.into()));
    archive.insert(
        "$archiver".into(),
        plist::Value::String("NSKeyedArchiver".into()),
    );
    archive.insert("$top".into(), plist::Value::Dictionary(top));
    archive.insert(
        "$objects".into(),
        plist::Value::Array(vec![
            plist::Value::String("$null".into()),
            plist::Value::String(value.into()),
        ]),
    );
    let mut output = Vec::new();
    plist::Value::Dictionary(archive).to_writer_binary(&mut output)?;
    Ok(output)
}

fn keyed_date_now() -> Result<Vec<u8>> {
    let apple_seconds = chrono::Utc::now().timestamp_micros() as f64 / 1_000_000.0 - 978_307_200.0;
    let mut date = plist::Dictionary::new();
    date.insert("NS.time".into(), plist::Value::Real(apple_seconds));
    date.insert("$class".into(), plist::Value::Uid(plist::Uid::new(2)));
    let mut class = plist::Dictionary::new();
    class.insert("$classname".into(), plist::Value::String("NSDate".into()));
    class.insert(
        "$classes".into(),
        plist::Value::Array(vec![
            plist::Value::String("NSDate".into()),
            plist::Value::String("NSObject".into()),
        ]),
    );
    let mut top = plist::Dictionary::new();
    top.insert("root".into(), plist::Value::Uid(plist::Uid::new(1)));
    let mut archive = plist::Dictionary::new();
    archive.insert("$version".into(), plist::Value::Integer(100000.into()));
    archive.insert(
        "$archiver".into(),
        plist::Value::String("NSKeyedArchiver".into()),
    );
    archive.insert("$top".into(), plist::Value::Dictionary(top));
    archive.insert(
        "$objects".into(),
        plist::Value::Array(vec![
            plist::Value::String("$null".into()),
            plist::Value::Dictionary(date),
            plist::Value::Dictionary(class),
        ]),
    );
    let mut output = Vec::new();
    plist::Value::Dictionary(archive).to_writer_binary(&mut output)?;
    Ok(output)
}

fn ckdp_date_now() -> Vec<u8> {
    let apple_seconds = chrono::Utc::now().timestamp_micros() as f64 / 1_000_000.0 - 978_307_200.0;
    let mut output = vec![0x2a, 0x09, 0x09];
    output.extend_from_slice(&apple_seconds.to_le_bytes());
    output
}

fn fresh_identity_hash(source: &[u8]) -> Vec<u8> {
    let mut output = source.to_vec();
    let random_len = output.len().saturating_sub(4);
    rand::rngs::OsRng.fill_bytes(&mut output[..random_len]);
    output
}

fn find_record(response: &[u8], wanted: &str) -> Result<Option<Vec<u8>>> {
    let response = Message::parse(response)?;
    for change in response.values(1) {
        let Value::Bytes(change) = change else {
            continue;
        };
        let change = Message::parse(change)?;
        let Some(record) = change.first_bytes(5) else {
            continue;
        };
        let parsed = Message::parse(record)?;
        let Some(identifier) = parsed.first_bytes(2) else {
            continue;
        };
        if identifier_name(identifier, true)? == wanted {
            return Ok(Some(record.to_vec()));
        }
    }
    Ok(None)
}

fn identifier_name(bytes: &[u8], record_identifier: bool) -> Result<String> {
    let message = Message::parse(bytes)?;
    let identifier = if record_identifier {
        message
            .first_bytes(1)
            .ok_or(Error::Protobuf("record identifier omitted name"))?
    } else {
        bytes
    };
    let identifier = Message::parse(identifier)?;
    let name = identifier
        .first_bytes(1)
        .ok_or(Error::Protobuf("identifier omitted string"))?;
    std::str::from_utf8(name)
        .map(str::to_owned)
        .map_err(|_| Error::Protobuf("identifier string is not UTF-8"))
}

fn metadata(dataset: Dataset, zone: &str, record: &Message) -> Result<RecordMetadata> {
    let name = identifier_name(
        record
            .first_bytes(2)
            .ok_or(Error::Protobuf("record omitted identifier"))?,
        true,
    )?;
    let record_type = identifier_name(
        record
            .first_bytes(3)
            .ok_or(Error::Protobuf("record omitted type"))?,
        false,
    )?;
    let etag = std::str::from_utf8(
        record
            .first_bytes(1)
            .ok_or(Error::Protobuf("record omitted etag"))?,
    )
    .map_err(|_| Error::Protobuf("record etag is not UTF-8"))?
    .to_owned();
    let protection = Message::parse(
        record
            .first_bytes(13)
            .ok_or(Error::Protobuf("record omitted protection info"))?,
    )?;
    let tag = std::str::from_utf8(
        protection
            .first_bytes(2)
            .ok_or(Error::Protobuf("record omitted protection-info tag"))?,
    )
    .map_err(|_| Error::Protobuf("protection-info tag is not UTF-8"))?
    .to_owned();
    Ok(RecordMetadata {
        dataset,
        zone: zone.into(),
        record_name: name,
        record_type,
        etag,
        protection_info_tag: tag,
    })
}

fn encrypted_field(record: &Message, wanted: &str) -> Result<Vec<u8>> {
    for field in record.values(7) {
        let Value::Bytes(field) = field else { continue };
        let field = Message::parse(field)?;
        let Some(identifier) = field.first_bytes(1) else {
            continue;
        };
        if identifier_name(identifier, false)? != wanted {
            continue;
        }
        let value = Message::parse(
            field
                .first_bytes(2)
                .ok_or(Error::Protobuf("record field omitted value"))?,
        )?;
        if value.first_varint(13) != Some(1) {
            return Err(Error::Unsupported("record field is not encrypted bytes"));
        }
        let blob = value
            .first_bytes(2)
            .ok_or(Error::Protobuf("encrypted field omitted bytes"))?
            .to_vec();
        return Ok(blob);
    }
    Err(Error::Fixture(format!("field {wanted:?} was not found")))
}

fn replace_encrypted_field(record: &mut Message, wanted: &str, blob: &[u8]) -> Result<()> {
    for outer in &mut record.fields {
        if outer.number != 7 {
            continue;
        }
        let Value::Bytes(field_bytes) = &outer.value else {
            continue;
        };
        let mut field = Message::parse(field_bytes)?;
        let Some(identifier) = field.first_bytes(1) else {
            continue;
        };
        if identifier_name(identifier, false)? != wanted {
            continue;
        }
        let mut value = Message::parse(
            field
                .first_bytes(2)
                .ok_or(Error::Protobuf("record field omitted value"))?,
        )?;
        value.set_varint(1, 20);
        if !value.replace_first_bytes(2, blob) {
            return Err(Error::Protobuf("encrypted field omitted bytes"));
        }
        value.set_varint(13, 1);
        if !field.replace_first_bytes(2, &value.encode()) {
            return Err(Error::Protobuf("record field omitted value"));
        }
        let encoded = field.encode();
        let mut raw = Vec::new();
        wire::encode_bytes(7, &encoded, &mut raw);
        outer.value = Value::Bytes(encoded);
        outer.raw = raw;
        return Ok(());
    }
    Err(Error::Fixture(format!("field {wanted:?} was not found")))
}

fn validate_changed_record_field(
    before: &wire::Field,
    after: &wire::Field,
    wanted: &str,
) -> Result<()> {
    let (Value::Bytes(before), Value::Bytes(after)) = (&before.value, &after.value) else {
        return Err(Error::Integrity);
    };
    let before = Message::parse(before)?;
    let after = Message::parse(after)?;
    if before.fields.len() != after.fields.len()
        || before.first_bytes(1) != after.first_bytes(1)
        || before
            .first_bytes(1)
            .map(|identifier| identifier_name(identifier, false))
            .transpose()?
            .as_deref()
            != Some(wanted)
    {
        return Err(Error::Integrity);
    }
    for (before, after) in before.fields.iter().zip(&after.fields) {
        if before.number != 2 && before.raw != after.raw {
            return Err(Error::Integrity);
        }
    }
    let before_value = Message::parse(
        before
            .first_bytes(2)
            .ok_or(Error::Protobuf("record field omitted value"))?,
    )?;
    let after_value = Message::parse(
        after
            .first_bytes(2)
            .ok_or(Error::Protobuf("record field omitted value"))?,
    )?;
    if before_value.fields.len() != after_value.fields.len() {
        return Err(Error::Integrity);
    }
    for (before, after) in before_value.fields.iter().zip(&after_value.fields) {
        if before.number != 2 && before.raw != after.raw {
            return Err(Error::Integrity);
        }
    }
    if before_value.first_bytes(2) == after_value.first_bytes(2) {
        return Err(Error::Integrity);
    }
    Ok(())
}

fn encode_ckdp_string(value: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    wire::encode_bytes(6, value.as_bytes(), &mut encoded);
    encoded
}

fn detect_string_codec(plaintext: &[u8]) -> Result<PlaintextCodec> {
    if let Ok(message) = Message::parse(plaintext)
        && let Some(value) = message.first_bytes(6)
        && message.fields.len() == 1
        && std::str::from_utf8(value).is_ok()
    {
        return Ok(PlaintextCodec::CkdpString);
    }
    if std::str::from_utf8(plaintext).is_ok() {
        return Ok(PlaintextCodec::Utf8);
    }
    Err(Error::Unsupported(
        "the existing field is not a recognized string encoding",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ckdp_string_is_a_field_six_value() {
        let encoded = encode_ckdp_string("Safari");
        let parsed = Message::parse(&encoded).unwrap();
        assert_eq!(parsed.first_bytes(6), Some(b"Safari".as_slice()));
    }
}
