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
        if self.format != "icloud-safari-prepared-field-update-v1"
            || hex::encode(Sha256::digest(source)) != self.original_record_sha256
        {
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
        encrypted_field(&original, &self.field_name)?;
        encrypted_field(&changed, &self.field_name)?;
        Ok(())
    }

    /// Bind a post-save record to the exact encrypted field that was submitted.
    /// A changed etag alone does not prove that the requested edit was stored.
    pub fn validate_applied_record(&self, record: &[u8]) -> Result<()> {
        let updated = STANDARD
            .decode(&self.updated_record_base64)
            .map_err(|_| Error::Fixture("prepared record is not valid base64".into()))?;
        if hex::encode(Sha256::digest(&updated)) != self.updated_record_sha256 {
            return Err(Error::Integrity);
        }
        let expected = Message::parse(&updated)?;
        let current = Message::parse(record)?;
        let etag = current.first_bytes(1).ok_or(Error::Integrity)?;
        if etag.is_empty()
            || etag == self.metadata.etag.as_bytes()
            || current.values(1).count() != 1
            || current.values(2).count() != 1
            || current.values(3).count() != 1
            || current.first_bytes(2) != expected.first_bytes(2)
            || current.first_bytes(3) != expected.first_bytes(3)
            || encrypted_field(&current, &self.field_name)?
                != encrypted_field(&expected, &self.field_name)?
        {
            return Err(Error::Integrity);
        }
        Ok(())
    }
}

impl PreparedDelete {
    /// Bind every destructive target and concurrency precondition to the fresh
    /// source. Serialized identifiers must never independently select a victim.
    pub fn validate_against_source(&self, source: &[u8]) -> Result<()> {
        if self.format != "icloud-safari-prepared-delete-v1"
            || hex::encode(Sha256::digest(source)) != self.source_record_sha256
        {
            return Err(Error::Integrity);
        }
        let record = Message::parse(source)?;
        let identifier = STANDARD
            .decode(&self.record_identifier_base64)
            .map_err(|_| Error::Fixture("prepared identifier is not valid base64".into()))?;
        if metadata(self.metadata.dataset, &self.metadata.zone, &record)? != self.metadata
            || record.values(2).count() != 1
            || record.first_bytes(2) != Some(identifier.as_slice())
        {
            return Err(Error::Integrity);
        }
        Ok(())
    }

    /// Encode Apple's `CKDPRecordDeleteRequest` with the fetched etag so the
    /// server can reject a stale delete.
    pub fn encode_record_delete_request(&self) -> Result<Vec<u8>> {
        let identifier = STANDARD
            .decode(&self.record_identifier_base64)
            .map_err(|_| Error::Fixture("prepared identifier is not valid base64".into()))?;
        Message::parse(&identifier)?;
        if identifier_name(&identifier, true)? != self.metadata.record_name {
            return Err(Error::Integrity);
        }
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

    /// Prepare a new `BookmarkLeaf`. An existing leaf only supplies the wire
    /// encoding of each field; every value is set explicitly (see
    /// [`bookmark_leaf_field`]). Leaves with fields outside the known schema
    /// are not used as templates, and the create is refused if none is left.
    pub fn prepare_bookmark_create(&self, value: NewBookmark<'_>) -> Result<PreparedCreate> {
        if value.title.is_empty() || value.url.is_empty() {
            return Err(Error::Fixture(
                "bookmark title and URL must not be empty".into(),
            ));
        }
        let parent = value.parent_id.unwrap_or(TOP_BOOKMARK);
        let new = NewLeafValues {
            title: value.title.as_bytes().to_vec(),
            url: value.url.as_bytes().to_vec(),
            date_added: keyed_date_now()?,
            parent: parent.to_owned(),
            position: encode_position(
                next_sort_value(&self.read_dataset(Dataset::Bookmarks)?, parent)?,
                &uuid::Uuid::new_v4().to_string().to_uppercase(),
            )?,
            device_identifier: writer_device_identifier(&self.root)?,
        };
        self.prepare_create(
            Dataset::Bookmarks,
            "BookmarkLeaf",
            BOOKMARK_LEAF_REQUIRED,
            &|name| bookmark_leaf_field(name, &new),
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
        let title = keyed_string(value.title)?;
        let url = keyed_string(value.url)?;
        let date = ckdp_date_now();
        // Tabs still copy every other template field, Position included.
        // Only bookmarks have an explicit schema so far.
        self.prepare_create(
            Dataset::Tabs,
            "CloudTab",
            &["Title", "URL", "DateLastViewed", "OwningDevice"],
            &|name| {
                Some(match name {
                    "Title" => NewField::Encrypted(title.clone()),
                    "URL" => NewField::Encrypted(url.clone()),
                    "DateLastViewed" => NewField::Encrypted(date.clone()),
                    "OwningDevice" => NewField::StringOrReference(owner.clone()),
                    _ => NewField::Keep { value_type: None },
                })
            },
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

    /// Build a new record from the first `record_type` record whose fields
    /// all have a [`NewField`] plan and include `required`. `plan` returns
    /// `None` for a field it does not know, which disqualifies that template.
    fn prepare_create(
        &self,
        dataset: Dataset,
        record_type: &str,
        required: &[&str],
        plan: &dyn Fn(&str) -> Option<NewField>,
    ) -> Result<PreparedCreate> {
        let stored = self.read_dataset(dataset)?;
        let mut objects = Vec::new();
        let mut template = None;
        let mut candidates = 0;
        let mut zone_tag = None;
        for page in &stored.pages {
            let raw = decode_page(page)?;
            objects.extend(extract_objects(&raw)?);
            zone_tag = zone_tag.or_else(|| zone_protection_tag(&raw).ok());
            if template.is_none() {
                for (_, record) in find_records_of_type(&raw, record_type)? {
                    candidates += 1;
                    let parsed = Message::parse(&record)?;
                    if template_fits(&parsed, required, plan)? {
                        template = Some(parsed);
                        break;
                    }
                }
            }
        }
        let template = template.ok_or_else(|| {
            Error::Fixture(if candidates == 0 {
                format!("no {record_type} record is available as a schema template")
            } else {
                format!(
                    "none of the {candidates} {record_type} records has a recognized field set; \
                     refusing to create a record from an unknown schema"
                )
            })
        })?;
        let mut encrypted_replacements = BTreeMap::new();
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
            let value_bytes = field
                .first_bytes(2)
                .ok_or(Error::Protobuf("record field omitted value"))?
                .to_vec();
            let action = plan(&name).ok_or(Error::Integrity)?;
            let replaced_value = match &action {
                NewField::Omit => continue,
                NewField::StringOrReference(replacement) => Some(
                    replace_string_or_reference_value(&value_bytes, replacement)?,
                ),
                NewField::Plain { value, .. } => Some(value.clone()),
                NewField::FreshIdentityHash if !is_encrypted_value(&value_bytes)? => {
                    let value = Message::parse(&value_bytes)?;
                    let old = value
                        .first_bytes(2)
                        .ok_or(Error::Protobuf("bytes field omitted value"))?;
                    Some(ck_value_bytes(&fresh_identity_hash(old)))
                }
                _ => None,
            };
            if let Some(replacement) = replaced_value {
                if !field.replace_first_bytes(2, &replacement) {
                    return Err(Error::Protobuf("record field omitted value"));
                }
                wire::encode_bytes(7, &field.encode(), &mut output);
                continue;
            }
            let value = Message::parse(&value_bytes)?;
            if is_encrypted_value(&value_bytes)? {
                let old_blob = value
                    .first_bytes(2)
                    .ok_or(Error::Protobuf("encrypted field omitted bytes"))?;
                let (old_plaintext, mode) = graph
                    .decrypt_field_with_mode(&stored.zone, &template_name, &name, old_blob)?
                    .ok_or(Error::Integrity)?;
                let plaintext = match action {
                    NewField::Encrypted(replacement) => {
                        encrypted_replacements.insert(name.clone(), replacement.clone());
                        replacement
                    }
                    NewField::FreshIdentityHash => fresh_identity_hash(&old_plaintext),
                    _ => old_plaintext,
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
    Ok(find_records_of_type(response, wanted_type)?
        .into_iter()
        .next())
}

/// Every `(record name, record bytes)` of one record type, in response order.
fn find_records_of_type(response: &[u8], wanted_type: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let response = Message::parse(response)?;
    let mut found = Vec::new();
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
            found.push((name, record.to_vec()));
        }
    }
    Ok(found)
}

/// How one field of a new record is produced from the template's field.
#[derive(Clone, Debug)]
enum NewField {
    /// Encrypt this plaintext under the new record's key. The template's field
    /// must be encrypted.
    Encrypted(Vec<u8>),
    /// Point a string or reference value at this record name.
    StringOrReference(String),
    /// Replace the whole CloudKit value with `value`. The template's field must
    /// have the same CloudKit value type.
    Plain { value_type: u64, value: Vec<u8> },
    /// Randomize all but the trailing four bytes of the template's value.
    FreshIdentityHash,
    /// Copy the template's value. `Some(type)` requires that value type.
    Keep { value_type: Option<u64> },
    /// Leave the field out of the new record.
    Omit,
}

/// CloudKit `RecordFieldValue` types observed in Safari records.
const CK_BYTES: u64 = 1;
const CK_STRING: u64 = 3;
const CK_REFERENCE: u64 = 5;
const CK_INT64: u64 = 7;

const TOP_BOOKMARK: &str = "com.apple.Safari.TopBookmark";

/// Fields a `BookmarkLeaf` template must have. Safari groups fields that
/// change together and stamps each group with `<Group>_deviceIdentifier` (the
/// last writer) and `<Group>_generation` (a per-group change counter).
const BOOKMARK_LEAF_GROUPS: &[&str] = &[
    "DateAdded",
    "MinimumAPIVersion",
    "ParentAndPosition",
    "TitleURLAndIdentityHash",
];
const BOOKMARK_LEAF_REQUIRED: &[&str] = &[
    "Title",
    "URL",
    "DateAdded",
    "ParentFolder",
    "IdentityHash",
    "Position",
    "MinimumAPIVersion",
    "DateAdded_deviceIdentifier",
    "DateAdded_generation",
    "MinimumAPIVersion_deviceIdentifier",
    "MinimumAPIVersion_generation",
    "ParentAndPosition_deviceIdentifier",
    "ParentAndPosition_generation",
    "TitleURLAndIdentityHash_deviceIdentifier",
    "TitleURLAndIdentityHash_generation",
];
/// Optional preview fields. They describe the template's page, so a new
/// bookmark leaves out the text and its group stamps together.
const BOOKMARK_LEAF_OMITTED: &[&str] = &[
    "PreviewText",
    "PreviewTextAndHasUserDefinedPreviewText_deviceIdentifier",
    "PreviewTextAndHasUserDefinedPreviewText_generation",
];

struct NewLeafValues {
    title: Vec<u8>,
    url: Vec<u8>,
    date_added: Vec<u8>,
    parent: String,
    position: Vec<u8>,
    device_identifier: String,
}

/// The value of each known `BookmarkLeaf` field in a new bookmark; `None` for
/// any other field, so a template carrying one (a Reading List item, say, or
/// a newer schema) is never cloned.
fn bookmark_leaf_field(name: &str, new: &NewLeafValues) -> Option<NewField> {
    if BOOKMARK_LEAF_OMITTED.contains(&name) {
        return Some(NewField::Omit);
    }
    let group_stamp = |suffix: &str| {
        name.strip_suffix(suffix)
            .is_some_and(|group| BOOKMARK_LEAF_GROUPS.contains(&group))
    };
    Some(match name {
        "Title" => NewField::Encrypted(new.title.clone()),
        "URL" => NewField::Encrypted(new.url.clone()),
        "DateAdded" => NewField::Encrypted(new.date_added.clone()),
        "ParentFolder" => NewField::StringOrReference(new.parent.clone()),
        "IdentityHash" => NewField::FreshIdentityHash,
        "Position" => NewField::Plain {
            value_type: CK_BYTES,
            value: ck_value_bytes(&new.position),
        },
        "MinimumAPIVersion" => NewField::Keep {
            value_type: Some(CK_INT64),
        },
        _ if group_stamp("_deviceIdentifier") => NewField::Plain {
            value_type: CK_STRING,
            value: ck_value_string(&new.device_identifier),
        },
        _ if group_stamp("_generation") => NewField::Plain {
            value_type: CK_INT64,
            value: ck_value_int(1),
        },
        _ => return None,
    })
}

/// Whether `record` can serve as the template for `plan`: every field has a
/// plan whose value-type expectation it meets, no field repeats, and all
/// `required` fields are present.
fn template_fits(
    record: &Message,
    required: &[&str],
    plan: &dyn Fn(&str) -> Option<NewField>,
) -> Result<bool> {
    let mut seen = std::collections::BTreeSet::new();
    for raw_field in record.values(7) {
        let Value::Bytes(raw_field) = raw_field else {
            continue;
        };
        let field = Message::parse(raw_field)?;
        let name = identifier_name(
            field
                .first_bytes(1)
                .ok_or(Error::Protobuf("record field omitted identifier"))?,
            false,
        )?;
        let Some(value_bytes) = field.first_bytes(2) else {
            return Ok(false);
        };
        let value = Message::parse(value_bytes)?;
        let value_type = value.first_varint(1);
        let encrypted = is_encrypted_value(value_bytes)?;
        let fits = match plan(&name) {
            None => false,
            Some(NewField::Omit) => true,
            Some(NewField::Encrypted(_)) => encrypted,
            Some(NewField::StringOrReference(_)) => {
                matches!(value_type, Some(CK_STRING | CK_REFERENCE))
            }
            Some(NewField::Plain { value_type: t, .. }) => !encrypted && value_type == Some(t),
            Some(NewField::FreshIdentityHash) => {
                encrypted
                    || (value_type == Some(CK_BYTES)
                        && value.first_bytes(2).is_some_and(|v| v.len() > 4))
            }
            Some(NewField::Keep { value_type: t }) => {
                t.is_none_or(|t| !encrypted && value_type == Some(t))
            }
        };
        if !fits || !seen.insert(name) {
            return Ok(false);
        }
    }
    Ok(required.iter().all(|name| seen.contains(*name)))
}

fn is_encrypted_value(value: &[u8]) -> Result<bool> {
    let value = Message::parse(value)?;
    Ok(value.first_varint(13) == Some(1) && value.first_bytes(2).is_some())
}

/// The sort value for a bookmark appended to `parent`: 1000 past the largest
/// sort value among its current children (1000 if it has none). Safari's own
/// appends were observed 1000 apart. A child `Position` that cannot be read
/// refuses the create instead of guessing an order.
fn next_sort_value(stored: &StoredDataset, parent: &str) -> Result<i64> {
    let mut largest: Option<i64> = None;
    for page in &stored.pages {
        let raw = decode_page(page)?;
        for record_type in ["BookmarkLeaf", "BookmarkList"] {
            for (_, record) in find_records_of_type(&raw, record_type)? {
                let record = Message::parse(&record)?;
                let fields = plain_fields(&record)?;
                if fields
                    .get("ParentFolder")
                    .map(|v| parent_name(v))
                    .transpose()?
                    .as_deref()
                    != Some(parent)
                {
                    continue;
                }
                let Some(position) = fields.get("Position") else {
                    continue;
                };
                let position = Message::parse(position)?;
                let bytes = position
                    .first_bytes(2)
                    .ok_or(Error::Unsupported("bookmark Position is not plain bytes"))?;
                for value in sort_values(bytes)? {
                    largest = Some(largest.map_or(value, |l| l.max(value)));
                }
            }
        }
    }
    largest
        .unwrap_or(0)
        .checked_add(1000)
        .ok_or(Error::Unsupported("bookmark sort value overflow"))
}

/// Unencrypted field values of a record, by field name.
fn plain_fields(record: &Message) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut fields = BTreeMap::new();
    for raw_field in record.values(7) {
        let Value::Bytes(raw_field) = raw_field else {
            continue;
        };
        let field = Message::parse(raw_field)?;
        let (Some(identifier), Some(value)) = (field.first_bytes(1), field.first_bytes(2)) else {
            continue;
        };
        if !is_encrypted_value(value)? {
            fields.insert(identifier_name(identifier, false)?, value.to_vec());
        }
    }
    Ok(fields)
}

/// The record name a `ParentFolder` value points at (a reference, or a plain
/// string in older records).
fn parent_name(value: &[u8]) -> Result<String> {
    let value = Message::parse(value)?;
    match value.first_varint(1) {
        Some(CK_REFERENCE) => {
            let reference = Message::parse(
                value
                    .first_bytes(9)
                    .ok_or(Error::Protobuf("reference value omitted reference"))?,
            )?;
            identifier_name(
                reference
                    .first_bytes(2)
                    .ok_or(Error::Protobuf("reference omitted record identifier"))?,
                true,
            )
        }
        _ => std::str::from_utf8(value.first_bytes(7).ok_or(Error::Protobuf(
            "ParentFolder is neither reference nor string",
        ))?)
        .map(str::to_owned)
        .map_err(|_| Error::Protobuf("ParentFolder string is not UTF-8")),
    }
}

/// Safari's `Position` value: zlib-compressed JSON of the form
/// `{"default":{"sortValues":[{"changeID":0,"sortValue":946,"deviceIdentifier":"…"}]}}`.
/// Folders at the top level carry `{}`, which has no sort values.
fn sort_values(position: &[u8]) -> Result<Vec<i64>> {
    use std::io::Read as _;
    let mut json = Vec::new();
    flate2::read::ZlibDecoder::new(position)
        .read_to_end(&mut json)
        .map_err(|_| Error::Unsupported("bookmark Position is not zlib data"))?;
    let json: serde_json::Value = serde_json::from_slice(&json)?;
    let Some(entries) = json.pointer("/default/sortValues") else {
        return if json.as_object().is_some_and(|o| o.is_empty()) {
            Ok(Vec::new())
        } else {
            Err(Error::Unsupported("bookmark Position has an unknown shape"))
        };
    };
    entries
        .as_array()
        .ok_or(Error::Unsupported("bookmark sortValues is not an array"))?
        .iter()
        .map(|entry| {
            let value = entry
                .get("sortValue")
                .and_then(serde_json::Value::as_f64)
                .ok_or(Error::Unsupported("bookmark sortValue is not a number"))?;
            if !value.is_finite() || value.abs() > 1e15 {
                return Err(Error::Unsupported("bookmark sortValue is out of range"));
            }
            Ok(value.ceil() as i64)
        })
        .collect()
}

/// Encode a `Position` with one sort value, in the same shape Safari uses.
/// The sort entry's `deviceIdentifier` differs per bookmark in Safari's own
/// records (and from the record's group stamps), so each entry gets a new one.
fn encode_position(sort_value: i64, entry_identifier: &str) -> Result<Vec<u8>> {
    use std::io::Write as _;
    // Written by hand to keep Safari's key order (serde_json sorts keys).
    let json = format!(
        r#"{{"default":{{"sortValues":[{{"changeID":0,"sortValue":{sort_value},"deviceIdentifier":{}}}]}}}}"#,
        serde_json::to_string(entry_identifier)?
    );
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(json.as_bytes())?;
    Ok(encoder.finish()?)
}

#[derive(Serialize, Deserialize)]
struct WriterDevice {
    device_identifier: String,
}

const WRITER_DEVICE_FILE: &str = "safari-writer-device.json";

/// This writer's identifier for Safari's per-group `_deviceIdentifier`
/// stamps: created once per state directory and reused, so the bridge shows
/// up as one consistent device instead of borrowing another device's id.
fn writer_device_identifier(root: &Path) -> Result<String> {
    let store = crate::state::FileStateStore::new(root);
    if root.join(WRITER_DEVICE_FILE).exists() {
        let device: WriterDevice = store.read_json(WRITER_DEVICE_FILE)?;
        if uuid::Uuid::parse_str(&device.device_identifier).is_err() {
            return Err(Error::Fixture(format!(
                "{WRITER_DEVICE_FILE} does not hold a UUID"
            )));
        }
        return Ok(device.device_identifier);
    }
    let device = WriterDevice {
        device_identifier: uuid::Uuid::new_v4().to_string().to_uppercase(),
    };
    store.write_json(WRITER_DEVICE_FILE, &device)?;
    Ok(device.device_identifier)
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
    wire::encode_uint(1, CK_STRING, &mut output);
    wire::encode_string(7, value, &mut output);
    output
}

fn ck_value_bytes(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    wire::encode_uint(1, CK_BYTES, &mut output);
    wire::encode_bytes(2, value, &mut output);
    output
}

fn ck_value_int(value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    wire::encode_uint(1, CK_INT64, &mut output);
    wire::encode_uint(4, value, &mut output);
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
    let mut result = None;
    for field in record.values(7) {
        let Value::Bytes(field) = field else { continue };
        let field = Message::parse(field)?;
        let Some(identifier) = field.first_bytes(1) else {
            continue;
        };
        if identifier_name(identifier, false)? != wanted {
            continue;
        }
        if result.is_some() || field.values(1).count() != 1 || field.values(2).count() != 1 {
            return Err(Error::Integrity);
        }
        let value = Message::parse(
            field
                .first_bytes(2)
                .ok_or(Error::Protobuf("record field omitted value"))?,
        )?;
        if value.first_varint(13) != Some(1)
            || value.values(13).count() != 1
            || value.values(2).count() != 1
        {
            return Err(Error::Unsupported("record field is not encrypted bytes"));
        }
        let blob = value
            .first_bytes(2)
            .ok_or(Error::Protobuf("encrypted field omitted bytes"))?
            .to_vec();
        result = Some(blob);
    }
    result.ok_or_else(|| Error::Fixture(format!("field {wanted:?} was not found")))
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

    fn name_message(name: &str) -> Vec<u8> {
        let mut output = Vec::new();
        wire::encode_string(1, name, &mut output);
        output
    }

    fn record_identifier(name: &str) -> Vec<u8> {
        let mut output = Vec::new();
        wire::encode_bytes(1, &name_message(name), &mut output);
        output
    }

    fn reference(parent: &str) -> Vec<u8> {
        let mut reference = Vec::new();
        wire::encode_uint(1, 2, &mut reference);
        wire::encode_bytes(2, &record_identifier(parent), &mut reference);
        let mut value = Vec::new();
        wire::encode_uint(1, CK_REFERENCE, &mut value);
        wire::encode_bytes(9, &reference, &mut value);
        value
    }

    fn encrypted(blob: &[u8]) -> Vec<u8> {
        let mut value = Vec::new();
        wire::encode_uint(1, 20, &mut value);
        wire::encode_bytes(2, blob, &mut value);
        wire::encode_uint(13, 1, &mut value);
        value
    }

    fn record(record_type: &str, name: &str, fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut output = Vec::new();
        wire::encode_bytes(2, &record_identifier(name), &mut output);
        wire::encode_bytes(3, &name_message(record_type), &mut output);
        for (field_name, value) in fields {
            let mut field = Vec::new();
            wire::encode_bytes(1, &name_message(field_name), &mut field);
            wire::encode_bytes(2, value, &mut field);
            wire::encode_bytes(7, &field, &mut output);
        }
        output
    }

    /// A leaf shaped like the ones Safari wrote in the captured fixtures.
    fn safari_leaf(name: &str, parent: &str, sort_value: i64) -> Vec<(&'static str, Vec<u8>)> {
        let mut fields = vec![
            ("Title", encrypted(b"t")),
            ("URL", encrypted(b"u")),
            ("DateAdded", encrypted(b"d")),
            ("ParentFolder", reference(parent)),
            ("IdentityHash", ck_value_bytes(&[7; 36])),
            (
                "Position",
                ck_value_bytes(&encode_position(sort_value, name).unwrap()),
            ),
            ("MinimumAPIVersion", ck_value_int(1)),
        ];
        for group in BOOKMARK_LEAF_GROUPS {
            let stamp: &'static str = Box::leak(format!("{group}_deviceIdentifier").into());
            let generation: &'static str = Box::leak(format!("{group}_generation").into());
            fields.push((
                stamp,
                ck_value_string("48C0AB8B-8BEE-4BE1-AD9E-7AF43E40EB55"),
            ));
            fields.push((generation, ck_value_int(3)));
        }
        fields
    }

    fn leaf_values() -> NewLeafValues {
        NewLeafValues {
            title: b"T".to_vec(),
            url: b"https://example.invalid/".to_vec(),
            date_added: b"D".to_vec(),
            parent: "Folder".into(),
            position: encode_position(2000, "E").unwrap(),
            device_identifier: "WRITER".into(),
        }
    }

    fn fits(fields: &[(&str, Vec<u8>)]) -> bool {
        let values = leaf_values();
        let parsed = Message::parse(&record("BookmarkLeaf", "R", fields)).unwrap();
        template_fits(&parsed, BOOKMARK_LEAF_REQUIRED, &|name| {
            bookmark_leaf_field(name, &values)
        })
        .unwrap()
    }

    #[test]
    fn safari_shaped_leaf_is_an_acceptable_template() {
        let mut fields = safari_leaf("A", "Folder", 1000);
        assert!(fits(&fields));
        fields.push(("PreviewText", encrypted(b"p")));
        fields.push((
            "PreviewTextAndHasUserDefinedPreviewText_deviceIdentifier",
            ck_value_string("X"),
        ));
        fields.push((
            "PreviewTextAndHasUserDefinedPreviewText_generation",
            ck_value_int(1),
        ));
        assert!(fits(&fields));
    }

    #[test]
    fn leaf_with_unknown_missing_or_mistyped_fields_is_not_a_template() {
        let base = safari_leaf("A", "Folder", 1000);

        let mut unknown = base.clone();
        unknown.push(("ReadingListDateLastViewed", encrypted(b"x")));
        assert!(!fits(&unknown), "unknown field");

        let mut unknown_group = base.clone();
        unknown_group.push(("SomethingNew_generation", ck_value_int(1)));
        assert!(!fits(&unknown_group), "stamp for an unknown group");

        let missing: Vec<_> = base
            .iter()
            .filter(|(name, _)| *name != "Position")
            .cloned()
            .collect();
        assert!(!fits(&missing), "missing Position");

        let mut mistyped = base.clone();
        for field in &mut mistyped {
            if field.0 == "Position" {
                field.1 = encrypted(b"p");
            }
        }
        assert!(!fits(&mistyped), "encrypted Position");

        let mut plain_title = base.clone();
        for field in &mut plain_title {
            if field.0 == "Title" {
                field.1 = ck_value_string("t");
            }
        }
        assert!(!fits(&plain_title), "unencrypted Title");

        let mut duplicate = base.clone();
        duplicate.push(("Position", ck_value_bytes(b"x")));
        assert!(!fits(&duplicate), "repeated field");
    }

    #[test]
    fn leaf_field_plan_sets_every_value_explicitly() {
        let values = leaf_values();
        let plan = |name| bookmark_leaf_field(name, &values);
        assert!(matches!(plan("PreviewText"), Some(NewField::Omit)));
        assert!(matches!(
            plan("IdentityHash"),
            Some(NewField::FreshIdentityHash)
        ));
        assert!(matches!(
            plan("MinimumAPIVersion"),
            Some(NewField::Keep {
                value_type: Some(CK_INT64)
            })
        ));
        let Some(NewField::Plain { value, .. }) = plan("ParentAndPosition_deviceIdentifier") else {
            panic!("device stamp is not replaced");
        };
        assert_eq!(value, ck_value_string("WRITER"));
        let Some(NewField::Plain { value, .. }) = plan("TitleURLAndIdentityHash_generation") else {
            panic!("generation is not replaced");
        };
        assert_eq!(value, ck_value_int(1));
        let Some(NewField::Plain { value, .. }) = plan("Position") else {
            panic!("Position is not replaced");
        };
        assert_eq!(value, ck_value_bytes(&values.position));
        assert!(plan("Unknown").is_none());
    }

    #[test]
    fn position_round_trips_in_safaris_shape() {
        let encoded = encode_position(2946, "ENTRY").unwrap();
        assert_eq!(&encoded[..2], &[0x78, 0xda]);
        let mut json = String::new();
        std::io::Read::read_to_string(
            &mut flate2::read::ZlibDecoder::new(encoded.as_slice()),
            &mut json,
        )
        .unwrap();
        assert_eq!(
            json,
            r#"{"default":{"sortValues":[{"changeID":0,"sortValue":2946,"deviceIdentifier":"ENTRY"}]}}"#
        );
        assert_eq!(sort_values(&encoded).unwrap(), vec![2946]);
    }

    #[test]
    fn empty_position_has_no_sort_values_and_garbage_is_refused() {
        let mut empty = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        std::io::Write::write_all(&mut empty, b"{}").unwrap();
        assert!(sort_values(&empty.finish().unwrap()).unwrap().is_empty());
        assert!(sort_values(b"not zlib").is_err());
        let mut odd = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        std::io::Write::write_all(&mut odd, br#"{"other":1}"#).unwrap();
        assert!(sort_values(&odd.finish().unwrap()).is_err());
    }

    fn dataset(records: &[Vec<u8>]) -> StoredDataset {
        let mut response = Vec::new();
        for record in records {
            let mut change = Vec::new();
            wire::encode_bytes(5, record, &mut change);
            wire::encode_bytes(1, &change, &mut response);
        }
        StoredDataset {
            zone: "Bookmarks".into(),
            pages: vec![StoredPage {
                raw_response_base64: STANDARD.encode(response),
            }],
        }
    }

    #[test]
    fn next_sort_value_appends_after_the_parents_last_child() {
        let stored = dataset(&[
            record("BookmarkLeaf", "A", &safari_leaf("A", "Folder", 946)),
            record("BookmarkLeaf", "B", &safari_leaf("B", "Folder", 1946)),
            record("BookmarkLeaf", "C", &safari_leaf("C", "Other", 90_000)),
        ]);
        assert_eq!(next_sort_value(&stored, "Folder").unwrap(), 2946);
        assert_eq!(next_sort_value(&stored, "Other").unwrap(), 91_000);
        assert_eq!(next_sort_value(&stored, "Empty").unwrap(), 1000);
    }

    #[test]
    fn next_sort_value_refuses_an_unreadable_sibling_position() {
        let mut broken = safari_leaf("A", "Folder", 946);
        for field in &mut broken {
            if field.0 == "Position" {
                field.1 = ck_value_bytes(b"garbage");
            }
        }
        let stored = dataset(&[record("BookmarkLeaf", "A", &broken)]);
        assert!(next_sort_value(&stored, "Folder").is_err());
        assert_eq!(next_sort_value(&stored, "Elsewhere").unwrap(), 1000);
    }

    #[test]
    fn writer_device_identifier_is_created_once_and_reused() {
        let root = tempfile::tempdir().unwrap();
        let first = writer_device_identifier(root.path()).unwrap();
        assert!(uuid::Uuid::parse_str(&first).is_ok());
        assert_eq!(writer_device_identifier(root.path()).unwrap(), first);
    }
}
