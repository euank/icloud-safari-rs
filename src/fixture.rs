//! Offline fixture reader and conformance reporting.

use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, TimeZone, Utc};
use flate2::read::ZlibDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    Error, Result,
    model::{
        Bookmark, Dataset, DecodedValue, HistoryRecord, RawRecord, SafariSnapshot, Tab, TabDevice,
    },
    pcs::{Identity, KeyGraph, extract_objects},
};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatasetReport {
    pub pages: usize,
    pub records: usize,
    pub pcs_objects: usize,
    pub unwrapped_objects: usize,
    pub authenticated_fields: usize,
    pub codecs: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptionReport {
    pub pcs_objects: usize,
    pub unwrapped_objects: usize,
    pub authenticated_fields: usize,
    pub codecs: BTreeMap<String, usize>,
    pub datasets: BTreeMap<String, DatasetReport>,
}

#[derive(Clone, Debug)]
pub struct OfflineReader {
    root: PathBuf,
}

#[derive(Deserialize)]
struct FixturePage {
    raw_response_base64: String,
    records: Vec<FixtureRecord>,
}

#[derive(Deserialize)]
struct FixtureDataset {
    zone: String,
    pages: Vec<FixturePage>,
}

#[derive(Deserialize)]
struct FixtureRecord {
    name: String,
    record_type: String,
    fields: BTreeMap<String, serde_json::Value>,
}

impl OfflineReader {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if !root.is_dir() {
            return Err(Error::Fixture(format!(
                "fixture directory not found: {}",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn verify_hashes(&self) -> Result<()> {
        let expected_path = self.root.join("expected.json");
        if !expected_path.is_file() {
            return Ok(());
        }
        let expected: serde_json::Value = serde_json::from_slice(&fs::read(expected_path)?)?;
        let files = expected["files"]
            .as_object()
            .ok_or_else(|| Error::Fixture("expected.json has no files map".into()))?;
        for (relative, expected_hash) in files {
            let path = self.root.join(relative);
            let actual = Sha256::digest(fs::read(&path)?);
            let expected_hash = expected_hash
                .as_str()
                .ok_or_else(|| Error::Fixture("non-string fixture hash".into()))?;
            if hex::encode(actual) != expected_hash {
                return Err(Error::Fixture(format!("hash mismatch for {relative}")));
            }
        }
        Ok(())
    }

    pub fn decrypt(&self) -> Result<(SafariSnapshot, DecryptionReport)> {
        self.decrypt_datasets(&Dataset::ALL)
    }

    pub fn decrypt_datasets(
        &self,
        datasets: &[Dataset],
    ) -> Result<(SafariSnapshot, DecryptionReport)> {
        self.verify_hashes()?;
        let identities = self.load_identities()?;
        let mut snapshot = SafariSnapshot {
            format: "icloud-safari-export-v1".into(),
            exported_at: Utc::now(),
            ..SafariSnapshot::default()
        };
        let mut report = DecryptionReport::default();
        for &dataset in datasets {
            let path = self
                .root
                .join("safari-cloudkit")
                .join(format!("{}.json", dataset.as_str()));
            let fixture: FixtureDataset = serde_json::from_slice(&fs::read(path)?)?;
            let (records, dataset_report) = decrypt_dataset(&fixture, identities.clone())?;
            project_records(&mut snapshot, &records);
            snapshot.records.insert(dataset.as_str().into(), records);
            report.pcs_objects += dataset_report.pcs_objects;
            report.unwrapped_objects += dataset_report.unwrapped_objects;
            report.authenticated_fields += dataset_report.authenticated_fields;
            for (codec, count) in &dataset_report.codecs {
                *report.codecs.entry(codec.clone()).or_default() += count;
            }
            report
                .datasets
                .insert(dataset.as_str().into(), dataset_report);
        }
        Ok((snapshot, report))
    }

    pub fn verify_expected(&self) -> Result<DecryptionReport> {
        let (_, report) = self.decrypt()?;
        let expected: serde_json::Value =
            serde_json::from_slice(&fs::read(self.root.join("expected.json"))?)?;
        for (name, actual) in &report.datasets {
            let wanted = &expected["datasets"][name];
            for (field, value) in [
                ("pages", actual.pages),
                ("records", actual.records),
                ("pcs_objects", actual.pcs_objects),
                ("unwrapped_objects", actual.unwrapped_objects),
                ("authenticated_fields", actual.authenticated_fields),
            ] {
                if wanted[field].as_u64() != Some(value as u64) {
                    return Err(Error::Fixture(format!(
                        "{name}.{field} is {value}, which does not match expected.json"
                    )));
                }
            }
            let wanted_codecs: BTreeMap<String, usize> =
                serde_json::from_value(wanted["codecs"].clone())?;
            if actual.codecs != wanted_codecs {
                return Err(Error::Fixture(format!(
                    "{name}.codecs does not match expected.json"
                )));
            }
        }
        Ok(report)
    }

    fn load_identities(&self) -> Result<Vec<Identity>> {
        let mut entries: Vec<_> =
            fs::read_dir(self.root.join("pcs-identities"))?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.path());
        entries
            .into_iter()
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "der")
            })
            .map(|entry| Identity::from_der(&fs::read(entry.path())?))
            .collect()
    }
}

fn decrypt_dataset(
    fixture: &FixtureDataset,
    identities: Vec<Identity>,
) -> Result<(Vec<RawRecord>, DatasetReport)> {
    let mut objects = Vec::new();
    let mut raw_pages = Vec::new();
    for page in &fixture.pages {
        let raw = STANDARD
            .decode(&page.raw_response_base64)
            .map_err(|_| Error::Fixture("invalid base64 response".into()))?;
        objects.extend(extract_objects(&raw)?);
        raw_pages.push(raw);
    }
    let graph = KeyGraph::recover(&objects, identities)?;
    let mut report = DatasetReport {
        pages: fixture.pages.len(),
        records: fixture.pages.iter().map(|page| page.records.len()).sum(),
        pcs_objects: objects.len(),
        unwrapped_objects: graph.unwrapped,
        ..DatasetReport::default()
    };
    let mut records = Vec::new();
    for page in &fixture.pages {
        for record in &page.records {
            let mut fields = BTreeMap::new();
            for (name, raw_value) in &record.fields {
                let mut value = fixture_value(raw_value)?;
                if let DecodedValue::Bytes { base64 } = &value {
                    let bytes = STANDARD
                        .decode(base64)
                        .map_err(|_| Error::Fixture("invalid base64 field".into()))?;
                    if let Some(plaintext) = graph
                        .decrypt_field(&fixture.zone, &record.name, name, &bytes)
                        .map_err(|error| {
                            Error::Fixture(format!(
                                "failed to authenticate {}.{}: {error}",
                                record.name, name
                            ))
                        })?
                    {
                        let (decoded, codec) = decode_plaintext(&plaintext)?;
                        value = decoded;
                        report.authenticated_fields += 1;
                        *report.codecs.entry(codec.into()).or_default() += 1;
                    }
                }
                fields.insert(name.clone(), value);
            }
            records.push(RawRecord {
                name: record.name.clone(),
                record_type: record.record_type.clone(),
                fields,
                unknown_fields_base64: Vec::new(),
            });
        }
    }
    Ok((records, report))
}

fn fixture_value(value: &serde_json::Value) -> Result<DecodedValue> {
    match value {
        serde_json::Value::String(value) => Ok(DecodedValue::String {
            value: value.clone(),
        }),
        serde_json::Value::Number(value) => value
            .as_i64()
            .map(|value| DecodedValue::Integer { value })
            .ok_or_else(|| Error::Fixture("number is not an integer".into())),
        serde_json::Value::Object(object)
            if object.get("type").and_then(|v| v.as_str()) == Some("bytes") =>
        {
            let base64 = object
                .get("base64")
                .and_then(|value| value.as_str())
                .ok_or_else(|| Error::Fixture("bytes field has no base64 value".into()))?;
            Ok(DecodedValue::Bytes {
                base64: base64.into(),
            })
        }
        serde_json::Value::Object(object)
            if object.get("type").and_then(|v| v.as_str()) == Some("date") =>
        {
            let apple = object
                .get("unix_seconds")
                .and_then(|value| value.as_f64())
                .ok_or_else(|| Error::Fixture("date field has no numeric value".into()))?;
            Ok(DecodedValue::Date {
                value: apple_date(apple)?,
            })
        }
        _ => Err(Error::Fixture(
            "unsupported normalized fixture value".into(),
        )),
    }
}

fn apple_date(seconds: f64) -> Result<DateTime<Utc>> {
    let unix = seconds + 978_307_200.0;
    let whole = unix.floor() as i64;
    let nanos = ((unix - whole as f64) * 1_000_000_000.0).round() as u32;
    Utc.timestamp_opt(whole, nanos)
        .single()
        .ok_or_else(|| Error::Fixture("date is out of range".into()))
}

fn decode_plaintext(bytes: &[u8]) -> Result<(DecodedValue, &'static str)> {
    if bytes.first() == Some(&0x78) {
        let mut output = Vec::new();
        if ZlibDecoder::new(bytes).read_to_end(&mut output).is_ok()
            && output.starts_with(b"bplist00")
        {
            let plist = plist::Value::from_reader(Cursor::new(output))?;
            return Ok((semantic_plist(plist)?, "zlib-bplist"));
        }
    }
    if bytes.starts_with(b"bplist00") {
        let plist = plist::Value::from_reader(Cursor::new(bytes))?;
        return Ok((semantic_plist(plist)?, "bplist"));
    }
    if bytes.first() == Some(&0x32) {
        let mut offset = 1;
        let len = usize::try_from(crate::wire::read_varint(bytes, &mut offset)?)
            .map_err(|_| Error::Protobuf("CKDP string length overflow"))?;
        if offset.checked_add(len) == Some(bytes.len()) {
            let value = std::str::from_utf8(&bytes[offset..])
                .map_err(|_| Error::Fixture("CKDP string is not UTF-8".into()))?;
            return Ok((
                DecodedValue::String {
                    value: value.into(),
                },
                "ckdp-string",
            ));
        }
    }
    if bytes.len() == 11 && bytes[..3] == [0x2a, 0x09, 0x09] {
        let seconds = f64::from_le_bytes(bytes[3..].try_into().unwrap());
        return Ok((
            DecodedValue::Date {
                value: apple_date(seconds)?,
            },
            "ckdp-date",
        ));
    }
    if let Ok(value) = std::str::from_utf8(bytes)
        && value
            .chars()
            .all(|character| !character.is_control() || character.is_whitespace())
    {
        return Ok((
            DecodedValue::String {
                value: value.into(),
            },
            "utf-8",
        ));
    }
    Ok((
        DecodedValue::Bytes {
            base64: STANDARD.encode(bytes),
        },
        "bytes",
    ))
}

fn semantic_plist(value: plist::Value) -> Result<DecodedValue> {
    let value = resolve_archive(&value).unwrap_or(value);
    match value {
        plist::Value::String(value) => Ok(DecodedValue::String { value }),
        plist::Value::Real(value) => Ok(DecodedValue::Double { value }),
        plist::Value::Integer(value) => value
            .as_signed()
            .map(|value| DecodedValue::Integer { value })
            .ok_or_else(|| Error::Fixture("plist integer exceeds i64".into())),
        plist::Value::Data(value) => Ok(DecodedValue::Bytes {
            base64: STANDARD.encode(value),
        }),
        value => Ok(DecodedValue::Plist { value }),
    }
}

fn resolve_archive(value: &plist::Value) -> Option<plist::Value> {
    let archive = value.as_dictionary()?;
    let objects = archive.get("$objects")?.as_array()?;
    let top = archive.get("$top")?.as_dictionary()?;
    let root = top.get("root")?;
    resolve_value(root, objects, 0)
}

fn resolve_value(
    value: &plist::Value,
    objects: &[plist::Value],
    depth: usize,
) -> Option<plist::Value> {
    if depth > 64 {
        return None;
    }
    if let Some(uid) = value.as_uid() {
        return resolve_value(objects.get(uid.get() as usize)?, objects, depth + 1);
    }
    match value {
        plist::Value::Dictionary(dictionary) => {
            if let Some(string) = dictionary.get("NS.string") {
                return resolve_value(string, objects, depth + 1);
            }
            if let Some(data) = dictionary.get("NS.data") {
                return resolve_value(data, objects, depth + 1);
            }
            if let Some(time) = dictionary.get("NS.time").and_then(plist::Value::as_real) {
                return Some(plist::Value::String(apple_date(time).ok()?.to_rfc3339()));
            }
            if let Some(items) = dictionary.get("NS.objects") {
                return resolve_value(items, objects, depth + 1);
            }
            let mut result = plist::Dictionary::new();
            for (key, item) in dictionary {
                if key != "$class" {
                    result.insert(key.clone(), resolve_value(item, objects, depth + 1)?);
                }
            }
            Some(plist::Value::Dictionary(result))
        }
        plist::Value::Array(array) => Some(plist::Value::Array(
            array
                .iter()
                .map(|item| resolve_value(item, objects, depth + 1))
                .collect::<Option<_>>()?,
        )),
        value => Some(value.clone()),
    }
}

fn string_field(record: &RawRecord, name: &str) -> Option<String> {
    match record.fields.get(name)? {
        DecodedValue::String { value } => Some(value.clone()),
        _ => None,
    }
}

fn date_field(record: &RawRecord, name: &str) -> Option<DateTime<Utc>> {
    match record.fields.get(name)? {
        DecodedValue::Date { value } => Some(*value),
        DecodedValue::String { value } => value.parse().ok(),
        _ => None,
    }
}

fn project_records(snapshot: &mut SafariSnapshot, records: &[RawRecord]) {
    for record in records {
        match record.record_type.as_str() {
            "CloudTabDevice" => snapshot.devices.push(TabDevice {
                id: record.name.clone(),
                name: string_field(record, "DeviceName"),
                device_type: string_field(record, "DeviceTypeIdentifier"),
                last_modified: date_field(record, "LastModified"),
            }),
            "CloudTab" => snapshot.tabs.push(Tab {
                id: record.name.clone(),
                owning_device_id: string_field(record, "OwningDevice"),
                title: string_field(record, "Title"),
                url: string_field(record, "URL"),
                date_last_viewed: date_field(record, "DateLastViewed"),
                position: record.fields.get("Position").cloned(),
            }),
            "BookmarkList" | "BookmarkLeaf" => snapshot.bookmarks.push(Bookmark {
                id: record.name.clone(),
                kind: if record.record_type == "BookmarkList" {
                    "folder"
                } else {
                    "leaf"
                }
                .into(),
                parent_id: string_field(record, "ParentFolder"),
                title: string_field(record, "Title"),
                url: string_field(record, "URL"),
                date_added: date_field(record, "DateAdded"),
                preview_text: string_field(record, "PreviewText"),
                position: record.fields.get("Position").cloned(),
            }),
            "Visits" => snapshot.history.push(HistoryRecord {
                id: record.name.clone(),
                uuid: string_field(record, "UUID"),
                version: match record.fields.get("Version") {
                    Some(DecodedValue::Integer { value }) => Some(*value),
                    _ => None,
                },
                data: record.fields.get("EncryptedData").cloned(),
            }),
            _ => {}
        }
    }
}
