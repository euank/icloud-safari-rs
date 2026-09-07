//! CKKS class-key and item recovery once Octagon TLKs are available.

use crate::{Error, Result, crypto};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::{collections::BTreeMap, io::Cursor};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Deserialize)]
pub struct Archive {
    pub records: Vec<Record>,
}
#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct Record {
    pub record_name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    #[serde(default)]
    pub zone: String,
    pub fields: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_record_base64: Option<String>,
}

#[derive(Clone)]
pub struct RecoveredItem {
    pub record_name: String,
    pub value: plist::Value,
}

impl std::fmt::Debug for RecoveredItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveredItem")
            .field("record_name", &self.record_name)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Archive {
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Recover TLKs and all descendant class keys in this archive.
    pub fn recover_keys(
        &self,
        tlks: &BTreeMap<String, Zeroizing<Vec<u8>>>,
    ) -> Result<BTreeMap<String, Zeroizing<Vec<u8>>>> {
        let mut keys: BTreeMap<String, Zeroizing<Vec<u8>>> = tlks
            .iter()
            .map(|(k, v)| (k.clone(), Zeroizing::new(v.to_vec())))
            .collect();
        loop {
            let mut progress = false;
            for record in self.records.iter().filter(|r| r.record_type == "synckey") {
                if keys.contains_key(&record.record_name) {
                    continue;
                }
                let Some(parent) = string(&record.fields, "parentkeyref") else {
                    continue;
                };
                let Some(parent_key) = keys.get(parent) else {
                    continue;
                };
                let wrapped = decode_string(&record.fields, "wrappedkey")?;
                let key = crypto::aes_siv_decrypt(parent_key, &[], &wrapped)?;
                if key.len() != 64 {
                    return Err(Error::Integrity);
                }
                keys.insert(record.record_name.clone(), Zeroizing::new(key));
                progress = true
            }
            if !progress {
                break;
            }
        }
        Ok(keys)
    }

    /// Recover authenticated items. `tlks` maps CKKS TLK record names to their
    /// 64-byte AES-SIV keys obtained from recoverable TLKShares.
    pub fn recover_items(
        &self,
        tlks: &BTreeMap<String, Zeroizing<Vec<u8>>>,
    ) -> Result<Vec<RecoveredItem>> {
        let keys = self.recover_keys(tlks)?;
        let mut output = Vec::new();
        for record in self.records.iter().filter(|r| r.record_type == "item") {
            let parent = string(&record.fields, "parentkeyref")
                .ok_or(Error::Protobuf("CKKS item omitted parent key"))?;
            let Some(parent_key) = keys.get(parent) else {
                continue;
            };
            let wrapped = decode_string(&record.fields, "wrappedkey")?;
            let item_key = Zeroizing::new(crypto::aes_siv_decrypt(parent_key, &[], &wrapped)?);
            if item_key.len() != 64 {
                return Err(Error::Integrity);
            }
            let data = decode_object(&record.fields, "data")?;
            if data.len() < 32 {
                return Err(Error::Integrity);
            }
            let random_iv = &data[..16];
            let mut metadata = BTreeMap::<String, Vec<u8>>::new();
            metadata.insert("UUID".into(), record.record_name.as_bytes().to_vec());
            metadata.insert(
                "encver".into(),
                number(&record.fields, "encver")
                    .unwrap_or(2)
                    .to_le_bytes()
                    .to_vec(),
            );
            metadata.insert(
                "gen".into(),
                number(&record.fields, "gen")
                    .unwrap_or(0)
                    .to_le_bytes()
                    .to_vec(),
            );
            metadata.insert("wrappedkey".into(), parent.as_bytes().to_vec());
            for name in ["pcsservice", "pcspublicidentity", "pcspublickey"] {
                if let Some(value) = record.fields.get(name) {
                    metadata.insert(name.into(), encode_metadata(value)?);
                }
            }
            let mut aad = Vec::with_capacity(metadata.len() + 1);
            aad.push(random_iv);
            for value in metadata.values() {
                aad.push(value.as_slice())
            }
            let mut plaintext = crypto::aes_siv_decrypt(&item_key, &aad, &data[16..])?;
            remove_iso7816(&mut plaintext)?;
            let value = plist::Value::from_reader(Cursor::new(plaintext))?;
            output.push(RecoveredItem {
                record_name: record.record_name.clone(),
                value,
            });
        }
        Ok(output)
    }
}
fn string<'a>(fields: &'a BTreeMap<String, serde_json::Value>, name: &str) -> Option<&'a str> {
    fields.get(name)?.as_str()
}
fn number(fields: &BTreeMap<String, serde_json::Value>, name: &str) -> Option<u64> {
    fields.get(name)?.as_u64()
}
fn decode_string(fields: &BTreeMap<String, serde_json::Value>, name: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(string(fields, name).ok_or(Error::Protobuf("CKKS field missing"))?)
        .map_err(|_| Error::Protobuf("invalid CKKS base64"))
}
fn decode_object(fields: &BTreeMap<String, serde_json::Value>, name: &str) -> Result<Vec<u8>> {
    let value = fields
        .get(name)
        .and_then(|v| v.get("base64"))
        .and_then(|v| v.as_str())
        .ok_or(Error::Protobuf("CKKS byte field missing"))?;
    STANDARD
        .decode(value)
        .map_err(|_| Error::Protobuf("invalid CKKS base64"))
}
fn encode_metadata(value: &serde_json::Value) -> Result<Vec<u8>> {
    if let Some(v) = value.as_u64() {
        return Ok(v.to_le_bytes().to_vec());
    }
    if let Some(v) = value.as_str() {
        return Ok(v.as_bytes().to_vec());
    }
    if let Some(v) = value.get("base64").and_then(|v| v.as_str()) {
        return STANDARD
            .decode(v)
            .map_err(|_| Error::Protobuf("invalid metadata base64"));
    }
    Err(Error::Protobuf("unsupported CKKS metadata"))
}
fn remove_iso7816(bytes: &mut Vec<u8>) -> Result<()> {
    let Some(position) = bytes.iter().rposition(|b| *b != 0) else {
        return Err(Error::Integrity);
    };
    if bytes[position] != 0x80 {
        return Err(Error::Integrity);
    }
    bytes.truncate(position);
    Ok(())
}
