//! iCloud Keychain (CKKS) transport, recoverable TLKs, and password projection.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
#[cfg(feature = "experimental-live-writes")]
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::{Digest as _, Sha1};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    anisette::identity_headers,
    ckks::{Archive, Record, RecoveredItem},
    cloudkit::{AnisetteProvider, DeviceState, HttpRequest, HttpTransport, SessionState},
    crypto,
    wire::{self, Message, Value as WireValue},
};

pub const KEYCHAIN_CONTAINER: &str = "com.apple.security.keychain";
const CUTTLEFISH_BUNDLE: &str = "com.apple.security.cuttlefish";
const SECURITYD_BUNDLE: &str = "com.apple.securityd";
const CKCODE_URL: &str = "https://gateway.icloud.com/ckcoderouter/api/client/code/invoke";
const SYNC_URL: &str = "https://gateway.icloud.com/ckdatabase/api/client/record/sync";
#[cfg(feature = "experimental-live-writes")]
const SAVE_URL: &str = "https://gateway.icloud.com/ckdatabase/api/client/record/save";
#[cfg(feature = "experimental-live-writes")]
const DELETE_URL: &str = "https://gateway.icloud.com/ckdatabase/api/client/record/delete";
const CLIENT_INFO: &str = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)>";
// Passwords holds current login items; Manatee is the supported legacy view.
// Unrelated CKKS views are intentionally not prerequisites for password reads.
const PASSWORD_ZONES: &[&str] = &["Passwords", "Manatee"];

#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub record_name: String,
    pub domain: String,
    pub username: String,
    pub password: String,
    pub title: String,
}

#[derive(Clone)]
pub struct NewPassword<'a> {
    pub domain: &'a str,
    pub username: &'a str,
    pub password: &'a str,
    pub title: Option<&'a str>,
}

impl std::fmt::Debug for NewPassword<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewPassword")
            .field("domain", &self.domain)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("title", &self.title)
            .finish()
    }
}

impl std::fmt::Debug for PasswordEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordEntry")
            .field("record_name", &self.record_name)
            .field("domain", &self.domain)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("title", &self.title)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeychainSnapshot {
    pub fetched_at: String,
    pub zones: Vec<String>,
    pub records: Vec<Record>,
}

pub struct KeychainClient<T, A> {
    transport: T,
    anisette: A,
    device: DeviceState,
    session: SessionState,
    user_id: String,
}

impl<T: HttpTransport, A: AnisetteProvider> KeychainClient<T, A> {
    /// Initialize the keychain container for an authenticated account.
    pub async fn initialize(
        transport: T,
        anisette: A,
        device: DeviceState,
        mut session: SessionState,
    ) -> Result<Self> {
        if session
            .mme
            .extra
            .get("cloudKitUserId")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        {
            let mut headers =
                common_headers(&anisette, &device, KEYCHAIN_CONTAINER, CUTTLEFISH_BUNDLE).await?;
            headers.retain(|(name, _)| name != "content-encoding");
            headers.push((
                "authorization".into(),
                format!(
                    "Basic {}",
                    STANDARD.encode(format!(
                        "{}:{}",
                        session.mme.dsid, session.mme.mme_auth_token
                    ))
                ),
            ));
            let response = transport.send(HttpRequest {
                method: "POST".into(),
                url: format!("https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit?container={KEYCHAIN_CONTAINER}"),
                headers, body: vec![],
            }).await?;
            if response.status / 100 != 2 {
                return Err(Error::Authentication(
                    "keychain container initialization failed".into(),
                ));
            }
            let result: serde_json::Value = serde_json::from_slice(&response.body)?;
            let user = result
                .get("cloudKitUserId")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or(Error::Protobuf("keychain initialization omitted user ID"))?;
            session
                .mme
                .extra
                .insert("cloudKitUserId".into(), user.into());
        }
        Self::new(transport, anisette, device, session)
    }

    pub fn session(&self) -> &SessionState {
        &self.session
    }

    /// Recover authenticated PCS identity exports for use by the Safari reader.
    pub async fn recover_pcs_identities(&self) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        let (tlks, keys) = self.fetch_recoverable_keys().await?;
        let mut snapshot = self
            .fetch_zones(&["Manatee", "ProtectedCloudStorage"])
            .await?;
        snapshot.records.extend(keys);
        let items = Archive {
            records: snapshot.records,
        }
        .recover_items(&tlks)?;
        let mut identities = Vec::new();
        for item in items {
            let Some(dict) = item.value.as_dictionary() else {
                continue;
            };
            let Some(data) = dict.get("v_Data").and_then(plist::Value::as_data) else {
                continue;
            };
            if crate::pcs::Identity::from_der(data).is_ok()
                && !identities
                    .iter()
                    .any(|old: &Zeroizing<Vec<u8>>| old.as_slice() == data)
            {
                identities.push(Zeroizing::new(data.to_vec()));
            }
        }
        if identities.is_empty() {
            return Err(Error::Authentication(
                "no authenticated PCS identities were recovered".into(),
            ));
        }
        Ok(identities)
    }
    pub fn new(
        transport: T,
        anisette: A,
        device: DeviceState,
        session: SessionState,
    ) -> Result<Self> {
        let user_id = session
            .mme
            .extra
            .get("cloudKitUserId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Error::Authentication(
                    "keychain CloudKit user ID is absent; run login/keychain enrollment first"
                        .into(),
                )
            })?
            .to_owned();
        Ok(Self {
            transport,
            anisette,
            device,
            session,
            user_id,
        })
    }

    /// Authenticate login items from the Passwords and legacy Manatee views.
    /// Both views must be retrieved completely; inaccessible views are errors.
    pub async fn fetch_and_decrypt_passwords(
        &self,
    ) -> Result<(KeychainSnapshot, Vec<PasswordEntry>)> {
        let (tlks, recoverable_keys) = self.fetch_recoverable_keys().await?;
        let mut snapshot = self.fetch_zones(PASSWORD_ZONES).await?;
        snapshot.records.extend(recoverable_keys);
        let archive = Archive {
            records: snapshot.records.clone(),
        };
        let items = archive.recover_items(&tlks)?;
        tracing::debug!(items = items.len(), "authenticated CKKS items");
        Ok((snapshot, project_passwords(&items)))
    }

    #[cfg(feature = "experimental-live-writes")]
    pub async fn create_password(&self, new: NewPassword<'_>) -> Result<PasswordEntry> {
        validate_new_password(&new)?;
        let material = self.password_material().await?;
        let record_name = uuid::Uuid::new_v4().to_string().to_uppercase();
        let value = new_password_plist(&new);
        let record = encrypt_password_record(
            &record_name,
            &self.user_id,
            &material.class_key_id,
            &material.class_key,
            &value,
            None,
        )?;
        let mut request = Vec::new();
        wire::encode_bytes(1, &record, &mut request);
        wire::encode_uint(6, 2, &mut request); // FailIfExists
        self.perform(SAVE_URL, 210, 210, &request, SECURITYD_BUNDLE, None)
            .await?;
        let expected = PasswordEntry {
            record_name,
            domain: new.domain.into(),
            username: new.username.into(),
            password: new.password.into(),
            title: new.title.unwrap_or(new.domain).into(),
        };
        let (_, passwords) = self.fetch_and_decrypt_passwords().await?;
        passwords
            .into_iter()
            .find(|actual| {
                actual.record_name == expected.record_name
                    && actual.domain == expected.domain
                    && actual.username == expected.username
                    && actual.password == expected.password
                    && actual.title == expected.title
            })
            .ok_or(Error::Integrity)
    }

    #[cfg(feature = "experimental-live-writes")]
    pub async fn update_password(&self, record_name: &str, password: &str) -> Result<()> {
        if password.is_empty() {
            return Err(Error::Fixture("password must not be empty".into()));
        }
        let material = self.password_material().await?;
        let record = material
            .snapshot
            .records
            .iter()
            .find(|record| {
                record.zone == "Passwords"
                    && record.record_type == "item"
                    && record.record_name == record_name
            })
            .ok_or_else(|| Error::Fixture("password record was not found".into()))?;
        let recovered = material
            .archive
            .recover_items(&material.tlks)?
            .into_iter()
            .find(|item| item.record_name == record_name)
            .ok_or(Error::Integrity)?;
        let mut value = recovered
            .value
            .as_dictionary()
            .cloned()
            .ok_or(Error::Integrity)?;
        value.insert(
            "v_Data".into(),
            plist::Value::Data(password.as_bytes().to_vec()),
        );
        let raw = decode_raw_record(record)?;
        let updated = encrypt_password_record(
            record_name,
            &self.user_id,
            &material.class_key_id,
            &material.class_key,
            &plist::Value::Dictionary(value),
            Some(&raw),
        )?;
        let mut request = Vec::new();
        wire::encode_bytes(1, &updated, &mut request);
        wire::encode_string(4, &record_etag(&raw)?, &mut request);
        wire::encode_uint(6, 1, &mut request); // FailIfOutdated
        self.perform(SAVE_URL, 210, 210, &request, SECURITYD_BUNDLE, None)
            .await?;
        let (_, passwords) = self.fetch_and_decrypt_passwords().await?;
        if passwords
            .iter()
            .any(|actual| actual.record_name == record_name && actual.password == password)
        {
            Ok(())
        } else {
            Err(Error::Integrity)
        }
    }

    #[cfg(feature = "experimental-live-writes")]
    pub async fn delete_password(&self, record_name: &str) -> Result<()> {
        let snapshot = self.fetch_zones(&["Passwords"]).await?;
        let record = snapshot
            .records
            .iter()
            .find(|record| record.record_type == "item" && record.record_name == record_name)
            .ok_or_else(|| Error::Fixture("password record was not found".into()))?;
        let raw = decode_raw_record(record)?;
        let parsed = Message::parse(&raw)?;
        let identifier = parsed
            .first_bytes(2)
            .ok_or(Error::Protobuf("record omitted identifier"))?;
        let mut request = Vec::new();
        wire::encode_bytes(1, identifier, &mut request);
        wire::encode_string(2, &record_etag(&raw)?, &mut request);
        self.perform(DELETE_URL, 214, 214, &request, SECURITYD_BUNDLE, None)
            .await?;
        let after = self.fetch_zones(&["Passwords"]).await?;
        if after
            .records
            .iter()
            .any(|record| record.record_type == "item" && record.record_name == record_name)
        {
            Err(Error::Integrity)
        } else {
            Ok(())
        }
    }

    #[cfg(feature = "experimental-live-writes")]
    async fn password_material(&self) -> Result<PasswordMaterial> {
        let (tlks, recoverable) = self.fetch_recoverable_keys().await?;
        let mut snapshot = self.fetch_zones(&["Passwords"]).await?;
        snapshot.records.extend(recoverable);
        let archive = Archive {
            records: snapshot.records.clone(),
        };
        let keys = archive.recover_keys(&tlks)?;
        let class_key_id = snapshot
            .records
            .iter()
            .find(|record| record.record_type == "currentkey" && record.record_name == "classC")
            .and_then(|record| string_field(&record.fields, "parentkeyref"))
            .ok_or(Error::Protobuf(
                "Passwords zone omitted current class C pointer",
            ))?
            .to_owned();
        let class_key = keys.get(&class_key_id).ok_or(Error::Integrity)?.to_vec();
        Ok(PasswordMaterial {
            snapshot,
            archive,
            tlks,
            class_key_id,
            class_key: Zeroizing::new(class_key),
        })
    }

    /// Fetch every requested zone completely. An unavailable zone or failed
    /// page is an error, never an empty snapshot or evidence of deletion.
    pub async fn fetch_zones(&self, zones: &[&str]) -> Result<KeychainSnapshot> {
        let mut records = Vec::new();
        let mut fetched = Vec::new();
        for zone in zones {
            let mut continuation = None;
            let mut zone_records = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            let mut complete = false;
            for _ in 0..1000 {
                let request =
                    retrieve_changes_request(zone, &self.user_id, continuation.as_deref());
                let response = self
                    .perform(SYNC_URL, 213, 213, &request, SECURITYD_BUNDLE, None)
                    .await?;
                let page = Message::parse(&response)?;
                for change in page.values(1) {
                    let WireValue::Bytes(change) = change else {
                        continue;
                    };
                    let change = Message::parse(change)?;
                    if let Some(record) = change.first_bytes(5) {
                        zone_records.push(parse_record(record, zone)?);
                    }
                }
                continuation = page.first_bytes(2).map(ToOwned::to_owned);
                match page.first_varint(4) {
                    Some(3) => {
                        complete = true;
                        break;
                    }
                    Some(1) => {}
                    _ => {
                        return Err(Error::Protobuf(
                            "unknown CKKS change status; refusing a partial snapshot",
                        ));
                    }
                }
                let token = continuation
                    .as_ref()
                    .filter(|token| !token.is_empty())
                    .ok_or(Error::Protobuf(
                        "CKKS pagination omitted its continuation token",
                    ))?;
                if !seen.insert(token.clone()) {
                    return Err(Error::Protobuf("CKKS pagination did not advance"));
                }
            }
            if !complete {
                return Err(Error::Protobuf("CKKS pagination exceeded the page limit"));
            }
            fetched.push((*zone).to_owned());
            records.extend(zone_records);
        }
        Ok(KeychainSnapshot {
            fetched_at: chrono::Utc::now().to_rfc3339(),
            zones: fetched,
            records,
        })
    }

    pub(crate) async fn fetch_recoverable_keys(
        &self,
    ) -> Result<(BTreeMap<String, Zeroizing<Vec<u8>>>, Vec<Record>)> {
        let octagon =
            self.session.extra.get("octagon").ok_or_else(|| {
                Error::Authentication("saved session has no Octagon state".into())
            })?;
        let identities = recovery_identities(octagon)?;
        let mut tlks = BTreeMap::new();
        let mut keys = Vec::new();
        for (peer_id, private_x963) in identities {
            let mut parameters = Vec::new();
            wire::encode_string(1, peer_id, &mut parameters);
            let response = self
                .invoke("fetchRecoverableTLKShares", &parameters)
                .await?;
            let (shares, recovered_keys) = parse_recoverable_response(&response)?;
            tracing::debug!(
                shares = shares.len(),
                keys = recovered_keys.len(),
                "received recoverable CKKS material"
            );
            let x963 = Zeroizing::new(hex::decode(private_x963).map_err(|_| Error::Integrity)?);
            let scalar: Zeroizing<[u8; 48]> = Zeroizing::new(
                x963.get(x963.len().saturating_sub(48)..)
                    .ok_or(Error::Integrity)?
                    .try_into()
                    .map_err(|_| Error::Integrity)?,
            );
            for share in shares {
                if string_field(&share.fields, "receiver") != Some(peer_id) {
                    continue;
                }
                match unwrap_tlkshare(&share, &scalar) {
                    Ok((id, key)) => {
                        tlks.insert(id, Zeroizing::new(key));
                    }
                    Err(error) => {
                        tracing::debug!(record = %share.record_name, %error, "could not unwrap TLK share");
                    }
                }
            }
            keys.extend(recovered_keys);
        }
        if tlks.is_empty() {
            return Err(Error::Authentication(
                "no recoverable Keychain TLKs were returned for the saved Octagon identities"
                    .into(),
            ));
        }
        Ok((tlks, keys))
    }

    pub(crate) async fn invoke(&self, name: &str, parameters: &[u8]) -> Result<Vec<u8>> {
        let mut request = Vec::new();
        wire::encode_string(1, "Cuttlefish", &mut request);
        wire::encode_string(2, name, &mut request);
        wire::encode_bytes(3, parameters, &mut request);
        let response = self
            .perform(
                CKCODE_URL,
                1101,
                1101,
                &request,
                CUTTLEFISH_BUNDLE,
                Some(&format!("Cuttlefish/{name}")),
            )
            .await?;
        Message::parse(&response)?
            .first_bytes(1)
            .map(ToOwned::to_owned)
            .ok_or(Error::Protobuf(
                "function response omitted serialized result",
            ))
    }

    async fn perform(
        &self,
        url: &str,
        operation_type: u64,
        field: u32,
        request: &[u8],
        bundle: &str,
        routing_hint: Option<&str>,
    ) -> Result<Vec<u8>> {
        let operation = request_operation(
            &self.device,
            KEYCHAIN_CONTAINER,
            bundle,
            operation_type,
            field,
            request,
        );
        let mut framed = Vec::new();
        wire::encode_varint(operation.len() as u64, &mut framed);
        framed.extend(operation);
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(&framed)?;
        let mut headers =
            common_headers(&self.anisette, &self.device, KEYCHAIN_CONTAINER, bundle).await?;
        headers.extend([
            ("x-cloudkit-userid".into(), self.user_id.clone()),
            (
                "x-cloudkit-authtoken".into(),
                self.session
                    .mme
                    .tokens
                    .get("cloudKitToken")
                    .ok_or(Error::AuthenticationRequired)?
                    .clone(),
            ),
        ]);
        if let Some(value) = routing_hint {
            headers.push(("x-cloudkit-functionroutinghint".into(), value.into()));
        }
        let response = self
            .transport
            .send(HttpRequest {
                method: "POST".into(),
                url: url.into(),
                headers,
                body: gzip.finish()?,
            })
            .await?;
        if response.status / 100 != 2 {
            return Err(Error::Network(format!(
                "Keychain CloudKit returned HTTP {}",
                response.status
            )));
        }
        let body = maybe_gunzip(&response.body)?;
        let responses = wire::decode_delimited(&body)
            .or_else(|_| Message::parse(&body).map(|value| vec![value]))?;
        let response = responses
            .first()
            .ok_or(Error::Protobuf("empty CloudKit response"))?;
        if let Some(result) = response.first_bytes(3) {
            let result = Message::parse(result)?;
            if result.first_varint(1).unwrap_or(1) != 1 {
                return Err(Error::Network("Keychain CloudKit operation failed".into()));
            }
        }
        response
            .first_bytes(field)
            .map(ToOwned::to_owned)
            .ok_or(Error::Protobuf("CloudKit response omitted operation field"))
    }
}

fn recovery_identities(octagon: &serde_json::Value) -> Result<Vec<(&str, &str)>> {
    let mut candidates = vec![(
        json_string(octagon, &["peer_id"])?,
        json_string(octagon, &["keys", "encryption_priv_x963"])?,
    )];
    if octagon.get("sponsor").is_some() {
        candidates.push((
            json_string(octagon, &["sponsor", "peer_id"])?,
            json_string(octagon, &["sponsor", "encryption_priv_x963"])?,
        ));
    }
    if let Some(saved) = octagon.get("recovery_identities") {
        for identity in saved.as_array().ok_or(Error::Integrity)? {
            candidates.push((
                json_string(identity, &["peer_id"])?,
                json_string(identity, &["encryption_priv_x963"])?,
            ));
        }
    }
    let mut unique = Vec::new();
    let mut seen = BTreeMap::new();
    for (peer, private) in candidates {
        if let Some(previous) = seen.insert(peer, private) {
            if previous != private {
                return Err(Error::Integrity);
            }
        } else {
            unique.push((peer, private));
        }
    }
    Ok(unique)
}

#[cfg(feature = "experimental-live-writes")]
struct PasswordMaterial {
    snapshot: KeychainSnapshot,
    archive: Archive,
    tlks: BTreeMap<String, Zeroizing<Vec<u8>>>,
    class_key_id: String,
    class_key: Zeroizing<Vec<u8>>,
}

#[cfg(feature = "experimental-live-writes")]
fn validate_new_password(value: &NewPassword<'_>) -> Result<()> {
    if value.domain.trim().is_empty() || value.username.is_empty() || value.password.is_empty() {
        return Err(Error::Fixture(
            "domain, username, and password must not be empty".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "experimental-live-writes")]
fn new_password_plist(new: &NewPassword<'_>) -> plist::Value {
    let mut value = plist::Dictionary::new();
    value.insert("class".into(), plist::Value::String("inet".into()));
    value.insert(
        "agrp".into(),
        plist::Value::String("com.apple.cfnetwork".into()),
    );
    value.insert("acct".into(), plist::Value::String(new.username.into()));
    value.insert("srvr".into(), plist::Value::String(new.domain.into()));
    value.insert(
        "labl".into(),
        plist::Value::String(new.title.unwrap_or(new.domain).into()),
    );
    value.insert(
        "v_Data".into(),
        plist::Value::Data(new.password.as_bytes().to_vec()),
    );
    value.insert("pdmn".into(), plist::Value::String("ck".into()));
    value.insert("sync".into(), plist::Value::Boolean(true));
    value.insert("tomb".into(), plist::Value::Integer(0.into()));
    value.insert("musr".into(), plist::Value::Data(Vec::new()));
    value.insert("sdmn".into(), plist::Value::String(String::new()));
    value.insert("path".into(), plist::Value::String(String::new()));
    value.insert("atyp".into(), plist::Value::String("dflt".into()));
    value.insert("port".into(), plist::Value::Integer(0.into()));
    value.insert(
        "ptcl".into(),
        plist::Value::Integer(u64::from(u32::from_be_bytes(*b"htps")).into()),
    );
    value.insert("vwht".into(), plist::Value::String("Passwords".into()));
    plist::Value::Dictionary(value)
}

#[cfg(feature = "experimental-live-writes")]
fn encrypt_password_record(
    record_name: &str,
    user_id: &str,
    parent_key_id: &str,
    parent_key: &[u8],
    value: &plist::Value,
    source_record: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut plaintext = Vec::new();
    value.to_writer_binary(&mut plaintext)?;
    let password_len = value
        .as_dictionary()
        .and_then(|value| value.get("v_Data"))
        .and_then(plist::Value::as_data)
        .map_or(0, <[u8]>::len);
    let mut padding = 20 - plaintext.len() % 20;
    if password_len < 20 {
        padding += 20;
    }
    plaintext.push(0x80);
    plaintext.resize(plaintext.len() + padding - 1, 0);

    let mut item_key = Zeroizing::new(vec![0u8; 64]);
    rand::thread_rng().fill_bytes(&mut item_key);
    let wrapped_key = crypto::aes_siv_encrypt(parent_key, &[], &item_key)?;
    let mut random_iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut random_iv);
    let generation = source_record
        .map(Message::parse)
        .transpose()?
        .as_ref()
        .and_then(|record| ck_record_number(record, "gen"))
        .unwrap_or(0);
    let mut metadata = BTreeMap::<&str, Vec<u8>>::new();
    metadata.insert("UUID", record_name.as_bytes().to_vec());
    metadata.insert("encver", 2u64.to_le_bytes().to_vec());
    metadata.insert("gen", generation.to_le_bytes().to_vec());
    metadata.insert("wrappedkey", parent_key_id.as_bytes().to_vec());
    let mut aad = vec![random_iv.as_slice()];
    aad.extend(metadata.values().map(Vec::as_slice));
    let encrypted = crypto::aes_siv_encrypt(&item_key, &aad, &plaintext)?;
    let mut data = random_iv.to_vec();
    data.extend(encrypted);

    let values = BTreeMap::from([
        ("data", ck_value_bytes(&data)),
        ("encver", ck_value_number(2)),
        ("gen", ck_value_number(generation)),
        ("parentkeyref", ck_value_reference(parent_key_id, user_id)),
        (
            "uploadver",
            ck_value_string(concat!("icloud-safari-rs/", env!("CARGO_PKG_VERSION"))),
        ),
        ("wrappedkey", ck_value_string(&STANDARD.encode(wrapped_key))),
    ]);
    if let Some(source) = source_record {
        return replace_ck_record_fields(source, &values);
    }
    let mut record = Vec::new();
    wire::encode_bytes(
        2,
        &record_identifier(record_name, "Passwords", user_id),
        &mut record,
    );
    let mut record_type = Vec::new();
    wire::encode_string(1, "item", &mut record_type);
    wire::encode_bytes(3, &record_type, &mut record);
    for (name, value) in values {
        wire::encode_bytes(7, &ck_record_field(name, &value), &mut record);
    }
    Ok(record)
}

#[cfg(feature = "experimental-live-writes")]
fn record_identifier(name: &str, zone: &str, user_id: &str) -> Vec<u8> {
    let mut zone_id = Vec::new();
    wire::encode_bytes(1, &identifier(zone, 6), &mut zone_id);
    wire::encode_bytes(2, &identifier(user_id, 7), &mut zone_id);
    let mut output = Vec::new();
    wire::encode_bytes(1, &identifier(name, 1), &mut output);
    wire::encode_bytes(2, &zone_id, &mut output);
    output
}

#[cfg(feature = "experimental-live-writes")]
fn ck_record_field(name: &str, value: &[u8]) -> Vec<u8> {
    let mut name_value = Vec::new();
    wire::encode_string(1, name, &mut name_value);
    let mut output = Vec::new();
    wire::encode_bytes(1, &name_value, &mut output);
    wire::encode_bytes(2, value, &mut output);
    output
}

#[cfg(feature = "experimental-live-writes")]
fn ck_value_number(value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    wire::encode_uint(1, 7, &mut output);
    wire::encode_uint(4, value, &mut output);
    output
}

#[cfg(feature = "experimental-live-writes")]
fn ck_value_string(value: &str) -> Vec<u8> {
    let mut output = Vec::new();
    wire::encode_uint(1, 3, &mut output);
    wire::encode_string(7, value, &mut output);
    output
}

#[cfg(feature = "experimental-live-writes")]
fn ck_value_bytes(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    wire::encode_uint(1, 1, &mut output);
    wire::encode_bytes(2, value, &mut output);
    output
}

#[cfg(feature = "experimental-live-writes")]
fn ck_value_reference(name: &str, user_id: &str) -> Vec<u8> {
    let mut reference = Vec::new();
    wire::encode_bytes(
        2,
        &record_identifier(name, "Passwords", user_id),
        &mut reference,
    );
    let mut output = Vec::new();
    wire::encode_uint(1, 5, &mut output);
    wire::encode_bytes(9, &reference, &mut output);
    output
}

#[cfg(feature = "experimental-live-writes")]
fn replace_ck_record_fields(
    source: &[u8],
    replacements: &BTreeMap<&str, Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut record = Message::parse(source)?;
    let mut replaced = BTreeMap::new();
    for outer in &mut record.fields {
        if outer.number != 7 {
            continue;
        }
        let WireValue::Bytes(raw_field) = &outer.value else {
            continue;
        };
        let mut field = Message::parse(raw_field)?;
        let Some(name) = field
            .first_bytes(1)
            .and_then(|value| Message::parse(value).ok())
            .and_then(|value| value.first_bytes(1).map(ToOwned::to_owned))
            .and_then(|value| String::from_utf8(value).ok())
        else {
            continue;
        };
        let Some(value) = replacements.get(name.as_str()) else {
            continue;
        };
        if !field.replace_first_bytes(2, value) {
            return Err(Error::Integrity);
        }
        let encoded = field.encode();
        outer.value = WireValue::Bytes(encoded.clone());
        outer.raw.clear();
        wire::encode_bytes(7, &encoded, &mut outer.raw);
        replaced.insert(name, ());
    }
    if replacements
        .keys()
        .any(|name| !replaced.contains_key(*name))
    {
        return Err(Error::Protobuf("CKKS record omitted a required field"));
    }
    Ok(record.encode())
}

#[cfg(feature = "experimental-live-writes")]
fn ck_record_number(record: &Message, name: &str) -> Option<u64> {
    record.values(7).find_map(|field| {
        let WireValue::Bytes(field) = field else {
            return None;
        };
        let field = Message::parse(field).ok()?;
        let actual_name = field
            .first_bytes(1)
            .and_then(|value| Message::parse(value).ok())?
            .first_bytes(1)
            .and_then(|value| std::str::from_utf8(value).ok())?
            .to_owned();
        (actual_name == name).then(|| {
            field
                .first_bytes(2)
                .and_then(|value| Message::parse(value).ok())?
                .first_varint(4)
        })?
    })
}

#[cfg(feature = "experimental-live-writes")]
fn decode_raw_record(record: &Record) -> Result<Vec<u8>> {
    STANDARD
        .decode(
            record
                .raw_record_base64
                .as_deref()
                .ok_or(Error::Protobuf("record omitted raw encoding"))?,
        )
        .map_err(|_| Error::Protobuf("invalid raw record base64"))
}

#[cfg(feature = "experimental-live-writes")]
fn record_etag(raw: &[u8]) -> Result<String> {
    let record = Message::parse(raw)?;
    std::str::from_utf8(
        record
            .first_bytes(1)
            .ok_or(Error::Protobuf("record omitted etag"))?,
    )
    .map(str::to_owned)
    .map_err(|_| Error::Protobuf("record etag is not UTF-8"))
}

async fn common_headers<A: AnisetteProvider>(
    anisette: &A,
    device: &DeviceState,
    container: &str,
    bundle: &str,
) -> Result<Vec<(String, String)>> {
    let op = || format!("{:016X}", rand::random::<u64>());
    let mut headers = vec![
        ("accept".into(), "application/x-protobuf".into()),
        ("accept-encoding".into(), "gzip".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("cache-control".into(), "no-transform".into()),
        ("content-encoding".into(), "gzip".into()),
        ("content-type".into(), "application/x-protobuf; desc=\"https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc\"; messageType=RequestOperation; delimited=true".into()),
        ("user-agent".into(), "CloudKit/1970 (19H384)".into()),
        ("x-apple-c2-metric-triggers".into(), "0".into()),
        ("x-apple-operation-group-id".into(), op()),
        ("x-apple-operation-id".into(), op()),
        ("x-apple-request-uuid".into(), uuid::Uuid::new_v4().to_string().to_uppercase()),
        ("x-cloudkit-bundleid".into(), bundle.into()),
        ("x-cloudkit-containerid".into(), container.into()),
        ("x-cloudkit-databasescope".into(), "Private".into()),
        ("x-cloudkit-duetpreclearedmode".into(), "None".into()),
        ("x-cloudkit-environment".into(), "Production".into()),
        ("x-mme-client-info".into(), CLIENT_INFO.into()),
    ];
    headers.extend(identity_headers(anisette, device).await?);
    Ok(headers)
}

fn request_operation(
    device: &DeviceState,
    container: &str,
    bundle: &str,
    operation_type: u64,
    field: u32,
    request: &[u8],
) -> Vec<u8> {
    let mut header = Vec::new();
    wire::encode_string(2, container, &mut header);
    wire::encode_string(3, bundle, &mut header);
    wire::encode_bytes(7, &identifier(&device.device_uuid, 2), &mut header);
    wire::encode_string(8, "Mac OS X;13.4.1;22F8", &mut header);
    wire::encode_string(9, "MacBookPro18,3", &mut header);
    wire::encode_string(10, "com.apple.cloudkit.CloudKitDaemon", &mut header);
    wire::encode_string(11, "1970", &mut header);
    wire::encode_string(18, "5.0", &mut header);
    wire::encode_uint(19, 1, &mut header);
    wire::encode_string(21, "Mac", &mut header);
    wire::encode_string(22, &device.device_uuid, &mut header);
    wire::encode_uint(23, 1, &mut header);
    wire::encode_uint(25, 1, &mut header);
    wire::encode_uint(29, 0, &mut header);
    wire::encode_string(
        32,
        &hex::encode(Sha1::digest(device.device_uuid.as_bytes())),
        &mut header,
    );
    wire::encode_string(33, &device.serial, &mut header);
    wire::encode_uint(34, 0, &mut header);
    wire::encode_uint(35, 1, &mut header);
    let mut operation = Vec::new();
    wire::encode_string(
        1,
        &uuid::Uuid::new_v4().to_string().to_uppercase(),
        &mut operation,
    );
    wire::encode_uint(2, operation_type, &mut operation);
    wire::encode_uint(4, 1, &mut operation);
    let mut output = Vec::new();
    wire::encode_bytes(1, &header, &mut output);
    wire::encode_bytes(2, &operation, &mut output);
    wire::encode_bytes(field, request, &mut output);
    output
}

fn retrieve_changes_request(zone: &str, user: &str, continuation: Option<&[u8]>) -> Vec<u8> {
    let mut zone_identifier = Vec::new();
    wire::encode_bytes(1, &identifier(zone, 6), &mut zone_identifier);
    wire::encode_bytes(2, &identifier(user, 7), &mut zone_identifier);
    let mut request = Vec::new();
    if let Some(token) = continuation {
        wire::encode_bytes(1, token, &mut request);
    }
    wire::encode_bytes(2, &zone_identifier, &mut request);
    wire::encode_uint(4, 500, &mut request);
    request
}

fn identifier(name: &str, kind: u64) -> Vec<u8> {
    let mut output = Vec::new();
    wire::encode_string(1, name, &mut output);
    wire::encode_uint(2, kind, &mut output);
    output
}

fn parse_record(raw: &[u8], zone: &str) -> Result<Record> {
    let record = Message::parse(raw)?;
    let record_name = nested_identifier(record.first_bytes(2))?;
    let record_type = record
        .first_bytes(3)
        .map(Message::parse)
        .transpose()?
        .and_then(|value| value.first_bytes(1).map(ToOwned::to_owned))
        .and_then(|value| String::from_utf8(value).ok())
        .unwrap_or_default();
    let mut fields = BTreeMap::new();
    for field in record.values(7) {
        let WireValue::Bytes(field) = field else {
            continue;
        };
        let field = Message::parse(field)?;
        let Some(name) = field.first_bytes(1) else {
            continue;
        };
        let name = Message::parse(name)?
            .first_bytes(1)
            .and_then(|value| std::str::from_utf8(value).ok())
            .map(str::to_owned);
        let value = field.first_bytes(2).map(parse_field_value).transpose()?;
        if let (Some(name), Some(value)) = (name, value) {
            fields.insert(name, value);
        }
    }
    Ok(Record {
        record_name,
        record_type,
        zone: zone.into(),
        fields,
        raw_record_base64: Some(STANDARD.encode(raw)),
    })
}

fn parse_field_value(raw: &[u8]) -> Result<serde_json::Value> {
    let value = Message::parse(raw)?;
    if let Some(bytes) = value.first_bytes(2) {
        return Ok(serde_json::json!({"type":"bytes","base64":STANDARD.encode(bytes)}));
    }
    if let Some(string) = value.first_bytes(7) {
        return Ok(serde_json::Value::String(
            std::str::from_utf8(string)
                .map_err(|_| Error::Protobuf("CloudKit string is not UTF-8"))?
                .into(),
        ));
    }
    if let Some(number) = value.first_varint(4) {
        return Ok(serde_json::Value::Number(number.into()));
    }
    if let Some(reference) = value.first_bytes(9) {
        let reference = Message::parse(reference)?;
        if let Some(id) = reference.first_bytes(2) {
            return Ok(serde_json::Value::String(nested_identifier(Some(id))?));
        }
    }
    Ok(serde_json::Value::Null)
}

fn nested_identifier(raw: Option<&[u8]>) -> Result<String> {
    let first = Message::parse(raw.ok_or(Error::Protobuf("record omitted identifier"))?)?;
    let second = Message::parse(
        first
            .first_bytes(1)
            .ok_or(Error::Protobuf("identifier omitted value"))?,
    )?;
    std::str::from_utf8(
        second
            .first_bytes(1)
            .ok_or(Error::Protobuf("identifier omitted name"))?,
    )
    .map(str::to_owned)
    .map_err(|_| Error::Protobuf("identifier name is not UTF-8"))
}

fn parse_recoverable_response(raw: &[u8]) -> Result<(Vec<Record>, Vec<Record>)> {
    let response = Message::parse(raw)?;
    let mut shares = Vec::new();
    let mut keys = Vec::new();
    for group in response.values(1) {
        let WireValue::Bytes(group) = group else {
            continue;
        };
        let group = Message::parse(group)?;
        if let Some(record) = group.first_bytes(3).and_then(cuttlefish_record) {
            shares.push(parse_record(&record, "Recoverable")?);
        }
        if let Some(view) = group.first_bytes(2) {
            let view = Message::parse(view)?;
            for field in [1, 2, 3] {
                if let Some(record) = view.first_bytes(field).and_then(cuttlefish_record) {
                    keys.push(parse_record(&record, "Recoverable")?);
                }
            }
        }
    }
    Ok((shares, keys))
}

fn cuttlefish_record(raw: &[u8]) -> Option<Vec<u8>> {
    Message::parse(raw)
        .ok()?
        .first_bytes(2)
        .map(ToOwned::to_owned)
}

fn unwrap_tlkshare(record: &Record, scalar: &[u8; 48]) -> Result<(String, Vec<u8>)> {
    let wrapped = STANDARD
        .decode(string_field(&record.fields, "wrappedkey").ok_or(Error::Integrity)?)
        .map_err(|_| Error::Integrity)?;
    let expanded = expand_nskeyed_archive(&wrapped)?;
    let dictionary = expanded.as_dictionary().ok_or(Error::Integrity)?;
    tracing::trace!(keys = ?dictionary.keys().collect::<Vec<_>>(), "expanded TLK archive");
    let ephemeral = plist_data(
        dictionary,
        "SFEphemeralSenderPublicKeyExternaRepresentation",
    )?;
    let ciphertext_with_suffix = plist_data(dictionary, "SFCiphertext")?;
    let tag = plist_data(dictionary, "SFIESAuthenticationCode")?;
    tracing::trace!(
        ephemeral_bytes = ephemeral.len(),
        ciphertext_bytes = ciphertext_with_suffix.len(),
        tag_bytes = tag.len(),
        "expanded SecurityFoundation ciphertext"
    );
    let ciphertext = ciphertext_with_suffix
        .get(
            ..ciphertext_with_suffix
                .len()
                .checked_sub(113)
                .ok_or(Error::Integrity)?,
        )
        .ok_or(Error::Integrity)?;
    let plaintext = crypto::sf_ecies_p384_decrypt(scalar, ephemeral, ciphertext, tag)?;
    let serialized = Message::parse(&plaintext)?;
    let id = serialized
        .first_bytes(1)
        .and_then(|value| std::str::from_utf8(value).ok())
        .ok_or(Error::Integrity)?
        .to_owned();
    let key = serialized.first_bytes(4).ok_or(Error::Integrity)?.to_vec();
    if key.len() != 64 {
        return Err(Error::Integrity);
    }
    Ok((id, key))
}

fn expand_nskeyed_archive(raw: &[u8]) -> Result<plist::Value> {
    let root = plist::Value::from_reader(Cursor::new(raw))?;
    let dictionary = root.as_dictionary().ok_or(Error::Integrity)?;
    let objects = dictionary
        .get("$objects")
        .and_then(plist::Value::as_array)
        .ok_or(Error::Integrity)?;
    let top_dictionary = dictionary
        .get("$top")
        .and_then(plist::Value::as_dictionary)
        .ok_or(Error::Integrity)?;
    let top = top_dictionary
        .get("root")
        .cloned()
        .unwrap_or_else(|| plist::Value::Dictionary(top_dictionary.clone()));
    resolve_archive_value(&top, objects, 0)
}

fn resolve_archive_value(
    value: &plist::Value,
    objects: &[plist::Value],
    depth: usize,
) -> Result<plist::Value> {
    if depth > 64 {
        return Err(Error::Integrity);
    }
    if let Some(uid) = value.as_uid() {
        return resolve_archive_value(
            objects.get(uid.get() as usize).ok_or(Error::Integrity)?,
            objects,
            depth + 1,
        );
    }
    match value {
        plist::Value::Dictionary(dictionary) => {
            let is_object = dictionary.contains_key("$class");
            let mut output = plist::Dictionary::new();
            for (key, value) in dictionary {
                if !key.starts_with('$') {
                    output.insert(
                        key.clone(),
                        resolve_archive_value(value, objects, depth + 1)?,
                    );
                }
            }
            if is_object {
                for key in ["NS.data", "NS.string", "NS.objects"] {
                    if let Some(value) = output.remove(key) {
                        return Ok(value);
                    }
                }
            }
            Ok(plist::Value::Dictionary(output))
        }
        plist::Value::Array(values) => Ok(plist::Value::Array(
            values
                .iter()
                .map(|value| resolve_archive_value(value, objects, depth + 1))
                .collect::<Result<Vec<_>>>()?,
        )),
        plist::Value::String(value) if value == "$null" => Ok(plist::Value::String(String::new())),
        _ => Ok(value.clone()),
    }
}

fn plist_data<'a>(dictionary: &'a plist::Dictionary, key: &str) -> Result<&'a [u8]> {
    dictionary
        .get(key)
        .and_then(plist::Value::as_data)
        .ok_or(Error::Integrity)
}

fn project_passwords(items: &[RecoveredItem]) -> Vec<PasswordEntry> {
    let mut output = Vec::new();
    for item in items {
        let Some(value) = item.value.as_dictionary() else {
            continue;
        };
        let access_group = plist_string(value, "agrp").unwrap_or_default();
        if access_group != "com.apple.cfnetwork" && access_group != "apple" {
            continue;
        }
        let domain = ["srvr", "server", "domain", "url", "svce"]
            .iter()
            .find_map(|key| plist_string(value, key))
            .unwrap_or_default();
        let username = ["acct", "username", "user"]
            .iter()
            .find_map(|key| plist_string(value, key))
            .unwrap_or_default();
        let password = match value.get("v_Data") {
            Some(plist::Value::String(value)) => value.clone(),
            Some(plist::Value::Data(value)) => String::from_utf8_lossy(value).into_owned(),
            _ => String::new(),
        };
        if domain.is_empty() || (username.is_empty() && password.is_empty()) {
            continue;
        }
        output.push(PasswordEntry {
            record_name: item.record_name.clone(),
            domain: domain.clone(),
            username,
            password,
            title: plist_string(value, "labl").unwrap_or(domain),
        });
    }
    output.sort_by(|a, b| (&a.domain, &a.username).cmp(&(&b.domain, &b.username)));
    output
}

fn plist_string(dictionary: &plist::Dictionary, key: &str) -> Option<String> {
    match dictionary.get(key)? {
        plist::Value::String(value) => Some(value.clone()),
        plist::Value::Data(value) => Some(String::from_utf8_lossy(value).into_owned()),
        _ => None,
    }
}

fn string_field<'a>(fields: &'a BTreeMap<String, serde_json::Value>, key: &str) -> Option<&'a str> {
    fields.get(key)?.as_str()
}

fn json_string<'a>(value: &'a serde_json::Value, path: &[&str]) -> Result<&'a str> {
    let mut value = value;
    for key in path {
        value = value.get(*key).ok_or(Error::AuthenticationRequired)?;
    }
    value.as_str().ok_or(Error::AuthenticationRequired)
}

fn maybe_gunzip(body: &[u8]) -> Result<Vec<u8>> {
    if body.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = GzDecoder::new(body);
        let mut output = Vec::new();
        decoder.read_to_end(&mut output)?;
        Ok(output)
    } else {
        Ok(body.to_vec())
    }
}

#[cfg(all(test, feature = "experimental-live-writes"))]
mod tests {
    use super::*;

    #[test]
    fn password_record_round_trips_through_ckks_authentication() {
        let class_key = [0x42; 64];
        let value = NewPassword {
            domain: "example.invalid",
            username: "alice",
            password: "correct horse battery staple",
            title: Some("Example"),
        };
        let raw = encrypt_password_record(
            "11111111-2222-4333-8444-555555555555",
            "_test-user",
            "class-c-key",
            &class_key,
            &new_password_plist(&value),
            None,
        )
        .unwrap();
        let record = parse_record(&raw, "Passwords").unwrap();
        let archive = Archive {
            records: vec![record],
        };
        let tlks = BTreeMap::from([("class-c-key".into(), Zeroizing::new(class_key.to_vec()))]);
        let entries = project_passwords(&archive.recover_items(&tlks).unwrap());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].domain, value.domain);
        assert_eq!(entries[0].username, value.username);
        assert_eq!(entries[0].password, value.password);
        assert_eq!(entries[0].title, value.title.unwrap());
        assert!(!format!("{:?}", entries[0]).contains(value.password));
    }
}

#[cfg(test)]
mod fetch_tests {
    use super::*;
    use crate::cloudkit::HttpResponse;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    #[test]
    fn recovery_candidates_include_fallbacks_without_duplicate_requests() {
        let mut octagon = serde_json::json!({
            "peer_id": "new", "keys": {"encryption_priv_x963": "key-new"},
            "sponsor": {"peer_id": "sponsor", "encryption_priv_x963": "key-sponsor"},
            "recovery_identities": [
                {"peer_id": "original", "encryption_priv_x963": "key-original"},
                {"peer_id": "original", "encryption_priv_x963": "key-original"},
                {"peer_id": "sponsor", "encryption_priv_x963": "key-sponsor"}
            ]
        });
        assert_eq!(
            recovery_identities(&octagon).unwrap(),
            vec![
                ("new", "key-new"),
                ("sponsor", "key-sponsor"),
                ("original", "key-original")
            ]
        );
        octagon["recovery_identities"][1]["encryption_priv_x963"] = "different-key".into();
        assert!(recovery_identities(&octagon).is_err());
        octagon["recovery_identities"] = serde_json::Value::Null;
        assert!(recovery_identities(&octagon).is_err());
    }

    struct Reply {
        field: u32,
        status: u16,
        payload: Vec<u8>,
    }
    #[derive(Clone)]
    struct Script(Arc<Mutex<VecDeque<Reply>>>);
    #[async_trait::async_trait]
    impl HttpTransport for Script {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
            let reply = self
                .0
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected request");
            let expected_path = if reply.field == 214 {
                "/delete"
            } else {
                "/sync"
            };
            assert!(request.url.ends_with(expected_path));
            let mut operation = Vec::new();
            wire::encode_bytes(reply.field, &reply.payload, &mut operation);
            let mut body = Vec::new();
            wire::encode_varint(operation.len() as u64, &mut body);
            body.extend(operation);
            Ok(HttpResponse {
                status: reply.status,
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
    fn client(replies: Vec<Reply>) -> (KeychainClient<Script, Anisette>, Script) {
        let script = Script(Arc::new(Mutex::new(replies.into())));
        let session = serde_json::from_value(serde_json::json!({
            "username": "test@example.invalid", "dsid": "123",
            "mme": {"dsid": "123", "mmeAuthToken": "synthetic", "tokens": {"cloudKitToken": "synthetic"}, "cloudKitUserId": "synthetic"}
        })).unwrap();
        (
            KeychainClient::new(script.clone(), Anisette, DeviceState::generate(), session)
                .unwrap(),
            script,
        )
    }
    fn page(more: bool, token: Option<&[u8]>, record: bool) -> Reply {
        let mut payload = Vec::new();
        if record {
            let mut record_id = Vec::new();
            wire::encode_bytes(1, &identifier("test-record", 1), &mut record_id);
            let mut raw = Vec::new();
            wire::encode_string(1, "etag", &mut raw);
            wire::encode_bytes(2, &record_id, &mut raw);
            wire::encode_bytes(3, &identifier("item", 1), &mut raw);
            let mut change = Vec::new();
            wire::encode_bytes(5, &raw, &mut change);
            wire::encode_bytes(1, &change, &mut payload);
        }
        if let Some(token) = token {
            wire::encode_bytes(2, token, &mut payload);
        }
        wire::encode_uint(4, if more { 1 } else { 3 }, &mut payload);
        Reply {
            field: 213,
            status: 200,
            payload,
        }
    }
    fn failure() -> Reply {
        Reply {
            field: 213,
            status: 503,
            payload: vec![],
        }
    }

    #[tokio::test]
    async fn successful_empty_zone_is_reported_as_fetched() {
        let (client, script) = client(vec![page(false, None, false)]);
        let snapshot = client.fetch_zones(&["Passwords"]).await.unwrap();
        assert_eq!(snapshot.zones, vec!["Passwords"]);
        assert!(snapshot.records.is_empty());
        assert!(script.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn zone_and_later_page_failures_never_return_partial_snapshots() {
        for replies in [
            vec![failure()],
            vec![page(true, Some(b"next"), true), failure()],
        ] {
            let (client, script) = client(replies);
            assert!(client.fetch_zones(&["Passwords"]).await.is_err());
            assert!(script.0.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn continuation_must_exist_and_advance() {
        for replies in [
            vec![page(true, None, false)],
            vec![page(true, Some(b""), false)],
            vec![
                page(true, Some(b"same"), false),
                page(true, Some(b"same"), false),
            ],
        ] {
            let (client, script) = client(replies);
            assert!(client.fetch_zones(&["Passwords"]).await.is_err());
            assert!(script.0.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn unknown_or_missing_final_status_never_completes_a_zone() {
        for status in [None, Some(0), Some(2), Some(4), Some(u64::MAX)] {
            let mut payload = Vec::new();
            if let Some(status) = status {
                wire::encode_uint(4, status, &mut payload);
            }
            let (client, script) = client(vec![
                page(true, Some(b"next"), true),
                Reply {
                    field: 213,
                    status: 200,
                    payload,
                },
            ]);
            assert!(client.fetch_zones(&["Passwords"]).await.is_err());
            assert!(script.0.lock().unwrap().is_empty());
        }
    }

    #[cfg(feature = "experimental-live-writes")]
    #[tokio::test]
    async fn malformed_post_delete_status_is_not_confirmed_absence() {
        let (client, script) = client(vec![
            page(false, None, true),
            Reply {
                field: 214,
                status: 200,
                payload: vec![],
            },
            Reply {
                field: 213,
                status: 200,
                payload: vec![],
            },
        ]);
        assert!(client.delete_password("test-record").await.is_err());
        assert!(script.0.lock().unwrap().is_empty());
    }

    #[cfg(feature = "experimental-live-writes")]
    #[tokio::test]
    async fn failed_post_delete_fetch_is_not_confirmed_absence() {
        let (client, script) = client(vec![
            page(false, None, true),
            Reply {
                field: 214,
                status: 200,
                payload: vec![],
            },
            failure(),
        ]);
        assert!(client.delete_password("test-record").await.is_err());
        assert!(script.0.lock().unwrap().is_empty());
    }
}
