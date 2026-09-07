//! CloudKit transport, Safari record acquisition, and feature-gated mutations.

use crate::{
    Error, Result,
    model::Dataset,
    wire::{self, Message, Value},
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
#[cfg(feature = "experimental-live-writes")]
use sha2::Sha256;
use std::collections::BTreeMap;
use std::io::Write;

#[cfg(feature = "experimental-live-writes")]
use crate::write::{PreparedCreate, PreparedDelete, PreparedFieldUpdate, zone_protection_tag};

#[derive(Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .finish()
    }
}
#[derive(Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse>;
}

#[derive(Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        // GrandSlam still serves a chain rooted at Apple's legacy private
        // Apple Root CA, which is intentionally absent from browser-oriented
        // public WebPKI root sets. Apple publishes this exact certificate at
        // https://www.apple.com/appleca/AppleIncRootCertificate.cer.
        let apple_root = reqwest::Certificate::from_pem(include_bytes!("apple_root_ca.pem"))
            .expect("embedded Apple Root CA must be valid PEM");
        let client = reqwest::Client::builder()
            .add_root_certificate(apple_root)
            .build()
            .expect("default reqwest client must build");
        Self { client }
    }
}
#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|e| Error::Network(e.to_string()))?;
        let mut builder = self.client.request(method, &request.url);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        let response = builder
            .body(request.body)
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_owned()))
            .collect();
        let body = response
            .bytes()
            .await
            .map_err(|e| Error::Network(e.to_string()))?
            .to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

#[async_trait]
pub trait AnisetteProvider: Send + Sync {
    async fn headers(&self) -> Result<BTreeMap<String, String>>;
}

#[derive(Clone)]
pub struct HttpAnisetteProvider {
    url: String,
    client: reqwest::Client,
}
impl HttpAnisetteProvider {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::new(),
        }
    }
}
#[async_trait]
impl AnisetteProvider for HttpAnisetteProvider {
    async fn headers(&self) -> Result<BTreeMap<String, String>> {
        let map: BTreeMap<String, String> = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?
            .json()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
        if !map.contains_key("X-Apple-I-MD") || !map.contains_key("X-Apple-I-MD-M") {
            return Err(Error::Network(
                "Anisette response omitted mandatory headers".into(),
            ));
        }
        Ok(map
            .into_iter()
            .filter(|(key, _)| ANISSETTE_ALLOWLIST.contains(&key.as_str()))
            .collect())
    }
}
const ANISSETTE_ALLOWLIST: &[&str] = crate::anisette::IDENTITY_HEADER_NAMES;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceState {
    #[serde(rename = "device_id")]
    pub device_uuid: String,
    pub serial: String,
    pub local_user_uuid: String,
}
impl DeviceState {
    pub fn generate() -> Self {
        Self {
            device_uuid: uuid::Uuid::new_v4().to_string().to_uppercase(),
            serial: format!("RUST{:08X}", rand::random::<u32>()),
            local_user_uuid: uuid::Uuid::new_v4().to_string().to_uppercase(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MmeState {
    pub dsid: String,
    #[serde(rename = "mmeAuthToken")]
    pub mme_auth_token: String,
    pub tokens: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl std::fmt::Debug for MmeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MmeState(<redacted>)")
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub username: String,
    pub dsid: String,
    pub mme: MmeState,
    #[serde(default)]
    pub safari_cloudkit_users: BTreeMap<String, String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionState")
            .field("username", &self.username)
            .field("dsid", &self.dsid)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchedPage {
    pub raw_response_base64: String,
    pub status: u64,
    pub records: Vec<FetchedRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation_token_base64: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchedRecord {
    pub name: String,
    pub record_type: String,
    pub fields: BTreeMap<String, serde_json::Value>,
    pub raw_record_base64: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchedDataset {
    pub container: String,
    pub zone: String,
    pub database: String,
    pub fetched_at: String,
    pub pages: Vec<FetchedPage>,
}

pub struct Client<T, A> {
    transport: T,
    anisette: A,
    pub device: DeviceState,
    pub session: SessionState,
}
impl<T: HttpTransport, A: AnisetteProvider> Client<T, A> {
    pub fn new(transport: T, anisette: A, device: DeviceState, session: SessionState) -> Self {
        Self {
            transport,
            anisette,
            device,
            session,
        }
    }
    pub async fn fetch(&mut self, dataset: Dataset) -> Result<FetchedDataset> {
        let (container, zone) = dataset_info(dataset);
        let user = self.container_user(container).await?;
        let token = self
            .session
            .mme
            .tokens
            .get("cloudKitToken")
            .ok_or(Error::AuthenticationRequired)?
            .clone();
        let mut pages = Vec::new();
        let mut continuation = None;
        loop {
            let operation = record_changes_operation(
                &self.device,
                container,
                zone,
                &user,
                continuation.as_deref(),
            );
            let mut framed = Vec::new();
            wire::encode_varint(operation.len() as u64, &mut framed);
            framed.extend(operation);
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&framed)?;
            let body = encoder.finish()?;
            let headers = self
                .common_headers(container)
                .await?
                .into_iter()
                .chain([
                    ("x-cloudkit-userid".into(), user.clone()),
                    ("x-cloudkit-authtoken".into(), token.clone()),
                ])
                .collect();
            let response = self
                .transport
                .send(HttpRequest {
                    method: "POST".into(),
                    url: "https://gateway.icloud.com/ckdatabase/api/client/record/sync".into(),
                    headers,
                    body,
                })
                .await?;
            if response.status / 100 != 2 {
                return Err(Error::Network(format!(
                    "CloudKit returned HTTP {}",
                    response.status
                )));
            }
            let messages = wire::decode_delimited(&response.body)
                .or_else(|_| Message::parse(&response.body).map(|m| vec![m]))?;
            let specific = messages
                .iter()
                .find_map(|m| m.first_bytes(213))
                .ok_or(Error::Protobuf("missing record-change response"))?;
            let parsed = parse_changes(specific)?;
            continuation = parsed.1.clone();
            pages.push(parsed.0);
            if pages.last().unwrap().status != 1 || continuation.is_none() {
                break;
            }
        }
        Ok(FetchedDataset {
            container: container.into(),
            zone: zone.into(),
            database: "private".into(),
            fetched_at: chrono::Utc::now().to_rfc3339(),
            pages,
        })
    }

    /// Apply one prepared compare-and-swap update. This API is deliberately
    /// feature-gated and refuses a stale source record or inexact confirmation.
    #[cfg(feature = "experimental-live-writes")]
    pub async fn apply_prepared_update(
        &mut self,
        plan: &PreparedFieldUpdate,
        confirm_record: &str,
    ) -> Result<FetchedDataset> {
        if confirm_record != plan.metadata.record_name {
            return Err(Error::Fixture(
                "write confirmation does not exactly match the record name".into(),
            ));
        }
        let fresh = self.fetch(plan.metadata.dataset).await?;
        let source = fetched_record_bytes(&fresh, &plan.metadata.record_name)?;
        if hex::encode(Sha256::digest(&source)) != plan.original_record_sha256 {
            return Err(Error::Fixture(
                "record changed after the update was prepared; prepare it again".into(),
            ));
        }
        plan.validate_against_source(&source)?;
        let request = plan.encode_record_save_request()?;
        self.send_mutation(plan.metadata.dataset, 210, &request, 210)
            .await?;
        let after = self.fetch(plan.metadata.dataset).await?;
        let current = Message::parse(&fetched_record_bytes(&after, &plan.metadata.record_name)?)?;
        if current.first_bytes(1) == Some(plan.metadata.etag.as_bytes()) {
            return Err(Error::Integrity);
        }
        Ok(after)
    }

    /// Apply one prepared etag-guarded delete without retrying conflicts.
    #[cfg(feature = "experimental-live-writes")]
    pub async fn apply_prepared_delete(
        &mut self,
        plan: &PreparedDelete,
        confirm_record: &str,
    ) -> Result<FetchedDataset> {
        if confirm_record != plan.metadata.record_name {
            return Err(Error::Fixture(
                "write confirmation does not exactly match the record name".into(),
            ));
        }
        let fresh = self.fetch(plan.metadata.dataset).await?;
        let source = fetched_record_bytes(&fresh, &plan.metadata.record_name)?;
        if hex::encode(Sha256::digest(&source)) != plan.source_record_sha256 {
            return Err(Error::Fixture(
                "record changed after the delete was prepared; prepare it again".into(),
            ));
        }
        let request = plan.encode_record_delete_request()?;
        self.send_mutation(plan.metadata.dataset, 214, &request, 214)
            .await?;
        let after = self.fetch(plan.metadata.dataset).await?;
        if fetched_record_bytes_optional(&after, &plan.metadata.record_name)?.is_some() {
            return Err(Error::Integrity);
        }
        Ok(after)
    }

    /// Create one PCS-protected Safari record and authenticate its returned fields.
    #[cfg(feature = "experimental-live-writes")]
    pub async fn apply_prepared_create(&mut self, plan: &PreparedCreate) -> Result<FetchedDataset> {
        let fresh = self.fetch(plan.dataset).await?;
        if fresh.zone != plan.zone
            || fetched_record_bytes_optional(&fresh, &plan.record_name)?.is_some()
        {
            return Err(Error::Integrity);
        }
        let current_zone_tag = fresh
            .pages
            .iter()
            .find_map(|page| {
                STANDARD
                    .decode(&page.raw_response_base64)
                    .ok()
                    .and_then(|raw| zone_protection_tag(&raw).ok())
            })
            .ok_or(Error::Protobuf(
                "fresh response omitted zone protection tag",
            ))?;
        if current_zone_tag != plan.zone_protection_info_tag {
            return Err(Error::Fixture(
                "zone protection changed after record creation was prepared".into(),
            ));
        }
        self.send_mutation(plan.dataset, 210, &plan.encode_record_save_request()?, 210)
            .await?;
        let after = self.fetch(plan.dataset).await?;
        let raw = fetched_record_bytes(&after, &plan.record_name)?;
        let record = Message::parse(&raw)?;
        if record.first_bytes(3).and_then(identifier_name).as_deref()
            != Some(plan.record_type.as_str())
        {
            return Err(Error::Integrity);
        }
        let protection = Message::parse(
            record
                .first_bytes(13)
                .ok_or(Error::Protobuf("created record omitted PCS protection"))?,
        )?;
        if protection.first_bytes(2) != Some(plan.record_protection_info_tag.as_bytes()) {
            return Err(Error::Integrity);
        }
        for (name, expected) in &plan.expected_fields {
            let blob = encrypted_record_field(&record, name)?;
            let context = format!("{}-{}-{name}", plan.zone, plan.record_name);
            let plaintext = crate::crypto::fp_v3_decrypt(&plan.master_key, name.as_bytes(), &blob)
                .or_else(|_| {
                    crate::crypto::fp_v3_decrypt(&plan.master_key, context.as_bytes(), &blob)
                })?;
            if plaintext.as_slice() != expected.as_slice() {
                return Err(Error::Integrity);
            }
        }
        Ok(after)
    }

    #[cfg(feature = "experimental-live-writes")]
    async fn send_mutation(
        &mut self,
        dataset: Dataset,
        operation_type: u64,
        specific: &[u8],
        response_field: u32,
    ) -> Result<()> {
        let (container, _) = dataset_info(dataset);
        let user = self.container_user(container).await?;
        let token = self
            .session
            .mme
            .tokens
            .get("cloudKitToken")
            .ok_or(Error::AuthenticationRequired)?
            .clone();
        let operation = mutation_operation(
            &self.device,
            container,
            operation_type,
            response_field,
            specific,
        );
        let mut framed = Vec::new();
        wire::encode_varint(operation.len() as u64, &mut framed);
        framed.extend(operation);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&framed)?;
        let headers = self
            .common_headers(container)
            .await?
            .into_iter()
            .chain([
                ("x-cloudkit-userid".into(), user),
                ("x-cloudkit-authtoken".into(), token),
            ])
            .collect();
        let endpoint = if operation_type == 210 {
            "save"
        } else {
            "delete"
        };
        let response = self
            .transport
            .send(HttpRequest {
                method: "POST".into(),
                url: format!("https://gateway.icloud.com/ckdatabase/api/client/record/{endpoint}"),
                headers,
                body: encoder.finish()?,
            })
            .await?;
        if response.status / 100 != 2 {
            return Err(Error::Network(format!(
                "CloudKit returned HTTP {}",
                response.status
            )));
        }
        let messages = wire::decode_delimited(&response.body)
            .or_else(|_| Message::parse(&response.body).map(|message| vec![message]))?;
        let response = messages
            .iter()
            .find(|message| message.first_bytes(3).is_some())
            .ok_or(Error::Protobuf("mutation response omitted result"))?;
        let result = Message::parse(
            response
                .first_bytes(3)
                .ok_or(Error::Protobuf("mutation response omitted result"))?,
        )?;
        if result.first_varint(1) != Some(1) {
            return Err(Error::Network(format!(
                "CloudKit rejected the mutation ({})",
                summarize_result(&result)
            )));
        }
        if response.first_bytes(response_field).is_none() {
            return Err(Error::Protobuf("missing mutation response"));
        }
        Ok(())
    }
    async fn container_user(&mut self, container: &str) -> Result<String> {
        if let Some(value) = self.session.safari_cloudkit_users.get(container) {
            return Ok(value.clone());
        }
        let auth = STANDARD.encode(format!(
            "{}:{}",
            self.session.mme.dsid, self.session.mme.mme_auth_token
        ));
        let headers = self
            .common_headers(container)
            .await?
            .into_iter()
            .chain([("authorization".into(), format!("Basic {auth}"))])
            .collect();
        let response = self
            .transport
            .send(HttpRequest {
                method: "POST".into(),
                url: format!(
                    "https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit?container={container}"
                ),
                headers,
                body: Vec::new(),
            })
            .await?;
        let value: serde_json::Value = serde_json::from_slice(&response.body)?;
        let user = value
            .get("cloudKitUserId")
            .and_then(|v| v.as_str())
            .ok_or(Error::Protobuf("ckAppInit omitted user ID"))?
            .to_owned();
        self.session
            .safari_cloudkit_users
            .insert(container.into(), user.clone());
        Ok(user)
    }
    async fn common_headers(&self, container: &str) -> Result<Vec<(String, String)>> {
        let op = || format!("{:016X}", rand::random::<u64>());
        let mut headers=vec![
            ("accept".into(),"application/x-protobuf".into()),("accept-encoding".into(),"gzip".into()),("accept-language".into(),"en-US,en;q=0.9".into()),("cache-control".into(),"no-transform".into()),("content-encoding".into(),"gzip".into()),
            ("content-type".into(),"application/x-protobuf; desc=\"https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc\"; messageType=RequestOperation; delimited=true".into()),("user-agent".into(),"CloudKit/1970 (19H384)".into()),
            ("x-apple-operation-group-id".into(),op()),("x-apple-operation-id".into(),op()),("x-apple-request-uuid".into(),uuid::Uuid::new_v4().to_string().to_uppercase()),("x-cloudkit-bundleid".into(),"com.apple.Safari".into()),("x-cloudkit-containerid".into(),container.into()),("x-cloudkit-databasescope".into(),"Private".into()),("x-cloudkit-environment".into(),"Production".into()),("x-cloudkit-duetpreclearedmode".into(),"None".into()),("x-apple-c2-metric-triggers".into(),"0".into()),
            ("x-mme-client-info".into(),"<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)>".into())];
        headers.extend(crate::anisette::identity_headers(&self.anisette, &self.device).await?);
        Ok(headers)
    }
}

#[cfg(feature = "experimental-live-writes")]
fn summarize_result(result: &Message) -> String {
    fn walk(message: &Message, depth: usize, output: &mut Vec<String>) {
        if depth > 3 {
            return;
        }
        for field in &message.fields {
            match &field.value {
                Value::Varint(value) => output.push(format!("{}.{}={value}", depth, field.number)),
                Value::Bytes(value) => {
                    if let Ok(nested) = Message::parse(value) {
                        walk(&nested, depth + 1, output);
                    } else {
                        output.push(format!(
                            "{}.{}=<{} bytes>",
                            depth,
                            field.number,
                            value.len()
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    let mut output = Vec::new();
    walk(result, 0, &mut output);
    output.join(", ")
}

#[cfg(feature = "experimental-live-writes")]
fn fetched_record_bytes(dataset: &FetchedDataset, name: &str) -> Result<Vec<u8>> {
    fetched_record_bytes_optional(dataset, name)?
        .ok_or_else(|| Error::Fixture(format!("record {name:?} is no longer present")))
}

#[cfg(feature = "experimental-live-writes")]
fn fetched_record_bytes_optional(dataset: &FetchedDataset, name: &str) -> Result<Option<Vec<u8>>> {
    dataset
        .pages
        .iter()
        .flat_map(|page| &page.records)
        .find(|record| record.name == name)
        .map(|record| {
            STANDARD
                .decode(&record.raw_record_base64)
                .map_err(|_| Error::Protobuf("fetched record has invalid base64"))
        })
        .transpose()
}

#[cfg(feature = "experimental-live-writes")]
fn encrypted_record_field(record: &Message, wanted: &str) -> Result<Vec<u8>> {
    for field in record.values(7) {
        let Value::Bytes(field) = field else {
            continue;
        };
        let field = Message::parse(field)?;
        if field.first_bytes(1).and_then(identifier_name).as_deref() != Some(wanted) {
            continue;
        }
        let value = Message::parse(
            field
                .first_bytes(2)
                .ok_or(Error::Protobuf("created field omitted value"))?,
        )?;
        if value.first_varint(13) != Some(1) {
            return Err(Error::Integrity);
        }
        return value
            .first_bytes(2)
            .map(ToOwned::to_owned)
            .ok_or(Error::Protobuf("created encrypted field omitted bytes"));
    }
    Err(Error::Protobuf("created record omitted expected field"))
}

fn dataset_info(dataset: Dataset) -> (&'static str, &'static str) {
    match dataset {
        Dataset::Tabs => ("com.apple.SafariShared.CloudTabs", "CloudTabs"),
        Dataset::Bookmarks => ("com.apple.SafariShared.WBSCloudBookmarksStore", "Bookmarks"),
        Dataset::History => ("com.apple.SafariShared.History", "History"),
    }
}
fn identifier(name: &str, kind: u64) -> Vec<u8> {
    let mut x = Vec::new();
    wire::encode_string(1, name, &mut x);
    wire::encode_uint(2, kind, &mut x);
    x
}
fn request_header(device: &DeviceState, container: &str) -> Vec<u8> {
    let mut header = Vec::new();
    wire::encode_string(2, container, &mut header);
    wire::encode_string(3, "com.apple.Safari", &mut header);
    wire::encode_bytes(7, &identifier(&device.device_uuid, 2), &mut header);
    wire::encode_string(8, "macOS 13.4.1 (22F8)", &mut header);
    wire::encode_string(9, "MacBookPro18,3", &mut header);
    wire::encode_string(10, "com.apple.cloudkit.CloudKitDaemon", &mut header);
    wire::encode_string(11, "1970", &mut header);
    wire::encode_string(18, "5.0", &mut header);
    wire::encode_uint(19, 1, &mut header);
    wire::encode_string(21, "icloud-safari", &mut header);
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
    header
}
fn record_changes_operation(
    device: &DeviceState,
    container: &str,
    zone: &str,
    user: &str,
    continuation: Option<&[u8]>,
) -> Vec<u8> {
    let header = request_header(device, container);
    let uuid = uuid::Uuid::new_v4().to_string().to_uppercase();
    let mut op = Vec::new();
    wire::encode_string(1, &uuid, &mut op);
    wire::encode_uint(2, 213, &mut op);
    wire::encode_uint(4, 1, &mut op);
    let mut zone_id = Vec::new();
    wire::encode_bytes(1, &identifier(zone, 6), &mut zone_id);
    wire::encode_bytes(2, &identifier(user, 7), &mut zone_id);
    let mut changes = Vec::new();
    if let Some(c) = continuation {
        wire::encode_bytes(1, c, &mut changes)
    }
    wire::encode_bytes(2, &zone_id, &mut changes);
    wire::encode_uint(4, 500, &mut changes);
    let mut request = Vec::new();
    wire::encode_bytes(1, &header, &mut request);
    wire::encode_bytes(2, &op, &mut request);
    wire::encode_bytes(213, &changes, &mut request);
    request
}

#[cfg(feature = "experimental-live-writes")]
fn mutation_operation(
    device: &DeviceState,
    container: &str,
    operation_type: u64,
    operation_field: u32,
    specific: &[u8],
) -> Vec<u8> {
    let mut operation = Vec::new();
    wire::encode_string(
        1,
        &uuid::Uuid::new_v4().to_string().to_uppercase(),
        &mut operation,
    );
    wire::encode_uint(2, operation_type, &mut operation);
    wire::encode_uint(4, 1, &mut operation);
    let mut request = Vec::new();
    wire::encode_bytes(1, &request_header(device, container), &mut request);
    wire::encode_bytes(2, &operation, &mut request);
    wire::encode_bytes(operation_field, specific, &mut request);
    request
}

fn nested_string(bytes: &[u8]) -> Option<String> {
    let msg = Message::parse(bytes).ok()?;
    for value in msg.values(1) {
        if let Value::Bytes(b) = value {
            if let Ok(s) = std::str::from_utf8(b) {
                return Some(s.into());
            }
            if let Some(s) = nested_string(b) {
                return Some(s);
            }
        }
    }
    None
}
fn identifier_name(bytes: &[u8]) -> Option<String> {
    let message = Message::parse(bytes).ok()?;
    std::str::from_utf8(message.first_bytes(1)?)
        .ok()
        .map(str::to_owned)
}
fn record_identifier_name(bytes: &[u8]) -> Option<String> {
    let message = Message::parse(bytes).ok()?;
    identifier_name(message.first_bytes(1)?)
}
fn parse_changes(bytes: &[u8]) -> Result<(FetchedPage, Option<Vec<u8>>)> {
    let msg = Message::parse(bytes)?;
    let status = msg.first_varint(4).unwrap_or(0);
    let token = msg.first_bytes(2).map(Vec::from);
    let mut records = Vec::new();
    for change in msg.values(1) {
        let Value::Bytes(change) = change else {
            continue;
        };
        let change = Message::parse(change)?;
        let Some(record_bytes) = change.first_bytes(5) else {
            continue;
        };
        let record = Message::parse(record_bytes)?;
        let name = record
            .first_bytes(2)
            .and_then(record_identifier_name)
            .unwrap_or_default();
        let record_type = record
            .first_bytes(3)
            .and_then(identifier_name)
            .unwrap_or_default();
        let mut fields = BTreeMap::new();
        for f in record.values(7) {
            let Value::Bytes(f) = f else { continue };
            let f = Message::parse(f)?;
            let Some(field_name) = f.first_bytes(1).and_then(identifier_name) else {
                continue;
            };
            let Some(v) = f.first_bytes(2) else { continue };
            fields.insert(field_name, parse_value(v)?);
        }
        records.push(FetchedRecord {
            name,
            record_type,
            fields,
            raw_record_base64: STANDARD.encode(record_bytes),
        });
    }
    Ok((
        FetchedPage {
            raw_response_base64: STANDARD.encode(bytes),
            status,
            records,
            continuation_token_base64: token.as_ref().map(|v| STANDARD.encode(v)),
        },
        token,
    ))
}
fn parse_value(bytes: &[u8]) -> Result<serde_json::Value> {
    let m = Message::parse(bytes)?;
    if let Some(v) = m.first_bytes(2) {
        return Ok(serde_json::json!({"type":"bytes","base64":STANDARD.encode(v)}));
    }
    if let Some(v) = m.first_varint(4) {
        return Ok(serde_json::json!(v as i64));
    }
    if let Some(Value::Fixed64(v)) = m.values(5).next() {
        return Ok(serde_json::json!(f64::from_bits(*v)));
    }
    if let Some(v) = m.first_bytes(6) {
        let d = Message::parse(v)?;
        if let Some(Value::Fixed64(v)) = d.values(1).next() {
            return Ok(serde_json::json!({"type":"date","unix_seconds":f64::from_bits(*v)}));
        }
    }
    if let Some(v) = m.first_bytes(7) {
        return Ok(serde_json::json!(String::from_utf8_lossy(v)));
    }
    if let Some(v) = m.first_bytes(9) {
        return Ok(serde_json::json!(nested_string(v).unwrap_or_default()));
    }
    Ok(serde_json::json!({"type":"bytes","base64":STANDARD.encode(bytes)}))
}

#[cfg(all(test, feature = "experimental-live-writes"))]
mod write_tests {
    use super::*;

    #[test]
    fn wraps_mutations_in_the_generated_operation_slot() {
        let device = DeviceState {
            device_uuid: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".into(),
            serial: "SERIAL".into(),
            local_user_uuid: "LOCAL".into(),
        };
        let encoded = mutation_operation(&device, "container", 210, 210, b"save");
        let request = Message::parse(&encoded).unwrap();
        assert!(request.first_bytes(1).is_some());
        let operation = Message::parse(request.first_bytes(2).unwrap()).unwrap();
        assert_eq!(operation.first_varint(2), Some(210));
        assert_eq!(operation.first_varint(4), Some(1));
        assert_eq!(request.first_bytes(210), Some(b"save".as_slice()));
    }
}
