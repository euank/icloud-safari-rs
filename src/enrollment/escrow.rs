//! Escrow SRP recovery. One invocation makes at most one recovery attempt.
use crate::{
    Error, Result,
    account::GrandSlamCredentials,
    anisette::identity_headers,
    cloudkit::{AnisetteProvider, DeviceState, HttpRequest, HttpTransport, SessionState},
};
use aes::{Aes128, Aes256};
use aes_gcm::{
    AesGcm,
    aead::{
        AeadInPlace, KeyInit,
        consts::{U12, U16, U32},
        generic_array::GenericArray,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub struct EscrowClient<'a, T, A> {
    transport: T,
    anisette: A,
    device: DeviceState,
    session: &'a SessionState,
    credentials: &'a GrandSlamCredentials,
    host: String,
}

/// Authenticate selection against GETRECORDS before spending a recovery attempt.
/// Returns only the device model, never the full backup metadata.
pub fn record_model(
    records: &plist::Value,
    label: &str,
    bottle_id: &str,
) -> Result<Option<String>> {
    let entries = records
        .as_dictionary()
        .and_then(|d| d.get("metadataList"))
        .and_then(plist::Value::as_array)
        .ok_or(Error::Integrity)?;
    let mut matching = entries
        .iter()
        .filter_map(plist::Value::as_dictionary)
        .filter(|entry| entry.get("label").and_then(plist::Value::as_string) == Some(label));
    let record = matching.next().ok_or_else(|| {
        Error::Authentication("viable bottle has no matching escrow record label".into())
    })?;
    if matching.next().is_some() {
        return Err(Error::Integrity);
    }
    let encoded = blob(record.get("metadata").ok_or(Error::Integrity)?)?;
    let metadata = plist::Value::from_reader(std::io::Cursor::new(&*encoded))?;
    let metadata = metadata.as_dictionary().ok_or(Error::Integrity)?;
    if let Some(id) = metadata.get("bottleID")
        && id.as_string() != Some(bottle_id)
    {
        return Err(Error::Integrity);
    }
    let client = metadata
        .get("ClientMetadata")
        .or_else(|| metadata.get("clientMetadata"))
        .and_then(plist::Value::as_dictionary);
    Ok(client
        .and_then(|client| {
            ["device_model", "model", "ProductType"]
                .iter()
                .find_map(|key| client.get(key).and_then(plist::Value::as_string))
        })
        .map(str::to_owned))
}
impl<'a, T: HttpTransport, A: AnisetteProvider> EscrowClient<'a, T, A> {
    pub fn new(
        transport: T,
        anisette: A,
        device: DeviceState,
        session: &'a SessionState,
        credentials: &'a GrandSlamCredentials,
    ) -> Result<Self> {
        let settings = session
            .mme
            .extra
            .get("accountSettings")
            .ok_or(Error::Authentication(
                "refresh account settings before recovery".into(),
            ))?;
        let account_adsid = settings
            .get("appleAccountInfo")
            .and_then(|info| info.get("aDsID"))
            .or_else(|| settings.get("adsid"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Error::Authentication(
                    "refresh account settings before escrow: account identifier missing".into(),
                )
            })?;
        if account_adsid != credentials.adsid || credentials.pet.is_empty() {
            return Err(Error::Authentication(
                "escrow credentials belong to another account or have no PET".into(),
            ));
        }
        let service = settings
            .get("com.apple.mobileme")
            .and_then(|services| services.get("com.apple.Dataclass.KeychainSync"))
            .or_else(|| {
                settings.get("webservices").and_then(|services| {
                    services
                        .get("keychainSync")
                        .or_else(|| services.get("keychainsync"))
                })
            })
            .ok_or(Error::Authentication(
                "account has no KeychainSync service".into(),
            ))?;
        let host = ["escrowProxyUrl", "url", "wsUrl", "configURL"]
            .iter()
            .find_map(|key| service.get(key).and_then(serde_json::Value::as_str))
            .ok_or(Error::Authentication("account omitted escrow URL".into()))?;
        let url = reqwest::Url::parse(host).map_err(|_| Error::Integrity)?;
        if url.scheme() != "https"
            || !url
                .host_str()
                .is_some_and(|host| host.ends_with(".icloud.com"))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
        {
            return Err(Error::Authentication(
                "invalid Apple escrow service URL".into(),
            ));
        }
        Ok(Self {
            transport,
            anisette,
            device,
            session,
            credentials,
            host: format!("https://{}", url.host_str().unwrap()),
        })
    }

    async fn command(
        &self,
        slug: &str,
        command: &str,
        label: &str,
        transaction: &str,
        extra: plist::Dictionary,
    ) -> Result<plist::Value> {
        let mut body = plist::Dictionary::new();
        for (key, value) in [
            ("command", command),
            ("label", label),
            ("transactionUUID", transaction),
            ("userActionLabel", "icloud-safari Rust client key recovery"),
        ] {
            body.insert(key.into(), value.into());
        }
        body.insert("version".into(), 1u64.into());
        body.extend(extra);
        let mut encoded = Zeroizing::new(Vec::new());
        plist::Value::Dictionary(body).to_writer_xml(&mut *encoded)?;
        let mut headers = identity_headers(&self.anisette, &self.device).await?;
        headers.extend([
            ("Authorization".into(), format!("Basic {}", STANDARD.encode(format!("{}:{}", self.session.username, self.credentials.pet)))),
            ("Content-Type".into(), "application/x-apple-plst".into()),
            ("User-Agent".into(), "com.apple.sbd/638.100.48 com.apple.iCloudHelper/282".into()),
            ("X-Mme-Client-Info".into(), "<MacBookPro18,3> <macOS;13.4.1;22F8> <com.apple.AuthKit/1 (com.apple.sbd/638.100.48)>".into()),
            ("Accept".into(), "*/*".into()), ("X-Apple-I-Locale".into(), "en_US".into()),
            ("Accept-Language".into(), "en-US,en;q=0.9".into()),
            ("x-apple-i-device-type".into(), "1".into()),
        ]);
        let response = self
            .transport
            .send(HttpRequest {
                method: "POST".into(),
                url: format!("{}/escrowproxy/api/{slug}", self.host),
                headers,
                body: encoded.to_vec(),
            })
            .await?;
        if response.status / 100 != 2 {
            let status = plist::Value::from_reader(std::io::Cursor::new(&response.body))
                .ok()
                .and_then(|value| rejection_status(&value));
            return Err(Error::Authentication(format!(
                "escrow {command} failed (HTTP {}, server status {}); no retry was attempted",
                response.status,
                status
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "unavailable".into())
            )));
        }
        let value = plist::Value::from_reader(std::io::Cursor::new(response.body))?;
        let dict = value.as_dictionary().ok_or(Error::Integrity)?;
        if dict.get("success").and_then(plist::Value::as_boolean) == Some(false)
            || rejection_status(&value).is_some_and(|status| status != 0)
            || dict
                .get("errorCode")
                .is_some_and(|value| value.as_signed_integer().unwrap_or(-1) != 0)
        {
            return Err(Error::Authentication(format!(
                "escrow {command} rejected; no retry was attempted"
            )));
        }
        Ok(value)
    }

    /// Non-mutating metadata listing; returned labels address recovery records.
    pub async fn records(&self) -> Result<plist::Value> {
        self.command(
            "get_records",
            "GETRECORDS",
            "com.apple.securebackup.record",
            &uuid::Uuid::new_v4().to_string().to_uppercase(),
            plist::Dictionary::new(),
        )
        .await
    }

    pub async fn recover(&self, label: &str, passcode: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if !cfg!(feature = "experimental-live-writes") {
            return Err(Error::Unsupported(
                "escrow recovery is disabled in this build",
            ));
        }
        if passcode.is_empty() || label.is_empty() {
            return Err(Error::Integrity);
        }
        let mut private = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *private);
        let a = BigUint::from_bytes_be(&private[..]);
        let public = BigUint::from(2u8)
            .modpow(&a, &crate::auth::modulus())
            .to_bytes_be();
        let transaction = uuid::Uuid::new_v4().to_string().to_uppercase();
        let init = self
            .command("srp_init", "SRP_INIT", label, &transaction, fields(&public))
            .await?;
        let dict = init.as_dictionary().ok_or(Error::Integrity)?;
        let dsid = dict
            .get("dsid")
            .and_then(|value| {
                value
                    .as_string()
                    .map(str::to_owned)
                    .or_else(|| value.as_unsigned_integer().map(|n| n.to_string()))
            })
            .ok_or(Error::Integrity)?;
        let club = dict
            .get("clubTypeID")
            .and_then(plist::Value::as_unsigned_integer)
            == Some(1);
        let blob = blob(dict.get("respBlob").ok_or(Error::Integrity)?)?;
        let (mut header, sections) = unframe(&blob, 24, 3)?;
        let (proof, expected, key) =
            srp_proof(&private[..], &dsid, passcode, &sections[1], &sections[2])?;
        header[0..4].copy_from_slice(&165u32.to_be_bytes());
        header[4..8].copy_from_slice(&(if club { 2u32 } else { 0u32 }).to_be_bytes());
        let mut extra = fields(&frame(&header, &[(&sections[0], 20), (&proof, 36)])?);
        extra.insert("dsid".into(), dsid.into());
        let recovered = self
            .command("recover", "RECOVER", label, &transaction, extra)
            .await?;
        let recovered = blob_value(&recovered, "respBlob")?;
        recover_entropy(&recovered, club, &expected, &key[..], passcode)
    }
}

fn rejection_status(value: &plist::Value) -> Option<i64> {
    let dict = value.as_dictionary()?;
    ["status", "errorCode"]
        .iter()
        .filter_map(|key| dict.get(key))
        .find_map(|value| {
            value
                .as_signed_integer()
                .or_else(|| value.as_string().and_then(|text| text.parse().ok()))
        })
}

fn recover_entropy(
    recovered: &[u8],
    club: bool,
    expected: &[u8],
    session_key: &[u8],
    passcode: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let (header, sections) = unframe(recovered, if club { 40 } else { 24 }, 3)?;
    if sections[0].len() != 32 || sections[0].ct_eq(expected).unwrap_u8() != 1 {
        return Err(Error::Integrity);
    }
    let outer = match word(&header, 4)? {
        // The legacy capture and independent implementation use opposite
        // section orders. The IV is exactly one block; the framed inner
        // payload is necessarily longer. Never retry the network exchange.
        0 if sections[1].len() == 16 && sections[2].len() > 16 => {
            cbc256(session_key, &sections[1], &sections[2])?
        }
        0 if sections[2].len() == 16 && sections[1].len() > 16 => {
            cbc256(session_key, &sections[2], &sections[1])?
        }
        0 => return Err(Error::Integrity),
        2 => {
            let split = sections[2].len().checked_sub(16).ok_or(Error::Integrity)?;
            gcm_decrypt(
                session_key,
                &sections[1],
                &sections[2][..split],
                &sections[2][split..],
            )?
        }
        _ => return Err(Error::Unsupported("unknown escrow ciphertext version")),
    };
    let (header, sections) = unframe(&outer, 16, 6)?;
    let rounds = word(&header, 8)?;
    if rounds == 0 || rounds > 10_000_000 || sections[1].len() < 16 {
        return Err(Error::Integrity);
    }
    let mut key = Zeroizing::new([0u8; 16]);
    pbkdf2::pbkdf2_hmac::<Sha256>(passcode, &sections[1], rounds, &mut *key);
    let mut plaintext = Zeroizing::new(sections[3].clone());
    let decrypted = cbc::Decryptor::<Aes128>::new_from_slices(&key[..], &sections[1][..16])
        .map_err(|_| Error::Integrity)?
        .decrypt_padded_mut::<Pkcs7>(&mut plaintext)
        .map_err(|_| Error::Integrity)?;
    let plist = plist::Value::from_reader(std::io::Cursor::new(decrypted))?;
    let entropy = blob_value(&plist, "BottledPeerEntropy")?;
    if entropy.is_empty() {
        return Err(Error::Integrity);
    }
    Ok(entropy)
}

fn fields(bytes: &[u8]) -> plist::Dictionary {
    let mut result = plist::Dictionary::new();
    result.insert("blob".into(), STANDARD.encode(bytes).into());
    for name in ["baseRootCertVersions", "trustedRootCertVersions"] {
        result.insert(
            name.into(),
            plist::Value::Array(
                [101u64, 102, 103, 500]
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            ),
        );
    }
    result
}
fn blob_value(value: &plist::Value, key: &str) -> Result<Zeroizing<Vec<u8>>> {
    blob(
        value
            .as_dictionary()
            .and_then(|dict| dict.get(key))
            .ok_or(Error::Integrity)?,
    )
}
fn blob(value: &plist::Value) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(bytes) = value.as_data() {
        return Ok(Zeroizing::new(bytes.to_vec()));
    }
    STANDARD
        .decode(value.as_string().ok_or(Error::Integrity)?)
        .map(Zeroizing::new)
        .map_err(|_| Error::Integrity)
}
fn word(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Integrity)?
            .try_into()
            .unwrap(),
    ))
}
type Sections = (Vec<u8>, Zeroizing<Vec<Vec<u8>>>);
fn unframe(bytes: &[u8], header: usize, count: usize) -> Result<Sections> {
    let base = 4 + header + (count + 1) * 4;
    if bytes.len() < base || word(bytes, 0)? as usize != bytes.len() {
        return Err(Error::Integrity);
    }
    let mut sections = Vec::new();
    if word(bytes, 4 + header)? != 0
        || word(bytes, 4 + header + count * 4)? as usize != bytes.len() - base
    {
        return Err(Error::Integrity);
    }
    for i in 0..count {
        let start = base
            .checked_add(word(bytes, 4 + header + i * 4)? as usize)
            .ok_or(Error::Integrity)?;
        let end = base
            .checked_add(word(bytes, 4 + header + (i + 1) * 4)? as usize)
            .ok_or(Error::Integrity)?;
        let size = word(bytes, start)? as usize;
        if end > bytes.len() || start.checked_add(4 + size).is_none_or(|value| value > end) {
            return Err(Error::Integrity);
        }
        sections.push(bytes[start + 4..start + 4 + size].to_vec());
    }
    Ok((bytes[4..4 + header].to_vec(), Zeroizing::new(sections)))
}
fn frame(header: &[u8], sections: &[(&[u8], usize)]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut offsets = Vec::new();
    for (data, footprint) in sections {
        if *footprint < data.len() + 4 {
            return Err(Error::Integrity);
        }
        offsets.extend_from_slice(&(body.len() as u32).to_be_bytes());
        body.extend_from_slice(&(data.len() as u32).to_be_bytes());
        body.extend_from_slice(data);
        body.resize(body.len() + footprint - data.len() - 4, 0);
    }
    offsets.extend_from_slice(&(body.len() as u32).to_be_bytes());
    Ok([
        ((4 + header.len() + offsets.len() + body.len()) as u32)
            .to_be_bytes()
            .to_vec(),
        header.to_vec(),
        offsets,
        body,
    ]
    .concat())
}
type Proof = ([u8; 32], [u8; 32], Zeroizing<[u8; 32]>);
fn srp_proof(
    private: &[u8],
    username: &str,
    password: &[u8],
    salt: &[u8],
    server: &[u8],
) -> Result<Proof> {
    let n = crate::auth::modulus();
    let g = BigUint::from(2u8);
    let a = BigUint::from_bytes_be(private);
    let b = BigUint::from_bytes_be(server);
    if a == BigUint::default() || b == BigUint::default() || b >= n {
        return Err(Error::Integrity);
    }
    let server = b.to_bytes_be();
    let public = g.modpow(&a, &n).to_bytes_be();
    let inner = Sha256::digest([username.as_bytes(), b":", password].concat());
    let x = BigUint::from_bytes_be(&Sha256::digest([salt, inner.as_slice()].concat()));
    let k = BigUint::from_bytes_be(&Sha256::digest(
        [crate::auth::pad(&n), crate::auth::pad(&g)].concat(),
    ));
    let u = BigUint::from_bytes_be(&Sha256::digest(
        [
            crate::auth::pad(&BigUint::from_bytes_be(&public)),
            crate::auth::pad(&b),
        ]
        .concat(),
    ));
    if u == BigUint::default() {
        return Err(Error::Integrity);
    }
    let shared = ((&b + &n - ((&k * g.modpow(&x, &n)) % &n)) % &n).modpow(&(&a + &u * &x), &n);
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(Sha256::digest(shared.to_bytes_be()).into());
    let xor: Vec<u8> = Sha256::digest(crate::auth::pad(&n))
        .iter()
        .zip(Sha256::digest(crate::auth::pad(&g)))
        .map(|(a, b)| a ^ b)
        .collect();
    let proof: [u8; 32] = Sha256::digest(
        [
            xor.as_slice(),
            Sha256::digest(username.as_bytes()).as_slice(),
            salt,
            public.as_slice(),
            server.as_slice(),
            &key[..],
        ]
        .concat(),
    )
    .into();
    let expected = Sha256::digest([public.as_slice(), &proof, &key[..]].concat()).into();
    Ok((proof, expected, key))
}
fn cbc256(key: &[u8], iv: &[u8], body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(body.to_vec());
    let plain = cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| Error::Integrity)?
        .decrypt_padded_mut::<Pkcs7>(&mut bytes)
        .map_err(|_| Error::Integrity)?;
    Ok(Zeroizing::new(plain.to_vec()))
}
pub(super) fn gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    body: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if tag.len() != 16 {
        return Err(Error::Integrity);
    }
    let mut bytes = Zeroizing::new(body.to_vec());
    macro_rules! decrypt {
        ($size:ty) => {{
            AesGcm::<Aes256, $size>::new_from_slice(key)
                .map_err(|_| Error::Integrity)?
                .decrypt_in_place_detached(
                    GenericArray::from_slice(iv),
                    b"",
                    &mut bytes,
                    GenericArray::from_slice(tag),
                )
                .map_err(|_| Error::Integrity)?;
        }};
    }
    match iv.len() {
        12 => decrypt!(U12),
        16 => decrypt!(U16),
        32 => decrypt!(U32),
        _ => return Err(Error::Unsupported("unsupported escrow GCM IV length")),
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escrow_metadata_binds_bottle_and_supports_data_or_base64() {
        let mut meta = plist::Dictionary::new();
        meta.insert("bottleID".into(), "bottle".into());
        let mut client = plist::Dictionary::new();
        client.insert("device_model".into(), "MacBookPro18,3".into());
        meta.insert("ClientMetadata".into(), client.into());
        let mut bytes = Vec::new();
        plist::Value::Dictionary(meta)
            .to_writer_binary(&mut bytes)
            .unwrap();
        for metadata in [
            plist::Value::Data(bytes.clone()),
            plist::Value::String(STANDARD.encode(&bytes)),
        ] {
            let mut entry = plist::Dictionary::new();
            entry.insert("label".into(), "record-label".into());
            entry.insert("metadata".into(), metadata);
            let mut response = plist::Dictionary::new();
            response.insert(
                "metadataList".into(),
                vec![plist::Value::Dictionary(entry.clone())].into(),
            );
            let value = plist::Value::Dictionary(response.clone());
            assert_eq!(
                record_model(&value, "record-label", "bottle")
                    .unwrap()
                    .as_deref(),
                Some("MacBookPro18,3")
            );
            assert!(record_model(&value, "record-label", "wrong-bottle").is_err());
            assert!(record_model(&value, "wrong-label", "bottle").is_err());
            response.insert(
                "metadataList".into(),
                vec![
                    plist::Value::Dictionary(entry.clone()),
                    plist::Value::Dictionary(entry),
                ]
                .into(),
            );
            assert!(record_model(&response.into(), "record-label", "bottle").is_err());
        }
    }
    use crate::cloudkit::HttpResponse;
    use std::{
        collections::{BTreeMap, VecDeque},
        sync::{Arc, Mutex},
    };

    #[derive(Default)]
    struct Exchange {
        replies: VecDeque<(&'static str, plist::Value)>,
        requests: Vec<HttpRequest>,
    }
    #[derive(Clone, Default)]
    struct Script(Arc<Mutex<Exchange>>);
    #[async_trait::async_trait]
    impl HttpTransport for Script {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
            let mut exchange = self.0.lock().unwrap();
            let (slug, reply) = exchange
                .replies
                .pop_front()
                .expect("unexpected escrow request or retry");
            assert_eq!(request.method, "POST");
            assert_eq!(
                request.url,
                format!("https://escrow.icloud.com/escrowproxy/api/{slug}")
            );
            exchange.requests.push(request);
            let mut body = Vec::new();
            reply.to_writer_xml(&mut body).unwrap();
            Ok(HttpResponse {
                status: 200,
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
    #[tokio::test]
    async fn rejection_diagnostics_show_only_numeric_status() {
        struct Reject;
        #[async_trait::async_trait]
        impl HttpTransport for Reject {
            async fn send(&self, _: HttpRequest) -> Result<HttpResponse> {
                let mut dict = plist::Dictionary::new();
                dict.insert("status".into(), "-6015".into());
                dict.insert("message".into(), "private-account-detail-do-not-log".into());
                dict.insert("respBlob".into(), "private-response-do-not-log".into());
                let mut body = Vec::new();
                plist::Value::Dictionary(dict)
                    .to_writer_xml(&mut body)
                    .unwrap();
                Ok(HttpResponse {
                    status: 409,
                    headers: vec![],
                    body,
                })
            }
        }
        let session = session("https://escrow.icloud.com");
        let credentials = credentials();
        let client = EscrowClient::new(
            Reject,
            Anisette,
            DeviceState::generate(),
            &session,
            &credentials,
        )
        .unwrap();
        let message = client.records().await.unwrap_err().to_string();
        assert!(message.contains("409") && message.contains("-6015"));
        assert!(!message.contains("private-account") && !message.contains("private-response"));
    }
    fn session(endpoint: &str) -> SessionState {
        serde_json::from_value(serde_json::json!({
            "username": "test@example.invalid", "dsid": "123",
            "mme": {
                "dsid": "123", "mmeAuthToken": "synthetic", "tokens": {},
                "accountSettings": {"dsid": "123", "adsid": "synthetic-adsid", "webservices": {
                    "keychainSync": {"escrowProxyUrl": endpoint}
                }}
            }
        }))
        .unwrap()
    }
    fn credentials() -> GrandSlamCredentials {
        GrandSlamCredentials {
            adsid: "synthetic-adsid".into(),
            idms_token: "synthetic".into(),
            pet: "synthetic".into(),
        }
    }
    fn client<'a>(
        script: Script,
        session: &'a SessionState,
        credentials: &'a GrandSlamCredentials,
    ) -> Result<EscrowClient<'a, Script, Anisette>> {
        EscrowClient::new(
            script,
            Anisette,
            DeviceState::generate(),
            session,
            credentials,
        )
    }

    #[test]
    fn rejects_untrusted_escrow_endpoints_before_any_request() {
        let credentials = credentials();
        let script = Script::default();
        for endpoint in [
            "http://escrow.icloud.com",
            "https://icloud.com.evil.invalid",
            "https://noticloud.com",
            "https://localhost",
            "https://127.0.0.1",
            "https://user@escrow.icloud.com",
            "https://user:password@escrow.icloud.com",
            "https://escrow.icloud.com:444",
            "not a URL",
        ] {
            assert!(
                client(script.clone(), &session(endpoint), &credentials).is_err(),
                "{endpoint}"
            );
        }
        assert!(
            client(
                script.clone(),
                &session("https://escrow.icloud.com/path"),
                &credentials
            )
            .is_ok()
        );
        assert!(script.0.lock().unwrap().requests.is_empty());
    }

    #[test]
    fn credentials_must_match_authenticated_account_settings() {
        let script = Script::default();
        let mut session = session("https://escrow.icloud.com");
        let mut credentials = credentials();
        credentials.adsid = "another-account".into();
        assert!(client(script.clone(), &session, &credentials).is_err());
        credentials.adsid = "synthetic-adsid".into();
        credentials.pet.clear();
        assert!(client(script.clone(), &session, &credentials).is_err());
        credentials.pet = "synthetic".into();
        session
            .mme
            .extra
            .get_mut("accountSettings")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("adsid");
        assert!(client(script.clone(), &session, &credentials).is_err());
        let settings = session.mme.extra.get_mut("accountSettings").unwrap();
        settings["appleAccountInfo"] = serde_json::json!({"aDsID": "synthetic-adsid"});
        assert!(client(script.clone(), &session, &credentials).is_ok());
        session.mme.extra.get_mut("accountSettings").unwrap()["appleAccountInfo"]["aDsID"] =
            "another-account".into();
        assert!(client(script.clone(), &session, &credentials).is_err());
        assert!(script.0.lock().unwrap().requests.is_empty());
    }

    #[test]
    fn accepts_native_keychain_service_nesting() {
        let script = Script::default();
        let credentials = credentials();
        let mut session = session("https://escrow.icloud.com");
        let settings = session.mme.extra.get_mut("accountSettings").unwrap();
        settings.as_object_mut().unwrap().remove("webservices");
        settings["com.apple.mobileme"] = serde_json::json!({
            "com.apple.Dataclass.KeychainSync": {"url": "https://escrow.icloud.com/ignored/config/path"}
        });
        let client = client(script.clone(), &session, &credentials).unwrap();
        assert_eq!(client.host, "https://escrow.icloud.com");
        assert!(script.0.lock().unwrap().requests.is_empty());
    }

    #[cfg(not(feature = "experimental-live-writes"))]
    #[tokio::test]
    async fn read_only_build_does_not_start_escrow_srp() {
        let script = Script::default();
        let session = session("https://escrow.icloud.com");
        let credentials = credentials();
        let client = client(script.clone(), &session, &credentials).unwrap();
        assert!(matches!(
            client
                .recover("synthetic-record", b"synthetic-passcode")
                .await,
            Err(Error::Unsupported(_))
        ));
        assert!(script.0.lock().unwrap().requests.is_empty());
    }

    #[cfg(feature = "experimental-live-writes")]
    fn init_reply(server: &[u8]) -> plist::Value {
        let framed = frame(
            &[0; 24],
            &[(&[1; 16], 20), (&[2; 16], 20), (server, server.len() + 4)],
        )
        .unwrap();
        let mut dict = plist::Dictionary::new();
        dict.insert("dsid".into(), "123".into());
        dict.insert("clubTypeID".into(), 0u64.into());
        dict.insert("respBlob".into(), STANDARD.encode(framed).into());
        plist::Value::Dictionary(dict)
    }

    #[cfg(feature = "experimental-live-writes")]
    #[tokio::test]
    async fn malformed_srp_init_never_sends_recover() {
        let mut bad_frame = plist::Dictionary::new();
        bad_frame.insert("dsid".into(), "123".into());
        bad_frame.insert("respBlob".into(), STANDARD.encode(b"truncated").into());
        for reply in [
            plist::Value::Dictionary(plist::Dictionary::new()),
            plist::Value::Dictionary(bad_frame),
            init_reply(&[0]),
        ] {
            let script = Script::default();
            script
                .0
                .lock()
                .unwrap()
                .replies
                .push_back(("srp_init", reply));
            let session = session("https://escrow.icloud.com");
            let credentials = credentials();
            let client = client(script.clone(), &session, &credentials).unwrap();
            assert!(
                client
                    .recover("synthetic-record", b"synthetic-passcode")
                    .await
                    .is_err()
            );
            assert_eq!(script.0.lock().unwrap().requests.len(), 1);
        }
    }

    #[cfg(feature = "experimental-live-writes")]
    #[tokio::test]
    async fn rejected_server_proof_consumes_only_one_recovery_attempt() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../fixtures/public/enrollment-vectors.json"
        ))
        .unwrap();
        let server = hex::decode(vectors["srp"]["server_b"].as_str().unwrap()).unwrap();
        let bad_proof = frame(&[0; 24], &[(&[0; 32], 36), (&[0; 16], 20), (&[0; 32], 36)]).unwrap();
        let mut recovered = plist::Dictionary::new();
        recovered.insert("respBlob".into(), STANDARD.encode(bad_proof).into());
        let script = Script::default();
        script.0.lock().unwrap().replies.extend([
            ("srp_init", init_reply(&server)),
            ("recover", plist::Value::Dictionary(recovered)),
        ]);
        let session = session("https://escrow.icloud.com");
        let credentials = credentials();
        let client = client(script.clone(), &session, &credentials).unwrap();
        assert!(matches!(
            client
                .recover("synthetic-record", b"synthetic-passcode")
                .await,
            Err(Error::Integrity)
        ));
        let exchange = script.0.lock().unwrap();
        assert_eq!(exchange.requests.len(), 2);
        assert!(exchange.replies.is_empty());
        let bodies: Vec<_> = exchange
            .requests
            .iter()
            .map(|request| plist::Value::from_reader(std::io::Cursor::new(&request.body)).unwrap())
            .collect();
        let initial = bodies[0].as_dictionary().unwrap();
        let recovery = bodies[1].as_dictionary().unwrap();
        assert_eq!(initial["command"].as_string(), Some("SRP_INIT"));
        assert_eq!(recovery["command"].as_string(), Some("RECOVER"));
        assert_eq!(initial["label"].as_string(), Some("synthetic-record"));
        assert_eq!(initial["label"], recovery["label"]);
        assert_eq!(initial["transactionUUID"], recovery["transactionUUID"]);
    }

    #[test]
    fn independently_encrypted_recovery_frames_authenticate() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../fixtures/public/enrollment-vectors.json"
        ))
        .unwrap();
        let expected = hex::decode(vectors["srp"]["m2"].as_str().unwrap()).unwrap();
        let key = hex::decode(vectors["srp"]["session"].as_str().unwrap()).unwrap();
        let entropy = hex::decode(vectors["entropy"].as_str().unwrap()).unwrap();
        for (name, club) in [("cbc", false), ("cbc_legacy", false), ("gcm", true)] {
            let frame = hex::decode(vectors["recovery"][name].as_str().unwrap()).unwrap();
            assert_eq!(
                &*recover_entropy(&frame, club, &expected, &key, b"synthetic-passcode").unwrap(),
                &entropy
            );
            assert!(recover_entropy(&frame, club, &[0; 32], &key, b"synthetic-passcode").is_err());
            assert!(recover_entropy(&frame, club, &expected, &key, b"wrong-passcode").is_err());
            assert!(
                recover_entropy(&frame, club, &expected, &[0; 32], b"synthetic-passcode").is_err()
            );
            let mut corrupt = frame.clone();
            let last = corrupt.len() - 1;
            corrupt[last] ^= 1;
            assert!(
                recover_entropy(&corrupt, club, &expected, &key, b"synthetic-passcode").is_err()
            );
        }
    }

    #[test]
    fn srp_matches_independent_server_calculation() {
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../../fixtures/public/enrollment-vectors.json"
        ))
        .unwrap();
        let vector = &value["srp"];
        let server = hex::decode(vector["server_b"].as_str().unwrap()).unwrap();
        let (proof, expected, key) = srp_proof(
            &[1],
            "123",
            b"synthetic-passcode",
            &(0..16).collect::<Vec<_>>(),
            &server,
        )
        .unwrap();
        assert_eq!(hex::encode(proof), vector["m1"].as_str().unwrap());
        assert_eq!(hex::encode(expected), vector["m2"].as_str().unwrap());
        assert_eq!(hex::encode(&key[..]), vector["session"].as_str().unwrap());
        let padded = [vec![0], server.clone()].concat();
        let (padded_proof, padded_expected, padded_key) = srp_proof(
            &[1],
            "123",
            b"synthetic-passcode",
            &(0..16).collect::<Vec<_>>(),
            &padded,
        )
        .unwrap();
        assert_eq!(padded_proof, proof);
        assert_eq!(padded_expected, expected);
        assert_eq!(*padded_key, *key);
        for bad in [vec![0], crate::auth::modulus().to_bytes_be()] {
            assert!(srp_proof(&[1], "123", b"passcode", &[1], &bad).is_err());
        }
    }

    #[test]
    fn padded_scrambling_matches_six_independent_pysrp_checked_exchanges() {
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../../fixtures/public/enrollment-vectors.json"
        ))
        .unwrap();
        let vectors = value["srp_differential"].as_array().unwrap();
        assert_eq!(vectors.len(), 6);
        for vector in vectors {
            let private = hex::decode(vector["private_a"].as_str().unwrap()).unwrap();
            let server = hex::decode(vector["server_b"].as_str().unwrap()).unwrap();
            let (proof, expected, key) = srp_proof(
                &private,
                "123",
                b"synthetic-passcode",
                &(0..16).collect::<Vec<_>>(),
                &server,
            )
            .unwrap();
            assert_eq!(hex::encode(proof), vector["m1"].as_str().unwrap());
            assert_eq!(hex::encode(expected), vector["m2"].as_str().unwrap());
            assert_eq!(hex::encode(&key[..]), vector["session"].as_str().unwrap());
        }
    }

    #[test]
    fn keyvault_offsets_padding_and_bounds() {
        // 4-byte total, 4-byte header, three relative offsets, then two
        // length-prefixed sections. The first has four padding bytes.
        let expected = hex::decode(
            "0000002501020304000000000000000c000000110000000461626364000000000000000178",
        )
        .unwrap();
        assert_eq!(
            frame(&[1, 2, 3, 4], &[(b"abcd", 12), (b"x", 5)]).unwrap(),
            expected
        );
        let (header, sections) = unframe(&expected, 4, 2).unwrap();
        assert_eq!(header, [1, 2, 3, 4]);
        assert_eq!(sections.as_slice(), [b"abcd".to_vec(), b"x".to_vec()]);
        for end in 0..expected.len() {
            assert!(unframe(&expected[..end], 4, 2).is_err());
        }
        let mut backwards = expected.clone();
        backwards[12..16].copy_from_slice(&1u32.to_be_bytes());
        assert!(unframe(&backwards, 4, 2).is_err());
        assert!(frame(&[0; 24], &[(b"too long for section", 4)]).is_err());
    }
}
