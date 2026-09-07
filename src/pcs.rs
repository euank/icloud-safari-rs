//! PCS object parsing and authenticated key-graph recovery.

use std::collections::{BTreeMap, HashMap};

use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use p256::ecdsa::{Signature as P256Signature, SigningKey, signature::Signer};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result, crypto, der::Node, wire::Message};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyHint(pub [u8; 4]);

#[derive(Clone, Zeroize)]
pub(crate) struct Identity {
    pub public_x: [u8; 32],
    pub scalar: [u8; 32],
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Identity")
            .field("public_x", &"<redacted>")
            .finish()
    }
}

impl Identity {
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let root = Node::parse_exact(bytes)?;
        let export = root
            .descendants()
            .into_iter()
            .find_map(|node| (node.octets()?.len() == 64).then(|| node.octets().unwrap()))
            .ok_or(Error::Der("PCS identity has no 64-byte private export"))?;
        let public_x = export[..32].try_into().unwrap();
        let scalar = export[32..].try_into().unwrap();
        crypto::validate_p256_identity(&public_x, &scalar)?;
        Ok(Self { public_x, scalar })
    }

    fn from_private_export(bytes: &[u8]) -> Result<Option<Self>> {
        let root = match Node::parse_exact(bytes) {
            Ok(root) => root,
            Err(_) => return Ok(None),
        };
        let Some(export) = find_nested_octet(&root, 64, 0) else {
            return Ok(None);
        };
        let public_x: [u8; 32] = export[..32].try_into().unwrap();
        let scalar: [u8; 32] = export[32..].try_into().unwrap();
        crypto::validate_p256_identity(&public_x, &scalar)?;
        Ok(Some(Self { public_x, scalar }))
    }
}

fn find_nested_octet(node: &Node, len: usize, depth: usize) -> Option<Vec<u8>> {
    if depth > 8 {
        return None;
    }
    for candidate in node.descendants() {
        let Some(octets) = candidate.octets() else {
            continue;
        };
        if octets.len() == len {
            return Some(octets.to_vec());
        }
        if let Ok(nested) = Node::parse_exact(octets)
            && let Some(found) = find_nested_octet(&nested, len, depth + 1)
        {
            return Some(found);
        }
    }
    None
}

#[derive(Clone, Debug)]
struct Recipient {
    public_x: [u8; 32],
    wrapped_master_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct Object {
    recipients: Vec<Recipient>,
    encrypted_private: Vec<u8>,
    public_export: Vec<u8>,
    master_key_hint: [u8; 4],
}

fn only_child(node: &Node, class: u8, tag: u32) -> Result<&Node> {
    node.children
        .iter()
        .find(|child| child.class == class && child.tag == tag)
        .ok_or(Error::Der("missing required PCS component"))
}

impl Object {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let app = Node::parse_exact(bytes)?;
        if app.class != 1 || app.tag != 1 || !app.constructed {
            return Err(Error::Der("PCS object is not APPLICATION[1]"));
        }
        let sequence = only_child(&app, 0, 16)?;
        if sequence.children.len() < 5 {
            return Err(Error::Der("truncated PCS object"));
        }
        let recipients_node = &sequence.children[0];
        let set = only_child(recipients_node, 0, 17)?;
        let mut recipients = Vec::new();
        for recipient in &set.children {
            if recipient.class != 0 || recipient.tag != 16 || recipient.children.len() != 2 {
                return Err(Error::Der("malformed PCS recipient"));
            }
            let identity = &recipient.children[0];
            let public = identity
                .children
                .iter()
                .find_map(Node::octets)
                .filter(|bytes| bytes.len() == 32)
                .ok_or(Error::Der("malformed PCS recipient identity"))?;
            let wrapped = recipient.children[1]
                .octets()
                .ok_or(Error::Der("malformed PCS wrapped key"))?;
            recipients.push(Recipient {
                public_x: public.try_into().unwrap(),
                wrapped_master_key: wrapped.to_vec(),
            });
        }
        let encrypted_private = only_child(&sequence.children[1], 0, 4)?
            .octets()
            .ok_or(Error::Der("malformed encrypted private export"))?
            .to_vec();
        let public_sequence = only_child(&sequence.children[2], 0, 16)?;
        let public_export = public_sequence
            .children
            .iter()
            .find_map(Node::octets)
            .ok_or(Error::Der("malformed public export"))?
            .to_vec();
        let hint = only_child(&sequence.children[4], 0, 4)?
            .octets()
            .filter(|bytes| bytes.len() == 4)
            .ok_or(Error::Der("malformed master-key hint"))?
            .try_into()
            .unwrap();
        Ok(Self {
            recipients,
            encrypted_private,
            public_export,
            master_key_hint: hint,
        })
    }

    pub(crate) fn expected_child_public_x(&self) -> Result<[u8; 32]> {
        let export = Node::parse_exact(&self.public_export)?;
        let mut candidates = Vec::new();
        collect_nested_octets(&export, 32, 0, &mut candidates);
        candidates
            .into_iter()
            .filter_map(|bytes| {
                let mut point = [0u8; 33];
                point[0] = 2;
                point[1..].copy_from_slice(&bytes);
                p256::PublicKey::from_sec1_bytes(&point).ok().map(|key| {
                    key.to_encoded_point(false)
                        .x()
                        .unwrap()
                        .to_vec()
                        .try_into()
                        .unwrap()
                })
            })
            .next_back()
            .ok_or(Error::Der(
                "public export contains no curve-valid x coordinate",
            ))
    }
}

fn collect_nested_octets(node: &Node, len: usize, depth: usize, output: &mut Vec<Vec<u8>>) {
    if depth > 8 {
        return;
    }
    for candidate in node.descendants() {
        let Some(octets) = candidate.octets() else {
            continue;
        };
        if octets.len() == len {
            output.push(octets.to_vec());
        }
        if let Ok(nested) = Node::parse_exact(octets) {
            collect_nested_octets(&nested, len, depth + 1, output);
        }
    }
}

#[derive(Default)]
pub(crate) struct KeyGraph {
    keys: BTreeMap<KeyHint, Vec<Zeroizing<Vec<u8>>>>,
    identities: HashMap<[u8; 32], Identity>,
    pub unwrapped: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FieldAadMode {
    Legacy,
    Context,
}

impl KeyGraph {
    pub(crate) fn recovered_identities(&self) -> Vec<Identity> {
        self.identities.values().cloned().collect()
    }

    pub fn recover(objects: &[Object], initial: Vec<Identity>) -> Result<Self> {
        let mut identities: HashMap<[u8; 32], Identity> = initial
            .into_iter()
            .map(|identity| (identity.public_x, identity))
            .collect();
        let mut graph = Self::default();
        let mut complete = vec![false; objects.len()];
        loop {
            let mut progress = false;
            for (index, object) in objects.iter().enumerate() {
                if complete[index] {
                    continue;
                }
                let Some((recipient, identity)) = object.recipients.iter().find_map(|recipient| {
                    identities
                        .get(&recipient.public_x)
                        .map(|identity| (recipient, identity))
                }) else {
                    continue;
                };
                let master = Zeroizing::new(
                    crypto::pcs_rfc6637_unwrap(&identity.scalar, &recipient.wrapped_master_key)
                        .map_err(|error| {
                            Error::Fixture(format!("PCS object {index} key unwrap failed: {error}"))
                        })?,
                );
                if master.len() != 16 {
                    return Err(Error::Integrity);
                }
                let full_id = crypto::fp_master_key_id(&master);
                if full_id[..4] != object.master_key_hint {
                    return Err(Error::Integrity);
                }
                let private_export = Zeroizing::new(
                    crypto::fp_v3_decrypt(&master, b"", &object.encrypted_private).map_err(
                        |error| {
                            Error::Fixture(format!("PCS object {index} metadata failed: {error}"))
                        },
                    )?,
                );
                if let Some(child) = Identity::from_private_export(&private_export)? {
                    let expected = object.expected_child_public_x()?;
                    if child.public_x != expected {
                        return Err(Error::Integrity);
                    }
                    identities.entry(child.public_x).or_insert(child);
                }
                let values = graph
                    .keys
                    .entry(KeyHint(object.master_key_hint))
                    .or_default();
                if !values
                    .iter()
                    .any(|existing| existing.as_slice() == master.as_slice())
                {
                    values.push(master);
                }
                complete[index] = true;
                graph.unwrapped += 1;
                progress = true;
            }
            if !progress {
                break;
            }
        }
        graph.identities = identities;
        Ok(graph)
    }

    pub fn decrypt_field(
        &self,
        zone: &str,
        record: &str,
        field: &str,
        blob: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .decrypt_field_with_mode(zone, record, field, blob)?
            .map(|value| value.0))
    }

    pub(crate) fn decrypt_field_with_mode(
        &self,
        zone: &str,
        record: &str,
        field: &str,
        blob: &[u8],
    ) -> Result<Option<(Vec<u8>, FieldAadMode)>> {
        if blob.len() < 30 || blob[0] != 3 || blob[3] != 2 {
            return Ok(None);
        }
        let hint = KeyHint([blob[1], blob[2], blob[4], blob[5]]);
        let Some(keys) = self.keys.get(&hint) else {
            return Ok(None);
        };
        if keys.len() != 1 {
            return Err(Error::AmbiguousKeyId);
        }
        let modern = format!("{zone}-{record}-{field}");
        for (aad, mode) in [
            (field.as_bytes(), FieldAadMode::Legacy),
            (modern.as_bytes(), FieldAadMode::Context),
        ] {
            if let Ok(plaintext) = crypto::fp_v3_decrypt(&keys[0], aad, blob) {
                return Ok(Some((plaintext, mode)));
            }
        }
        Err(Error::Integrity)
    }

    pub fn reencrypt_field(
        &self,
        zone: &str,
        record: &str,
        field: &str,
        existing_blob: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, FieldAadMode)> {
        if existing_blob.len() < 30 || existing_blob[0] != 3 || existing_blob[3] != 2 {
            return Err(Error::Unsupported(
                "field is not an FP version-3 encrypted value",
            ));
        }
        let hint = KeyHint([
            existing_blob[1],
            existing_blob[2],
            existing_blob[4],
            existing_blob[5],
        ]);
        let keys = self.keys.get(&hint).ok_or(Error::Integrity)?;
        if keys.len() != 1 {
            return Err(Error::AmbiguousKeyId);
        }
        let context = format!("{zone}-{record}-{field}");
        for (aad, mode) in [
            (field.as_bytes(), FieldAadMode::Legacy),
            (context.as_bytes(), FieldAadMode::Context),
        ] {
            if crypto::fp_v3_decrypt(&keys[0], aad, existing_blob).is_ok() {
                let encrypted = crypto::fp_v3_encrypt(&keys[0], aad, plaintext)?;
                return Ok((encrypted, mode));
            }
        }
        Err(Error::Integrity)
    }
}

pub(crate) struct CreatedProtection {
    pub der: Vec<u8>,
    pub tag: String,
    pub master_key: Zeroizing<Vec<u8>>,
}

// Single-recipient, version-5 profile from the PCS ASN.1 and signed-data
// contract documented in docs/PROVENANCE.md. Optional rotation/sharing fields
// are deliberately outside this writer's supported profile.
// The metadata tag also contains an empty OCTET STRING.
fn empty_metadata() -> Vec<u8> {
    der_tlv(0x30, &der_tlv(0xa1, &der_tlv(0x30, &[2, 1, 0, 4, 0])))
}

pub(crate) fn create_record_protection(
    objects: &[Object],
    graph: &KeyGraph,
) -> Result<CreatedProtection> {
    let parent = objects
        .iter()
        .filter_map(|object| object.expected_child_public_x().ok())
        .find_map(|public| graph.identities.get(&public))
        .ok_or(Error::Integrity)?;
    let mut master = Zeroizing::new(vec![0; 16]);
    rand::rngs::OsRng.fill_bytes(&mut master);
    let wrapped = crypto::pcs_rfc6637_wrap(&parent.public_x, &master)?;
    let meta = crypto::fp_v3_encrypt(&master, b"", &empty_metadata())?;
    encode_fresh_protection(parent, master, &wrapped, &meta)
}

fn encode_fresh_protection(
    parent: &Identity,
    master: Zeroizing<Vec<u8>>,
    wrapped: &[u8],
    meta: &[u8],
) -> Result<CreatedProtection> {
    crypto::validate_p256_identity(&parent.public_x, &parent.scalar)?;
    if master.len() != 16 {
        return Err(Error::Integrity);
    }
    let reference =
        |kind: u8, public: &[u8]| der_tlv(0x30, &[vec![2, 1, kind], der_tlv(4, public)].concat());
    let recipient = der_tlv(
        0x30,
        &[reference(3, &parent.public_x), der_tlv(4, wrapped)].concat(),
    );
    let keyset = der_tlv(0x30, &[vec![2, 1, 0], der_tlv(0x31, &recipient)].concat());
    let signer = derive_master_signing_key(&master)?;
    let public = signer.verifying_key().to_encoded_point(false);

    // These integers are BE32 values in the signature input, not ASN.1.
    let mut signed = [keyset.as_slice(), meta].concat();
    for value in [3u32, 1, 0, 1] {
        signed.extend_from_slice(&value.to_be_bytes());
    }
    signed.extend_from_slice(public.as_bytes());
    let signature = |key: &SigningKey, id: &[u8]| {
        let value: P256Signature = key.sign(&signed);
        der_tlv(
            0x30,
            &[
                der_tlv(4, id),
                vec![2, 1, 1],
                der_tlv(4, value.to_der().as_bytes()),
            ]
            .concat(),
        )
    };
    let inner = der_tlv(
        0x30,
        &[
            vec![2, 1, 1, 2, 1, 3],
            reference(1, public.as_bytes()),
            signature(&signer, b""),
        ]
        .concat(),
    );
    let parent_signer = SigningKey::from_slice(&parent.scalar).map_err(|_| Error::Integrity)?;
    let outer = signature(&parent_signer, &parent.public_x);

    let hmac_key = Zeroizing::new(crypto::sp800_108_hmac_sha256(
        &master,
        b"hmackey-of-masterkey",
        b"",
        16,
    ));
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).map_err(|_| Error::Integrity)?;
    for part in [keyset.as_slice(), meta, inner.as_slice()] {
        mac.update(part);
    }
    let envelope = der_tlv(0x30, &[vec![2, 1, 5], der_tlv(4, &inner)].concat());
    let body = [
        keyset,
        der_tlv(0xa0, &der_tlv(4, meta)),
        der_tlv(0xa1, &envelope),
        der_tlv(4, &mac.finalize().into_bytes()),
        der_tlv(0xa2, &der_tlv(4, &crypto::fp_master_key_id(&master)[..4])),
        der_tlv(0xa3, &outer),
    ]
    .concat();
    let der = der_tlv(0x61, &der_tlv(0x30, &body));
    Object::parse(&der)?;
    Ok(CreatedProtection {
        tag: hex::encode_upper(Sha1::digest(&der)),
        der,
        master_key: master,
    })
}

// Only single-byte tags are used by this fixed profile. Lengths are encoded
// minimally as required by DER; SET sorting is trivial for one recipient.
fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        let length = body.len().to_be_bytes();
        let first = length.iter().position(|byte| *byte != 0).unwrap();
        out.push(0x80 | (length.len() - first) as u8);
        out.extend_from_slice(&length[first..]);
    }
    out.extend_from_slice(body);
    out
}

fn derive_master_signing_key(master_key: &[u8]) -> Result<SigningKey> {
    let mut expanded = Zeroizing::new([0u8; 128]);
    pbkdf2_hmac::<Sha256>(master_key, b"full master key", 10, &mut *expanded);
    let order = BigUint::parse_bytes(
        b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        16,
    )
    .ok_or(Error::Integrity)?;
    let mut value = BigUint::from_bytes_le(&expanded[..32]);
    if value >= order {
        value -= order;
    }
    let bytes = Zeroizing::new(value.to_bytes_be());
    let mut scalar = Zeroizing::new([0u8; 32]);
    scalar[32 - bytes.len()..].copy_from_slice(&bytes);
    SigningKey::from_slice(&*scalar).map_err(|_| Error::Integrity)
}

pub(crate) fn extract_objects(raw_response: &[u8]) -> Result<Vec<Object>> {
    let response = Message::parse(raw_response)?;
    let mut ders = Vec::new();
    if let Some(metadata) = response.first_bytes(12) {
        let metadata = Message::parse(metadata)?;
        if let Some(zone_info) = metadata.first_bytes(1) {
            let zone_info = Message::parse(zone_info)?;
            for field in [3, 6] {
                if let Some(wrapper) = zone_info.first_bytes(field)
                    && let Ok(wrapper) = Message::parse(wrapper)
                    && let Some(der) = wrapper.first_bytes(1)
                {
                    ders.push(der.to_vec());
                }
            }
        }
    }
    for change in response.values(1) {
        let crate::wire::Value::Bytes(change) = change else {
            continue;
        };
        let change = Message::parse(change)?;
        let Some(record) = change.first_bytes(5) else {
            continue;
        };
        let record = Message::parse(record)?;
        if let Some(wrapper) = record.first_bytes(13)
            && let Ok(wrapper) = Message::parse(wrapper)
            && let Some(der) = wrapper.first_bytes(1)
            && Object::parse(der).is_ok()
        {
            ders.push(der.to_vec());
        }
    }
    ders.iter().map(|der| Object::parse(der)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, signature::Verifier};

    #[test]
    fn rejects_ambiguous_truncated_key_ids() {
        let hint = KeyHint([1, 2, 3, 4]);
        let mut graph = KeyGraph::default();
        graph.keys.insert(
            hint,
            vec![Zeroizing::new(vec![0; 16]), Zeroizing::new(vec![1; 16])],
        );
        let mut blob = vec![0; 30];
        blob[0] = 3;
        blob[1] = 1;
        blob[2] = 2;
        blob[3] = 2;
        blob[4] = 3;
        blob[5] = 4;
        assert!(matches!(
            graph.decrypt_field("zone", "record", "field", &blob),
            Err(Error::AmbiguousKeyId)
        ));
    }

    #[test]
    fn master_signing_key_matches_independent_vector() {
        // Calculated independently with Python's hashlib/cryptography from the
        // clean-room protocol description: PBKDF2-HMAC-SHA256, 10 rounds,
        // low 256 bits interpreted little-endian, then one conditional subtract.
        let master_key: Vec<u8> = (0..16).collect();
        let signing_key = derive_master_signing_key(&master_key).unwrap();

        assert_eq!(
            hex::encode(signing_key.to_bytes()),
            "8fa5b9fffa4cce66d412ca6cf7fdf1ea0c36150a9c5800c0179222bc68613929"
        );
        assert_eq!(
            hex::encode(signing_key.verifying_key().to_encoded_point(false)),
            "04be4fe3975ba1e5cc2b27e36d34530f40c1a02e1d83c82d80f0a65f4592bbf3bcde206347997554ad3af621b90c9a6d71770d4657f45bf0b428e858662d27ef1a"
        );
        assert_eq!(
            hex::encode(crypto::sp800_108_hmac_sha256(
                &master_key,
                b"hmackey-of-masterkey",
                b"",
                16,
            )),
            "057f783c0a12d613c8c4b9cf7fafaf41"
        );
        assert_eq!(
            hex::encode(crypto::fp_master_key_id(&master_key)),
            "4f951a940dbd05e722e9fa5b2ab4b96c43ed60c003d7d3e0384132c1290eb8a5"
        );
    }

    #[test]
    fn fresh_protection_has_verifiable_signatures_hmac_and_recipient() {
        let master_key = Zeroizing::new((0..16).collect::<Vec<_>>());
        let mut parent_scalar = [0u8; 32];
        parent_scalar[31] = 1;
        let parent = Identity {
            public_x: hex::decode(
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            scalar: parent_scalar,
        };
        let encrypted_metadata =
            crypto::fp_v3_encrypt_with_iv(&master_key, b"", &empty_metadata(), &[0x55; 12])
                .unwrap();
        let wrapped_master_key = hex::decode(
            "01007cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997830c3193c47ccac501cd446cc76e3320c7c76219f93189467075d4396b645331567a1953c4a21b771ed0edc5094405574e5",
        )
        .unwrap();

        let created = encode_fresh_protection(
            &parent,
            master_key,
            &wrapped_master_key,
            &encrypted_metadata,
        )
        .unwrap();
        // Decode using the separate strict read parser, preserving the exact
        // wire bytes for verification rather than reusing the writer.
        let root = Node::parse_exact(&created.der).unwrap();
        let fields = &root.children[0].children;
        assert_eq!(fields.len(), 6);
        let keyset = &fields[0];
        let meta = fields[1].children[0].octets().unwrap();
        let envelope = &fields[2].children[0].children;
        assert_eq!(envelope[0].integer_u64().unwrap(), 5);
        let inner_der = envelope[1].octets().unwrap();
        let inner = Node::parse_exact(inner_der).unwrap();
        let public = inner.children[2].children[1].octets().unwrap();
        assert_eq!(inner.children[0].integer_u64().unwrap(), 1);
        assert_eq!(inner.children[1].integer_u64().unwrap(), 3);
        assert_eq!(inner.children[2].children[0].integer_u64().unwrap(), 1);
        let mut signed = [keyset.raw.as_slice(), meta].concat();
        signed.extend_from_slice(&hex::decode("00000003000000010000000000000001").unwrap());
        signed.extend_from_slice(public);
        let self_signature =
            Signature::from_der(inner.children[3].children[2].octets().unwrap()).unwrap();
        let verifier = derive_master_signing_key(&created.master_key).unwrap();
        verifier
            .verifying_key()
            .verify(&signed, &self_signature)
            .unwrap();
        let outer = &fields[5].children[0].children;
        assert_eq!(outer[0].octets().unwrap(), parent.public_x);
        let signature = Signature::from_der(outer[2].octets().unwrap()).unwrap();
        SigningKey::from_slice(&parent.scalar)
            .unwrap()
            .verifying_key()
            .verify(&signed, &signature)
            .unwrap();
        signed[0] ^= 1;
        assert!(
            verifier
                .verifying_key()
                .verify(&signed, &self_signature)
                .is_err()
        );

        let hmac_key =
            crypto::sp800_108_hmac_sha256(&created.master_key, b"hmackey-of-masterkey", b"", 16);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).unwrap();
        mac.update(&[keyset.raw.as_slice(), meta, inner_der].concat());
        mac.verify_slice(fields[3].octets().unwrap()).unwrap();
        assert_eq!(
            fields[4].children[0].octets().unwrap(),
            [0x4f, 0x95, 0x1a, 0x94]
        );
        assert_eq!(
            crypto::fp_v3_decrypt(&created.master_key, b"", meta).unwrap(),
            hex::decode("3009a10730050201000400").unwrap()
        );

        let object = Object::parse(&created.der).unwrap();
        let recovered = KeyGraph::recover(&[object], vec![parent]).unwrap();
        assert_eq!(recovered.unwrapped, 1);
        assert_eq!(created.tag, hex::encode_upper(Sha1::digest(&created.der)));
    }
}
