use std::{fs, path::PathBuf};

use icloud_safari::crypto;
use serde_json::Value;

fn vectors() -> Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/public/protocol-vectors.json");
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(value[key].as_str().unwrap()).unwrap()
}

#[test]
fn pcs_v3_kdf_and_fp_blob() {
    let vectors = vectors();
    let pcs = &vectors["pcs_v3"];
    let master = bytes(pcs, "master_key");
    assert_eq!(
        crypto::sp800_108_hmac_sha256(&master, b"master key id labell", b"", 16),
        bytes(pcs, "kdf_t16")
    );
    assert_eq!(
        crypto::fp_master_key_id(&master).as_slice(),
        bytes(pcs, "key_id")
    );
    assert_eq!(
        crypto::fp_encryption_key(&master).as_slice(),
        bytes(pcs, "fp_encryption_key")
    );

    let fp = &vectors["fp_v3"];
    let plaintext = crypto::fp_v3_decrypt(
        &bytes(fp, "master_key"),
        &bytes(fp, "extra_aad"),
        &bytes(fp, "blob"),
    )
    .unwrap();
    assert_eq!(plaintext, bytes(fp, "plaintext"));
    let mut wrong_aad = bytes(fp, "extra_aad");
    wrong_aad[0] ^= 1;
    assert!(crypto::fp_v3_decrypt(&master, &wrong_aad, &bytes(fp, "blob")).is_err());
    let mut wrong_key = master.clone();
    wrong_key[0] ^= 1;
    assert!(
        crypto::fp_v3_decrypt(&wrong_key, &bytes(fp, "extra_aad"), &bytes(fp, "blob")).is_err()
    );
    let blob = bytes(fp, "blob");
    let iv: [u8; 12] = blob[6..18].try_into().unwrap();
    assert_eq!(
        crypto::fp_v3_encrypt_with_iv(
            &master,
            &bytes(fp, "extra_aad"),
            &bytes(fp, "plaintext"),
            &iv
        )
        .unwrap(),
        blob
    );

    for index in 0..bytes(fp, "blob").len() {
        let mut corrupt = bytes(fp, "blob");
        corrupt[index] ^= 1;
        assert!(crypto::fp_v3_decrypt(&master, &bytes(fp, "extra_aad"), &corrupt).is_err());
    }
}

#[test]
fn aes_siv_vector() {
    let vector = &vectors()["aes_siv"];
    let aad: Vec<Vec<u8>> = vector["associated_data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| hex::decode(item.as_str().unwrap()).unwrap())
        .collect();
    let refs: Vec<&[u8]> = aad.iter().map(Vec::as_slice).collect();
    let plaintext =
        crypto::aes_siv_decrypt(&bytes(vector, "key"), &refs, &bytes(vector, "ciphertext"))
            .unwrap();
    assert_eq!(plaintext, bytes(vector, "plaintext"));
}

#[test]
fn security_foundation_ecies_vector() {
    let vector = &vectors()["sf_ecies_p384"];
    let scalar: [u8; 48] = {
        let short = bytes(vector, "recipient_private_scalar");
        let mut scalar = [0u8; 48];
        scalar[48 - short.len()..].copy_from_slice(&short);
        scalar
    };
    let combined = bytes(vector, "ciphertext_and_tag");
    let plaintext = crypto::sf_ecies_p384_decrypt(
        &scalar,
        &bytes(vector, "ephemeral_public_x963"),
        &combined[..combined.len() - 16],
        &combined[combined.len() - 16..],
    )
    .unwrap();
    assert_eq!(plaintext, bytes(vector, "plaintext"));
}

#[test]
fn rfc6637_vectors() {
    for name in ["rfc6637_plain", "rfc6637_diversified"] {
        let vector = &vectors()[name];
        let scalar: [u8; 32] = bytes(vector, "recipient_private_scalar")
            .try_into()
            .unwrap();
        let fingerprint: [u8; 20] = bytes(vector, "fingerprint").try_into().unwrap();
        let key = crypto::rfc6637_unwrap(&scalar, &fingerprint, &bytes(vector, "wrapped"))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(key, bytes(vector, "unwrapped_key"));
    }
}
