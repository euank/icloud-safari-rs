//! Protocol-specific cryptographic operations. All decryptors fail closed.

use aes::{Aes128, Aes256};
use aes_gcm::{
    AesGcm, KeyInit as _,
    aead::{AeadInPlace, consts::U12, generic_array::GenericArray},
};
use aes_siv::siv::Aes256Siv;
use cipher::{BlockDecrypt, BlockEncrypt, generic_array::GenericArray as CipherArray};
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey as PublicKey256, SecretKey as SecretKey256, ecdh};
use p384::{PublicKey as PublicKey384, SecretKey as SecretKey384};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{Error, Result};

type HmacSha256 = Hmac<Sha256>;
type Aes128Gcm12 = AesGcm<Aes128, U12, U12>;
type Aes256Gcm16Nonce = AesGcm<Aes256, aes_gcm::aead::consts::U16>;

pub fn sp800_108_hmac_sha256(key: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(len);
    let mut counter = 1u32;
    let bit_len = u32::try_from(len.checked_mul(8).expect("KDF length overflow"))
        .expect("KDF length exceeds protocol limit");
    while output.len() < len {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(&counter.to_be_bytes());
        mac.update(label);
        mac.update(&[0]);
        mac.update(context);
        mac.update(&bit_len.to_be_bytes());
        output.extend_from_slice(&mac.finalize().into_bytes());
        counter = counter.checked_add(1).expect("KDF counter overflow");
    }
    output.truncate(len);
    output
}

pub fn fp_master_key_id(master_key: &[u8]) -> [u8; 32] {
    let t = sp800_108_hmac_sha256(master_key, b"master key id labell", b"", 16);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&t).expect("HMAC key");
    mac.update(b"M key input data 2 u");
    mac.finalize().into_bytes().into()
}

pub fn fp_encryption_key(master_key: &[u8]) -> [u8; 16] {
    sp800_108_hmac_sha256(master_key, b"encryption key key m", b"", 16)
        .try_into()
        .unwrap()
}

pub fn fp_v3_decrypt(master_key: &[u8], extra_aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 6 + 12 + 12 || blob[0] != 3 || blob[3] != 2 {
        return Err(Error::Unsupported("expected an FP version-3 blob"));
    }
    let full_id = fp_master_key_id(master_key);
    let hint = [blob[1], blob[2], blob[4], blob[5]];
    if hint.ct_eq(&full_id[..4]).unwrap_u8() != 1 {
        return Err(Error::Integrity);
    }
    let key = fp_encryption_key(master_key);
    let mut aad = Vec::with_capacity(6 + extra_aad.len());
    aad.extend_from_slice(&blob[..6]);
    aad.extend_from_slice(extra_aad);
    let iv = &blob[6..18];
    let tag = &blob[18..30];
    let mut plaintext = blob[30..].to_vec();
    let cipher = Aes128Gcm12::new_from_slice(&key).map_err(|_| Error::Integrity)?;
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(iv),
            &aad,
            &mut plaintext,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| Error::Integrity)?;
    Ok(plaintext)
}

/// Construct an FP v3 field value. This is an offline primitive: it does not
/// create PCS objects or authorize a CloudKit mutation.
pub fn fp_v3_encrypt(master_key: &[u8], extra_aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    fp_v3_encrypt_with_iv(master_key, extra_aad, plaintext, &iv)
}

pub fn fp_v3_encrypt_with_iv(
    master_key: &[u8],
    extra_aad: &[u8],
    plaintext: &[u8],
    iv: &[u8; 12],
) -> Result<Vec<u8>> {
    let id = fp_master_key_id(master_key);
    let header = [3, id[0], id[1], 2, id[2], id[3]];
    let mut aad = Vec::with_capacity(header.len() + extra_aad.len());
    aad.extend_from_slice(&header);
    aad.extend_from_slice(extra_aad);
    let mut ciphertext = plaintext.to_vec();
    let cipher = Aes128Gcm12::new_from_slice(&fp_encryption_key(master_key))
        .map_err(|_| Error::Integrity)?;
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(iv), &aad, &mut ciphertext)
        .map_err(|_| Error::Integrity)?;
    let mut blob = Vec::with_capacity(30 + ciphertext.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(iv);
    blob.extend_from_slice(&tag);
    blob.extend(ciphertext);
    // Make the derived write primitive self-checking before returning bytes.
    if fp_v3_decrypt(master_key, extra_aad, &blob)?.as_slice() != plaintext {
        return Err(Error::Integrity);
    }
    Ok(blob)
}

pub fn aes_siv_decrypt(
    key: &[u8],
    associated_data: &[&[u8]],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut cipher = Aes256Siv::new_from_slice(key).map_err(|_| Error::Integrity)?;
    cipher
        .decrypt(associated_data.iter().copied(), ciphertext)
        .map_err(|_| Error::Integrity)
}

pub fn aes_siv_encrypt(key: &[u8], associated_data: &[&[u8]], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = Aes256Siv::new_from_slice(key).map_err(|_| Error::Integrity)?;
    let ciphertext = cipher
        .encrypt(associated_data.iter().copied(), plaintext)
        .map_err(|_| Error::Integrity)?;
    // Catch accidental key/AAD construction errors at the primitive boundary.
    if aes_siv_decrypt(key, associated_data, &ciphertext)? != plaintext {
        return Err(Error::Integrity);
    }
    Ok(ciphertext)
}

pub fn aes_key_unwrap_128(kek: &[u8; 16], wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return Err(Error::Integrity);
    }
    let n = wrapped.len() / 8 - 1;
    let mut a: [u8; 8] = wrapped[..8].try_into().unwrap();
    let mut r = wrapped[8..].to_vec();
    let cipher = Aes128::new_from_slice(kek).map_err(|_| Error::Integrity)?;
    for j in (0..=5u64).rev() {
        for i in (1..=n).rev() {
            let t = n as u64 * j + i as u64;
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&(u64::from_be_bytes(a) ^ t).to_be_bytes());
            block[8..].copy_from_slice(&r[(i - 1) * 8..i * 8]);
            cipher.decrypt_block(CipherArray::from_mut_slice(&mut block));
            a.copy_from_slice(&block[..8]);
            r[(i - 1) * 8..i * 8].copy_from_slice(&block[8..]);
        }
    }
    if a.ct_eq(&[0xa6; 8]).unwrap_u8() != 1 {
        return Err(Error::Integrity);
    }
    Ok(r)
}

pub fn aes_key_wrap_128(kek: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() < 16 || !plaintext.len().is_multiple_of(8) {
        return Err(Error::Integrity);
    }
    let n = plaintext.len() / 8;
    let mut a = [0xa6; 8];
    let mut r = plaintext.to_vec();
    let cipher = Aes128::new_from_slice(kek).map_err(|_| Error::Integrity)?;
    for j in 0..=5u64 {
        for i in 1..=n {
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(&r[(i - 1) * 8..i * 8]);
            cipher.encrypt_block(CipherArray::from_mut_slice(&mut block));
            let t = n as u64 * j + i as u64;
            a.copy_from_slice(
                &(u64::from_be_bytes(block[..8].try_into().unwrap()) ^ t).to_be_bytes(),
            );
            r[(i - 1) * 8..i * 8].copy_from_slice(&block[8..]);
        }
    }
    let mut wrapped = Vec::with_capacity(plaintext.len() + 8);
    wrapped.extend_from_slice(&a);
    wrapped.extend_from_slice(&r);
    if aes_key_unwrap_128(kek, &wrapped)? != plaintext {
        return Err(Error::Integrity);
    }
    Ok(wrapped)
}

pub fn pcs_rfc6637_wrap(public_x: &[u8; 32], key: &[u8]) -> Result<Vec<u8>> {
    let ephemeral = SecretKey256::random(&mut rand::rngs::OsRng);
    pcs_rfc6637_wrap_with_ephemeral(public_x, key, &ephemeral)
}

fn pcs_rfc6637_wrap_with_ephemeral(
    public_x: &[u8; 32],
    key: &[u8],
    ephemeral: &SecretKey256,
) -> Result<Vec<u8>> {
    if key.len() > 36 {
        return Err(Error::Integrity);
    }
    let recipient = compact_p256_public(public_x)?;
    let shared = ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    let mut fingerprint = b"fingerprint".to_vec();
    fingerprint.resize(20, 0);
    let params = [
        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x12, 0x03, 0x01, 0x08, 0x07,
    ];
    let mut digest_input = Vec::new();
    digest_input.extend_from_slice(&1u32.to_be_bytes());
    digest_input.extend_from_slice(shared.raw_secret_bytes());
    digest_input.extend_from_slice(&params);
    digest_input.extend_from_slice(b"Anonymous Sender    ");
    digest_input.extend_from_slice(&fingerprint);
    let digest = Sha256::digest(&digest_input);
    let kek: [u8; 16] = digest[..16].try_into().unwrap();
    let mut framed = [0u8; 40];
    framed[0] = 1;
    framed[1..1 + key.len()].copy_from_slice(key);
    let checksum = key
        .iter()
        .fold(0u16, |sum, byte| sum.wrapping_add(u16::from(*byte)));
    framed[1 + key.len()..3 + key.len()].copy_from_slice(&checksum.to_be_bytes());
    let padding = 40 - key.len() - 3;
    framed[3 + key.len()..].fill(padding as u8);
    let wrapped = aes_key_wrap_128(&kek, &framed)?;
    let ephemeral_public = ephemeral.public_key().to_encoded_point(false);
    let x = ephemeral_public.x().ok_or(Error::Integrity)?;
    let mut output = Vec::with_capacity(2 + 32 + 1 + wrapped.len());
    output.extend_from_slice(&256u16.to_be_bytes());
    output.extend_from_slice(x);
    output.push(u8::try_from(wrapped.len()).map_err(|_| Error::Integrity)?);
    output.extend_from_slice(&wrapped);
    Ok(output)
}

fn compact_p256_public(bytes: &[u8]) -> Result<PublicKey256> {
    let encoded = match bytes.len() {
        32 => {
            let mut encoded = Vec::with_capacity(33);
            encoded.push(2);
            encoded.extend_from_slice(bytes);
            encoded
        }
        65 if bytes[0] == 4 => bytes.to_vec(),
        _ => return Err(Error::Integrity),
    };
    PublicKey256::from_sec1_bytes(&encoded).map_err(|_| Error::Integrity)
}

pub fn validate_p256_identity(public_x: &[u8; 32], scalar: &[u8; 32]) -> Result<SecretKey256> {
    let secret = SecretKey256::from_slice(scalar).map_err(|_| Error::Integrity)?;
    let encoded = secret.public_key().to_encoded_point(false);
    if encoded
        .x()
        .ok_or(Error::Integrity)?
        .ct_eq(public_x)
        .unwrap_u8()
        != 1
    {
        return Err(Error::Integrity);
    }
    Ok(secret)
}

pub fn rfc6637_unwrap(
    recipient_scalar: &[u8; 32],
    fingerprint: &[u8; 20],
    wrapped: &[u8],
) -> Result<Vec<u8>> {
    if wrapped.len() < 2 {
        return Err(Error::Integrity);
    }
    let bit_len = usize::from(u16::from_be_bytes([wrapped[0], wrapped[1]]));
    let public_len = bit_len.div_ceil(8);
    let ephemeral = wrapped.get(2..2 + public_len).ok_or(Error::Integrity)?;
    let length_offset = 2 + public_len;
    let wrapped_len = usize::from(*wrapped.get(length_offset).ok_or(Error::Integrity)?);
    let key_wrapped = wrapped
        .get(length_offset + 1..length_offset + 1 + wrapped_len)
        .ok_or(Error::Integrity)?;
    if length_offset + 1 + wrapped_len != wrapped.len() {
        return Err(Error::Integrity);
    }

    let secret = SecretKey256::from_slice(recipient_scalar).map_err(|_| Error::Integrity)?;
    let public = compact_p256_public(ephemeral)?;
    let shared = ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    // RFC 6637 encodes the raw curve OID length (8), followed by the OID.
    // The prose protocol shows 09 here, but its authoritative vectors and
    // RFC encoding use 08.
    let params = hex::decode("082a8648ce3d0301071203010807").unwrap();
    let mut digest = Sha256::new();
    digest.update(1u32.to_be_bytes());
    digest.update(shared.raw_secret_bytes());
    digest.update(params);
    digest.update(b"Anonymous Sender    ");
    digest.update(fingerprint);
    let kek: [u8; 16] = digest.finalize()[..16].try_into().unwrap();
    let padded = aes_key_unwrap_128(&kek, key_wrapped)?;
    if padded.len() != 40 {
        return Err(Error::Integrity);
    }
    let padding_len = usize::from(*padded.last().ok_or(Error::Integrity)?);
    if padding_len == 0 || padding_len > 37 {
        return Err(Error::Integrity);
    }
    let key_len = 40usize
        .checked_sub(padding_len + 3)
        .ok_or(Error::Integrity)?;
    if padded[3 + key_len..]
        .iter()
        .any(|byte| usize::from(*byte) != padding_len)
    {
        return Err(Error::Integrity);
    }
    let key = &padded[1..1 + key_len];
    let checksum = u16::from_be_bytes([padded[1 + key_len], padded[2 + key_len]]);
    let expected = key
        .iter()
        .fold(0u16, |sum, byte| sum.wrapping_add(u16::from(*byte)));
    if checksum != expected {
        return Err(Error::Integrity);
    }
    Ok(key.to_vec())
}

pub fn pcs_rfc6637_unwrap(recipient_scalar: &[u8; 32], wrapped: &[u8]) -> Result<Vec<u8>> {
    rfc6637_unwrap(recipient_scalar, b"fingerprint\0\0\0\0\0\0\0\0\0", wrapped)
}

pub fn sf_ecies_p384_decrypt(
    recipient_scalar: &[u8; 48],
    ephemeral_x963: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    let secret = SecretKey384::from_slice(recipient_scalar).map_err(|_| Error::Integrity)?;
    let public = PublicKey384::from_sec1_bytes(ephemeral_x963).map_err(|_| Error::Integrity)?;
    let shared = p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let mut derived = Vec::with_capacity(64);
    for counter in 1..=2u32 {
        let mut digest = Sha256::new();
        digest.update(shared.raw_secret_bytes());
        digest.update(counter.to_be_bytes());
        digest.update(ephemeral_x963);
        derived.extend_from_slice(&digest.finalize());
    }
    let mut plaintext = ciphertext.to_vec();
    let cipher = Aes256Gcm16Nonce::new_from_slice(&derived[..32]).map_err(|_| Error::Integrity)?;
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(&derived[32..48]),
            b"",
            &mut plaintext,
            GenericArray::from_slice(tag),
        )
        .map_err(|_| Error::Integrity)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcs_rfc6637_wrap_round_trips_through_authoritative_unwrap() {
        let recipient = SecretKey256::random(&mut rand::rngs::OsRng);
        let encoded = recipient.public_key().to_encoded_point(false);
        let public_x: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();
        let scalar: [u8; 32] = recipient.to_bytes().as_slice().try_into().unwrap();
        let key = [0x5au8; 16];

        let wrapped = pcs_rfc6637_wrap(&public_x, &key).unwrap();

        assert_eq!(pcs_rfc6637_unwrap(&scalar, &wrapped).unwrap(), key);
    }

    #[test]
    fn pcs_rfc6637_wrap_matches_independent_fixed_vector() {
        // Independently calculated with Python cryptography from RFC 6637 and
        // Apple's fixed PCS parameter block. Recipient scalar = 1, ephemeral
        // scalar = 2, and master key = 00..0f.
        let recipient_x: [u8; 32] =
            hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                .unwrap()
                .try_into()
                .unwrap();
        let mut ephemeral_scalar = [0u8; 32];
        ephemeral_scalar[31] = 2;
        let ephemeral = SecretKey256::from_slice(&ephemeral_scalar).unwrap();
        let master_key: Vec<u8> = (0..16).collect();

        let wrapped =
            pcs_rfc6637_wrap_with_ephemeral(&recipient_x, &master_key, &ephemeral).unwrap();

        assert_eq!(
            hex::encode(wrapped),
            "01007cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997830c3193c47ccac501cd446cc76e3320c7c76219f93189467075d4396b645331567a1953c4a21b771ed0edc5094405574e5"
        );
    }
}
