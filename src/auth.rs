//! GrandSlam SRP-6a primitives used by Apple Account bootstrap.

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

type HmacSha256 = Hmac<Sha256>;
const N_HEX: &str = "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordScheme {
    S2k,
    S2kFo,
}

#[derive(Clone, Zeroize)]
pub struct SrpProof {
    pub m1: [u8; 32],
    pub expected_m2: [u8; 32],
    pub session_key: [u8; 32],
}
impl std::fmt::Debug for SrpProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SrpProof(<redacted>)")
    }
}

pub struct SrpClient {
    username: String,
    password: Zeroizing<Vec<u8>>,
    private: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
}
impl std::fmt::Debug for SrpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrpClient")
            .field("username", &self.username)
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl SrpClient {
    pub fn new(username: impl Into<String>, password: impl AsRef<[u8]>) -> Self {
        let mut private = vec![0u8; 256];
        rand::rngs::OsRng.fill_bytes(&mut private);
        private[0] |= 0x80;
        Self::with_private(username, password, private)
    }
    pub fn with_private(
        username: impl Into<String>,
        password: impl AsRef<[u8]>,
        mut private: Vec<u8>,
    ) -> Self {
        assert_eq!(private.len(), 256);
        private[0] |= 0x80;
        let n = modulus();
        let public = minimal(&BigUint::from(2u8).modpow(&BigUint::from_bytes_be(&private), &n));
        Self {
            username: username.into(),
            password: Zeroizing::new(password.as_ref().to_vec()),
            private: Zeroizing::new(private),
            public,
        }
    }
    pub fn public_a(&self) -> &[u8] {
        &self.public
    }
    pub fn complete(
        &self,
        scheme: PasswordScheme,
        salt: &[u8],
        iterations: u32,
        server_b: &[u8],
    ) -> Result<SrpProof> {
        let n = modulus();
        let g = BigUint::from(2u8);
        let a = BigUint::from_bytes_be(&self.private);
        let a_pub = BigUint::from_bytes_be(&self.public);
        let b = BigUint::from_bytes_be(server_b);
        if b.is_zero() || (&b % &n).is_zero() {
            return Err(Error::Integrity);
        }
        let p0 = Sha256::digest(&*self.password);
        let p1 = match scheme {
            PasswordScheme::S2k => p0.to_vec(),
            PasswordScheme::S2kFo => hex::encode(p0).into_bytes(),
        };
        let mut p = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(&p1, salt, iterations, &mut p);
        let inner = Sha256::digest([b":".as_slice(), p.as_slice()].concat());
        let x = BigUint::from_bytes_be(&Sha256::digest([salt, inner.as_slice()].concat()));
        let k = BigUint::from_bytes_be(&Sha256::digest([pad(&n), pad(&g)].concat()));
        let u = BigUint::from_bytes_be(&Sha256::digest([pad(&a_pub), pad(&b)].concat()));
        if u.is_zero() {
            p.zeroize();
            return Err(Error::Integrity);
        }
        let base = (&b + &n - ((&k * g.modpow(&x, &n)) % &n)) % &n;
        let shared = base.modpow(&(&a + &u * &x), &n);
        let key: [u8; 32] = Sha256::digest(minimal(&shared)).into();
        let hn = Sha256::digest(minimal(&n));
        let hg = Sha256::digest(pad(&g));
        let xor: Vec<u8> = hn.iter().zip(hg).map(|(a, b)| a ^ b).collect();
        let hu = Sha256::digest(self.username.as_bytes());
        let m1: [u8; 32] = Sha256::digest(
            [
                xor.as_slice(),
                hu.as_slice(),
                salt,
                self.public.as_slice(),
                server_b,
                key.as_slice(),
            ]
            .concat(),
        )
        .into();
        let expected_m2: [u8; 32] =
            Sha256::digest([self.public.as_slice(), m1.as_slice(), key.as_slice()].concat()).into();
        p.zeroize();
        Ok(SrpProof {
            m1,
            expected_m2,
            session_key: key,
        })
    }
}

fn modulus() -> BigUint {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).unwrap()
}
fn minimal(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.is_empty() { vec![0] } else { bytes }
}
fn pad(value: &BigUint) -> Vec<u8> {
    let bytes = minimal(value);
    let mut out = vec![0u8; 256usize.saturating_sub(bytes.len())];
    out.extend(bytes);
    out
}

pub fn verify_server_proof(proof: &SrpProof, received: &[u8]) -> Result<()> {
    use subtle::ConstantTimeEq;
    if received.len() != 32 || received.ct_eq(proof.expected_m2.as_slice()).unwrap_u8() != 1 {
        return Err(Error::Integrity);
    }
    Ok(())
}
pub fn decrypt_spd(proof: &SrpProof, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut km = <HmacSha256 as Mac>::new_from_slice(&proof.session_key).unwrap();
    km.update(b"extra data key:");
    let key = km.finalize().into_bytes();
    let mut im = <HmacSha256 as Mac>::new_from_slice(&proof.session_key).unwrap();
    im.update(b"extra data iv:");
    let iv = im.finalize().into_bytes();
    let mut buffer = ciphertext.to_vec();
    let plain = cbc::Decryptor::<Aes256>::new_from_slices(&key, &iv[..16])
        .map_err(|_| Error::Integrity)?
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| Error::Integrity)?;
    Ok(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_value_is_group_element() {
        let c = SrpClient::with_private("user", b"password", vec![1; 256]);
        assert!(!c.public_a().is_empty());
        assert!(c.public_a().len() <= 256);
    }
    #[test]
    fn rejects_invalid_server_element() {
        let c = SrpClient::with_private("user", b"password", vec![2; 256]);
        assert!(c.complete(PasswordScheme::S2k, b"salt", 1, &[0]).is_err());
    }
}
