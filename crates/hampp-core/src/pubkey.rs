use crate::identity::key_id_of;
use crate::p256sw;
use sha2::{Digest, Sha256};

pub const SUITE_ED25519_SHA256: u8 = 1;
pub const SUITE_ECDSA_P256_SHA256: u8 = 2;

/// A public key together with its suite. The length tells the suite apart on the wire
/// and in files: 32 bytes = Ed25519, 33 bytes (SEC1 compressed) = ECDSA P-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519([u8; 32]),
    P256([u8; 33]),
}

impl From<[u8; 32]> for PublicKey {
    fn from(k: [u8; 32]) -> Self {
        PublicKey::Ed25519(k)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = ();
    fn try_from(v: Vec<u8>) -> Result<Self, ()> {
        PublicKey::from_slice(&v).ok_or(())
    }
}

impl PublicKey {
    pub fn suite(&self) -> u8 {
        match self {
            PublicKey::Ed25519(_) => SUITE_ED25519_SHA256,
            PublicKey::P256(_) => SUITE_ECDSA_P256_SHA256,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::Ed25519(k) => k,
            PublicKey::P256(k) => k,
        }
    }

    /// 32 bytes = Ed25519 (not validated here, like before), 33 bytes = a valid P-256 point.
    pub fn from_slice(b: &[u8]) -> Option<PublicKey> {
        match b.len() {
            32 => Some(PublicKey::Ed25519(b.try_into().ok()?)),
            33 if p256sw::is_valid_point(b) => Some(PublicKey::P256(b.try_into().ok()?)),
            _ => None,
        }
    }

    pub fn from_hex(s: &str) -> Result<PublicKey, String> {
        let bytes = hex::decode(s.trim()).map_err(|e| format!("public key is not hex: {e}"))?;
        PublicKey::from_slice(&bytes).ok_or_else(|| {
            "public key must be 32 bytes (Ed25519) or a valid 33-byte compressed P-256 point, as hex"
                .to_string()
        })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Suite 1: `SHA-256(pubkey)[..8]` (unchanged). Suite 2: the same over the 33-byte point;
    /// the input lengths differ, so ids never collide across suites.
    pub fn key_id(&self) -> [u8; 8] {
        match self {
            PublicKey::Ed25519(k) => key_id_of(k),
            PublicKey::P256(k) => {
                let mut out = [0u8; 8];
                out.copy_from_slice(&Sha256::digest(k)[..8]);
                out
            }
        }
    }
}

/// Verifies `sig` over `msg` with the suite implied by the key. Never panics.
/// ECDSA signatures with a high `s` are rejected (`spec/PROTOCOL.md`, section 2).
pub fn verify_signature(pk: &PublicKey, msg: &[u8], sig: &[u8; 64]) -> bool {
    match pk {
        PublicKey::Ed25519(k) => crate::identity::verify_sig(k, msg, sig),
        PublicKey::P256(k) => p256sw::verify(k, msg, sig),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256sw::P256Software;

    fn key() -> P256Software {
        P256Software::from_scalar("a", [5u8; 32], [1u8; 16]).unwrap()
    }

    #[test]
    fn p256_sign_verify_roundtrip_is_low_s() {
        let k = key();
        for i in 0..64u8 {
            let sig = k.sign_low_s(&[i; 16]);
            assert!(verify_signature(&k.public_key(), &[i; 16], &sig), "{i}");
            assert!(!verify_signature(&k.public_key(), &[i ^ 1; 16], &sig));
        }
    }

    #[test]
    fn high_s_signature_is_rejected() {
        let k = key();
        let sig = k.sign_low_s(b"m");
        let high = crate::p256sw::flip_s(&sig);
        assert_ne!(high, sig);
        assert!(!verify_signature(&k.public_key(), b"m", &high));
    }

    #[test]
    fn key_ids_differ_between_suites_and_suite1_is_unchanged() {
        let ed = PublicKey::Ed25519([9; 32]);
        assert_eq!(ed.key_id(), key_id_of(&[9; 32]));
        let p = key().public_key();
        assert_eq!(&Sha256::digest(p.as_bytes())[..8], &p.key_id());
        assert_eq!(p.suite(), 2);
    }

    #[test]
    fn garbage_points_and_wrong_lengths_are_rejected() {
        assert!(PublicKey::from_slice(&[0u8; 33]).is_none());
        assert!(PublicKey::from_slice(&[2u8; 34]).is_none());
        assert!(PublicKey::from_slice(&[2u8; 31]).is_none());
        assert!(!verify_signature(
            &PublicKey::Ed25519([0; 32]),
            b"m",
            &[0; 64]
        ));
        assert!(PublicKey::from_hex("zz").is_err());
        let p = key().public_key();
        assert_eq!(PublicKey::from_hex(&p.to_hex()), Ok(p));
    }
}
