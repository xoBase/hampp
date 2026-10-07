use crate::p256sw::P256Software;
use crate::{
    Protection, PublicKey, SigningIdentity, SUITE_ECDSA_P256_SHA256, SUITE_ED25519_SHA256,
};

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("protection {requested:?} is not available for this key (it offers at most {max:?})")]
    LevelNotAvailable {
        requested: Protection,
        max: Protection,
    },
    #[error("signing backend: {0}")]
    Backend(String),
}

/// Something that signs bytes without exposing key material. `level` is the highest
/// protection this key may honestly claim; callers may claim less, never more.
pub trait Signer {
    fn suite(&self) -> u8;
    fn public_key(&self) -> PublicKey;
    fn level(&self) -> Protection;
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], SignError>;
}

impl Signer for SigningIdentity {
    fn suite(&self) -> u8 {
        SUITE_ED25519_SHA256
    }
    fn public_key(&self) -> PublicKey {
        PublicKey::Ed25519(self.identity.public_key)
    }
    fn level(&self) -> Protection {
        Protection::Software
    }
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], SignError> {
        Ok(SigningIdentity::sign(self, msg))
    }
}

impl Signer for P256Software {
    fn suite(&self) -> u8 {
        SUITE_ECDSA_P256_SHA256
    }
    fn public_key(&self) -> PublicKey {
        P256Software::public_key(self)
    }
    fn level(&self) -> Protection {
        self.claimed_level()
    }
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], SignError> {
        Ok(self.sign_low_s(msg))
    }
}
