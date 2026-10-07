//! ECDSA P-256 (suite 2): software key and the shared verifier. Signatures are raw `r || s`
//! with a low `s`; see `spec/PROTOCOL.md`, section 2.
use crate::PublicKey;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;

pub(crate) fn is_valid_point(sec1: &[u8]) -> bool {
    VerifyingKey::from_sec1_bytes(sec1).is_ok()
}

pub(crate) fn verify(pk: &[u8; 33], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(sig) = Signature::from_slice(sig) else {
        return false;
    };
    if sig.normalize_s().is_some() {
        return false; // high s
    }
    match VerifyingKey::from_sec1_bytes(pk) {
        Ok(vk) => vk.verify(msg, &sig).is_ok(),
        Err(_) => false,
    }
}

/// Converts `s` to `n - s` when it is high (for signers that do not normalise, such as a TPM).
pub fn normalize_low_s(r_s: &[u8; 64]) -> Option<[u8; 64]> {
    let sig = Signature::from_slice(r_s).ok()?;
    Some(sig.normalize_s().unwrap_or(sig).to_bytes().into())
}

/// `s -> n - s`, producing the (valid but forbidden) high-s twin. For tests.
#[doc(hidden)]
pub fn flip_s(r_s: &[u8; 64]) -> [u8; 64] {
    let sig = Signature::from_slice(r_s).expect("valid signature bytes");
    let (r, s) = sig.split_scalars();
    let neg = -*s;
    Signature::from_scalars(r.to_bytes(), neg.to_bytes())
        .expect("n - s is a valid scalar")
        .to_bytes()
        .into()
}

pub struct P256Software {
    pub agent_id: String,
    pub instance_id: [u8; 16],
    key: SigningKey,
    public: [u8; 33],
    level: crate::Protection,
}

impl P256Software {
    pub fn generate(agent_id: &str) -> Self {
        let key = SigningKey::random(&mut OsRng);
        let mut instance = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut instance);
        Self::from_key(agent_id, key, instance)
    }

    pub fn from_scalar(
        agent_id: &str,
        scalar: [u8; 32],
        instance_id: [u8; 16],
    ) -> Result<Self, String> {
        let key =
            SigningKey::from_bytes((&scalar).into()).map_err(|_| "invalid P-256 secret scalar")?;
        Ok(Self::from_key(agent_id, key, instance_id))
    }

    fn from_key(agent_id: &str, key: SigningKey, instance_id: [u8; 16]) -> Self {
        let mut public = [0u8; 33];
        public.copy_from_slice(key.verifying_key().to_encoded_point(true).as_bytes());
        Self {
            agent_id: agent_id.to_string(),
            instance_id,
            key,
            public,
            level: crate::Protection::Software,
        }
    }

    pub fn scalar(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::P256(self.public)
    }

    /// Signs `msg` (hashed with SHA-256 inside) and returns raw `r || s` with a low `s`.
    pub fn sign_low_s(&self, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = self.key.sign(msg);
        sig.normalize_s().unwrap_or(sig).to_bytes().into()
    }

    /// Test vectors only (feature `test-support`): lets a software key claim a higher level,
    /// which real key stores never do. Not compiled into normal builds.
    #[cfg(feature = "test-support")]
    pub fn claim_level_for_tests(mut self, level: crate::Protection) -> Self {
        self.level = level;
        self
    }

    pub(crate) fn claimed_level(&self) -> crate::Protection {
        self.level
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_s_twin_is_cryptographically_valid_so_only_our_rule_rejects_it() {
        let k = P256Software::from_scalar("a", [5u8; 32], [1u8; 16]).unwrap();
        let sig = k.sign_low_s(b"m");
        let high = flip_s(&sig);
        let raw = Signature::from_slice(&high).unwrap();
        assert!(raw.normalize_s().is_some(), "twin must be high-s");
        let vk = VerifyingKey::from_sec1_bytes(&k.public).unwrap();
        assert!(vk.verify(b"m", &raw).is_ok(), "the library accepts high-s");
        assert!(!verify(&k.public, b"m", &high));
        assert_eq!(normalize_low_s(&high), Some(sig));
    }
}
