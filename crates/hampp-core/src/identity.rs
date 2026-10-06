use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

pub const SUITE_ED25519_SHA256: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub agent_id: String,
    pub instance_id: [u8; 16],
    pub public_key: [u8; 32],
}

impl Identity {
    pub fn key_id(&self) -> [u8; 8] {
        key_id_of(&self.public_key)
    }
}

pub fn key_id_of(public_key: &[u8; 32]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&Sha256::digest(public_key)[..8]);
    out
}

pub struct SigningIdentity {
    pub identity: Identity,
    signing: SigningKey,
}

impl SigningIdentity {
    pub fn generate(agent_id: &str) -> Self {
        let mut seed = [0u8; 32];
        let mut instance = [0u8; 16];
        OsRng.fill_bytes(&mut seed);
        OsRng.fill_bytes(&mut instance);
        Self::from_seed(agent_id, seed, instance)
    }

    pub fn from_seed(agent_id: &str, seed: [u8; 32], instance_id: [u8; 16]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let public_key = signing.verifying_key().to_bytes();
        Self {
            identity: Identity {
                agent_id: agent_id.to_string(),
                instance_id,
                public_key,
            },
            signing,
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}

pub fn verify_sig(public_key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(public_key) {
        Ok(vk) => vk.verify_strict(msg, &Signature::from_bytes(sig)).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn from_seed_is_deterministic_and_sign_verify_works() {
        let a = SigningIdentity::from_seed("agent-a", [7u8; 32], [1u8; 16]);
        let b = SigningIdentity::from_seed("agent-a", [7u8; 32], [1u8; 16]);
        assert_eq!(a.identity.public_key, b.identity.public_key);
        let sig = a.sign(b"hello");
        assert!(verify_sig(&a.identity.public_key, b"hello", &sig));
        assert!(!verify_sig(&a.identity.public_key, b"hellp", &sig));
    }
    #[test]
    fn key_id_is_first_8_bytes_of_sha256_of_public_key() {
        let a = SigningIdentity::from_seed("x", [9u8; 32], [0u8; 16]);
        assert_eq!(a.identity.key_id(), key_id_of(&a.identity.public_key));
        use sha2::{Digest, Sha256};
        assert_eq!(
            &Sha256::digest(a.identity.public_key)[..8],
            &a.identity.key_id()
        );
    }
    #[test]
    fn generate_makes_distinct_identities() {
        assert_ne!(
            SigningIdentity::generate("a").identity.public_key,
            SigningIdentity::generate("a").identity.public_key
        );
    }
    #[test]
    fn garbage_public_key_never_verifies() {
        assert!(!verify_sig(&[0u8; 32], b"m", &[0u8; 64]));
    }
}
