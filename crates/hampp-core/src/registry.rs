use crate::{hexfmt, io_ctx, write_atomic, Identity, KeyResolver, ResolvedKey, TrustState};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid registry file: {0}")]
    Format(String),
    #[error("a different public key is already registered under this key id")]
    KeyIdConflict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub agent_id: String,
    #[serde(with = "hexfmt")]
    pub instance_id: [u8; 16],
    #[serde(with = "hexfmt")]
    pub key_id: [u8; 8],
    #[serde(with = "hexfmt")]
    pub public_key: [u8; 32],
    pub trust: TrustState,
    pub first_seen: u64,
    pub expires: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    pub entries: Vec<Entry>,
}

impl Registry {
    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| RegistryError::Format(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Registry::default()),
            Err(e) => Err(io_ctx(path)(e).into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), RegistryError> {
        let s =
            serde_json::to_string_pretty(self).map_err(|e| RegistryError::Format(e.to_string()))?;
        write_atomic(path, s.as_bytes()).map_err(io_ctx(path))?;
        Ok(())
    }

    pub fn add(
        &mut self,
        id: &Identity,
        trust: TrustState,
        now: u64,
        expires: Option<u64>,
    ) -> Result<(), RegistryError> {
        let key_id = id.key_id();
        if let Some(e) = self.entries.iter_mut().find(|e| e.key_id == key_id) {
            if e.public_key != id.public_key {
                return Err(RegistryError::KeyIdConflict);
            }
            e.trust = trust;
            e.expires = expires;
            return Ok(());
        }
        self.entries.push(Entry {
            agent_id: id.agent_id.clone(),
            instance_id: id.instance_id,
            key_id,
            public_key: id.public_key,
            trust,
            first_seen: now,
            expires,
        });
        Ok(())
    }

    pub fn set_trust(&mut self, key_id: &[u8; 8], trust: TrustState) -> bool {
        match self.entries.iter_mut().find(|e| &e.key_id == key_id) {
            Some(e) => {
                e.trust = trust;
                true
            }
            None => false,
        }
    }

    pub fn effective_trust(e: &Entry, now: u64) -> TrustState {
        match (e.trust, e.expires) {
            (TrustState::Trusted | TrustState::Pending, Some(x)) if now >= x => TrustState::Expired,
            (t, _) => t,
        }
    }
}

impl KeyResolver for Registry {
    fn resolve(&self, key_id: &[u8; 8], now: u64) -> Option<ResolvedKey> {
        self.entries
            .iter()
            .find(|e| &e.key_id == key_id)
            .map(|e| ResolvedKey {
                public_key: e.public_key,
                agent_id: Some(e.agent_id.clone()),
                instance_id: Some(e.instance_id),
                trust: Some(Registry::effective_trust(e, now)),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sign_text, verify_text, Carrier, SignParams, SigningIdentity};

    fn id(n: u8) -> SigningIdentity {
        SigningIdentity::from_seed(&format!("agent-{n}"), [n; 32], [n; 16])
    }

    #[test]
    fn add_save_load_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("reg.json");
        let a = id(1);
        let mut r = Registry::default();
        r.add(&a.identity, TrustState::Trusted, 100, None).unwrap();
        r.save(&p).unwrap();
        let back = Registry::load(&p).unwrap();
        let k = back.resolve(&a.identity.key_id(), 200).unwrap();
        assert_eq!(k.agent_id.as_deref(), Some("agent-1"));
        assert_eq!(k.trust, Some(TrustState::Trusted));
    }

    #[test]
    fn missing_file_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Registry::load(&dir.path().join("none.json"))
            .unwrap()
            .entries
            .is_empty());
    }

    #[test]
    fn expiry_is_computed_from_now() {
        let a = id(1);
        let mut r = Registry::default();
        r.add(&a.identity, TrustState::Trusted, 0, Some(1000))
            .unwrap();
        assert_eq!(
            r.resolve(&a.identity.key_id(), 999).unwrap().trust,
            Some(TrustState::Trusted)
        );
        assert_eq!(
            r.resolve(&a.identity.key_id(), 1000).unwrap().trust,
            Some(TrustState::Expired)
        );
    }

    #[test]
    fn revoked_key_gives_invalid_key_revoked_even_with_good_signature() {
        let a = id(1);
        let mut r = Registry::default();
        r.add(&a.identity, TrustState::Trusted, 0, None).unwrap();
        let msg = sign_text(&a, "hi", &SignParams::lite(5), Carrier::ZeroWidth);
        assert_eq!(
            verify_text(&msg, &r, 5).code(),
            "authenticated:signed-by-agent"
        );
        assert!(r.set_trust(&a.identity.key_id(), TrustState::Revoked));
        assert_eq!(verify_text(&msg, &r, 5).code(), "invalid:key-revoked");
    }

    #[test]
    fn unknown_key_is_unverified() {
        let r = Registry::default();
        let msg = sign_text(&id(1), "hi", &SignParams::lite(5), Carrier::ZeroWidth);
        assert_eq!(verify_text(&msg, &r, 5).code(), "unverified:unknown-key");
    }

    #[test]
    fn key_id_conflict_with_different_public_key_is_rejected() {
        let a = id(1);
        let mut r = Registry::default();
        r.add(&a.identity, TrustState::Pending, 0, None).unwrap();
        let mut forged = a.identity.clone();
        forged.public_key[0] ^= 1; // different key, we force the same key_id below
        r.entries[0].key_id = forged.key_id();
        assert!(matches!(
            r.add(&forged, TrustState::Trusted, 0, None),
            Err(RegistryError::KeyIdConflict)
        ));
    }

    #[test]
    fn unreadable_registry_error_names_the_path() {
        let dir = tempfile::tempdir().unwrap();
        // a directory cannot be read as a file
        let msg = Registry::load(dir.path()).err().unwrap().to_string();
        assert!(msg.contains(&dir.path().display().to_string()), "{msg}");
    }
}
