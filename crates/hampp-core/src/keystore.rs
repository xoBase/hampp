use crate::{io_ctx, SigningIdentity};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid key file: {0}")]
    Format(String),
    #[error("key file {0} must not be accessible by group/others (chmod 600)")]
    InsecurePermissions(String),
    #[error("{0} already exists; refusing to overwrite a key")]
    AlreadyExists(String),
}

/// Storage backend for the private key. Hardware-backed stores (TPM, HSM)
/// are future implementations of this trait.
pub trait KeyStore {
    fn load(&self) -> Result<SigningIdentity, KeyStoreError>;
    fn save(&self, id: &SigningIdentity) -> Result<(), KeyStoreError>;
}

pub struct FileKeyStore {
    pub path: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    agent_id: String,
    instance_id: String,
    secret: String,
    public: String,
}

fn hex_array<const N: usize>(s: &str, what: &str) -> Result<[u8; N], KeyStoreError> {
    hex::decode(s)
        .ok()
        .and_then(|v| <[u8; N]>::try_from(v).ok())
        .ok_or_else(|| KeyStoreError::Format(format!("bad {what}")))
}

impl KeyStore for FileKeyStore {
    fn load(&self) -> Result<SigningIdentity, KeyStoreError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&self.path)
                .map_err(io_ctx(&self.path))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(KeyStoreError::InsecurePermissions(
                    self.path.display().to_string(),
                ));
            }
        }
        let kf: KeyFile =
            serde_json::from_str(&std::fs::read_to_string(&self.path).map_err(io_ctx(&self.path))?)
                .map_err(|e| KeyStoreError::Format(e.to_string()))?;
        let seed = hex_array::<32>(&kf.secret, "secret")?;
        let id = SigningIdentity::from_seed(
            &kf.agent_id,
            seed,
            hex_array::<16>(&kf.instance_id, "instance_id")?,
        );
        if hex::encode(id.identity.public_key) != kf.public {
            return Err(KeyStoreError::Format(
                "public key does not match secret".into(),
            ));
        }
        Ok(id)
    }

    fn save(&self, id: &SigningIdentity) -> Result<(), KeyStoreError> {
        let kf = KeyFile {
            agent_id: id.identity.agent_id.clone(),
            instance_id: hex::encode(id.identity.instance_id),
            secret: hex::encode(id.seed()),
            public: hex::encode(id.identity.public_key),
        };
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&self.path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                KeyStoreError::AlreadyExists(self.path.display().to_string())
            } else {
                KeyStoreError::Io(e)
            }
        })?;
        let json =
            serde_json::to_string_pretty(&kf).map_err(|e| KeyStoreError::Format(e.to_string()))?;
        f.write_all(json.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningIdentity;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn save_then_load_roundtrip_with_0600() {
        let dir = tempfile::tempdir().unwrap();
        let ks = FileKeyStore {
            path: dir.path().join("key.json"),
        };
        let id = SigningIdentity::generate("agent-1");
        ks.save(&id).unwrap();
        let mode = std::fs::metadata(&ks.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let back = ks.load().unwrap();
        assert_eq!(back.identity.public_key, id.identity.public_key);
        assert_eq!(back.identity.agent_id, "agent-1");
        assert_eq!(back.identity.instance_id, id.identity.instance_id);
    }

    #[test]
    fn save_never_overwrites_an_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let ks = FileKeyStore {
            path: dir.path().join("key.json"),
        };
        ks.save(&SigningIdentity::generate("a")).unwrap();
        assert!(matches!(
            ks.save(&SigningIdentity::generate("b")),
            Err(KeyStoreError::AlreadyExists(_))
        ));
    }

    #[test]
    fn world_readable_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ks = FileKeyStore {
            path: dir.path().join("key.json"),
        };
        ks.save(&SigningIdentity::generate("a")).unwrap();
        std::fs::set_permissions(&ks.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            ks.load(),
            Err(KeyStoreError::InsecurePermissions(_))
        ));
    }

    #[test]
    fn tampered_public_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ks = FileKeyStore {
            path: dir.path().join("key.json"),
        };
        ks.save(&SigningIdentity::generate("a")).unwrap();
        let txt = std::fs::read_to_string(&ks.path).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&txt).unwrap();
        v["public"] = serde_json::Value::String("00".repeat(32));
        std::fs::write(&ks.path, serde_json::to_string(&v).unwrap()).unwrap();
        assert!(matches!(ks.load(), Err(KeyStoreError::Format(_))));
    }

    #[test]
    fn missing_key_file_error_names_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let ks = FileKeyStore {
            path: dir.path().join("missing-key.json"),
        };
        let msg = ks.load().err().unwrap().to_string();
        assert!(msg.contains("missing-key.json"), "{msg}");
    }
}
