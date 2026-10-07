use crate::{io_ctx, P256Software, PublicKey, Signer, SigningIdentity};
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

fn check_permissions(path: &std::path::Path) -> Result<(), KeyStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(io_ctx(path))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(KeyStoreError::InsecurePermissions(
                path.display().to_string(),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub const ALG_ED25519: &str = "ed25519";
pub const ALG_P256_SOFTWARE: &str = "ecdsa-p256-software";
pub const ALG_P256_TPM: &str = "ecdsa-p256-tpm";

/// Who a key file belongs to, independent of the algorithm.
#[derive(Debug, Clone)]
pub struct KeyMeta {
    pub agent_id: String,
    pub instance_id: [u8; 16],
    pub public_key: PublicKey,
    pub alg: String,
}

/// Algorithm tag of a key file; files without `alg` are Ed25519 (the format before suite 2).
pub fn key_alg(path: &std::path::Path) -> Result<String, KeyStoreError> {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).map_err(io_ctx(path))?)
            .map_err(|e| KeyStoreError::Format(e.to_string()))?;
    Ok(v.get("alg")
        .and_then(|a| a.as_str())
        .unwrap_or(ALG_ED25519)
        .to_string())
}

#[derive(Serialize, Deserialize)]
struct P256KeyFile {
    alg: String,
    agent_id: String,
    instance_id: String,
    secret: String,
    public: String,
}

/// Loads an Ed25519 or software P-256 key file as a [`Signer`]. Other algorithms (a TPM key)
/// belong to backends that this crate does not depend on.
pub fn load_signer(path: &std::path::Path) -> Result<(Box<dyn Signer>, KeyMeta), KeyStoreError> {
    match key_alg(path)?.as_str() {
        ALG_ED25519 => {
            let id = FileKeyStore { path: path.into() }.load()?;
            let meta = KeyMeta {
                agent_id: id.identity.agent_id.clone(),
                instance_id: id.identity.instance_id,
                public_key: PublicKey::Ed25519(id.identity.public_key),
                alg: ALG_ED25519.into(),
            };
            Ok((Box::new(id), meta))
        }
        ALG_P256_SOFTWARE => {
            check_permissions(path)?;
            let kf: P256KeyFile =
                serde_json::from_str(&std::fs::read_to_string(path).map_err(io_ctx(path))?)
                    .map_err(|e| KeyStoreError::Format(e.to_string()))?;
            let key = P256Software::from_scalar(
                &kf.agent_id,
                hex_array::<32>(&kf.secret, "secret")?,
                hex_array::<16>(&kf.instance_id, "instance_id")?,
            )
            .map_err(KeyStoreError::Format)?;
            if key.public_key().to_hex() != kf.public {
                return Err(KeyStoreError::Format(
                    "public key does not match secret".into(),
                ));
            }
            let meta = KeyMeta {
                agent_id: key.agent_id.clone(),
                instance_id: key.instance_id,
                public_key: key.public_key(),
                alg: ALG_P256_SOFTWARE.into(),
            };
            Ok((Box::new(key), meta))
        }
        other => Err(KeyStoreError::Format(format!(
            "unsupported key algorithm {other:?} in {}",
            path.display()
        ))),
    }
}

/// Creates the key file (mode 0600, never overwrites) with the given JSON text.
pub fn create_key_file(path: &std::path::Path, json: &str) -> Result<(), KeyStoreError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            KeyStoreError::AlreadyExists(path.display().to_string())
        } else {
            KeyStoreError::Io(e)
        }
    })?;
    f.write_all(json.as_bytes())?;
    Ok(())
}

pub fn save_p256_software(path: &std::path::Path, key: &P256Software) -> Result<(), KeyStoreError> {
    let kf = P256KeyFile {
        alg: ALG_P256_SOFTWARE.into(),
        agent_id: key.agent_id.clone(),
        instance_id: hex::encode(key.instance_id),
        secret: hex::encode(key.scalar()),
        public: key.public_key().to_hex(),
    };
    create_key_file(
        path,
        &serde_json::to_string_pretty(&kf).map_err(|e| KeyStoreError::Format(e.to_string()))?,
    )
}

impl KeyStore for FileKeyStore {
    fn load(&self) -> Result<SigningIdentity, KeyStoreError> {
        check_permissions(&self.path)?;
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
        let json =
            serde_json::to_string_pretty(&kf).map_err(|e| KeyStoreError::Format(e.to_string()))?;
        create_key_file(&self.path, &json)
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
