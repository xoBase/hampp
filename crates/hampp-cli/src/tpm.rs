//! TPM-backed keys (feature `tpm`), a thin layer over the `hampp-tpm` crate.
use crate::io::Res;
use hampp_core::{KeyMeta, Signer, ALG_P256_TPM};
use hampp_tpm::{KeyFileJson, TpmSigner};
use std::path::Path;

/// Creates a key inside the TPM and writes its key file (only the TPM-wrapped blob, mode 0600).
/// Returns the key id.
pub fn create(path: &Path, agent: &str) -> Res<String> {
    let (signer, file) = TpmSigner::create(agent, None)?;
    hampp_core::create_key_file(path, &serde_json::to_string_pretty(&file)?)?;
    Ok(hex::encode(signer.public_key().key_id()))
}

pub fn load(path: &Path) -> Res<(Box<dyn Signer>, KeyMeta)> {
    let file: KeyFileJson = serde_json::from_str(&crate::io::read_file(path)?)?;
    let signer = TpmSigner::load(&file, None)?;
    let meta = KeyMeta {
        agent_id: signer.agent_id.clone(),
        instance_id: signer.instance_id,
        public_key: signer.public_key(),
        alg: ALG_P256_TPM.to_string(),
    };
    Ok((Box::new(signer), meta))
}

/// `Ok` when a TPM is reachable and can create our primary key; otherwise the reason.
pub fn probe() -> Result<(), String> {
    hampp_tpm::probe(None).map_err(|e| e.to_string())
}
