use crate::io::Res;
use clap::Args;
use hampp_core::{KeyResolver, PublicKey, Registry, SingleKey};
use std::path::PathBuf;

#[derive(Args, Clone)]
pub struct KeyArgs {
    /// Public key as hex: 64 characters (Ed25519) or 66 characters (P-256, compressed).
    #[arg(long)]
    pub pubkey: Option<String>,
    /// File containing the public key as hex.
    #[arg(long)]
    pub pubkey_file: Option<PathBuf>,
    /// Registry file (agent -> key -> trust).
    #[arg(long)]
    pub registry: Option<PathBuf>,
}

pub fn parse_pubkey(hex_str: &str) -> Res<PublicKey> {
    Ok(PublicKey::from_hex(hex_str)?)
}

pub fn resolver(a: &KeyArgs) -> Res<Box<dyn KeyResolver>> {
    if let Some(r) = &a.registry {
        return Ok(Box::new(Registry::load(r)?));
    }
    if let Some(h) = &a.pubkey {
        return Ok(Box::new(SingleKey(parse_pubkey(h)?)));
    }
    if let Some(f) = &a.pubkey_file {
        return Ok(Box::new(SingleKey(parse_pubkey(&crate::io::read_file(
            f,
        )?)?)));
    }
    Err("one of --pubkey, --pubkey-file, --registry or --session is required".into())
}

pub fn key_path(opt: &Option<PathBuf>) -> PathBuf {
    opt.clone()
        .or_else(|| std::env::var_os("HAMPP_KEY").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("hampp-key.json"))
}

/// Loads the signer of a key file: Ed25519 and software P-256 files here, TPM files via the
/// `tpm` feature.
pub fn load_signer(
    path: &std::path::Path,
) -> Res<(Box<dyn hampp_core::Signer>, hampp_core::KeyMeta)> {
    if hampp_core::key_alg(path)? == hampp_core::ALG_P256_TPM {
        #[cfg(feature = "tpm")]
        return crate::tpm::load(path);
        #[cfg(not(feature = "tpm"))]
        return Err(format!(
            "{} is a TPM key, but this hampp was built without tpm support (cargo build --features tpm)",
            path.display()
        )
        .into());
    }
    Ok(hampp_core::load_signer(path)?)
}
