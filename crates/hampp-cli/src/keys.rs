use crate::io::Res;
use clap::Args;
use hampp_core::{KeyResolver, Registry, SingleKey};
use std::path::PathBuf;

#[derive(Args, Clone)]
pub struct KeyArgs {
    /// Public key as 64 hex characters.
    #[arg(long)]
    pub pubkey: Option<String>,
    /// File containing the public key as hex.
    #[arg(long)]
    pub pubkey_file: Option<PathBuf>,
    /// Registry file (agent -> key -> trust).
    #[arg(long)]
    pub registry: Option<PathBuf>,
}

pub fn parse_pubkey(hex_str: &str) -> Res<[u8; 32]> {
    let v = hex::decode(hex_str.trim())?;
    <[u8; 32]>::try_from(v).map_err(|_| "public key must be 32 bytes (64 hex characters)".into())
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
