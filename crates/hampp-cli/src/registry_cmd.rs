use crate::io::{now, Res};
use crate::keys::parse_pubkey;
use clap::{Subcommand, ValueEnum};
use hampp_core::{key_id_of, Identity, Registry, TrustState};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Clone, ValueEnum)]
pub enum TrustArg {
    Pending,
    Trusted,
    Revoked,
}

impl From<TrustArg> for TrustState {
    fn from(t: TrustArg) -> Self {
        match t {
            TrustArg::Pending => TrustState::Pending,
            TrustArg::Trusted => TrustState::Trusted,
            TrustArg::Revoked => TrustState::Revoked,
        }
    }
}

#[derive(Subcommand)]
pub enum RegCmd {
    Add {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        pubkey: String,
        #[arg(long)]
        agent: String,
        #[arg(long, value_enum, default_value = "pending")]
        trust: TrustArg,
        /// Unix time after which the entry counts as EXPIRED.
        #[arg(long)]
        expires: Option<u64>,
    },
    List {
        #[arg(long)]
        file: PathBuf,
    },
    Trust {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        pubkey: String,
    },
    Revoke {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        pubkey: String,
    },
}

fn set(file: &Path, pubkey: &str, t: TrustState) -> Res<ExitCode> {
    let mut r = Registry::load(file)?;
    let kid = key_id_of(&parse_pubkey(pubkey)?);
    if !r.set_trust(&kid, t) {
        return Err("key is not in the registry; use `registry add` first".into());
    }
    r.save(file)?;
    Ok(ExitCode::SUCCESS)
}

pub fn run(cmd: RegCmd) -> Res<ExitCode> {
    match cmd {
        RegCmd::Add {
            file,
            pubkey,
            agent,
            trust,
            expires,
        } => {
            let mut r = Registry::load(&file)?;
            let public_key = parse_pubkey(&pubkey)?;
            // The instance id is unknown to the registrar; zeros until a handshake supplies it.
            let id = Identity {
                agent_id: agent,
                instance_id: [0; 16],
                public_key,
            };
            r.add(&id, trust.into(), now(), expires)?;
            r.save(&file)?;
            Ok(ExitCode::SUCCESS)
        }
        RegCmd::List { file } => {
            let r = Registry::load(&file)?;
            let n = now();
            for e in &r.entries {
                let trust = format!("{:?}", Registry::effective_trust(e, n)).to_uppercase();
                println!(
                    "{}  {}  {}  {}",
                    hex::encode(e.key_id),
                    e.agent_id,
                    trust,
                    hex::encode(e.public_key)
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        RegCmd::Trust { file, pubkey } => set(&file, &pubkey, TrustState::Trusted),
        RegCmd::Revoke { file, pubkey } => set(&file, &pubkey, TrustState::Revoked),
    }
}
