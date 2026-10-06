use crate::io::{now, read_file, Res};
use crate::keys::key_path;
use clap::Subcommand;
use hampp_core::{canonicalize, sign_text, Carrier, FileKeyStore, KeyStore, SignParams};
use hampp_envelope::{extract_any, Envelope};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Subcommand)]
pub enum ProbeCmd {
    /// Print a signed probe message. Post it on the platform, copy it back, then run `probe check`.
    Generate {
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Compare the text you sent with what the platform returned.
    Check {
        #[arg(long)]
        sent: PathBuf,
        #[arg(long)]
        received: PathBuf,
    },
}

pub fn run(cmd: ProbeCmd) -> Res<ExitCode> {
    match cmd {
        ProbeCmd::Generate { key } => {
            let id = FileKeyStore {
                path: key_path(&key),
            }
            .load()?;
            let text = format!("hampp probe {}", now());
            print!(
                "{}",
                sign_text(&id, &text, &SignParams::lite(now()), Carrier::ZeroWidth)
            );
            Ok(ExitCode::SUCCESS)
        }
        ProbeCmd::Check { sent, received } => {
            let s = extract_any(&read_file(&sent)?);
            let r = extract_any(&read_file(&received)?);
            let text_same = canonicalize(&s.visible) == canonicalize(&r.visible);
            let text_state = if text_same { "unchanged" } else { "changed" };
            match (&s.envelope, &r.envelope) {
                (_, Envelope::Missing) => {
                    println!("STRIPPED: the platform removed the envelope (text {text_state}).");
                    println!("Use the visible fallback (`hampp sign --visible`) on this platform.");
                    Ok(ExitCode::from(10))
                }
                (a, b) if a == b && text_same => {
                    println!("SURVIVED: envelope and text came back unchanged.");
                    Ok(ExitCode::SUCCESS)
                }
                _ => {
                    println!(
                        "ALTERED: envelope or text differs from what was sent (text {text_state})."
                    );
                    Ok(ExitCode::from(20))
                }
            }
        }
    }
}
