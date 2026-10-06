mod handshake;
mod io;
mod keys;
mod output;
mod probe;
mod registry_cmd;

use clap::{Args, Parser, Subcommand};
use hampp_core::{
    annotate, sign_text, verify_text, Carrier, FileKeyStore, KeyStore, SignParams, SigningIdentity,
};
use hampp_envelope::{extract_any, strip_all, Envelope, DEFAULT};
use hampp_session::Session;
use io::{now, read_input, Res};
use keys::{key_path, resolver, KeyArgs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "hampp",
    version,
    about = "Hardware-Bound Agent Message Provenance Protocol"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct FileArg {
    file: Option<PathBuf>,
}

#[derive(Args)]
struct VerifyArgs {
    file: Option<PathBuf>,
    #[command(flatten)]
    keys: KeyArgs,
    /// Session file (see `hampp handshake`); updated after each message.
    #[arg(long)]
    session: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new agent key (never overwrites).
    Keygen {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Show the identity of a key file.
    Identity {
        #[arg(long)]
        key: Option<PathBuf>,
        /// Print only the public key as hex.
        #[arg(long)]
        public: bool,
    },
    /// Sign text from FILE or stdin; the signed text goes to stdout.
    Sign {
        file: Option<PathBuf>,
        #[arg(long)]
        key: Option<PathBuf>,
        /// Use the visible fallback carrier instead of zero-width characters.
        #[arg(long)]
        visible: bool,
        #[arg(long)]
        session: Option<PathBuf>,
    },
    /// Verify a signed message. Exit codes: 0 authenticated, 10 unverified, 20 invalid.
    Verify(VerifyArgs),
    /// Show envelope fields without any key (claims nothing).
    Inspect(FileArg),
    /// Remove the envelope; prints the visible text unchanged.
    Strip(FileArg),
    /// Sidecar mode: print a status line followed by the (sanitised) text.
    Annotate(VerifyArgs),
    Registry {
        #[command(subcommand)]
        cmd: registry_cmd::RegCmd,
    },
    Handshake {
        #[command(subcommand)]
        cmd: handshake::HsCmd,
    },
    Probe {
        #[command(subcommand)]
        cmd: probe::ProbeCmd,
    },
}

fn load_session(p: &Path) -> Res<Session> {
    Ok(serde_json::from_str(&io::read_file(p)?)?)
}

fn save_session(p: &Path, s: &Session) -> Res<()> {
    io::write_state(p, &serde_json::to_string_pretty(s)?)
}

fn verdict_for(a: &VerifyArgs, text: &str) -> Res<hampp_core::Verdict> {
    if let Some(sp) = &a.session {
        let mut s = load_session(sp)?;
        let v = s.verify_next(text, now());
        save_session(sp, &s)?;
        return Ok(v);
    }
    Ok(verify_text(text, resolver(&a.keys)?.as_ref(), now()))
}

fn inspect(text: &str) -> ExitCode {
    let ex = extract_any(text);
    match ex.envelope {
        Envelope::Missing => {
            println!("Result:       UNVERIFIED (envelope-missing)");
            ExitCode::from(10)
        }
        Envelope::Corrupt(e) => {
            println!("Result:       UNVERIFIED (envelope-corrupt: {e:?})");
            ExitCode::from(10)
        }
        Envelope::Present(bytes) => match hampp_core::Header::decode(&bytes) {
            Ok(h) => {
                println!("Protocol:     HAMPP/1 (suite {})", h.suite);
                println!("Key ID:       {}", hex::encode(h.key_id));
                let session = if h.session_id == [0; 8] {
                    "none (lite)".to_string()
                } else {
                    hex::encode(h.session_id)
                };
                println!("Session:      {session}");
                println!("Sequence:     {}", h.seq);
                println!(
                    "Timestamp:    {} ({})",
                    h.timestamp,
                    io::iso8601(h.timestamp)
                );
                println!("Signature:    present, not verified (no key given; use `hampp verify`)");
                println!("Hardware:     SOFTWARE_ONLY (no hardware claim in the envelope)");
                ExitCode::SUCCESS
            }
            Err(e) => {
                println!("Result:       UNVERIFIED (header: {e:?})");
                ExitCode::from(10)
            }
        },
    }
}

fn run(cli: Cli) -> Res<ExitCode> {
    match cli.cmd {
        Cmd::Keygen { agent, key } => {
            let path = key_path(&key);
            let id = SigningIdentity::generate(&agent);
            FileKeyStore { path: path.clone() }.save(&id)?;
            println!(
                "created {} (agent {}, key id {})",
                path.display(),
                agent,
                hex::encode(id.identity.key_id())
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Identity { key, public } => {
            let id = FileKeyStore {
                path: key_path(&key),
            }
            .load()?;
            if public {
                println!("{}", hex::encode(id.identity.public_key));
            } else {
                println!("agent_id:    {}", id.identity.agent_id);
                println!("instance_id: {}", hex::encode(id.identity.instance_id));
                println!("key_id:      {}", hex::encode(id.identity.key_id()));
                println!("public_key:  {}", hex::encode(id.identity.public_key));
                println!("hardware:    SOFTWARE_ONLY");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Sign {
            file,
            key,
            visible,
            session,
        } => {
            let text = read_input(&file)?;
            let id = FileKeyStore {
                path: key_path(&key),
            }
            .load()?;
            let carrier = if visible {
                Carrier::Visible
            } else {
                Carrier::ZeroWidth
            };
            let out = match session {
                Some(sp) => {
                    let mut s = load_session(&sp)?;
                    let o = s.sign_next(&id, &text, now(), carrier);
                    save_session(&sp, &s)?;
                    o
                }
                None => sign_text(&id, &text, &SignParams::lite(now()), carrier),
            };
            print!("{out}");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Verify(a) => {
            let text = read_input(&a.file)?;
            let v = verdict_for(&a, &text)?;
            if a.json {
                println!("{}", serde_json::to_string_pretty(&v.to_json())?);
            } else {
                output::print_human(&v);
            }
            Ok(output::exit_for(&v))
        }
        Cmd::Annotate(a) => {
            let text = read_input(&a.file)?;
            let v = verdict_for(&a, &text)?;
            println!("{}", annotate(&v));
            Ok(output::exit_for(&v))
        }
        Cmd::Inspect(f) => Ok(inspect(&read_input(&f.file)?)),
        Cmd::Strip(f) => {
            let text = read_input(&f.file)?;
            let ex = extract_any(&text);
            let base = if ex.envelope == Envelope::Missing {
                text
            } else {
                ex.visible
            };
            print!("{}", strip_all(&DEFAULT, &base));
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Registry { cmd } => registry_cmd::run(cmd),
        Cmd::Handshake { cmd } => handshake::run(cmd),
        Cmd::Probe { cmd } => probe::run(cmd),
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
