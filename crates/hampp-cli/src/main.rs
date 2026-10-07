mod handshake;
mod io;
mod keys;
mod output;
mod probe;
mod registry_cmd;
#[cfg(feature = "tpm")]
mod tpm;

use clap::ValueEnum;
use clap::{Args, Parser, Subcommand};
use hampp_core::{
    annotate, try_sign_text, verify_text_with, Carrier, FileKeyStore, KeyStore, P256Software,
    Protection, SignParams, SigningIdentity, VerifyOptions,
};
use hampp_envelope::{extract_any, strip_all, Envelope, DEFAULT};
use hampp_session::Session;
use io::{now, read_input, Res};
use keys::{key_path, load_signer, resolver, KeyArgs};
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

/// Protection level on the command line.
#[derive(Clone, Copy, ValueEnum)]
pub enum ProtectionArg {
    Software,
    Bound,
    Attested,
}

impl From<ProtectionArg> for Protection {
    fn from(p: ProtectionArg) -> Self {
        match p {
            ProtectionArg::Software => Protection::Software,
            ProtectionArg::Bound => Protection::Bound,
            ProtectionArg::Attested => Protection::Attested,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum AlgArg {
    Ed25519,
    EcdsaP256,
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
    /// Require at least this effective protection; lower results become
    /// `unverified:protection-too-low`.
    #[arg(long, value_enum)]
    min_protection: Option<ProtectionArg>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new agent key (never overwrites).
    Keygen {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        key: Option<PathBuf>,
        /// Key algorithm: ed25519 (default, suite 1) or ecdsa-p256 (suite 2).
        #[arg(long, value_enum)]
        alg: Option<AlgArg>,
        /// `bound` creates a hardware (TPM) key; needs a build with the `tpm` feature.
        #[arg(long, value_enum)]
        protection: Option<ProtectionArg>,
    },
    /// Show the identity of a key file.
    Identity {
        #[arg(long)]
        key: Option<PathBuf>,
        /// Print only the public key as hex.
        #[arg(long)]
        public: bool,
        /// Machine-readable output (includes the key protection level).
        #[arg(long, conflicts_with = "public")]
        json: bool,
    },
    /// Describe what this build supports (for agents and skills to detect).
    Capabilities {
        #[arg(long)]
        json: bool,
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
        /// Protection level to claim (default: the highest this key offers).
        #[arg(long, value_enum)]
        protection: Option<ProtectionArg>,
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
    let min = a.min_protection.map(Protection::from);
    if let Some(sp) = &a.session {
        let mut s = load_session(sp)?;
        // The session state advances for every authentic message; the policy only changes the verdict.
        let v = s.verify_next(text, now()).with_min_protection(min);
        save_session(sp, &s)?;
        return Ok(v);
    }
    let opts = VerifyOptions {
        min_protection: min,
    };
    Ok(verify_text_with(
        text,
        resolver(&a.keys)?.as_ref(),
        now(),
        &opts,
    ))
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
                println!(
                    "Protection:   {} (claimed in the header, not verified)",
                    h.protection().label()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                println!("Result:       UNVERIFIED (header: {e:?})");
                ExitCode::from(10)
            }
        },
    }
}

/// Which protection levels this installation can actually offer, with the reason when it cannot.
fn protection_availability() -> Vec<(Protection, Result<(), String>)> {
    #[cfg(feature = "tpm")]
    let bound = tpm::probe();
    #[cfg(not(feature = "tpm"))]
    let bound = Err("built without tpm support".to_string());
    vec![
        (Protection::Software, Ok(())),
        (Protection::Bound, bound),
        (
            Protection::Attested,
            Err("attestation evidence verification is not implemented".to_string()),
        ),
    ]
}

fn capabilities(json: bool) {
    let version = env!("CARGO_PKG_VERSION");
    let avail = protection_availability();
    if json {
        let protection: serde_json::Map<String, serde_json::Value> = avail
            .iter()
            .map(|(p, r)| {
                let v = match r {
                    Ok(()) => serde_json::json!({ "available": true }),
                    Err(why) => serde_json::json!({ "available": false, "reason": why }),
                };
                (p.as_str().to_string(), v)
            })
            .collect();
        let v = serde_json::json!({
            "software": "hampp",
            "software_version": version,
            "protocol_versions": [1],
            "suites": [hampp_core::SUITE_ED25519_SHA256, hampp_core::SUITE_ECDSA_P256_SHA256],
            "carriers": ["zero-width", "visible"],
            "profiles": ["lite", "full", "verify-only"],
            "protection": protection,
            "key_protection": avail.iter().filter(|(_, r)| r.is_ok()).map(|(p, _)| if *p == Protection::Software { "software" } else { "tpm" }).collect::<Vec<_>>(),
            "attestation": [],
        });
        println!("{}", serde_json::to_string_pretty(&v).expect("static json"));
    } else {
        println!("hampp {version}");
        println!("protocol:       HAMPP/1");
        println!("suites:         1 (Ed25519 + SHA-256), 2 (ECDSA P-256 + SHA-256)");
        println!("carriers:       zero-width, visible");
        println!("profiles:       lite, full, verify-only");
        for (p, r) in &avail {
            match r {
                Ok(()) => println!("protection:     {} available", p.as_str()),
                Err(why) => println!("protection:     {} unavailable ({why})", p.as_str()),
            }
        }
        println!("attestation:    none");
    }
}

fn run(cli: Cli) -> Res<ExitCode> {
    match cli.cmd {
        Cmd::Keygen {
            agent,
            key,
            alg,
            protection,
        } => {
            let path = key_path(&key);
            let wants_tpm = matches!(protection, Some(ProtectionArg::Bound));
            if matches!(protection, Some(ProtectionArg::Attested)) {
                return Err(
                    "protection attested needs verified evidence and is not available".into(),
                );
            }
            if wants_tpm && matches!(alg, Some(AlgArg::Ed25519)) {
                return Err("a TPM key is ECDSA P-256; use --alg ecdsa-p256 or omit --alg".into());
            }
            let key_id = if wants_tpm {
                #[cfg(feature = "tpm")]
                {
                    tpm::create(&path, &agent)?
                }
                #[cfg(not(feature = "tpm"))]
                {
                    return Err(
                        "this hampp was built without tpm support (cargo build --features tpm)"
                            .into(),
                    );
                }
            } else if matches!(alg, Some(AlgArg::EcdsaP256)) {
                let k = P256Software::generate(&agent);
                hampp_core::save_p256_software(&path, &k)?;
                hex::encode(k.public_key().key_id())
            } else {
                let id = SigningIdentity::generate(&agent);
                FileKeyStore { path: path.clone() }.save(&id)?;
                hex::encode(id.identity.key_id())
            };
            println!(
                "created {} (agent {}, key id {})",
                path.display(),
                agent,
                key_id
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Capabilities { json } => {
            capabilities(json);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Identity { key, public, json } => {
            let (signer, meta) = load_signer(&key_path(&key))?;
            let storage = if meta.alg == hampp_core::ALG_P256_TPM {
                "tpm"
            } else {
                "software"
            };
            if json {
                let v = serde_json::json!({
                    "agent_id": meta.agent_id,
                    "instance_id": hex::encode(meta.instance_id),
                    "key_id": hex::encode(meta.public_key.key_id()),
                    "public_key": meta.public_key.to_hex(),
                    "suite": meta.public_key.suite(),
                    // Where the key lives, and the highest protection it may claim. Nothing
                    // stronger is ever claimed without proof (spec/HARDWARE_BINDING.md).
                    "key_protection": storage,
                    "max_protection": signer.level().as_str(),
                    "attestation": "none",
                });
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else if public {
                println!("{}", meta.public_key.to_hex());
            } else {
                println!("agent_id:    {}", meta.agent_id);
                println!("instance_id: {}", hex::encode(meta.instance_id));
                println!("key_id:      {}", hex::encode(meta.public_key.key_id()));
                println!("public_key:  {}", meta.public_key.to_hex());
                println!(
                    "protection:  {} (highest this key may claim)",
                    signer.level().label()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Sign {
            file,
            key,
            visible,
            session,
            protection,
        } => {
            let text = read_input(&file)?;
            let (signer, meta) = load_signer(&key_path(&key))?;
            let level = protection.map(Protection::from).unwrap_or(signer.level());
            let carrier = if visible {
                Carrier::Visible
            } else {
                Carrier::ZeroWidth
            };
            let out = match session {
                Some(sp) => {
                    if meta.alg != hampp_core::ALG_ED25519 {
                        return Err("sessions support Ed25519 keys only (suite 1)".into());
                    }
                    if level != Protection::Software {
                        return Err("a session has the protection of its key; sessions currently use software keys only".into());
                    }
                    let id = FileKeyStore {
                        path: key_path(&key),
                    }
                    .load()?;
                    let mut s = load_session(&sp)?;
                    let o = s.sign_next(&id, &text, now(), carrier);
                    save_session(&sp, &s)?;
                    o
                }
                None => try_sign_text(
                    signer.as_ref(),
                    &text,
                    &SignParams::lite(now()).with_protection(level),
                    carrier,
                )?,
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
