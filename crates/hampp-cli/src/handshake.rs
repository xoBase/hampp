use crate::io::{read_file, write_state, Res};
use crate::keys::{key_path, load_signer, parse_pubkey};
use clap::Subcommand;
use hampp_session::{
    accept_auth, initiate_finish, make_hello, random_nonce, respond, AuthResponse, Hello,
    HelloResponse, Supported,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Subcommand)]
pub enum HsCmd {
    /// Step 1 (initiator): print HELLO JSON.
    Hello {
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Step 2 (responder): read HELLO, print HELLO_RESPONSE JSON.
    Respond {
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        hello: PathBuf,
    },
    /// Step 3 (initiator): read both, print AUTH_RESPONSE JSON and write the session file.
    Auth {
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        hello: PathBuf,
        #[arg(long)]
        response: PathBuf,
        #[arg(long)]
        session_out: PathBuf,
        /// Pin the responder's public key (hex); fail if it differs.
        #[arg(long)]
        expect_peer: Option<String>,
    },
    /// Step 4 (responder): verify AUTH_RESPONSE and write the session file.
    Accept {
        #[arg(long)]
        hello: PathBuf,
        #[arg(long)]
        response: PathBuf,
        #[arg(long)]
        auth: PathBuf,
        #[arg(long)]
        session_out: PathBuf,
    },
}

fn read_json<T: serde::de::DeserializeOwned>(p: &Path) -> Res<T> {
    Ok(serde_json::from_str(&read_file(p)?)?)
}

pub fn run(cmd: HsCmd) -> Res<ExitCode> {
    match cmd {
        HsCmd::Hello { key } => {
            let (signer, _) = load_signer(&key_path(&key))?;
            let sup = Supported::for_signer(signer.as_ref());
            println!(
                "{}",
                serde_json::to_string_pretty(&make_hello(
                    signer.as_ref(),
                    &sup,
                    vec![],
                    random_nonce()
                ))?
            );
        }
        HsCmd::Respond { key, hello } => {
            let (signer, _) = load_signer(&key_path(&key))?;
            let sup = Supported::for_signer(signer.as_ref());
            let h: Hello = read_json(&hello)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&respond(
                    signer.as_ref(),
                    &h,
                    &sup,
                    vec![],
                    random_nonce()
                )?)?
            );
        }
        HsCmd::Auth {
            key,
            hello,
            response,
            session_out,
            expect_peer,
        } => {
            let (signer, _) = load_signer(&key_path(&key))?;
            let h: Hello = read_json(&hello)?;
            let r: HelloResponse = read_json(&response)?;
            let pin = expect_peer.map(|s| parse_pubkey(&s)).transpose()?;
            let (auth, session) = initiate_finish(signer.as_ref(), &h, &r, pin)?;
            write_state(&session_out, &serde_json::to_string_pretty(&session)?)?;
            eprintln!("session {}", hex::encode(session.id));
            println!("{}", serde_json::to_string_pretty(&auth)?);
        }
        HsCmd::Accept {
            hello,
            response,
            auth,
            session_out,
        } => {
            let h: Hello = read_json(&hello)?;
            let r: HelloResponse = read_json(&response)?;
            let a: AuthResponse = read_json(&auth)?;
            let session = accept_auth(&h, &r, &a)?;
            write_state(&session_out, &serde_json::to_string_pretty(&session)?)?;
            eprintln!("session {}", hex::encode(session.id));
        }
    }
    Ok(ExitCode::SUCCESS)
}
