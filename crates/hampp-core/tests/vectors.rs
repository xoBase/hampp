use hampp_core::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Vector {
    name: String,
    seed_hex: String,
    agent_id: String,
    instance_id_hex: String,
    text: String,
    timestamp: u64,
    signed_text_hex: String,
    expected: String,
}

const SEED: [u8; 32] = [0x11; 32];
const OTHER_SEED: [u8; 32] = [0x22; 32];
const INSTANCE: [u8; 16] = [0xA5; 16];
const TS: u64 = 1_791_000_000;

fn build() -> Vec<Vector> {
    let id = SigningIdentity::from_seed("agent-42", SEED, INSTANCE);
    let mk = |name: &str, text: &str, signed: String, expected: &str| Vector {
        name: name.into(),
        seed_hex: hex::encode(SEED),
        agent_id: "agent-42".into(),
        instance_id_hex: hex::encode(INSTANCE),
        text: text.into(),
        timestamp: TS,
        signed_text_hex: hex::encode(signed.as_bytes()),
        expected: expected.into(),
    };
    let p = SignParams::lite(TS);
    let ok = "Der Auftrag wurde erfolgreich ausgeführt.";
    let good = sign_text(&id, ok, &p, Carrier::ZeroWidth);
    let strip = |s: &str| hampp_envelope::strip_all(&hampp_envelope::DEFAULT, s);
    let other = SigningIdentity::from_seed("agent-43", OTHER_SEED, INSTANCE);
    vec![
        mk("lite-ok", ok, good.clone(), "authenticated:signed-by-agent"),
        mk(
            "lite-short-ja",
            "Ja.",
            sign_text(&id, "Ja.", &p, Carrier::ZeroWidth),
            "authenticated:signed-by-agent",
        ),
        mk(
            "lite-empty",
            "",
            sign_text(&id, "", &p, Carrier::ZeroWidth),
            "authenticated:signed-by-agent",
        ),
        mk(
            "lite-visible-carrier",
            ok,
            sign_text(&id, ok, &p, Carrier::Visible),
            "authenticated:signed-by-agent",
        ),
        mk(
            "lite-trailing-crlf",
            ok,
            format!("{good}\r\n"),
            "authenticated:signed-by-agent",
        ),
        mk(
            "neg-tampered-text",
            ok,
            good.replace("erfolgreich", "erfolglos"),
            "invalid:signature-invalid",
        ),
        mk(
            "neg-envelope-stripped",
            ok,
            strip(&good),
            "unverified:envelope-missing",
        ),
        mk(
            "neg-truncated",
            ok,
            good.chars().take(good.chars().count() - 3).collect(),
            "unverified:envelope-corrupt",
        ),
        mk(
            "neg-wrong-signer",
            ok,
            sign_text(&other, ok, &p, Carrier::ZeroWidth),
            "unverified:unknown-key",
        ),
    ]
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/lite.json")
}

#[test]
fn vectors_file_is_current() {
    let built = build();
    if std::env::var("HAMPP_UPDATE_VECTORS").is_ok() {
        std::fs::create_dir_all(path().parent().unwrap()).unwrap();
        std::fs::write(path(), serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let on_disk: Vec<Vector> = serde_json::from_str(
        &std::fs::read_to_string(path()).expect("run with HAMPP_UPDATE_VECTORS=1 once"),
    )
    .unwrap();
    assert_eq!(
        on_disk, built,
        "vectors differ; regenerate with HAMPP_UPDATE_VECTORS=1 and review the diff"
    );
}

#[test]
fn every_vector_yields_its_expected_verdict() {
    let id = SigningIdentity::from_seed("agent-42", SEED, INSTANCE);
    let keys = SingleKey(id.identity.public_key.into());
    let on_disk: Vec<Vector> =
        serde_json::from_str(&std::fs::read_to_string(path()).unwrap()).unwrap();
    assert!(on_disk.len() >= 9);
    for v in on_disk {
        let text = String::from_utf8(hex::decode(&v.signed_text_hex).unwrap()).unwrap();
        assert_eq!(
            verify_text(&text, &keys, TS).code(),
            v.expected,
            "vector {}",
            v.name
        );
    }
}
