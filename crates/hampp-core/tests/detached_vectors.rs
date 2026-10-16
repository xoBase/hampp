//! Vectors for detached envelopes (`spec/vectors/detached.json`). Generated here, verified
//! independently by `spec/vectors/verify_vectors.py --detached`.
use hampp_core::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Vector {
    name: String,
    suite: u8,
    public_key_hex: String,
    /// The text, taken literally (no envelope is extracted from it).
    text: String,
    /// The detached envelope line, as stored next to the text.
    signature: String,
    expected: String,
    expected_protection: Option<String>,
}

const TS: u64 = 1_791_000_000;
const TEXT: &str = "{\"question\":\"q-1\",\"vote\":\"yes\"}";

fn ed() -> SigningIdentity {
    SigningIdentity::from_seed("agent-ed", [0x11; 32], [0xA5; 16])
}
fn p256(level: Protection) -> P256Software {
    P256Software::from_scalar("agent-p256", [0x33; 32], [0xA6; 16])
        .unwrap()
        .claim_level_for_tests(level)
}

fn build() -> Vec<Vector> {
    let ok = "authenticated:signed-by-agent";
    let edk = ed().public_key();
    let swk = p256(Protection::Software).public_key();
    let lite = SignParams::lite(TS);
    let compact = lite.clone().with_compact(true);
    let det = |s: &dyn Signer, p: &SignParams, b64: bool| sign_detached(s, TEXT, p, b64).unwrap();
    let mk = |name: &str,
              key: &PublicKey,
              text: &str,
              sig: String,
              expected: &str,
              prot: Option<&str>| {
        Vector {
            name: name.into(),
            suite: key.suite(),
            public_key_hex: key.to_hex(),
            text: text.into(),
            signature: sig,
            expected: expected.into(),
            expected_protection: prot.map(String::from),
        }
    };
    let good_b64 = det(&ed(), &compact, true);
    // the same header, but with the session flag: a detached envelope is Lite
    let session_line = {
        let p = SignParams {
            session_id: [7; 8],
            seq: 1,
            ..lite.clone()
        };
        let msg = sign_text(&ed(), TEXT, &p, Carrier::Visible);
        msg.rsplit('\n').next().unwrap().to_string()
    };
    let zero_width = {
        let msg = sign_text(&ed(), TEXT, &lite, Carrier::ZeroWidth);
        msg[TEXT.len()..].to_string()
    };
    let inline_signed = sign_text(&ed(), TEXT, &lite, Carrier::ZeroWidth);
    vec![
        mk(
            "detached-b64-compact",
            &edk,
            TEXT,
            good_b64.clone(),
            ok,
            Some("software"),
        ),
        mk(
            "detached-b64-long",
            &edk,
            TEXT,
            det(&ed(), &lite, true),
            ok,
            Some("software"),
        ),
        mk(
            "detached-hex-compact",
            &edk,
            TEXT,
            det(&ed(), &compact, false),
            ok,
            Some("software"),
        ),
        mk(
            "detached-hex-long",
            &edk,
            TEXT,
            det(&ed(), &lite, false),
            ok,
            Some("software"),
        ),
        mk(
            "detached-p256-b64-compact",
            &swk,
            TEXT,
            det(&p256(Protection::Software), &compact, true),
            ok,
            Some("software"),
        ),
        mk(
            "detached-p256-bound-claimed",
            &swk,
            TEXT,
            det(
                &p256(Protection::Bound),
                &lite
                    .clone()
                    .with_protection(Protection::Bound)
                    .with_compact(true),
                true,
            ),
            ok,
            Some("bound"),
        ),
        mk(
            "detached-trailing-crlf-in-text",
            &edk,
            &format!("{TEXT}\r\n"),
            good_b64.clone(),
            ok,
            Some("software"),
        ),
        mk(
            "detached-trailing-newline-after-line",
            &edk,
            TEXT,
            format!("{good_b64}\n"),
            ok,
            Some("software"),
        ),
        mk(
            "neg-detached-changed-text",
            &edk,
            "{\"question\":\"q-1\",\"vote\":\"no\"}",
            good_b64.clone(),
            "invalid:signature-invalid",
            None,
        ),
        mk(
            "neg-detached-text-with-envelope-is-literal",
            &edk,
            &inline_signed,
            good_b64.clone(),
            "invalid:signature-invalid",
            None,
        ),
        mk(
            "neg-detached-empty-signature",
            &edk,
            TEXT,
            String::new(),
            "unverified:envelope-missing",
            None,
        ),
        mk(
            "neg-detached-leading-space",
            &edk,
            TEXT,
            format!(" {good_b64}"),
            "unverified:envelope-missing",
            None,
        ),
        mk(
            "neg-detached-zero-width-envelope",
            &edk,
            TEXT,
            zero_width,
            "unverified:envelope-missing",
            None,
        ),
        mk(
            "neg-detached-padded",
            &edk,
            TEXT,
            good_b64.replacen(']', "=]", 1),
            "unverified:envelope-corrupt",
            None,
        ),
        mk(
            "neg-detached-two-lines",
            &edk,
            TEXT,
            format!("{good_b64}\n{good_b64}"),
            "unverified:envelope-corrupt",
            None,
        ),
        mk(
            "neg-detached-upper-case-hex",
            &edk,
            TEXT,
            {
                let h = det(&ed(), &compact, false);
                let body = &h["[hampp1:".len()..h.len() - 1];
                format!("[hampp1:{}]", body.to_uppercase())
            },
            "unverified:envelope-corrupt",
            None,
        ),
        mk(
            "neg-detached-session-header",
            &edk,
            TEXT,
            session_line,
            "unverified:envelope-corrupt",
            None,
        ),
    ]
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/detached.json")
}

#[test]
fn detached_vectors_file_is_current() {
    let built = build();
    if std::env::var("HAMPP_UPDATE_VECTORS").is_ok() {
        std::fs::write(path(), serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let on_disk: Vec<Vector> = serde_json::from_str(
        &std::fs::read_to_string(path()).expect("run with HAMPP_UPDATE_VECTORS=1 once"),
    )
    .unwrap();
    assert_eq!(
        on_disk, built,
        "vectors differ; regenerate with HAMPP_UPDATE_VECTORS=1"
    );
}

#[test]
fn every_detached_vector_yields_its_expected_verdict() {
    let on_disk: Vec<Vector> =
        serde_json::from_str(&std::fs::read_to_string(path()).unwrap()).unwrap();
    assert!(on_disk.len() >= 15);
    for v in on_disk {
        let key = PublicKey::from_hex(&v.public_key_hex).unwrap();
        let got = verify_detached(&v.signature, &v.text, &SingleKey(key), TS);
        assert_eq!(got.code(), v.expected, "vector {}", v.name);
        assert_eq!(
            got.protection.map(|p| p.level.as_str().to_string()),
            v.expected_protection,
            "protection of {}",
            v.name
        );
    }
}
