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
    // A correctly signed header whose flags carry a reserved bit (bit 4): a decode failure, never valid.
    let reserved_bit = {
        let mut h = sign_header(&id, ok, &p);
        h.flags |= 0x10;
        h.signature = id.sign(&h.signing_input(&payload_hash(ok)));
        render(ok, &h, Carrier::ZeroWidth)
    };
    let visible = sign_text(&id, ok, &p, Carrier::Visible);
    let hex_body = visible
        .rsplit("[hampp1:")
        .next()
        .unwrap()
        .trim_end_matches(']')
        .to_string();
    let upper_hex = visible.replace(&hex_body, &hex_body.to_uppercase());
    let spaced_hex = visible.replace(
        &hex_body,
        &format!("{} {}", &hex_body[..20], &hex_body[20..]),
    );
    let pc = SignParams::lite(TS).with_compact(true);
    // base64url visible line: `[hampp1u:...]`
    let b64 = sign_text(&id, ok, &p, Carrier::VisibleB64);
    let b64_padded = b64.replacen(']', "=]", 1);
    let b64_spaced = b64.replacen("[hampp1u:", "[hampp1u: ", 1);
    let b64_spare_bits = {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut bytes = b64.clone().into_bytes();
        let last = bytes.len() - 2; // before the closing bracket
        let idx = A.iter().position(|c| *c == bytes[last]).unwrap();
        bytes[last] = A[(idx & !15) | 1]; // same 6 bytes of payload, non-zero unused bits
        String::from_utf8(bytes).unwrap()
    };
    // an older line of the other kind quoted inside the text: the LAST line is the envelope
    let quoted_hex = sign_text(&id, "alt", &p, Carrier::Visible);
    let quoted_b64 = sign_text(&id, "alt", &p, Carrier::VisibleB64);
    let reply_b64 = format!("> {quoted_hex}\nneu");
    let reply_hex = format!("> {quoted_b64}\nneu");
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
            "lite-compact-zero-width",
            ok,
            sign_text(&id, ok, &pc, Carrier::ZeroWidth),
            "authenticated:signed-by-agent",
        ),
        mk(
            "lite-compact-visible",
            ok,
            sign_text(&id, ok, &pc, Carrier::Visible),
            "authenticated:signed-by-agent",
        ),
        mk(
            "lite-visible-b64",
            ok,
            b64.clone(),
            "authenticated:signed-by-agent",
        ),
        mk(
            "lite-compact-visible-b64",
            ok,
            sign_text(&id, ok, &pc, Carrier::VisibleB64),
            "authenticated:signed-by-agent",
        ),
        mk(
            "lite-quoted-hex-line-then-b64-line",
            &reply_b64,
            sign_text(&id, &reply_b64, &p, Carrier::VisibleB64),
            "authenticated:signed-by-agent",
        ),
        mk(
            "lite-quoted-b64-line-then-hex-line",
            &reply_hex,
            sign_text(&id, &reply_hex, &p, Carrier::Visible),
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
            "neg-reserved-flag-bit",
            ok,
            reserved_bit,
            "unverified:envelope-corrupt",
        ),
        mk(
            "neg-visible-upper-case-hex",
            ok,
            upper_hex,
            "unverified:envelope-corrupt",
        ),
        mk(
            "neg-visible-hex-with-space",
            ok,
            spaced_hex,
            "unverified:envelope-corrupt",
        ),
        mk(
            "neg-visible-b64-padding",
            ok,
            b64_padded,
            "unverified:envelope-corrupt",
        ),
        mk(
            "neg-visible-b64-space",
            ok,
            b64_spaced,
            "unverified:envelope-corrupt",
        ),
        mk(
            "neg-visible-b64-nonzero-spare-bits",
            ok,
            b64_spare_bits,
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
