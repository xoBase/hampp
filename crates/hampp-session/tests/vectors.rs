use hampp_core::{Carrier, SigningIdentity};
use hampp_session::*;
use serde_json::{json, Value};
use std::path::PathBuf;

const NOW: u64 = 1_791_000_000;

fn build() -> (Value, Vec<String>, Session) {
    let alice = SigningIdentity::from_seed("alice", [1; 32], [1; 16]);
    let bob = SigningIdentity::from_seed("bob", [2; 32], [2; 16]);
    let sup = Supported::v1();
    let hello = make_hello(&alice, &sup, vec![], [0xAA; 32]);
    let resp = respond(&bob, &hello, &sup, vec![], [0xBB; 32]).unwrap();
    let (auth, mut sa) = initiate_finish(&alice, &hello, &resp, None).unwrap();
    let responder = accept_auth(&hello, &resp, &auth).unwrap();
    let texts = ["Hallo Bob", "Zweite Nachricht", "Ja."];
    let signed: Vec<String> = texts
        .iter()
        .enumerate()
        .map(|(i, t)| sa.sign_next(&alice, t, NOW + i as u64, Carrier::ZeroWidth))
        .collect();
    let v = json!({
        "alice_seed_hex": hex::encode([1u8; 32]),
        "bob_seed_hex": hex::encode([2u8; 32]),
        "nonce_a_hex": hex::encode([0xAAu8; 32]),
        "nonce_b_hex": hex::encode([0xBBu8; 32]),
        "transcript_hex": hex::encode(transcript_hash(&hello, &resp)),
        "session_id_hex": hex::encode(responder.id),
        "sig_b_hex": hex::encode(resp.signature),
        "sig_a_hex": hex::encode(auth.signature),
        "messages": texts.iter().zip(&signed).enumerate().map(|(i, (t, s))| json!({
            "seq": i + 1, "timestamp": NOW + i as u64, "text": t, "signed_text_hex": hex::encode(s.as_bytes())
        })).collect::<Vec<_>>(),
    });
    (v, signed, responder)
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/handshake.json")
}

#[test]
fn handshake_vectors_are_current_and_replay_cleanly() {
    let (built, signed, mut responder) = build();
    if std::env::var("HAMPP_UPDATE_VECTORS").is_ok() {
        std::fs::write(path(), serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let on_disk: Value = serde_json::from_str(
        &std::fs::read_to_string(path()).expect("run with HAMPP_UPDATE_VECTORS=1 once"),
    )
    .unwrap();
    assert_eq!(on_disk, built);
    for (i, s) in signed.iter().enumerate() {
        assert_eq!(
            responder.verify_next(s, NOW + i as u64).code(),
            "authenticated:registered-instance"
        );
    }
}

// ---- handshake and session with suite 2 (ECDSA P-256) ----

fn p256_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/handshake_p256.json")
}

const P256_MESSAGES: [(&str, hampp_core::Protection); 3] = [
    ("Deploy freigegeben", hampp_core::Protection::Bound),
    ("Routine", hampp_core::Protection::Software),
    ("Ja.", hampp_core::Protection::Bound),
];

fn p256_key(scalar: u8, agent: &str, instance: u8) -> hampp_core::P256Software {
    hampp_core::P256Software::from_scalar(agent, [scalar; 32], [instance; 16])
        .unwrap()
        .claim_level_for_tests(hampp_core::Protection::Bound)
}

fn build_p256() -> (Value, Vec<String>, Session) {
    let alice = p256_key(0x33, "alice", 1);
    let bob = p256_key(0x44, "bob", 2);
    let hello = make_hello(&alice, &Supported::for_signer(&alice), vec![], [0xAA; 32]);
    let resp = respond(
        &bob,
        &hello,
        &Supported::for_signer(&bob),
        vec![],
        [0xBB; 32],
    )
    .unwrap();
    let (auth, mut sa) = initiate_finish(&alice, &hello, &resp, None).unwrap();
    let responder = accept_auth(&hello, &resp, &auth).unwrap();
    let signed: Vec<String> = P256_MESSAGES
        .iter()
        .enumerate()
        .map(|(i, (t, p))| {
            sa.try_sign_next(&alice, t, NOW + i as u64, Carrier::ZeroWidth, *p)
                .unwrap()
        })
        .collect();
    let v = json!({
        "alice_scalar_hex": hex::encode([0x33u8; 32]),
        "bob_scalar_hex": hex::encode([0x44u8; 32]),
        "nonce_a_hex": hex::encode([0xAAu8; 32]),
        "nonce_b_hex": hex::encode([0xBBu8; 32]),
        "transcript_hex": hex::encode(transcript_hash(&hello, &resp)),
        "session_id_hex": hex::encode(responder.id),
        "sig_b_hex": hex::encode(resp.signature),
        "sig_a_hex": hex::encode(auth.signature),
        "messages": P256_MESSAGES.iter().zip(&signed).enumerate().map(|(i, ((t, p), s))| json!({
            "seq": i + 1, "timestamp": NOW + i as u64, "text": t, "protection": p.as_str(),
            "signed_text_hex": hex::encode(s.as_bytes())
        })).collect::<Vec<_>>(),
    });
    (v, signed, responder)
}

#[test]
fn p256_handshake_vectors_are_current_and_replay_cleanly() {
    let (built, signed, mut responder) = build_p256();
    if std::env::var("HAMPP_UPDATE_VECTORS").is_ok() {
        std::fs::write(
            p256_path(),
            serde_json::to_string_pretty(&built).unwrap() + "\n",
        )
        .unwrap();
    }
    let on_disk: Value = serde_json::from_str(
        &std::fs::read_to_string(p256_path()).expect("run with HAMPP_UPDATE_VECTORS=1 once"),
    )
    .unwrap();
    assert_eq!(on_disk, built);
    for (i, s) in signed.iter().enumerate() {
        let v = responder.verify_next(s, NOW + i as u64);
        assert_eq!(v.code(), "authenticated:registered-instance");
        assert_eq!(
            v.protection.unwrap().level.as_str(),
            P256_MESSAGES[i].1.as_str()
        );
    }
}
