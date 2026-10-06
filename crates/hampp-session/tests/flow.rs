use hampp_core::{Carrier, SigningIdentity};
use hampp_session::*;

fn alice() -> SigningIdentity {
    SigningIdentity::from_seed("alice", [1; 32], [1; 16])
}
fn bob() -> SigningIdentity {
    SigningIdentity::from_seed("bob", [2; 32], [2; 16])
}
const NA: [u8; 32] = [0xAA; 32];
const NB: [u8; 32] = [0xBB; 32];
const NOW: u64 = 1_791_000_000;

fn full_handshake() -> (Session, Session) {
    let sup = Supported::v1();
    let hello = make_hello(&alice(), &sup, vec![], NA);
    let resp = respond(&bob(), &hello, &sup, vec![], NB).unwrap();
    let (auth, sa) = initiate_finish(&alice(), &hello, &resp, None).unwrap();
    let sb = accept_auth(&hello, &resp, &auth).unwrap();
    (sa, sb)
}

#[test]
fn handshake_yields_matching_session_ids() {
    let (sa, sb) = full_handshake();
    assert_eq!(sa.id, sb.id);
    assert_ne!(sa.id, [0u8; 8]);
    assert_eq!(sa.peer_public_key, bob().identity.public_key);
    assert_eq!(sb.peer_public_key, alice().identity.public_key);
}

#[test]
fn handshake_is_deterministic_for_fixed_nonces() {
    assert_eq!(full_handshake().0.id, full_handshake().0.id);
}

#[test]
fn messages_flow_both_ways_with_registered_instance_level() {
    let (mut sa, mut sb) = full_handshake();
    let m1 = sa.sign_next(&alice(), "Hallo Bob", NOW, Carrier::ZeroWidth);
    assert_eq!(
        sb.verify_next(&m1, NOW).code(),
        "authenticated:registered-instance"
    );
    let m2 = sb.sign_next(&bob(), "Hallo Alice", NOW + 1, Carrier::ZeroWidth);
    assert_eq!(
        sa.verify_next(&m2, NOW + 1).code(),
        "authenticated:registered-instance"
    );
    let m3 = sa.sign_next(&alice(), "Zweite", NOW + 2, Carrier::ZeroWidth);
    assert_eq!(
        sb.verify_next(&m3, NOW + 2).code(),
        "authenticated:registered-instance"
    );
}

#[test]
fn replay_and_duplicate_are_invalid() {
    let (mut sa, mut sb) = full_handshake();
    let m1 = sa.sign_next(&alice(), "eins", NOW, Carrier::ZeroWidth);
    assert_eq!(
        sb.verify_next(&m1, NOW).code(),
        "authenticated:registered-instance"
    );
    assert_eq!(sb.verify_next(&m1, NOW).code(), "invalid:replay");
}

#[test]
fn gap_is_a_note_not_a_failure_and_late_message_is_replay() {
    let (mut sa, mut sb) = full_handshake();
    let m1 = sa.sign_next(&alice(), "eins", NOW, Carrier::ZeroWidth);
    let m2 = sa.sign_next(&alice(), "zwei", NOW, Carrier::ZeroWidth);
    let m3 = sa.sign_next(&alice(), "drei", NOW, Carrier::ZeroWidth);
    let v = sb.verify_next(&m3, NOW);
    assert_eq!(v.code(), "authenticated:registered-instance");
    assert!(v.notes.contains(&"gap:2".to_string()), "{:?}", v.notes);
    assert_eq!(sb.verify_next(&m1, NOW).code(), "invalid:replay");
    assert_eq!(sb.verify_next(&m2, NOW).code(), "invalid:replay");
}

#[test]
fn message_from_another_session_is_wrong_session() {
    let (mut sa, _sb) = full_handshake();
    // second, different session between the same parties
    let sup = Supported::v1();
    let hello = make_hello(&alice(), &sup, vec![], [0xCC; 32]);
    let resp = respond(&bob(), &hello, &sup, vec![], [0xDD; 32]).unwrap();
    let (auth, _sa2) = initiate_finish(&alice(), &hello, &resp, None).unwrap();
    let mut sb2 = accept_auth(&hello, &resp, &auth).unwrap();
    let m = sa.sign_next(&alice(), "x", NOW, Carrier::ZeroWidth);
    assert_eq!(sb2.verify_next(&m, NOW).code(), "invalid:wrong-session");
}

#[test]
fn tampered_text_and_stripped_envelope_do_not_advance_state() {
    let (mut sa, mut sb) = full_handshake();
    let m1 = sa.sign_next(&alice(), "Zahle 100", NOW, Carrier::ZeroWidth);
    assert_eq!(
        sb.verify_next(&m1.replace("100", "900"), NOW).code(),
        "invalid:signature-invalid"
    );
    let stripped = hampp_envelope_strip(&m1);
    assert_eq!(
        sb.verify_next(&stripped, NOW).code(),
        "unverified:envelope-missing"
    );
    assert_eq!(
        sb.verify_next(&m1, NOW).code(),
        "authenticated:registered-instance"
    );
}

fn hampp_envelope_strip(s: &str) -> String {
    hampp_envelope::strip_all(&hampp_envelope::DEFAULT, s)
}

#[test]
fn clock_skew_is_off_by_default_and_enforced_when_set() {
    let (mut sa, mut sb) = full_handshake();
    let m = sa.sign_next(&alice(), "alt", NOW, Carrier::ZeroWidth);
    assert_eq!(
        sb.verify_next(&m, NOW + 86_400).code(),
        "authenticated:registered-instance"
    );
    let m = sa.sign_next(&alice(), "alt2", NOW, Carrier::ZeroWidth);
    sb.max_skew = Some(300);
    assert_eq!(
        sb.verify_next(&m, NOW + 86_400).code(),
        "invalid:clock-skew"
    );
}

#[test]
fn sessionless_message_inside_a_session_is_wrong_session() {
    let (_sa, mut sb) = full_handshake();
    let lite = hampp_core::sign_text(
        &alice(),
        "x",
        &hampp_core::SignParams::lite(NOW),
        Carrier::ZeroWidth,
    );
    assert_eq!(sb.verify_next(&lite, NOW).code(), "invalid:wrong-session");
}

#[test]
fn session_state_survives_json_roundtrip() {
    let (mut sa, sb) = full_handshake();
    let _ = sa.sign_next(&alice(), "eins", NOW, Carrier::ZeroWidth);
    let again: Session = serde_json::from_str(&serde_json::to_string(&sa).unwrap()).unwrap();
    assert_eq!(again.out_seq, 1);
    assert_eq!(again.id, sb.id);
}
