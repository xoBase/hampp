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
    assert_eq!(sa.peer_public_key, bob().identity.public_key.into());
    assert_eq!(sb.peer_public_key, alice().identity.public_key.into());
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

#[test]
fn session_state_advances_when_a_protection_policy_downgrades_the_verdict() {
    use hampp_core::Protection;
    let (mut sa, mut sb) = full_handshake();
    let m = sa.sign_next(&alice(), "Hallo Bob", NOW, Carrier::ZeroWidth);
    let v = sb
        .verify_next(&m, NOW)
        .with_min_protection(Some(Protection::Bound));
    assert_eq!(v.code(), "unverified:protection-too-low");
    assert_eq!(sb.in_seq, 1, "an authentic message advances the state");
    // the same message again is a replay, not acceptable later by lowering the policy
    assert_eq!(sb.verify_next(&m, NOW).code(), "invalid:replay");
}

// ---- sessions with suite 2 (ECDSA P-256) ----

mod p256 {
    use super::*;
    use hampp_core::{P256Software, Protection, PublicKey, SignError, Signer};

    fn pa() -> P256Software {
        P256Software::from_scalar("pa", [0x33; 32], [3; 16])
            .unwrap()
            .claim_level_for_tests(Protection::Bound)
    }
    fn pb() -> P256Software {
        P256Software::from_scalar("pb", [0x44; 32], [4; 16])
            .unwrap()
            .claim_level_for_tests(Protection::Bound)
    }

    fn handshake() -> (Session, Session) {
        let hello = make_hello(&pa(), &Supported::for_signer(&pa()), vec![], NA);
        let resp = respond(&pb(), &hello, &Supported::for_signer(&pb()), vec![], NB).unwrap();
        let (auth, sa) = initiate_finish(&pa(), &hello, &resp, None).unwrap();
        let sb = accept_auth(&hello, &resp, &auth).unwrap();
        (sa, sb)
    }

    #[test]
    fn handshake_yields_matching_sessions_with_suite_2() {
        let (sa, sb) = handshake();
        assert_eq!(sa.id, sb.id);
        assert_eq!((sa.suite, sb.suite), (2, 2));
        assert_eq!(sa.peer_public_key, pb().public_key());
        assert_eq!(sb.peer_public_key, pa().public_key());
    }

    #[test]
    fn messages_flow_with_a_protection_chosen_per_message() {
        let (mut sa, mut sb) = handshake();
        let m1 = sa
            .try_sign_next(
                &pa(),
                "folgenreich",
                NOW,
                Carrier::ZeroWidth,
                Protection::Bound,
            )
            .unwrap();
        let m2 = sa
            .try_sign_next(
                &pa(),
                "Routine",
                NOW + 1,
                Carrier::Visible,
                Protection::Software,
            )
            .unwrap();
        let v1 = sb.verify_next(&m1, NOW);
        assert_eq!(v1.code(), "authenticated:registered-instance");
        assert_eq!(v1.protection.unwrap().level, Protection::Bound);
        assert!(v1.protection.unwrap().claimed);
        let v2 = sb.verify_next(&m2, NOW + 1);
        assert_eq!(v2.code(), "authenticated:registered-instance");
        assert_eq!(v2.protection.unwrap().level, Protection::Software);
        // the bound message cannot be replayed, which is the point of running it in a session
        assert_eq!(sb.verify_next(&m1, NOW + 2).code(), "invalid:replay");
    }

    #[test]
    fn a_policy_downgrade_still_advances_the_session() {
        let (mut sa, mut sb) = handshake();
        let m = sa
            .try_sign_next(
                &pa(),
                "Routine",
                NOW,
                Carrier::ZeroWidth,
                Protection::Software,
            )
            .unwrap();
        let v = sb
            .verify_next(&m, NOW)
            .with_min_protection(Some(Protection::Bound));
        assert_eq!(v.code(), "unverified:protection-too-low");
        assert_eq!(sb.in_seq, 1);
    }

    #[test]
    fn a_tampered_signature_or_a_wrong_pin_fails_the_handshake() {
        let hello = make_hello(&pa(), &Supported::for_signer(&pa()), vec![], NA);
        let mut resp = respond(&pb(), &hello, &Supported::for_signer(&pb()), vec![], NB).unwrap();
        let wrong: PublicKey = pa().public_key();
        assert_eq!(
            initiate_finish(&pa(), &hello, &resp, Some(wrong)).err(),
            Some(HandshakeError::PeerKeyMismatch)
        );
        assert!(initiate_finish(&pa(), &hello, &resp, Some(pb().public_key())).is_ok());
        resp.signature[10] ^= 1;
        assert_eq!(
            initiate_finish(&pa(), &hello, &resp, None).err(),
            Some(HandshakeError::BadSignature)
        );
    }

    #[test]
    fn peers_with_different_key_types_cannot_open_a_session() {
        // Ed25519 initiator, P-256 responder: no common suite
        let hello = make_hello(&alice(), &Supported::for_signer(&alice()), vec![], NA);
        assert_eq!(
            respond(&pb(), &hello, &Supported::for_signer(&pb()), vec![], NB).err(),
            Some(HandshakeError::NoCommonSuite)
        );
    }

    #[test]
    fn a_key_that_does_not_match_the_advertised_suite_is_refused() {
        // a P-256 key in a hello that claims suite 1
        let mut hello = make_hello(&pa(), &Supported::for_signer(&pa()), vec![], NA);
        hello.suites = vec![1, 2];
        let sup = Supported {
            suites: vec![1, 2],
            ..Supported::v1()
        };
        // the responder is an Ed25519 key but would pick suite 2 from the offer: its key does not fit
        let err = respond(&bob(), &hello, &sup, vec![], NB).err();
        assert_eq!(err, Some(HandshakeError::KeyDoesNotMatchSuite));
    }

    struct Failing;
    impl Signer for Failing {
        fn suite(&self) -> u8 {
            2
        }
        fn public_key(&self) -> PublicKey {
            pa().public_key()
        }
        fn level(&self) -> Protection {
            Protection::Bound
        }
        fn agent_id(&self) -> &str {
            "failing"
        }
        fn instance_id(&self) -> [u8; 16] {
            [0; 16]
        }
        fn sign(&self, _: &[u8]) -> Result<[u8; 64], SignError> {
            Err(SignError::Backend("TPM unavailable".into()))
        }
    }

    #[test]
    fn a_failed_signature_does_not_advance_the_session() {
        let (mut sa, mut sb) = handshake();
        assert!(sa
            .try_sign_next(&Failing, "x", NOW, Carrier::ZeroWidth, Protection::Bound)
            .is_err());
        assert_eq!((sa.out_seq, sa.out_prev), (0, [0; 16]));
        // the next real message is still seq 1 and verifies
        let m = sa
            .try_sign_next(&pa(), "ok", NOW, Carrier::ZeroWidth, Protection::Bound)
            .unwrap();
        assert_eq!(
            sb.verify_next(&m, NOW).code(),
            "authenticated:registered-instance"
        );
    }

    #[test]
    fn a_signer_of_the_wrong_suite_or_level_is_refused_by_the_session() {
        let (mut sa, _) = handshake();
        assert!(sa
            .try_sign_next(&alice(), "x", NOW, Carrier::ZeroWidth, Protection::Software)
            .is_err());
        let weak = P256Software::from_scalar("w", [0x33; 32], [3; 16]).unwrap();
        assert!(matches!(
            sa.try_sign_next(&weak, "x", NOW, Carrier::ZeroWidth, Protection::Bound),
            Err(SignError::LevelNotAvailable { .. })
        ));
        assert_eq!(sa.out_seq, 0);
    }
}
