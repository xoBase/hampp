use hampp_core::*;

fn alice() -> SigningIdentity {
    SigningIdentity::from_seed("alice", [1; 32], [1; 16])
}
fn bob() -> SigningIdentity {
    SigningIdentity::from_seed("bob", [2; 32], [2; 16])
}
const NOW: u64 = 1_700_000_000;

fn signed(text: &str) -> String {
    sign_text(&alice(), text, &SignParams::lite(NOW), Carrier::ZeroWidth)
}

#[test]
fn lite_roundtrip_is_authenticated_by_agent() {
    let msg = signed("Der Auftrag wurde erfolgreich ausgeführt.");
    let v = verify_text(&msg, &SingleKey(alice().identity.public_key.into()), NOW);
    assert_eq!(v.code(), "authenticated:signed-by-agent");
    assert_eq!(v.visible, "Der Auftrag wurde erfolgreich ausgeführt.");
}

#[test]
fn visible_text_is_unchanged_by_signing() {
    let msg = signed("Ja.");
    assert!(msg.starts_with("Ja."));
    assert_eq!(
        hampp_envelope::strip_all(&hampp_envelope::DEFAULT, &msg),
        "Ja."
    );
}

#[test]
fn visible_carrier_roundtrip() {
    let msg = sign_text(&alice(), "Ja.", &SignParams::lite(NOW), Carrier::Visible);
    let v = verify_text(&msg, &SingleKey(alice().identity.public_key.into()), NOW);
    assert_eq!(v.code(), "authenticated:signed-by-agent");
}

#[test]
fn manipulated_text_is_invalid() {
    let msg = signed("Zahle 100 Euro").replace("100", "900");
    let v = verify_text(&msg, &SingleKey(alice().identity.public_key.into()), NOW);
    assert_eq!(v.code(), "invalid:signature-invalid");
}

#[test]
fn stripped_envelope_is_unverified_and_text_survives() {
    let msg = hampp_envelope::strip_all(&hampp_envelope::DEFAULT, &signed("Hallo"));
    let v = verify_text(&msg, &SingleKey(alice().identity.public_key.into()), NOW);
    assert_eq!(v.code(), "unverified:envelope-missing");
    assert_eq!(v.visible, "Hallo");
}

#[test]
fn wrong_key_is_unknown_key_not_authenticated() {
    let v = verify_text(
        &signed("x"),
        &SingleKey(bob().identity.public_key.into()),
        NOW,
    );
    assert_eq!(v.code(), "unverified:unknown-key");
}

#[test]
fn trailing_newline_crlf_and_trailing_spaces_still_verify() {
    let pk = SingleKey(alice().identity.public_key.into());
    let base = signed("Zeile 1\nZeile 2");
    for variant in [
        format!("{base}\n"),
        format!("{base}\r\n"),
        base.replace('\n', "\r\n"),
    ] {
        let v = verify_text(&variant, &pk, NOW);
        assert_eq!(
            v.code(),
            "authenticated:signed-by-agent",
            "variant {variant:?}"
        );
    }
    let spaced = sign_text(
        &alice(),
        "Hallo   \n",
        &SignParams::lite(NOW),
        Carrier::ZeroWidth,
    );
    assert_eq!(
        verify_text(&spaced, &pk, NOW).code(),
        "authenticated:signed-by-agent"
    );
}

#[test]
fn quoting_a_signed_message_inside_a_signed_reply_verifies() {
    let quoted = signed("alt");
    let reply = sign_text(
        &bob(),
        &format!("> {quoted}\nneu"),
        &SignParams::lite(NOW),
        Carrier::ZeroWidth,
    );
    let v = verify_text(&reply, &SingleKey(bob().identity.public_key.into()), NOW);
    assert_eq!(v.code(), "authenticated:signed-by-agent");
}

#[test]
fn empty_text_can_be_signed() {
    let msg = signed("");
    assert_eq!(
        verify_text(&msg, &SingleKey(alice().identity.public_key.into()), NOW).code(),
        "authenticated:signed-by-agent"
    );
}

#[test]
fn unsupported_version_and_suite_are_named() {
    let mut h = sign_header(&alice(), "x", &SignParams::lite(NOW));
    h.suite = 99;
    let msg = render("x", &h, Carrier::ZeroWidth);
    let v = verify_text(&msg, &SingleKey(alice().identity.public_key.into()), NOW);
    assert_eq!(v.code(), "invalid:unsupported-suite");
    let mut bytes = sign_header(&alice(), "x", &SignParams::lite(NOW)).encode();
    bytes[2] = 7;
    let msg = hampp_envelope::embed("x", &bytes).unwrap();
    assert_eq!(
        verify_text(&msg, &SingleKey(alice().identity.public_key.into()), NOW).code(),
        "invalid:unsupported-version"
    );
}

#[test]
fn verdict_json_has_stable_fields() {
    let v = verify_text(
        &signed("x"),
        &SingleKey(alice().identity.public_key.into()),
        NOW,
    );
    let j = v.to_json();
    assert_eq!(j["code"], "authenticated:signed-by-agent");
    assert_eq!(j["status"], "authenticated");
    assert_eq!(j["key_id"], hex::encode(alice().identity.key_id()));
}

// ---- suite 2 and protection ----

fn p256(level: Protection) -> P256Software {
    P256Software::from_scalar("p", [5; 32], [1; 16])
        .unwrap()
        .claim_level_for_tests(level)
}

#[test]
fn suite2_message_verifies_and_carries_the_chosen_protection() {
    let k = p256(Protection::Bound);
    let p = SignParams::lite(NOW).with_protection(Protection::Bound);
    let t = try_sign_text(&k, "hi", &p, Carrier::ZeroWidth).unwrap();
    let v = verify_text(&t, &SingleKey(k.public_key()), NOW);
    assert_eq!(v.code(), "authenticated:signed-by-agent");
    let h = v.header.unwrap();
    assert_eq!(h.suite, SUITE_ECDSA_P256_SHA256);
    assert_eq!(h.protection(), Protection::Bound);
}

#[test]
fn suite2_works_in_the_visible_carrier_too() {
    let k = p256(Protection::Software);
    let t = try_sign_text(&k, "hi", &SignParams::lite(NOW), Carrier::Visible).unwrap();
    assert_eq!(
        verify_text(&t, &SingleKey(k.public_key()), NOW).code(),
        "authenticated:signed-by-agent"
    );
}

#[test]
fn cannot_claim_more_than_the_key_offers() {
    let k = p256(Protection::Software);
    let p = SignParams::lite(NOW).with_protection(Protection::Bound);
    assert!(matches!(
        try_sign_text(&k, "hi", &p, Carrier::ZeroWidth),
        Err(SignError::LevelNotAvailable {
            requested: Protection::Bound,
            max: Protection::Software
        })
    ));
    // an Ed25519 software identity cannot claim `bound` either
    assert!(try_sign_text(&alice(), "hi", &p, Carrier::ZeroWidth).is_err());
}

#[test]
fn lower_protection_than_the_key_offers_is_allowed() {
    let k = p256(Protection::Bound);
    let t = try_sign_text(&k, "hi", &SignParams::lite(NOW), Carrier::ZeroWidth).unwrap();
    let v = verify_text(&t, &SingleKey(k.public_key()), NOW);
    assert_eq!(v.header.unwrap().protection(), Protection::Software);
}

#[test]
fn flipping_the_protection_bits_invalidates_the_signature() {
    let k = p256(Protection::Bound);
    let t = try_sign_text(&k, "hi", &SignParams::lite(NOW), Carrier::ZeroWidth).unwrap();
    let ex = hampp_envelope::extract_any(&t);
    let hampp_envelope::Envelope::Present(bytes) = ex.envelope else {
        panic!("envelope expected")
    };
    let mut h = Header::decode(&bytes).unwrap();
    h.flags = flags_for(false, Protection::Bound); // sender signed `software`
    let forged = render(&ex.visible, &h, Carrier::ZeroWidth);
    assert_eq!(
        verify_text(&forged, &SingleKey(k.public_key()), NOW).code(),
        "invalid:signature-invalid"
    );
}

#[test]
fn high_s_signature_is_never_authenticated() {
    let k = p256(Protection::Software);
    let t = try_sign_text(&k, "hi", &SignParams::lite(NOW), Carrier::ZeroWidth).unwrap();
    let ex = hampp_envelope::extract_any(&t);
    let hampp_envelope::Envelope::Present(bytes) = ex.envelope else {
        panic!("envelope expected")
    };
    let mut h = Header::decode(&bytes).unwrap();
    h.signature = flip_s(&h.signature);
    let forged = render(&ex.visible, &h, Carrier::ZeroWidth);
    assert_eq!(
        verify_text(&forged, &SingleKey(k.public_key()), NOW).code(),
        "invalid:signature-invalid"
    );
}

#[test]
fn a_key_of_the_wrong_suite_never_verifies() {
    // An Ed25519 message checked against a resolver that only knows a P-256 key: key ids never
    // collide across suites, so the key is simply unknown.
    let t = signed("hi");
    let other = p256(Protection::Software).public_key();
    assert_eq!(
        verify_text(&t, &SingleKey(other), NOW).code(),
        "unverified:unknown-key"
    );
}

#[test]
fn reserved_protection_value_is_envelope_corrupt() {
    let k = p256(Protection::Software);
    let t = try_sign_text(&k, "hi", &SignParams::lite(NOW), Carrier::ZeroWidth).unwrap();
    let ex = hampp_envelope::extract_any(&t);
    let hampp_envelope::Envelope::Present(mut bytes) = ex.envelope else {
        panic!("envelope expected")
    };
    bytes[3] = 0b0000_0110; // protection = 3
    let forged = hampp_envelope::embed(&ex.visible, &bytes).unwrap();
    assert_eq!(
        verify_text(&forged, &SingleKey(k.public_key()), NOW).code(),
        "unverified:envelope-corrupt"
    );
}

// ---- policy and registry capping ----

fn registry_with(k: &P256Software, known: Option<Protection>) -> Registry {
    let mut r = Registry::default();
    r.add_key("p", [0; 16], k.public_key(), TrustState::Trusted, 0, None)
        .unwrap();
    assert!(r.set_protection(&k.public_key().key_id(), known));
    r
}

fn bound_message(k: &P256Software) -> String {
    let p = SignParams::lite(NOW).with_protection(Protection::Bound);
    try_sign_text(k, "hi", &p, Carrier::ZeroWidth).unwrap()
}

#[test]
fn min_protection_downgrades_only_authenticated_results() {
    let sw = alice();
    let t = sign_text(&sw, "hi", &SignParams::lite(NOW), Carrier::ZeroWidth);
    let keys = SingleKey(sw.identity.public_key.into());
    let too_low = VerifyOptions {
        min_protection: Some(Protection::Bound),
    };
    let v = verify_text_with(&t, &keys, NOW, &too_low);
    assert_eq!(v.code(), "unverified:protection-too-low");
    assert_eq!(v.protection.unwrap().level, Protection::Software);
    // no policy -> unchanged
    assert_eq!(
        verify_text(&t, &keys, NOW).code(),
        "authenticated:signed-by-agent"
    );
    // unknown key keeps its reason
    let other = SingleKey(bob().identity.public_key.into());
    assert_eq!(
        verify_text_with(&t, &other, NOW, &too_low).code(),
        "unverified:unknown-key"
    );
    // a bound message passes the same policy
    let k = p256(Protection::Bound);
    let v = verify_text_with(
        &bound_message(&k),
        &SingleKey(k.public_key()),
        NOW,
        &too_low,
    );
    assert_eq!(v.code(), "authenticated:signed-by-agent");
    assert!(v.protection.unwrap().claimed);
}

#[test]
fn revoked_key_beats_the_protection_policy() {
    let k = p256(Protection::Bound);
    let mut r = registry_with(&k, Some(Protection::Bound));
    assert!(r.set_trust(&k.public_key().key_id(), TrustState::Revoked));
    let o = VerifyOptions {
        min_protection: Some(Protection::Attested),
    };
    assert_eq!(
        verify_text_with(&bound_message(&k), &r, NOW, &o).code(),
        "invalid:key-revoked"
    );
}

#[test]
fn registry_caps_a_higher_header_claim_and_never_raises_it() {
    let k = p256(Protection::Bound);
    let capped = registry_with(&k, Some(Protection::Software));
    let v = verify_text(&bound_message(&k), &capped, NOW);
    assert_eq!(v.protection.unwrap().level, Protection::Software);
    assert!(!v.protection.unwrap().claimed);
    assert!(v.notes.contains(&"protection-capped".to_string()));
    // the registry says bound but the sender claims software: the lower claim stands
    let high = registry_with(&k, Some(Protection::Bound));
    let t = try_sign_text(&k, "hi", &SignParams::lite(NOW), Carrier::ZeroWidth).unwrap();
    assert_eq!(
        verify_text(&t, &high, NOW).protection.unwrap().level,
        Protection::Software
    );
    // the policy now uses the capped value
    let o = VerifyOptions {
        min_protection: Some(Protection::Bound),
    };
    assert_eq!(
        verify_text_with(&bound_message(&k), &capped, NOW, &o).code(),
        "unverified:protection-too-low"
    );
}

#[test]
fn attested_claim_without_evidence_counts_as_bound() {
    let k = p256(Protection::Attested);
    let p = SignParams::lite(NOW).with_protection(Protection::Attested);
    let t = try_sign_text(&k, "hi", &p, Carrier::ZeroWidth).unwrap();
    let v = verify_text(&t, &SingleKey(k.public_key()), NOW);
    assert_eq!(v.protection.unwrap().level, Protection::Bound);
    assert!(v.notes.contains(&"attestation-not-verified".to_string()));
    let o = VerifyOptions {
        min_protection: Some(Protection::Attested),
    };
    assert_eq!(
        verify_text_with(&t, &SingleKey(k.public_key()), NOW, &o).code(),
        "unverified:protection-too-low"
    );
}

#[test]
fn old_registry_files_without_protection_still_load() {
    let json = r#"{"entries":[{"agent_id":"a","instance_id":"00000000000000000000000000000000",
      "key_id":"0000000000000000","public_key":"0909090909090909090909090909090909090909090909090909090909090909",
      "trust":"TRUSTED","first_seen":1,"expires":null}]}"#;
    let r: Registry = serde_json::from_str(json).unwrap();
    assert_eq!(r.entries[0].protection, None);
    assert!(!serde_json::to_string(&r).unwrap().contains("protection"));
}

#[test]
fn verdict_json_reports_protection() {
    let k = p256(Protection::Bound);
    let j = verify_text(&bound_message(&k), &SingleKey(k.public_key()), NOW).to_json();
    assert_eq!(j["protection"], "bound");
    assert_eq!(j["protection_claimed"], true);
}
