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
    let v = verify_text(&msg, &SingleKey(alice().identity.public_key), NOW);
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
    let v = verify_text(&msg, &SingleKey(alice().identity.public_key), NOW);
    assert_eq!(v.code(), "authenticated:signed-by-agent");
}

#[test]
fn manipulated_text_is_invalid() {
    let msg = signed("Zahle 100 Euro").replace("100", "900");
    let v = verify_text(&msg, &SingleKey(alice().identity.public_key), NOW);
    assert_eq!(v.code(), "invalid:signature-invalid");
}

#[test]
fn stripped_envelope_is_unverified_and_text_survives() {
    let msg = hampp_envelope::strip_all(&hampp_envelope::DEFAULT, &signed("Hallo"));
    let v = verify_text(&msg, &SingleKey(alice().identity.public_key), NOW);
    assert_eq!(v.code(), "unverified:envelope-missing");
    assert_eq!(v.visible, "Hallo");
}

#[test]
fn wrong_key_is_unknown_key_not_authenticated() {
    let v = verify_text(&signed("x"), &SingleKey(bob().identity.public_key), NOW);
    assert_eq!(v.code(), "unverified:unknown-key");
}

#[test]
fn trailing_newline_crlf_and_trailing_spaces_still_verify() {
    let pk = SingleKey(alice().identity.public_key);
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
    let v = verify_text(&reply, &SingleKey(bob().identity.public_key), NOW);
    assert_eq!(v.code(), "authenticated:signed-by-agent");
}

#[test]
fn empty_text_can_be_signed() {
    let msg = signed("");
    assert_eq!(
        verify_text(&msg, &SingleKey(alice().identity.public_key), NOW).code(),
        "authenticated:signed-by-agent"
    );
}

#[test]
fn unsupported_version_and_suite_are_named() {
    let mut h = sign_header(&alice(), "x", &SignParams::lite(NOW));
    h.suite = 99;
    let msg = render("x", &h, Carrier::ZeroWidth);
    let v = verify_text(&msg, &SingleKey(alice().identity.public_key), NOW);
    assert_eq!(v.code(), "invalid:unsupported-suite");
    let mut bytes = sign_header(&alice(), "x", &SignParams::lite(NOW)).encode();
    bytes[2] = 7;
    let msg = hampp_envelope::embed("x", &bytes).unwrap();
    assert_eq!(
        verify_text(&msg, &SingleKey(alice().identity.public_key), NOW).code(),
        "invalid:unsupported-version"
    );
}

#[test]
fn verdict_json_has_stable_fields() {
    let v = verify_text(&signed("x"), &SingleKey(alice().identity.public_key), NOW);
    let j = v.to_json();
    assert_eq!(j["code"], "authenticated:signed-by-agent");
    assert_eq!(j["status"], "authenticated");
    assert_eq!(j["key_id"], hex::encode(alice().identity.key_id()));
}
