use hampp_core::*;
use proptest::prelude::*;

fn alice() -> SigningIdentity {
    SigningIdentity::from_seed("alice", [1; 32], [1; 16])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn any_text_roundtrips_in_both_carriers(text in "\\PC{0,300}", visible in any::<bool>()) {
        let carrier = if visible { Carrier::Visible } else { Carrier::ZeroWidth };
        let msg = sign_text(&alice(), &text, &SignParams::lite(5), carrier);
        let v = verify_text(&msg, &SingleKey(alice().identity.public_key), 5);
        prop_assert_eq!(v.code(), "authenticated:signed-by-agent");
    }

    #[test]
    fn random_input_never_panics_and_is_never_authenticated(text in "\\PC{0,400}") {
        let v = verify_text(&text, &SingleKey(alice().identity.public_key), 5);
        prop_assert_ne!(v.status, Status::Authenticated);
    }

    #[test]
    fn alphabet_soup_never_panics(chars in proptest::collection::vec(
        prop::sample::select(vec!['\u{200B}','\u{200C}','\u{200D}','\u{2060}','\u{2063}','\u{2064}','a',']','[','\n']), 0..600)) {
        let s: String = chars.into_iter().collect();
        let v = verify_text(&s, &SingleKey(alice().identity.public_key), 5);
        prop_assert_ne!(v.status, Status::Authenticated);
    }

    #[test]
    fn flipping_any_envelope_symbol_is_never_authenticated(pos in 0usize..400, repl in 0usize..4) {
        let msg = sign_text(&alice(), "Beispieltext", &SignParams::lite(5), Carrier::ZeroWidth);
        let mut chars: Vec<char> = msg.chars().collect();
        let start = chars.iter().position(|c| *c == '\u{2064}').unwrap();
        let end = chars.len() - 1;
        let idx = start + 1 + pos % (end - start - 1);
        let alphabet = ['\u{200B}','\u{200C}','\u{200D}','\u{2060}'];
        if chars[idx] == alphabet[repl] { return Ok(()); }
        chars[idx] = alphabet[repl];
        let v = verify_text(&chars.into_iter().collect::<String>(), &SingleKey(alice().identity.public_key), 5);
        prop_assert_ne!(v.status, Status::Authenticated);
    }
}

#[test]
fn one_megabyte_message_signs_and_verifies_quickly() {
    let big = "ä".repeat(500_000);
    let t = std::time::Instant::now();
    let msg = sign_text(&alice(), &big, &SignParams::lite(5), Carrier::ZeroWidth);
    let v = verify_text(&msg, &SingleKey(alice().identity.public_key), 5);
    assert_eq!(v.code(), "authenticated:signed-by-agent");
    assert!(t.elapsed().as_secs() < 5);
}
