//! Property tests for the transport layer: roundtrips, and "never panics, never invents a payload".
use hampp_envelope::*;
use proptest::prelude::*;

/// Text that contains none of the envelope's own characters.
fn plain_text() -> impl Strategy<Value = String> {
    "\\PC{0,200}".prop_map(|s| strip_all(&DEFAULT, &s))
}

fn alphabet_soup() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop::sample::select(vec![
            '\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{2063}', '\u{2064}', 'a', '[', ']',
            ':', '\n', '0', 'f',
        ]),
        0..300,
    )
    .prop_map(|v| v.into_iter().collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn zero_width_roundtrip(text in plain_text(), payload in proptest::collection::vec(any::<u8>(), 0..300)) {
        let signed = embed(&text, &payload).unwrap();
        let got = extract(&signed);
        prop_assert_eq!(got.visible, text);
        prop_assert_eq!(got.envelope, Envelope::Present(payload));
    }

    #[test]
    fn visible_roundtrip_keeps_text_up_to_trailing_whitespace(
        text in plain_text(),
        payload in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let signed = embed_visible(&text, &payload);
        let got = extract_visible(&signed);
        prop_assert_eq!(got.visible, text.trim_end());
        prop_assert_eq!(got.envelope, Envelope::Present(payload.clone()));
        // `extract_any` finds it too
        prop_assert_eq!(extract_any(&signed).envelope, Envelope::Present(payload));
    }

    #[test]
    fn visible_b64_roundtrip(
        text in plain_text(),
        payload in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let signed = embed_visible_b64(&text, &payload);
        let got = extract_visible(&signed);
        prop_assert_eq!(got.visible, text.trim_end());
        prop_assert_eq!(got.envelope, Envelope::Present(payload.clone()));
        prop_assert_eq!(extract_any(&signed).envelope, Envelope::Present(payload));
    }

    /// One spelling: whatever body the extractor accepts must be the canonical encoding of the
    /// payload it returns (upper-case hex, padding, spare bits, whitespace are all rejected).
    #[test]
    fn an_accepted_visible_line_is_the_canonical_spelling(
        hexish in "[0-9a-fA-F ]{0,40}",
        b64ish in "[A-Za-z0-9_=+/ -]{0,40}",
    ) {
        for (prefix, body, b64) in [("[hampp1:", hexish, false), ("[hampp1u:", b64ish, true)] {
            let text = format!("x\n{prefix}{body}]");
            if let Envelope::Present(p) = extract_visible(&text).envelope {
                let canonical = if b64 { embed_visible_b64("x", &p) } else { embed_visible("x", &p) };
                prop_assert_eq!(canonical, text);
            }
        }
    }

    #[test]
    fn other_spellings_of_a_valid_line_are_corrupt(payload in proptest::collection::vec(any::<u8>(), 0..64)) {
        let hexl = embed_visible("x", &payload);
        let upper = format!("x\n[hampp1:{}]", hexl["x\n[hampp1:".len()..hexl.len() - 1].to_uppercase());
        if upper != hexl {
            prop_assert!(matches!(extract_visible(&upper).envelope, Envelope::Corrupt(_)));
        }
        let b64 = embed_visible_b64("x", &payload);
        let padded = b64.replacen(']', "=]", 1);
        prop_assert!(matches!(extract_visible(&padded).envelope, Envelope::Corrupt(_)));
        let std_alphabet = b64.replace('-', "+").replace('_', "/");
        if std_alphabet != b64 {
            prop_assert!(matches!(extract_visible(&std_alphabet).envelope, Envelope::Corrupt(_)));
        }
    }

    #[test]
    fn strip_all_is_idempotent_and_leaves_no_member(text in "\\PC{0,200}", soup in alphabet_soup()) {
        for s in [text, soup] {
            let once = strip_all(&DEFAULT, &s);
            prop_assert!(!once.chars().any(|c| DEFAULT.is_member(c)));
            prop_assert_eq!(strip_all(&DEFAULT, &once), once);
        }
    }

    #[test]
    fn extractors_never_panic_on_arbitrary_input(text in "\\PC{0,300}", soup in alphabet_soup()) {
        for s in [text, soup] {
            let _ = extract(&s);
            let _ = extract_visible(&s);
            let _ = extract_visible(&format!("{s}\n[hampp1u:{s}]"));
            let _ = extract_any(&s);
        }
    }

    /// Whatever the extractor calls a payload must reproduce the exact input when embedded again.
    #[test]
    fn a_present_payload_always_comes_from_a_well_formed_frame(soup in alphabet_soup()) {
        if let Envelope::Present(p) = extract(&soup).envelope {
            let again = extract(&embed("", &p).unwrap());
            prop_assert_eq!(again.envelope, Envelope::Present(p));
        }
    }

    /// Dropping or changing any single symbol of a real envelope never yields the original payload.
    #[test]
    fn single_symbol_damage_is_never_accepted_as_the_original(
        payload in proptest::collection::vec(any::<u8>(), 1..60),
        pos in 0usize..10_000,
        drop_it in any::<bool>(),
        repl in 0usize..4,
    ) {
        let signed = embed("x", &payload).unwrap();
        let mut chars: Vec<char> = signed.chars().collect();
        let first = chars.iter().position(|c| *c == DEFAULT.start).unwrap() + 1;
        let last = chars.len() - 1; // END marker
        let idx = first + pos % (last - first);
        if drop_it {
            chars.remove(idx);
        } else if chars[idx] == DEFAULT.symbols[repl] {
            return Ok(());
        } else {
            chars[idx] = DEFAULT.symbols[repl];
        }
        let damaged: String = chars.into_iter().collect();
        prop_assert_ne!(extract(&damaged).envelope, Envelope::Present(payload));
    }
}
