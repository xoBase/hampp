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
