//! Property tests for the signed header: canonical encoding, strict parsing, no panics.
use hampp_core::*;
use proptest::prelude::*;

fn header() -> impl Strategy<Value = Header> {
    (
        any::<bool>(),
        0u8..=2, // defined protection levels
        any::<u8>(),
        any::<[u8; 8]>(),
        any::<[u8; 8]>(),
        any::<u64>(),
        any::<u64>(),
        any::<[u8; 16]>(),
        proptest::collection::vec(any::<u8>(), 64),
    )
        .prop_map(
            |(session, level, suite, key_id, session_id, seq, timestamp, prev_hash, sig)| Header {
                flags: flags_for(session, Protection::from_bits(level).unwrap()),
                suite,
                key_id,
                session_id,
                seq,
                timestamp,
                prev_hash,
                signature: sig.try_into().unwrap(),
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn decode_inverts_encode(h in header()) {
        prop_assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn every_strict_prefix_is_rejected(h in header(), cut in any::<prop::sample::Index>()) {
        let bytes = h.encode();
        let n = cut.index(bytes.len()); // 0..len, so always a strict prefix
        prop_assert!(Header::decode(&bytes[..n]).is_err());
    }

    #[test]
    fn appended_bytes_are_rejected(h in header(), extra in proptest::collection::vec(any::<u8>(), 1..8)) {
        let mut bytes = h.encode();
        bytes.extend(extra);
        prop_assert_eq!(Header::decode(&bytes), Err(HeaderError::TrailingBytes));
    }

    /// One flipped byte in a real header either fails to parse or parses to a header that encodes
    /// back to exactly those bytes (no second spelling of the same header, so no malleability).
    #[test]
    fn one_changed_byte_is_rejected_or_canonical(
        h in header(),
        at in any::<prop::sample::Index>(),
        new in any::<u8>(),
    ) {
        let mut bytes = h.encode();
        let i = at.index(bytes.len());
        if bytes[i] == new { return Ok(()); }
        bytes[i] = new;
        if let Ok(parsed) = Header::decode(&bytes) {
            prop_assert_eq!(parsed.encode(), bytes);
            prop_assert_ne!(parsed, h);
        }
    }

    #[test]
    fn undefined_flag_bits_are_rejected(h in header(), bad in 1u8..=255) {
        let defined = FLAG_SESSION | FLAG_PROTECTION_MASK;
        let flags = (h.flags & defined) | (bad & !defined);
        prop_assume!(flags & !defined != 0);
        let mut bytes = h.encode();
        bytes[3] = flags; // MAGIC(2) + VERSION(1), then flags
        prop_assert_eq!(Header::decode(&bytes), Err(HeaderError::UnsupportedFlags));
    }

    #[test]
    fn reserved_protection_value_is_rejected(h in header()) {
        let mut bytes = h.encode();
        bytes[3] = (bytes[3] & !FLAG_PROTECTION_MASK) | (3 << FLAG_PROTECTION_SHIFT);
        prop_assert_eq!(Header::decode(&bytes), Err(HeaderError::UnsupportedFlags));
    }

    /// The signature covers every other header field: changing any of them changes the signing input.
    #[test]
    fn signing_input_binds_the_fields(h in header(), payload_hash in any::<[u8; 32]>(), which in 0usize..7) {
        let mut g = h.clone();
        match which {
            0 => g.flags ^= FLAG_SESSION,
            1 => g.suite = g.suite.wrapping_add(1),
            2 => g.key_id[0] ^= 1,
            3 => g.session_id[0] ^= 1,
            4 => g.seq ^= 1,
            5 => g.timestamp ^= 1,
            _ => g.prev_hash[0] ^= 1,
        }
        prop_assert_ne!(h.signing_input(&payload_hash), g.signing_input(&payload_hash));
        // ... and the signature bytes themselves are not part of what is signed
        let mut s = h.clone();
        s.signature[0] ^= 1;
        prop_assert_eq!(h.signing_input(&payload_hash), s.signing_input(&payload_hash));
    }
}
