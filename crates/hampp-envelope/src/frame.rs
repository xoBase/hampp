use crate::alphabet::{Alphabet, DEFAULT};
use crate::crc::crc16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    Malformed,
    BadLength,
    BadChecksum,
    TooLong,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Envelope {
    Missing,
    Present(Vec<u8>),
    Corrupt(EnvelopeError),
}

#[derive(Debug, Clone)]
pub struct Extracted {
    pub visible: String,
    pub envelope: Envelope,
}

pub fn embed(text: &str, payload: &[u8]) -> Result<String, EnvelopeError> {
    embed_with(&DEFAULT, text, payload)
}

pub fn extract(text: &str) -> Extracted {
    extract_with(&DEFAULT, text)
}

/// Appends `START symbols(len|payload|crc) END` to `text`.
pub fn embed_with(a: &Alphabet, text: &str, payload: &[u8]) -> Result<String, EnvelopeError> {
    if payload.len() > u16::MAX as usize {
        return Err(EnvelopeError::TooLong);
    }
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend((payload.len() as u16).to_be_bytes());
    frame.extend(payload);
    let crc = crc16(&frame);
    frame.extend(crc.to_be_bytes());

    let mut out = String::with_capacity(text.len() + frame.len() * 12 + 8);
    out.push_str(text);
    out.push(a.start);
    for b in frame {
        for shift in [6u8, 4, 2, 0] {
            out.push(a.symbols[((b >> shift) & 3) as usize]);
        }
    }
    out.push(a.end);
    Ok(out)
}

/// Finds the LAST envelope in `text`. Anything before START and after END is
/// the visible text (quoted older envelopes stay visible).
pub fn extract_with(a: &Alphabet, text: &str) -> Extracted {
    let Some(start) = text.rfind(a.start) else {
        return Extracted {
            visible: text.to_string(),
            envelope: Envelope::Missing,
        };
    };
    let after = start + a.start.len_utf8();
    let Some(rel_end) = text[after..].find(a.end) else {
        return Extracted {
            visible: text[..start].to_string(),
            envelope: Envelope::Corrupt(EnvelopeError::Malformed),
        };
    };
    let end = after + rel_end;
    let mut visible = String::with_capacity(text.len());
    visible.push_str(&text[..start]);
    visible.push_str(&text[end + a.end.len_utf8()..]);
    Extracted {
        visible,
        envelope: decode_body(a, &text[after..end]),
    }
}

fn decode_body(a: &Alphabet, body: &str) -> Envelope {
    let mut symbols = Vec::with_capacity(body.len() / 3);
    for c in body.chars() {
        match a.symbol_index(c) {
            Some(i) => symbols.push(i),
            None => return Envelope::Corrupt(EnvelopeError::Malformed),
        }
    }
    if symbols.len() % 4 != 0 {
        return Envelope::Corrupt(EnvelopeError::Malformed);
    }
    let bytes: Vec<u8> = symbols
        .chunks(4)
        .map(|q| (q[0] << 6) | (q[1] << 4) | (q[2] << 2) | q[3])
        .collect();
    if bytes.len() < 4 {
        return Envelope::Corrupt(EnvelopeError::BadLength);
    }
    let declared = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if declared != bytes.len() - 4 {
        return Envelope::Corrupt(EnvelopeError::BadLength);
    }
    let crc_pos = bytes.len() - 2;
    let crc = u16::from_be_bytes([bytes[crc_pos], bytes[crc_pos + 1]]);
    if crc16(&bytes[..crc_pos]) != crc {
        return Envelope::Corrupt(EnvelopeError::BadChecksum);
    }
    Envelope::Present(bytes[2..crc_pos].to_vec())
}

/// Removes every alphabet character (used by `hampp strip` and the simulator).
pub fn strip_all(a: &Alphabet, text: &str) -> String {
    text.chars().filter(|c| !a.is_member(*c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT;

    #[test]
    fn roundtrip_keeps_visible_text_and_payload() {
        let signed = embed("Hallo Welt", b"payload-bytes").unwrap();
        assert!(signed.starts_with("Hallo Welt"));
        let ex = extract(&signed);
        assert_eq!(ex.visible, "Hallo Welt");
        assert_eq!(ex.envelope, Envelope::Present(b"payload-bytes".to_vec()));
    }

    #[test]
    fn plain_text_is_missing() {
        let ex = extract("nur Text");
        assert_eq!(ex.visible, "nur Text");
        assert_eq!(ex.envelope, Envelope::Missing);
    }

    #[test]
    fn flipped_symbol_is_bad_checksum() {
        let signed = embed("x", b"abc").unwrap();
        let mut chars: Vec<char> = signed.chars().collect();
        // +1 skips START, +8 skips the 2-byte length field (4 symbols per byte)
        let i = chars.iter().position(|c| *c == DEFAULT.start).unwrap() + 1 + 8;
        chars[i] = if chars[i] == DEFAULT.symbols[0] {
            DEFAULT.symbols[1]
        } else {
            DEFAULT.symbols[0]
        };
        let ex = extract(&chars.into_iter().collect::<String>());
        assert_eq!(ex.envelope, Envelope::Corrupt(EnvelopeError::BadChecksum));
        assert_eq!(ex.visible, "x");
    }

    #[test]
    fn missing_end_marker_is_malformed_and_keeps_text() {
        let signed = embed("x", b"abc").unwrap();
        let cut: String = signed.chars().take(signed.chars().count() - 1).collect();
        let ex = extract(&cut);
        assert_eq!(ex.envelope, Envelope::Corrupt(EnvelopeError::Malformed));
        assert_eq!(ex.visible, "x");
    }

    #[test]
    fn dropped_symbol_breaks_alignment() {
        let signed = embed("x", b"abc").unwrap();
        let mut chars: Vec<char> = signed.chars().collect();
        let i = chars.iter().position(|c| *c == DEFAULT.start).unwrap() + 3;
        chars.remove(i);
        let ex = extract(&chars.into_iter().collect::<String>());
        assert!(matches!(ex.envelope, Envelope::Corrupt(_)));
    }

    #[test]
    fn quoted_older_envelope_is_part_of_the_visible_text() {
        let old = embed("alt", b"old").unwrap();
        let reply = embed(&format!("> {old}\nneu"), b"new").unwrap();
        let ex = extract(&reply);
        assert_eq!(ex.envelope, Envelope::Present(b"new".to_vec()));
        assert_eq!(ex.visible, format!("> {old}\nneu"));
    }

    #[test]
    fn text_after_the_envelope_is_kept_as_visible() {
        let signed = embed("a", b"p").unwrap() + "\n";
        let ex = extract(&signed);
        assert_eq!(ex.visible, "a\n");
        assert_eq!(ex.envelope, Envelope::Present(b"p".to_vec()));
    }

    #[test]
    fn empty_text_and_marker_chars_in_user_text_do_not_panic() {
        let ex = extract("");
        assert_eq!(ex.envelope, Envelope::Missing);
        let tricky = format!("a{}b{}c", DEFAULT.start, DEFAULT.end);
        let ex = extract(&tricky);
        assert!(matches!(ex.envelope, Envelope::Corrupt(_)));
        let signed = embed(&tricky, b"p").unwrap();
        assert_eq!(extract(&signed).envelope, Envelope::Present(b"p".to_vec()));
        assert_eq!(extract(&signed).visible, tricky);
    }

    #[test]
    fn one_megabyte_text_is_fast() {
        let big = "x".repeat(1_000_000);
        let signed = embed(&big, b"p").unwrap();
        let ex = extract(&signed);
        assert_eq!(ex.visible.len(), 1_000_000);
    }

    #[test]
    fn strip_all_removes_every_alphabet_char() {
        let signed = embed("abc", b"p").unwrap();
        assert_eq!(strip_all(&DEFAULT, &signed), "abc");
    }

    #[test]
    fn payload_too_long_is_rejected() {
        assert_eq!(embed("x", &vec![0u8; 70_000]), Err(EnvelopeError::TooLong));
    }
}
