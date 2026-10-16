use crate::crc::crc16;
use crate::frame::{extract, Envelope, EnvelopeError, Extracted};

/// Visible line, hex body: `[hampp1:<hex>]`.
const HEX_TAG: &str = "[hampp1:";
/// Visible line, base64url body: `[hampp1u:<b64url>]`.
const B64_TAG: &str = "[hampp1u:";

/// Fallback for platforms that strip zero-width characters: a short visible line.
pub fn embed_visible(text: &str, payload: &[u8]) -> String {
    format!("{}\n{}", text.trim_end(), visible_line(payload, false))
}

/// Like [`embed_visible`] with a base64url body (`[hampp1u:...]`): fewer characters and tokens.
pub fn embed_visible_b64(text: &str, payload: &[u8]) -> String {
    format!("{}\n{}", text.trim_end(), visible_line(payload, true))
}

/// The bracketed line on its own (also the detached form): `[hampp1:<hex>]` or `[hampp1u:<b64url>]`.
pub fn visible_line(payload: &[u8], base64url: bool) -> String {
    let mut data = payload.to_vec();
    data.extend(crc16(payload).to_be_bytes());
    if base64url {
        format!("{B64_TAG}{}]", b64url_encode(&data))
    } else {
        format!("{HEX_TAG}{}]", hex::encode(data))
    }
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// RFC 4648 section 5 without padding.
fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
        let chars = chunk.len() + 1;
        for k in 0..chars {
            out.push(B64_ALPHABET[((n >> (18 - 6 * k)) & 63) as usize] as char);
        }
    }
    out
}

/// Strict decoder: alphabet `A-Za-z0-9-_` only, no padding, no whitespace, and the unused
/// trailing bits must be zero, so every byte string has exactly one spelling.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 2);
    for chunk in s.as_bytes().chunks(4) {
        let mut n = 0u32;
        for (k, c) in chunk.iter().enumerate() {
            let v = B64_ALPHABET.iter().position(|a| a == c)? as u32;
            n |= v << (18 - 6 * k);
        }
        let bytes = chunk.len() * 6 / 8;
        for k in 0..bytes {
            out.push((n >> (16 - 8 * k)) as u8);
        }
        let used = bytes * 8;
        let spare = chunk.len() * 6 - used; // unused low bits of the last character
        if spare > 0 && (n >> (24 - chunk.len() * 6)) & ((1 << spare) - 1) != 0 {
            return None;
        }
    }
    Some(out)
}

/// Decodes one bracketed line (`[hampp1:..]` or `[hampp1u:..]`, nothing before or after).
/// `None`: the line does not start with a HAMPP tag at all.
pub(crate) fn parse_line(line: &str) -> Option<Result<Vec<u8>, EnvelopeError>> {
    let (tag_is_b64, rest) = if let Some(r) = line.strip_prefix(B64_TAG) {
        (true, r)
    } else if let Some(r) = line.strip_prefix(HEX_TAG) {
        (false, r)
    } else {
        return None;
    };
    let Some(body) = rest.strip_suffix(']') else {
        return Some(Err(EnvelopeError::Malformed));
    };
    let bytes = if tag_is_b64 {
        b64url_decode(body)
    } else if body.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        // exactly one spelling: lower-case hex, no whitespace (hex::decode alone accepts upper case)
        hex::decode(body).ok()
    } else {
        None
    };
    let Some(bytes) = bytes else {
        return Some(Err(EnvelopeError::Malformed));
    };
    if bytes.len() < 2 {
        return Some(Err(EnvelopeError::BadLength));
    }
    let (payload, crc) = bytes.split_at(bytes.len() - 2);
    if crc16(payload) != u16::from_be_bytes([crc[0], crc[1]]) {
        return Some(Err(EnvelopeError::BadChecksum));
    }
    Some(Ok(payload.to_vec()))
}

/// The visible line at the very end of `text`, in either spelling. The LAST such line wins, so
/// a quoted older line (of either kind) stays part of the text.
pub fn extract_visible(text: &str) -> Extracted {
    let trimmed = text.trim_end();
    let missing = || Extracted {
        visible: text.to_string(),
        envelope: Envelope::Missing,
    };
    if !trimmed.ends_with(']') {
        return missing();
    }
    let at = |tag: &str| trimmed.rfind(&format!("\n{tag}"));
    let Some(idx) = at(HEX_TAG).into_iter().chain(at(B64_TAG)).max() else {
        return missing();
    };
    let visible = trimmed[..idx].to_string();
    match parse_line(&trimmed[idx + 1..]) {
        Some(Ok(payload)) => Extracted {
            visible,
            envelope: Envelope::Present(payload),
        },
        Some(Err(e)) => Extracted {
            visible,
            envelope: Envelope::Corrupt(e),
        },
        None => missing(),
    }
}

/// Zero-width first, visible fallback second.
pub fn extract_any(text: &str) -> Extracted {
    let zw = extract(text);
    if zw.envelope != Envelope::Missing {
        return zw;
    }
    extract_visible(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Envelope;

    #[test]
    fn roundtrip() {
        let s = embed_visible("Hallo", b"abc");
        assert!(s.starts_with("Hallo\n[hampp1:"));
        let ex = extract_visible(&s);
        assert_eq!(ex.visible, "Hallo");
        assert_eq!(ex.envelope, Envelope::Present(b"abc".to_vec()));
    }

    #[test]
    fn plain_is_missing() {
        assert_eq!(extract_visible("Hallo").envelope, Envelope::Missing);
    }

    #[test]
    fn altered_hex_is_corrupt() {
        let s = embed_visible("Hallo", b"abc").replace("616263", "616264");
        assert!(matches!(extract_visible(&s).envelope, Envelope::Corrupt(_)));
    }

    #[test]
    fn upper_case_and_spaced_hex_are_corrupt() {
        let s = embed_visible("Hallo", &[0xab, 0xcd]);
        assert_eq!(
            extract_visible(&s).envelope,
            Envelope::Present(vec![0xab, 0xcd])
        );
        let up = s.replace("abcd", "ABCD");
        assert_ne!(up, s);
        assert!(matches!(
            extract_visible(&up).envelope,
            Envelope::Corrupt(_)
        ));
        let sp = s.replace("abcd", "ab cd");
        assert!(matches!(
            extract_visible(&sp).envelope,
            Envelope::Corrupt(_)
        ));
    }

    #[test]
    fn base64url_roundtrip_all_lengths_and_known_value() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let enc = b64url_encode(&data);
            assert_eq!(b64url_decode(&enc).as_deref(), Some(&data[..]), "len {n}");
        }
        // RFC 4648 test vectors (padding stripped) and the url alphabet
        assert_eq!(b64url_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64url_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(b64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn base64url_has_exactly_one_spelling() {
        assert_eq!(b64url_decode("Zm9vYg"), Some(b"foob".to_vec()));
        for bad in [
            "Zm9vYg==", "Zm9vYh", "Zm9vY", "Zm9v Yg", "Zm9vYg\n", "Zm9v+g", "Zm9v/g", "Zg=",
            "Zm9vYmE=", "Zh",
        ] {
            assert_eq!(b64url_decode(bad), None, "{bad:?}");
        }
        // 'h' sets a spare low bit of the last character
        assert_eq!(b64url_decode("Zg"), Some(b"f".to_vec()));
        assert_eq!(b64url_decode("Zh"), None);
    }

    #[test]
    fn b64_line_roundtrip_and_last_line_wins() {
        let s = embed_visible_b64("Hallo", &[0xab, 0xcd, 0xef]);
        assert!(s.starts_with("Hallo\n[hampp1u:"));
        let ex = extract_visible(&s);
        assert_eq!(ex.visible, "Hallo");
        assert_eq!(ex.envelope, Envelope::Present(vec![0xab, 0xcd, 0xef]));
        // a quoted older hex line in the text does not disturb the real b64 line, and vice versa
        let old = embed_visible("alt", b"old");
        let reply = embed_visible_b64(&format!("> {old}\nneu"), b"new");
        assert_eq!(
            extract_any(&reply).envelope,
            Envelope::Present(b"new".to_vec())
        );
        let old = embed_visible_b64("alt", b"old");
        let reply = embed_visible(&format!("> {old}\nneu"), b"new");
        assert_eq!(
            extract_any(&reply).envelope,
            Envelope::Present(b"new".to_vec())
        );
    }

    #[test]
    fn b64_damage_is_corrupt() {
        let s = embed_visible_b64("Hallo", b"abcdef");
        let line = s.rsplit('\n').next().unwrap().to_string();
        for bad in [
            line.replace("]", "=]"),
            line.replace("[hampp1u:", "[hampp1u: "),
            line.replace("[hampp1u:", "[hampp1u:+"),
            line.replace("YWJj", "ZWJj"), // one changed character: CRC mismatch
        ] {
            let t = format!("Hallo\n{bad}");
            assert!(
                matches!(extract_visible(&t).envelope, Envelope::Corrupt(_)),
                "{bad} {:?}",
                extract_visible(&t).envelope
            );
        }
    }

    #[test]
    fn extract_any_prefers_zero_width_then_falls_back() {
        let zw = crate::embed("a", b"zw").unwrap();
        assert_eq!(extract_any(&zw).envelope, Envelope::Present(b"zw".to_vec()));
        let vis = embed_visible("a", b"vis");
        assert_eq!(
            extract_any(&vis).envelope,
            Envelope::Present(b"vis".to_vec())
        );
        assert_eq!(extract_any("a").envelope, Envelope::Missing);
    }
}
