use crate::crc::crc16;
use crate::frame::{extract, Envelope, EnvelopeError, Extracted};

const PREFIX: &str = "\n[hampp1:";

/// Fallback for platforms that strip zero-width characters: a short visible line.
pub fn embed_visible(text: &str, payload: &[u8]) -> String {
    let mut data = payload.to_vec();
    data.extend(crc16(payload).to_be_bytes());
    format!("{}{}{}]", text.trim_end(), PREFIX, hex::encode(data))
}

pub fn extract_visible(text: &str) -> Extracted {
    let trimmed = text.trim_end();
    let missing = || Extracted {
        visible: text.to_string(),
        envelope: Envelope::Missing,
    };
    if !trimmed.ends_with(']') {
        return missing();
    }
    let Some(idx) = trimmed.rfind(PREFIX) else {
        return missing();
    };
    let body = &trimmed[idx + PREFIX.len()..trimmed.len() - 1];
    let visible = trimmed[..idx].to_string();
    let corrupt = |e| Extracted {
        visible: visible.clone(),
        envelope: Envelope::Corrupt(e),
    };
    let Ok(bytes) = hex::decode(body) else {
        return corrupt(EnvelopeError::Malformed);
    };
    if bytes.len() < 2 {
        return corrupt(EnvelopeError::BadLength);
    }
    let (payload, crc) = bytes.split_at(bytes.len() - 2);
    if crc16(payload) != u16::from_be_bytes([crc[0], crc[1]]) {
        return corrupt(EnvelopeError::BadChecksum);
    }
    Extracted {
        visible,
        envelope: Envelope::Present(payload.to_vec()),
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
