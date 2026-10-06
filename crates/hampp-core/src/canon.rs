use sha2::{Digest, Sha256};

/// `\r\n` -> `\n`, trailing whitespace removed. Both sides hash this form so that
/// transports which append a newline or normalise line endings stay verifiable.
pub fn canonicalize(text: &str) -> String {
    text.replace("\r\n", "\n").trim_end().to_string()
}

pub fn payload_hash(visible: &str) -> [u8; 32] {
    Sha256::digest(canonicalize(visible).as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crlf_and_trailing_whitespace_are_ignored() {
        assert_eq!(canonicalize("a\r\nb\r\n"), "a\nb");
        assert_eq!(canonicalize("a\nb   \n\n"), "a\nb");
        assert_eq!(payload_hash("a\r\nb\r\n"), payload_hash("a\nb"));
    }
    #[test]
    fn different_text_has_different_hash() {
        assert_ne!(payload_hash("a"), payload_hash("b"));
    }
    #[test]
    fn only_unicode_white_space_is_trimmed() {
        assert_eq!(canonicalize("a\u{1f}"), "a\u{1f}");
        assert_eq!(canonicalize("a\u{3000}\u{a0}"), "a");
        assert_eq!(canonicalize("a\u{200b}"), "a\u{200b}");
    }
}
