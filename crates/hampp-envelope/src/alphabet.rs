/// Four data symbols (2 bits each) plus start/end markers. All are invisible
/// Unicode format characters (category Cf) that survive NFC/NFD/NFKC/NFKD
/// (verified 2026-10-06 with Python `unicodedata`; see spec/UNICODE_ENCODING.md).
#[derive(Debug, Clone, Copy)]
pub struct Alphabet {
    pub symbols: [char; 4],
    pub start: char,
    pub end: char,
}

pub const DEFAULT: Alphabet = Alphabet {
    symbols: ['\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}'],
    start: '\u{2064}',
    end: '\u{2063}',
};

impl Alphabet {
    pub fn is_member(&self, c: char) -> bool {
        c == self.start || c == self.end || self.symbols.contains(&c)
    }

    pub(crate) fn symbol_index(&self, c: char) -> Option<u8> {
        self.symbols.iter().position(|&s| s == c).map(|i| i as u8)
    }
}
