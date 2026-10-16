use crate::Protection;
pub const MAGIC: [u8; 2] = *b"HP";
pub const VERSION: u8 = 1;
pub const FLAG_SESSION: u8 = 0x01;
/// Compact Lite header: `session_id`, `seq` and `prev_hash` (all zero) are not on the wire.
/// The bit is part of the signed flags byte, so a message has exactly one spelling.
pub const FLAG_COMPACT: u8 = 0x08;
pub const FLAG_PROTECTION_SHIFT: u8 = 1;
pub const FLAG_PROTECTION_MASK: u8 = 0b0000_0110;

/// Flags byte for a message: session bit plus protection bits.
pub fn flags_for(session: bool, protection: Protection) -> u8 {
    (if session { FLAG_SESSION } else { 0 }) | ((protection as u8) << FLAG_PROTECTION_SHIFT)
}

fn protection_of(flags: u8) -> Option<Protection> {
    Protection::from_bits((flags & FLAG_PROTECTION_MASK) >> FLAG_PROTECTION_SHIFT)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub flags: u8,
    pub suite: u8,
    pub key_id: [u8; 8],
    pub session_id: [u8; 8],
    pub seq: u64,
    pub timestamp: u64,
    pub prev_hash: [u8; 16],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    Truncated,
    BadMagic,
    UnsupportedVersion(u8),
    UnsupportedFlags,
    BadVarint,
    TrailingBytes,
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], HeaderError> {
        if self.i + n > self.b.len() {
            return Err(HeaderError::Truncated);
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], HeaderError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn varint(&mut self) -> Result<u64, HeaderError> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.take(1)?[0];
            if shift == 63 && (b & 0x7f) > 1 {
                return Err(HeaderError::BadVarint);
            }
            result |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                if b == 0 && shift > 0 {
                    return Err(HeaderError::BadVarint); // non-canonical encoding
                }
                return Ok(result);
            }
            shift += 7;
            if shift > 63 {
                return Err(HeaderError::BadVarint);
            }
        }
    }
}

impl Header {
    /// Protection level claimed in the (signed) flags. Headers built by hand with a
    /// reserved value read as `Software`; `decode` never produces such a header.
    pub fn protection(&self) -> Protection {
        protection_of(self.flags).unwrap_or(Protection::Software)
    }

    /// Compact form: sessionless fields are implied zeros (see [`FLAG_COMPACT`]).
    pub fn is_compact(&self) -> bool {
        self.flags & FLAG_COMPACT != 0
    }

    /// A header may carry [`FLAG_COMPACT`] only if the omitted fields are really zero and it is
    /// not a session message; otherwise the wire form would not match what was signed.
    pub fn compact_applicable(&self) -> bool {
        self.flags & FLAG_SESSION == 0
            && self.session_id == [0; 8]
            && self.seq == 0
            && self.prev_hash == [0; 16]
    }

    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(!self.is_compact() || self.compact_applicable());
        let mut v = Vec::with_capacity(112);
        v.extend(MAGIC);
        v.push(VERSION);
        v.push(self.flags);
        v.push(self.suite);
        v.extend(self.key_id);
        if !self.is_compact() {
            v.extend(self.session_id);
            put_varint(&mut v, self.seq);
        }
        put_varint(&mut v, self.timestamp);
        if !self.is_compact() {
            v.extend(self.prev_hash);
        }
        v.extend(self.signature);
        v
    }

    pub fn decode(bytes: &[u8]) -> Result<Header, HeaderError> {
        let mut c = Cur { b: bytes, i: 0 };
        if c.arr::<2>()? != MAGIC {
            return Err(HeaderError::BadMagic);
        }
        let version = c.take(1)?[0];
        if version != VERSION {
            return Err(HeaderError::UnsupportedVersion(version));
        }
        let flags = c.take(1)?[0];
        let known = FLAG_SESSION | FLAG_PROTECTION_MASK | FLAG_COMPACT;
        // compact is only for sessionless messages: a session needs its id, seq and chain
        let both = FLAG_SESSION | FLAG_COMPACT;
        if flags & !known != 0 || protection_of(flags).is_none() || flags & both == both {
            return Err(HeaderError::UnsupportedFlags);
        }
        let compact = flags & FLAG_COMPACT != 0;
        let suite = c.take(1)?[0];
        let key_id = c.arr()?;
        let (session_id, seq) = if compact {
            ([0; 8], 0)
        } else {
            (c.arr()?, c.varint()?)
        };
        let timestamp = c.varint()?;
        let prev_hash = if compact { [0; 16] } else { c.arr()? };
        let h = Header {
            flags,
            suite,
            key_id,
            session_id,
            seq,
            timestamp,
            prev_hash,
            signature: c.arr()?,
        };
        if c.i != bytes.len() {
            return Err(HeaderError::TrailingBytes);
        }
        Ok(h)
    }

    /// Bytes covered by the signature (see spec/PROTOCOL.md).
    pub fn signing_input(&self, payload_hash: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(11 + 3 + 8 + 8 + 16 + 32 + 16);
        v.extend(b"HAMPP/1 msg");
        v.push(VERSION);
        v.push(self.flags);
        v.push(self.suite);
        v.extend(self.key_id);
        v.extend(self.session_id);
        v.extend(self.seq.to_be_bytes());
        v.extend(self.timestamp.to_be_bytes());
        v.extend(payload_hash);
        v.extend(self.prev_hash);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Header {
        Header {
            flags: FLAG_SESSION,
            suite: 1,
            key_id: [1; 8],
            session_id: [2; 8],
            seq: 300,
            timestamp: 1_700_000_000,
            prev_hash: [3; 16],
            signature: [4; 64],
        }
    }
    #[test]
    fn encode_decode_roundtrip() {
        let h = sample();
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }
    #[test]
    fn starts_with_magic_and_version() {
        assert_eq!(&sample().encode()[..3], &[b'H', b'P', 1]);
    }
    #[test]
    fn rejects_bad_magic_version_flags_truncation_and_trailing() {
        let good = sample().encode();
        let mut bad = good.clone();
        bad[0] = b'X';
        assert_eq!(Header::decode(&bad), Err(HeaderError::BadMagic));
        let mut bad = good.clone();
        bad[2] = 9;
        assert_eq!(
            Header::decode(&bad),
            Err(HeaderError::UnsupportedVersion(9))
        );
        let mut bad = good.clone();
        bad[3] = 0x80;
        assert_eq!(Header::decode(&bad), Err(HeaderError::UnsupportedFlags));
        assert_eq!(
            Header::decode(&good[..good.len() - 1]),
            Err(HeaderError::Truncated)
        );
        let mut bad = good.clone();
        bad.push(0);
        assert_eq!(Header::decode(&bad), Err(HeaderError::TrailingBytes));
    }
    #[test]
    fn protection_bits_roundtrip_and_are_signed() {
        let mut h = sample();
        for p in [
            Protection::Software,
            Protection::Bound,
            Protection::Attested,
        ] {
            h.flags = flags_for(true, p);
            let d = Header::decode(&h.encode()).unwrap();
            assert_eq!(d.protection(), p);
            assert_eq!(d.flags & FLAG_SESSION, FLAG_SESSION);
        }
        let ph = [9u8; 32];
        let mut a = sample();
        a.flags = flags_for(false, Protection::Software);
        let mut b = sample();
        b.flags = flags_for(false, Protection::Bound);
        assert_ne!(a.signing_input(&ph), b.signing_input(&ph));
    }
    #[test]
    fn reserved_protection_value_and_high_flag_bits_are_rejected() {
        let mut bytes = sample().encode();
        bytes[3] = 0b0000_0110; // protection = 3
        assert_eq!(Header::decode(&bytes), Err(HeaderError::UnsupportedFlags));
        for bit in 4..8 {
            let mut b = sample().encode();
            b[3] = 1 << bit;
            assert_eq!(
                Header::decode(&b),
                Err(HeaderError::UnsupportedFlags),
                "bit {bit}"
            );
        }
    }
    fn compact_sample() -> Header {
        Header {
            flags: flags_for(false, Protection::Software) | FLAG_COMPACT,
            suite: 1,
            key_id: [1; 8],
            session_id: [0; 8],
            seq: 0,
            timestamp: 1_791_000_000,
            prev_hash: [0; 16],
            signature: [4; 64],
        }
    }

    #[test]
    fn compact_header_roundtrips_and_is_25_bytes_shorter() {
        let c = compact_sample();
        let mut long = c.clone();
        long.flags &= !FLAG_COMPACT;
        assert_eq!(c.encode().len(), 82);
        assert_eq!(long.encode().len(), 107);
        assert_eq!(Header::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn compact_bit_is_signed() {
        let ph = [9u8; 32];
        let c = compact_sample();
        let mut long = c.clone();
        long.flags &= !FLAG_COMPACT;
        assert_ne!(c.signing_input(&ph), long.signing_input(&ph));
        // everything else in the signing input is identical (same layout, same zero fields)
        assert_eq!(c.signing_input(&ph).len(), long.signing_input(&ph).len());
    }

    #[test]
    fn compact_rejects_session_bit_truncation_and_trailing_bytes() {
        let good = compact_sample().encode();
        let mut bad = good.clone();
        bad[3] |= FLAG_SESSION;
        assert_eq!(Header::decode(&bad), Err(HeaderError::UnsupportedFlags));
        assert_eq!(
            Header::decode(&good[..good.len() - 1]),
            Err(HeaderError::Truncated)
        );
        let mut bad = good.clone();
        bad.push(0);
        assert_eq!(Header::decode(&bad), Err(HeaderError::TrailingBytes));
        // a long-form body under the compact flag is trailing garbage, not a second spelling
        let mut long = compact_sample();
        long.flags &= !FLAG_COMPACT;
        let mut bad = long.encode();
        bad[3] |= FLAG_COMPACT;
        assert!(Header::decode(&bad).is_err());
    }

    #[test]
    fn non_canonical_varint_is_rejected() {
        let mut h = sample();
        h.seq = 1;
        let mut bytes = h.encode();
        // seq starts after 2+1+1+1+8+8 = 21 bytes; replace 0x01 by 0x81 0x00 (non-canonical 1)
        bytes.splice(21..22, [0x81, 0x00]);
        assert_eq!(Header::decode(&bytes), Err(HeaderError::BadVarint));
    }
    #[test]
    fn signing_input_binds_every_field() {
        let h = sample();
        let ph = [9u8; 32];
        let base = h.signing_input(&ph);
        let mut t = h.clone();
        t.seq += 1;
        assert_ne!(t.signing_input(&ph), base);
        let mut t = h.clone();
        t.timestamp += 1;
        assert_ne!(t.signing_input(&ph), base);
        let mut t = h.clone();
        t.session_id[0] ^= 1;
        assert_ne!(t.signing_input(&ph), base);
        let mut t = h.clone();
        t.prev_hash[0] ^= 1;
        assert_ne!(t.signing_input(&ph), base);
        let mut t = h.clone();
        t.key_id[0] ^= 1;
        assert_ne!(t.signing_input(&ph), base);
        assert_ne!(h.signing_input(&[8u8; 32]), base);
        assert!(base.starts_with(b"HAMPP/1 msg"));
    }
}
