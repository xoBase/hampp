pub const MAGIC: [u8; 2] = *b"HP";
pub const VERSION: u8 = 1;
pub const FLAG_SESSION: u8 = 0x01;

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
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(112);
        v.extend(MAGIC);
        v.push(VERSION);
        v.push(self.flags);
        v.push(self.suite);
        v.extend(self.key_id);
        v.extend(self.session_id);
        put_varint(&mut v, self.seq);
        put_varint(&mut v, self.timestamp);
        v.extend(self.prev_hash);
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
        if flags & !FLAG_SESSION != 0 {
            return Err(HeaderError::UnsupportedFlags);
        }
        let suite = c.take(1)?[0];
        let h = Header {
            flags,
            suite,
            key_id: c.arr()?,
            session_id: c.arr()?,
            seq: c.varint()?,
            timestamp: c.varint()?,
            prev_hash: c.arr()?,
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
