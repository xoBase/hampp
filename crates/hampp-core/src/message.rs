use crate::header::{Header, HeaderError, FLAG_SESSION};
use crate::verdict::{KeyResolver, Level, Reason, Status, TrustState, Verdict};
use crate::{key_id_of, payload_hash, verify_sig, SigningIdentity, SUITE_ED25519_SHA256};
use hampp_envelope::{embed, embed_visible, extract_any, Envelope};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct SignParams {
    pub session_id: [u8; 8],
    pub seq: u64,
    pub timestamp: u64,
    pub prev_hash: [u8; 16],
}

impl SignParams {
    /// Sessionless ("Lite") parameters.
    pub fn lite(timestamp: u64) -> Self {
        SignParams {
            session_id: [0; 8],
            seq: 0,
            timestamp,
            prev_hash: [0; 16],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    ZeroWidth,
    Visible,
}

pub fn sign_header(id: &SigningIdentity, visible: &str, p: &SignParams) -> Header {
    let mut h = Header {
        flags: if p.session_id != [0; 8] {
            FLAG_SESSION
        } else {
            0
        },
        suite: SUITE_ED25519_SHA256,
        key_id: id.identity.key_id(),
        session_id: p.session_id,
        seq: p.seq,
        timestamp: p.timestamp,
        prev_hash: p.prev_hash,
        signature: [0; 64],
    };
    h.signature = id.sign(&h.signing_input(&payload_hash(visible)));
    h
}

pub fn render(visible: &str, h: &Header, carrier: Carrier) -> String {
    let bytes = h.encode();
    match carrier {
        Carrier::ZeroWidth => embed(visible, &bytes).expect("header always fits in an envelope"),
        Carrier::Visible => embed_visible(visible, &bytes),
    }
}

pub fn sign_text(id: &SigningIdentity, visible: &str, p: &SignParams, carrier: Carrier) -> String {
    render(visible, &sign_header(id, visible, p), carrier)
}

/// Hash chained into the next message's `prev_hash` (first 16 bytes are used).
pub fn message_hash(h: &Header, payload_hash: &[u8; 32]) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(payload_hash);
    d.update(h.signature);
    d.finalize().into()
}

pub fn verify_text(text: &str, keys: &dyn KeyResolver, now: u64) -> Verdict {
    let ex = extract_any(text);
    let visible = ex.visible;
    let bytes = match ex.envelope {
        Envelope::Missing => {
            return Verdict::bare(Status::Unverified, Reason::EnvelopeMissing, visible)
        }
        Envelope::Corrupt(_) => {
            return Verdict::bare(Status::Unverified, Reason::EnvelopeCorrupt, visible)
        }
        Envelope::Present(b) => b,
    };
    let h = match Header::decode(&bytes) {
        Ok(h) => h,
        Err(HeaderError::UnsupportedVersion(_)) => {
            return Verdict::bare(Status::Invalid, Reason::UnsupportedVersion, visible)
        }
        Err(_) => return Verdict::bare(Status::Unverified, Reason::EnvelopeCorrupt, visible),
    };
    if h.suite != SUITE_ED25519_SHA256 {
        let mut v = Verdict::bare(Status::Invalid, Reason::UnsupportedSuite, visible);
        v.header = Some(h);
        return v;
    }
    let Some(key) = keys.resolve(&h.key_id, now) else {
        let mut v = Verdict::bare(Status::Unverified, Reason::UnknownKey, visible);
        v.header = Some(h);
        return v;
    };
    let mut v = Verdict {
        status: Status::Invalid,
        reason: Some(Reason::SignatureInvalid),
        level: None,
        header: Some(h.clone()),
        visible,
        key: Some(key.clone()),
        notes: vec![],
    };
    let input = h.signing_input(&payload_hash(&v.visible));
    if key_id_of(&key.public_key) != h.key_id || !verify_sig(&key.public_key, &input, &h.signature)
    {
        return v;
    }
    match key.trust {
        Some(TrustState::Revoked) => v.reason = Some(Reason::KeyRevoked),
        Some(TrustState::Expired) => v.reason = Some(Reason::KeyExpired),
        _ => {
            v.status = Status::Authenticated;
            v.reason = None;
            v.level = Some(Level::SignedByAgent);
        }
    }
    v
}
