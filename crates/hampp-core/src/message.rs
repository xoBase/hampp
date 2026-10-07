use crate::header::{flags_for, Header, HeaderError};
use crate::verdict::{KeyResolver, Level, Reason, Status, TrustState, Verdict};
use crate::{
    effective_protection, payload_hash, verify_signature, Protection, SignError, Signer,
    SigningIdentity, SUITE_ECDSA_P256_SHA256, SUITE_ED25519_SHA256,
};
use hampp_envelope::{embed, embed_visible, extract_any, Envelope};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct SignParams {
    pub session_id: [u8; 8],
    pub seq: u64,
    pub timestamp: u64,
    pub prev_hash: [u8; 16],
    /// Protection level to claim in the header; must not exceed the signer's level.
    pub protection: Protection,
}

impl SignParams {
    pub fn with_protection(mut self, protection: Protection) -> Self {
        self.protection = protection;
        self
    }

    /// Sessionless ("Lite") parameters.
    pub fn lite(timestamp: u64) -> Self {
        SignParams {
            session_id: [0; 8],
            seq: 0,
            timestamp,
            prev_hash: [0; 16],
            protection: Protection::Software,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    ZeroWidth,
    Visible,
}

/// Signs with any [`Signer`] and the protection level in `p`. Fails with
/// `LevelNotAvailable` when `p.protection` exceeds what the signer can claim.
pub fn try_sign_header(s: &dyn Signer, visible: &str, p: &SignParams) -> Result<Header, SignError> {
    if p.protection > s.level() {
        return Err(SignError::LevelNotAvailable {
            requested: p.protection,
            max: s.level(),
        });
    }
    let mut h = Header {
        flags: flags_for(p.session_id != [0; 8], p.protection),
        suite: s.suite(),
        key_id: s.public_key().key_id(),
        session_id: p.session_id,
        seq: p.seq,
        timestamp: p.timestamp,
        prev_hash: p.prev_hash,
        signature: [0; 64],
    };
    h.signature = s.sign(&h.signing_input(&payload_hash(visible)))?;
    Ok(h)
}

/// Software Ed25519 identity: always protection `software`, cannot fail.
pub fn sign_header(id: &SigningIdentity, visible: &str, p: &SignParams) -> Header {
    let p = p.clone().with_protection(Protection::Software);
    try_sign_header(id, visible, &p).expect("a software identity signs at protection software")
}

pub fn render(visible: &str, h: &Header, carrier: Carrier) -> String {
    let bytes = h.encode();
    match carrier {
        Carrier::ZeroWidth => embed(visible, &bytes).expect("header always fits in an envelope"),
        Carrier::Visible => embed_visible(visible, &bytes),
    }
}

pub fn try_sign_text(
    s: &dyn Signer,
    visible: &str,
    p: &SignParams,
    carrier: Carrier,
) -> Result<String, SignError> {
    Ok(render(visible, &try_sign_header(s, visible, p)?, carrier))
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

#[derive(Debug, Default, Clone, Copy)]
pub struct VerifyOptions {
    /// Receiver policy: authenticated messages below this effective protection become
    /// `unverified:protection-too-low`.
    pub min_protection: Option<Protection>,
}

pub fn verify_text(text: &str, keys: &dyn KeyResolver, now: u64) -> Verdict {
    verify_text_with(text, keys, now, &VerifyOptions::default())
}

pub fn verify_text_with(
    text: &str,
    keys: &dyn KeyResolver,
    now: u64,
    opts: &VerifyOptions,
) -> Verdict {
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
    if h.suite != SUITE_ED25519_SHA256 && h.suite != SUITE_ECDSA_P256_SHA256 {
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
        protection: None,
        header: Some(h.clone()),
        visible,
        key: Some(key.clone()),
        notes: vec![],
    };
    let input = h.signing_input(&payload_hash(&v.visible));
    if key.public_key.suite() != h.suite
        || key.public_key.key_id() != h.key_id
        || !verify_signature(&key.public_key, &input, &h.signature)
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
            let (eff, capped) = effective_protection(h.protection(), key.protection);
            if h.protection() == Protection::Attested {
                v.notes.push("attestation-not-verified".into());
            }
            if capped {
                v.notes.push("protection-capped".into());
            }
            v.protection = Some(eff);
        }
    }
    v.with_min_protection(opts.min_protection)
}
