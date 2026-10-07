use crate::Header;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TrustState {
    Unknown,
    Pending,
    Trusted,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Authenticated,
    Unverified,
    Invalid,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Authenticated => "authenticated",
            Status::Unverified => "unverified",
            Status::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    SignedByAgent,
    RegisteredInstance,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::SignedByAgent => "signed-by-agent",
            Level::RegisteredInstance => "registered-instance",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    EnvelopeMissing,
    EnvelopeCorrupt,
    UnknownKey,
    UnsupportedVersion,
    UnsupportedSuite,
    SignatureInvalid,
    KeyRevoked,
    KeyExpired,
    WrongSession,
    Replay,
    ChainBroken,
    ClockSkew,
    ProtectionTooLow,
}

impl Reason {
    pub fn code(&self) -> &'static str {
        match self {
            Reason::EnvelopeMissing => "envelope-missing",
            Reason::EnvelopeCorrupt => "envelope-corrupt",
            Reason::UnknownKey => "unknown-key",
            Reason::UnsupportedVersion => "unsupported-version",
            Reason::UnsupportedSuite => "unsupported-suite",
            Reason::SignatureInvalid => "signature-invalid",
            Reason::KeyRevoked => "key-revoked",
            Reason::KeyExpired => "key-expired",
            Reason::WrongSession => "wrong-session",
            Reason::Replay => "replay",
            Reason::ChainBroken => "chain-broken",
            Reason::ClockSkew => "clock-skew",
            Reason::ProtectionTooLow => "protection-too-low",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub public_key: crate::PublicKey,
    pub agent_id: Option<String>,
    pub instance_id: Option<[u8; 16]>,
    pub trust: Option<TrustState>,
    /// Protection the receiver's registry records for this key, if any.
    pub protection: Option<crate::Protection>,
}

pub trait KeyResolver {
    fn resolve(&self, key_id: &[u8; 8], now: u64) -> Option<ResolvedKey>;
}

/// Resolver for one known public key (no registry).
pub struct SingleKey(pub crate::PublicKey);

impl KeyResolver for SingleKey {
    fn resolve(&self, key_id: &[u8; 8], _now: u64) -> Option<ResolvedKey> {
        (self.0.key_id() == *key_id).then_some(ResolvedKey {
            public_key: self.0.clone(),
            agent_id: None,
            instance_id: None,
            trust: None,
            protection: None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub status: Status,
    pub reason: Option<Reason>,
    pub level: Option<Level>,
    /// Set for authenticated messages (and kept when a policy downgrades them).
    pub protection: Option<crate::EffectiveProtection>,
    pub header: Option<Header>,
    pub visible: String,
    pub key: Option<ResolvedKey>,
    pub notes: Vec<String>,
}

impl Verdict {
    pub(crate) fn bare(status: Status, reason: Reason, visible: String) -> Self {
        Verdict {
            status,
            reason: Some(reason),
            level: None,
            protection: None,
            header: None,
            visible,
            key: None,
            notes: vec![],
        }
    }

    pub fn code(&self) -> String {
        match self.status {
            Status::Authenticated => {
                format!(
                    "authenticated:{}",
                    self.level.map(|l| l.as_str()).unwrap_or("none")
                )
            }
            s => format!(
                "{}:{}",
                s.as_str(),
                self.reason.map(|r| r.code()).unwrap_or("unknown")
            ),
        }
    }

    /// Applies a receiver policy: an `authenticated` verdict whose effective protection is below
    /// `min` becomes `unverified:protection-too-low`. Every other verdict is returned unchanged
    /// (invalid and unknown-key results take precedence).
    pub fn with_min_protection(mut self, min: Option<crate::Protection>) -> Verdict {
        if let (Status::Authenticated, Some(min), Some(p)) = (self.status, min, self.protection) {
            if p.level < min {
                self.status = Status::Unverified;
                self.reason = Some(Reason::ProtectionTooLow);
                self.level = None;
            }
        }
        self
    }

    /// Turns a verdict into `invalid:<reason>` (used by session checks).
    pub fn fail(mut self, reason: Reason) -> Verdict {
        self.status = Status::Invalid;
        self.reason = Some(reason);
        self.level = None;
        self
    }

    pub fn to_json(&self) -> serde_json::Value {
        let h = self.header.as_ref();
        serde_json::json!({
            "code": self.code(),
            "status": self.status.as_str(),
            "reason": self.reason.map(|r| r.code()),
            "level": self.level.map(|l| l.as_str()),
            "protection": self.protection.map(|p| p.level.as_str()),
            "protection_claimed": self.protection.map(|p| p.claimed),
            "key_id": h.map(|h| hex::encode(h.key_id)),
            "agent_id": self.key.as_ref().and_then(|k| k.agent_id.clone()),
            "trust": self.key.as_ref().and_then(|k| k.trust),
            "session_id": h.map(|h| hex::encode(h.session_id)),
            "seq": h.map(|h| h.seq),
            "timestamp": h.map(|h| h.timestamp),
            "notes": self.notes,
        })
    }
}
