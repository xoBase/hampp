use hampp_core::{
    hexfmt, message_hash, payload_hash, render, try_sign_header, verify_text, Carrier, Level,
    Protection, PublicKey, Reason, SignError, SignParams, Signer, SigningIdentity, SingleKey,
    Status, Verdict,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    #[serde(with = "hexfmt")]
    pub id: [u8; 8],
    #[serde(with = "hexfmt")]
    pub peer_public_key: PublicKey,
    pub version: u8,
    pub suite: u8,
    pub out_seq: u64,
    #[serde(with = "hexfmt")]
    pub out_prev: [u8; 16],
    pub in_seq: u64,
    #[serde(with = "hexfmt")]
    pub in_prev: [u8; 16],
    /// Timestamp window in seconds. `None` (default) disables it, which is what
    /// asynchronous platforms (forums) need; use it only for live channels.
    pub max_skew: Option<u64>,
}

impl Session {
    pub fn new(id: [u8; 8], peer_public_key: PublicKey, version: u8, suite: u8) -> Self {
        Session {
            id,
            peer_public_key,
            version,
            suite,
            out_seq: 0,
            out_prev: [0; 16],
            in_seq: 0,
            in_prev: [0; 16],
            max_skew: None,
        }
    }

    /// Signs the next message of this session with any signer of the session's suite, claiming
    /// `protection` (at most what the signer offers). The session state only advances when the
    /// signature succeeded, so a failing TPM leaves the session as it was.
    pub fn try_sign_next(
        &mut self,
        signer: &dyn Signer,
        text: &str,
        now: u64,
        carrier: Carrier,
        protection: Protection,
    ) -> Result<String, SignError> {
        if signer.suite() != self.suite {
            return Err(SignError::SuiteMismatch {
                signer: signer.suite(),
                session: self.suite,
            });
        }
        let p = SignParams {
            session_id: self.id,
            seq: self.out_seq + 1,
            timestamp: now,
            prev_hash: self.out_prev,
            protection,
        };
        let h = try_sign_header(signer, text, &p)?;
        self.out_seq += 1;
        self.out_prev
            .copy_from_slice(&message_hash(&h, &payload_hash(text))[..16]);
        Ok(render(text, &h, carrier))
    }

    /// Software Ed25519 identity, protection `software`; cannot fail.
    pub fn sign_next(
        &mut self,
        id: &SigningIdentity,
        text: &str,
        now: u64,
        carrier: Carrier,
    ) -> String {
        self.try_sign_next(id, text, now, carrier, Protection::Software)
            .expect("a software identity signs at protection software in a suite 1 session")
    }

    /// Verifies the signature with the peer key and the session rules. State only
    /// advances for authenticated messages.
    pub fn verify_next(&mut self, text: &str, now: u64) -> Verdict {
        let mut v = verify_text(text, &SingleKey(self.peer_public_key.clone()), now);
        if v.status != Status::Authenticated {
            return v;
        }
        let h = v
            .header
            .clone()
            .expect("authenticated verdict has a header");
        if h.session_id != self.id {
            return v.fail(Reason::WrongSession);
        }
        if let Some(skew) = self.max_skew {
            if now.abs_diff(h.timestamp) > skew {
                return v.fail(Reason::ClockSkew);
            }
        }
        if h.seq <= self.in_seq {
            return v.fail(Reason::Replay);
        }
        if h.seq == self.in_seq + 1 {
            if h.prev_hash != self.in_prev {
                return v.fail(Reason::ChainBroken);
            }
        } else {
            v.notes.push(format!("gap:{}", h.seq - self.in_seq - 1));
        }
        self.in_seq = h.seq;
        self.in_prev
            .copy_from_slice(&message_hash(&h, &payload_hash(&v.visible))[..16]);
        v.level = Some(Level::RegisteredInstance);
        v
    }
}
