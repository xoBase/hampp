use hampp_core::{
    hexfmt, message_hash, payload_hash, render, sign_header, verify_text, Carrier, Level,
    Protection, Reason, SignParams, SigningIdentity, SingleKey, Status, Verdict,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    #[serde(with = "hexfmt")]
    pub id: [u8; 8],
    #[serde(with = "hexfmt")]
    pub peer_public_key: [u8; 32],
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
    pub fn new(id: [u8; 8], peer_public_key: [u8; 32], version: u8, suite: u8) -> Self {
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

    pub fn sign_next(
        &mut self,
        id: &SigningIdentity,
        text: &str,
        now: u64,
        carrier: Carrier,
    ) -> String {
        self.out_seq += 1;
        let p = SignParams {
            session_id: self.id,
            seq: self.out_seq,
            timestamp: now,
            prev_hash: self.out_prev,
            protection: Protection::Software,
        };
        let h = sign_header(id, text, &p);
        self.out_prev
            .copy_from_slice(&message_hash(&h, &payload_hash(text))[..16]);
        render(text, &h, carrier)
    }

    /// Verifies the signature with the peer key and the session rules. State only
    /// advances for authenticated messages.
    pub fn verify_next(&mut self, text: &str, now: u64) -> Verdict {
        let mut v = verify_text(text, &SingleKey(self.peer_public_key.into()), now);
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
