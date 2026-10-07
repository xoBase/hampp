use crate::session::Session;
use hampp_core::{hexfmt, verify_signature, PublicKey, Signer};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CAP_PROFILE_LITE: u8 = 1;
pub const CAP_PROFILE_FULL: u8 = 2;
pub const CAP_VERIFY_ONLY: u8 = 3;
pub const CAP_VISIBLE_FALLBACK: u8 = 4;

const LABEL_A: &[u8] = b"HAMPP/1 hs A";
const LABEL_B: &[u8] = b"HAMPP/1 hs B";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub tag: u8,
    pub critical: bool,
    #[serde(with = "hexfmt")]
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Supported {
    pub versions: Vec<u8>,
    pub suites: Vec<u8>,
    /// Capability tags this implementation understands.
    pub known_caps: Vec<u8>,
}

impl Supported {
    pub fn v1() -> Self {
        Supported {
            versions: vec![1],
            suites: vec![1],
            known_caps: Self::all_caps(),
        }
    }

    /// What a party with this key can offer: exactly the suite of its key (one key, one suite).
    pub fn for_signer(s: &dyn Signer) -> Self {
        Supported {
            versions: vec![1],
            suites: vec![s.suite()],
            known_caps: Self::all_caps(),
        }
    }

    fn all_caps() -> Vec<u8> {
        vec![
            CAP_PROFILE_LITE,
            CAP_PROFILE_FULL,
            CAP_VERIFY_ONLY,
            CAP_VISIBLE_FALLBACK,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub versions: Vec<u8>,
    pub suites: Vec<u8>,
    pub caps: Vec<Capability>,
    pub agent_id: String,
    #[serde(with = "hexfmt")]
    pub instance_id: [u8; 16],
    #[serde(with = "hexfmt")]
    pub public_key: PublicKey,
    #[serde(with = "hexfmt")]
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloResponse {
    pub version: u8,
    pub suite: u8,
    pub caps: Vec<Capability>,
    pub agent_id: String,
    #[serde(with = "hexfmt")]
    pub instance_id: [u8; 16],
    #[serde(with = "hexfmt")]
    pub public_key: PublicKey,
    #[serde(with = "hexfmt")]
    pub nonce: [u8; 32],
    #[serde(with = "hexfmt")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    #[serde(with = "hexfmt")]
    pub signature: [u8; 64],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HandshakeError {
    #[error("no common protocol version")]
    NoCommonVersion,
    #[error("no common signature suite")]
    NoCommonSuite,
    #[error("peer sent an unknown critical capability (tag {0})")]
    UnknownCriticalCapability(u8),
    #[error("peer chose a version or suite that was not offered")]
    NotOffered,
    #[error("signature verification failed")]
    BadSignature,
    #[error("peer public key differs from the expected key")]
    PeerKeyMismatch,
    #[error(
        "a key does not match the negotiated signature suite (both peers need a key of that suite)"
    )]
    KeyDoesNotMatchSuite,
    #[error("signing failed: {0}")]
    Signing(String),
}

pub fn random_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    n
}

fn put(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend((b.len() as u32).to_be_bytes());
    buf.extend(b);
}

fn put_caps(buf: &mut Vec<u8>, caps: &[Capability]) {
    put(buf, &(caps.len() as u32).to_be_bytes());
    for c in caps {
        put(buf, &[c.tag, c.critical as u8]);
        put(buf, &c.value);
    }
}

pub fn transcript_hash(h: &Hello, r: &HelloResponse) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend(b"HAMPP/1 transcript");
    put(&mut b, &h.versions);
    put(&mut b, &h.suites);
    put_caps(&mut b, &h.caps);
    put(&mut b, h.agent_id.as_bytes());
    put(&mut b, &h.instance_id);
    put(&mut b, h.public_key.as_bytes());
    put(&mut b, &h.nonce);
    put(&mut b, &[r.version, r.suite]);
    put_caps(&mut b, &r.caps);
    put(&mut b, r.agent_id.as_bytes());
    put(&mut b, &r.instance_id);
    put(&mut b, r.public_key.as_bytes());
    put(&mut b, &r.nonce);
    Sha256::digest(&b).into()
}

/// `pk_a || pk_b` is unambiguous because both keys belong to the negotiated suite and so have
/// the same length (32 bytes for suite 1, 33 for suite 2).
pub fn session_id(
    pk_a: &[u8],
    pk_b: &[u8],
    na: &[u8; 32],
    nb: &[u8; 32],
    version: u8,
    suite: u8,
) -> [u8; 8] {
    let mut d = Sha256::new();
    d.update(b"HAMPP/1 session");
    d.update(pk_a);
    d.update(pk_b);
    d.update(na);
    d.update(nb);
    d.update([version, suite]);
    let mut out = [0u8; 8];
    out.copy_from_slice(&d.finalize()[..8]);
    out
}

fn signed_label(label: &[u8], transcript: &[u8; 32]) -> Vec<u8> {
    [label, transcript.as_slice()].concat()
}

fn reject_unknown_critical(caps: &[Capability], known: &[u8]) -> Result<(), HandshakeError> {
    match caps.iter().find(|c| c.critical && !known.contains(&c.tag)) {
        Some(c) => Err(HandshakeError::UnknownCriticalCapability(c.tag)),
        None => Ok(()),
    }
}

pub fn make_hello(
    id: &dyn Signer,
    sup: &Supported,
    caps: Vec<Capability>,
    nonce: [u8; 32],
) -> Hello {
    Hello {
        versions: sup.versions.clone(),
        suites: sup.suites.clone(),
        caps,
        agent_id: id.agent_id().to_string(),
        instance_id: id.instance_id(),
        public_key: id.public_key(),
        nonce,
    }
}

pub fn respond(
    id: &dyn Signer,
    hello: &Hello,
    sup: &Supported,
    caps: Vec<Capability>,
    nonce: [u8; 32],
) -> Result<HelloResponse, HandshakeError> {
    reject_unknown_critical(&hello.caps, &sup.known_caps)?;
    let version = hello
        .versions
        .iter()
        .filter(|v| sup.versions.contains(v))
        .max()
        .copied()
        .ok_or(HandshakeError::NoCommonVersion)?;
    let suite = hello
        .suites
        .iter()
        .filter(|s| sup.suites.contains(s))
        .max()
        .copied()
        .ok_or(HandshakeError::NoCommonSuite)?;
    // one key per party: both keys must belong to the chosen suite
    if id.suite() != suite || hello.public_key.suite() != suite {
        return Err(HandshakeError::KeyDoesNotMatchSuite);
    }
    let mut resp = HelloResponse {
        version,
        suite,
        caps,
        agent_id: id.agent_id().to_string(),
        instance_id: id.instance_id(),
        public_key: id.public_key(),
        nonce,
        signature: [0; 64],
    };
    resp.signature = id
        .sign(&signed_label(LABEL_B, &transcript_hash(hello, &resp)))
        .map_err(|e| HandshakeError::Signing(e.to_string()))?;
    Ok(resp)
}

/// Initiator: verify B, sign the transcript as A. `expected_peer` pins B's key.
pub fn initiate_finish(
    id: &dyn Signer,
    hello: &Hello,
    resp: &HelloResponse,
    expected_peer: Option<PublicKey>,
) -> Result<(AuthResponse, Session), HandshakeError> {
    if !hello.versions.contains(&resp.version) || !hello.suites.contains(&resp.suite) {
        return Err(HandshakeError::NotOffered);
    }
    if let Some(pk) = expected_peer {
        if pk != resp.public_key {
            return Err(HandshakeError::PeerKeyMismatch);
        }
    }
    if id.suite() != resp.suite || resp.public_key.suite() != resp.suite {
        return Err(HandshakeError::KeyDoesNotMatchSuite);
    }
    let t = transcript_hash(hello, resp);
    if !verify_signature(
        &resp.public_key,
        &signed_label(LABEL_B, &t),
        &resp.signature,
    ) {
        return Err(HandshakeError::BadSignature);
    }
    let auth = AuthResponse {
        signature: id
            .sign(&signed_label(LABEL_A, &t))
            .map_err(|e| HandshakeError::Signing(e.to_string()))?,
    };
    let sid = session_id(
        hello.public_key.as_bytes(),
        resp.public_key.as_bytes(),
        &hello.nonce,
        &resp.nonce,
        resp.version,
        resp.suite,
    );
    Ok((
        auth,
        Session::new(sid, resp.public_key.clone(), resp.version, resp.suite),
    ))
}

/// Responder: verify A's signature over the transcript and open the session.
pub fn accept_auth(
    hello: &Hello,
    resp: &HelloResponse,
    auth: &AuthResponse,
) -> Result<Session, HandshakeError> {
    if hello.public_key.suite() != resp.suite || resp.public_key.suite() != resp.suite {
        return Err(HandshakeError::KeyDoesNotMatchSuite);
    }
    let t = transcript_hash(hello, resp);
    if !verify_signature(
        &hello.public_key,
        &signed_label(LABEL_A, &t),
        &auth.signature,
    ) {
        return Err(HandshakeError::BadSignature);
    }
    let sid = session_id(
        hello.public_key.as_bytes(),
        resp.public_key.as_bytes(),
        &hello.nonce,
        &resp.nonce,
        resp.version,
        resp.suite,
    );
    Ok(Session::new(
        sid,
        hello.public_key.clone(),
        resp.version,
        resp.suite,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hampp_core::SigningIdentity;

    fn alice() -> SigningIdentity {
        SigningIdentity::from_seed("alice", [1; 32], [1; 16])
    }
    fn bob() -> SigningIdentity {
        SigningIdentity::from_seed("bob", [2; 32], [2; 16])
    }
    fn mallory() -> SigningIdentity {
        SigningIdentity::from_seed("mallory", [3; 32], [3; 16])
    }

    fn setup() -> (Hello, HelloResponse) {
        let sup = Supported::v1();
        let hello = make_hello(&alice(), &sup, vec![], [0xAA; 32]);
        let resp = respond(&bob(), &hello, &sup, vec![], [0xBB; 32]).unwrap();
        (hello, resp)
    }

    #[test]
    fn reflected_signature_is_rejected_as_auth() {
        let (hello, resp) = setup();
        let bad = AuthResponse {
            signature: resp.signature,
        }; // B's signature replayed as A's
        assert!(matches!(
            accept_auth(&hello, &resp, &bad),
            Err(HandshakeError::BadSignature)
        ));
    }

    #[test]
    fn downgrade_by_editing_the_response_breaks_the_transcript() {
        let sup = Supported {
            versions: vec![1],
            suites: vec![1, 2],
            known_caps: vec![],
        };
        let hello = make_hello(&alice(), &sup, vec![], [0xAA; 32]);
        let mut resp = respond(&bob(), &hello, &Supported::v1(), vec![], [0xBB; 32]).unwrap();
        resp.suite = 2; // attacker rewrites the chosen suite
        assert!(initiate_finish(&alice(), &hello, &resp, None).is_err());
    }

    #[test]
    fn response_with_a_suite_that_was_not_offered_is_rejected() {
        let (hello, mut resp) = setup();
        resp.suite = 77;
        assert!(matches!(
            initiate_finish(&alice(), &hello, &resp, None),
            Err(HandshakeError::NotOffered)
        ));
    }

    #[test]
    fn man_in_the_middle_with_other_key_is_detected_by_pinning() {
        let sup = Supported::v1();
        let hello = make_hello(&alice(), &sup, vec![], [0xAA; 32]);
        let resp = respond(&mallory(), &hello, &sup, vec![], [0xBB; 32]).unwrap();
        // without pinning the handshake succeeds (authenticates *some* key) ...
        assert!(initiate_finish(&alice(), &hello, &resp, None).is_ok());
        // ... with the expected peer key it must fail
        assert!(matches!(
            initiate_finish(
                &alice(),
                &hello,
                &resp,
                Some(bob().identity.public_key.into())
            ),
            Err(HandshakeError::PeerKeyMismatch)
        ));
    }

    #[test]
    fn unknown_critical_capability_aborts_but_unknown_optional_is_ignored() {
        let sup = Supported::v1();
        let crit = Capability {
            tag: 200,
            critical: true,
            value: vec![],
        };
        let opt = Capability {
            tag: 201,
            critical: false,
            value: vec![],
        };
        let hello = make_hello(&alice(), &sup, vec![opt.clone()], [0xAA; 32]);
        assert!(respond(&bob(), &hello, &sup, vec![], [0xBB; 32]).is_ok());
        let hello = make_hello(&alice(), &sup, vec![crit], [0xAA; 32]);
        assert!(matches!(
            respond(&bob(), &hello, &sup, vec![], [0xBB; 32]),
            Err(HandshakeError::UnknownCriticalCapability(200))
        ));
    }

    #[test]
    fn no_common_version_or_suite_is_an_error() {
        let hello = make_hello(
            &alice(),
            &Supported {
                versions: vec![9],
                suites: vec![1],
                known_caps: vec![],
            },
            vec![],
            [0xAA; 32],
        );
        assert!(matches!(
            respond(&bob(), &hello, &Supported::v1(), vec![], [0xBB; 32]),
            Err(HandshakeError::NoCommonVersion)
        ));
        let hello = make_hello(
            &alice(),
            &Supported {
                versions: vec![1],
                suites: vec![9],
                known_caps: vec![],
            },
            vec![],
            [0xAA; 32],
        );
        assert!(matches!(
            respond(&bob(), &hello, &Supported::v1(), vec![], [0xBB; 32]),
            Err(HandshakeError::NoCommonSuite)
        ));
    }

    #[test]
    fn highest_common_version_is_chosen() {
        let a = Supported {
            versions: vec![1, 2],
            suites: vec![1],
            known_caps: vec![],
        };
        let b = Supported {
            versions: vec![1, 2, 3],
            suites: vec![1],
            known_caps: vec![],
        };
        let hello = make_hello(&alice(), &a, vec![], [0xAA; 32]);
        let resp = respond(&bob(), &hello, &b, vec![], [0xBB; 32]).unwrap();
        assert_eq!(resp.version, 2);
    }

    #[test]
    fn hello_json_roundtrip() {
        let (hello, resp) = setup();
        let h2: Hello = serde_json::from_str(&serde_json::to_string(&hello).unwrap()).unwrap();
        let r2: HelloResponse =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(transcript_hash(&hello, &resp), transcript_hash(&h2, &r2));
    }
}
