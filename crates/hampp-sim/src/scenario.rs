use crate::channel;
use hampp_core::{sign_text, verify_text, Carrier, SignParams, SigningIdentity, SingleKey};
use hampp_session::{accept_auth, initiate_finish, make_hello, respond, Session, Supported};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct AgentDef {
    pub name: String,
}

fn default_kind() -> String {
    "send".into()
}

/// Step kinds: `send` (sign, deliver unless `hold`), `deliver` (deliver the signed
/// message of step `of` again or late), `inject` (the agent `from` signs with its
/// own key and delivers into the session of the peer named in `claim`).
#[derive(Debug, Deserialize)]
pub struct Step {
    #[serde(default = "default_kind")]
    pub kind: String,
    pub from: String,
    #[serde(default)]
    pub to: String,
    pub text: Option<String>,
    #[serde(default)]
    pub via: Vec<String>,
    #[serde(default)]
    pub hold: bool,
    pub of: Option<usize>,
    /// `lite` = sessionless signing, no handshake.
    pub mode: Option<String>,
    pub claim: Option<String>,
    pub expect: String,
}

#[derive(Debug, Deserialize)]
pub struct Scenario {
    pub name: String,
    pub agents: Vec<AgentDef>,
    pub steps: Vec<Step>,
}

#[derive(Debug)]
pub enum SimError {
    Parse(String),
    Config(String),
    Mismatch {
        step: usize,
        expected: String,
        got: String,
    },
}

pub fn load(path: &Path) -> Result<Scenario, SimError> {
    let s = std::fs::read_to_string(path).map_err(|e| SimError::Parse(e.to_string()))?;
    toml::from_str(&s).map_err(|e| SimError::Parse(e.to_string()))
}

const BASE_TIME: u64 = 1_791_000_000;

fn seed(name: &str, domain: &str) -> [u8; 32] {
    Sha256::digest(format!("hampp-sim/{domain}/{name}")).into()
}

/// Deterministic identity per agent name.
fn identity_of(name: &str) -> SigningIdentity {
    let mut instance = [0u8; 16];
    instance.copy_from_slice(&seed(name, "instance")[..16]);
    SigningIdentity::from_seed(name, seed(name, "key"), instance)
}

/// A signed message waiting for (or already given) delivery.
#[derive(Clone)]
struct Sent {
    to: String,
    claimed: String,
    signed: String,
    lite: bool,
}

#[derive(Default)]
struct World {
    /// sessions[agent][peer]
    sessions: HashMap<String, HashMap<String, Session>>,
}

impl World {
    fn ensure_session(&mut self, a: &str, b: &str) -> Result<(), SimError> {
        if self.sessions.get(a).is_some_and(|m| m.contains_key(b)) {
            return Ok(());
        }
        let (ia, ib) = (identity_of(a), identity_of(b));
        let sup = Supported::v1();
        let pair = format!("{a}->{b}");
        let hello = make_hello(&ia, &sup, vec![], seed(&pair, "nonce-a"));
        let resp = respond(&ib, &hello, &sup, vec![], seed(&pair, "nonce-b"))
            .map_err(|e| SimError::Config(e.to_string()))?;
        let (auth, sa) = initiate_finish(&ia, &hello, &resp, None)
            .map_err(|e| SimError::Config(e.to_string()))?;
        let sb = accept_auth(&hello, &resp, &auth).map_err(|e| SimError::Config(e.to_string()))?;
        self.sessions
            .entry(a.into())
            .or_default()
            .insert(b.into(), sa);
        self.sessions
            .entry(b.into())
            .or_default()
            .insert(a.into(), sb);
        Ok(())
    }

    fn session_mut(&mut self, agent: &str, peer: &str) -> &mut Session {
        self.sessions
            .get_mut(agent)
            .and_then(|m| m.get_mut(peer))
            .expect("session was ensured")
    }
}

fn check(step: usize, got: &str, expected: &str) -> Result<(), SimError> {
    if got == expected {
        Ok(())
    } else {
        Err(SimError::Mismatch {
            step,
            expected: expected.into(),
            got: got.into(),
        })
    }
}

fn need(names: &HashSet<&str>, n: &str, step: usize) -> Result<(), SimError> {
    if names.contains(n) {
        Ok(())
    } else {
        Err(SimError::Config(format!(
            "step {step}: unknown agent '{n}'"
        )))
    }
}

fn sign_step(w: &mut World, st: &Step, i: usize, now: u64) -> Result<Sent, SimError> {
    let text = st
        .text
        .clone()
        .ok_or_else(|| SimError::Config(format!("step {i}: text missing")))?;
    let lite = st.mode.as_deref() == Some("lite");
    let claimed = st.claim.clone().unwrap_or_else(|| st.from.clone());
    let signer = identity_of(&st.from);
    let signed = if lite {
        sign_text(&signer, &text, &SignParams::lite(now), Carrier::ZeroWidth)
    } else if st.kind == "inject" {
        // Impersonation: signed with the injector's own key, but inside the session id
        // that the receiver shares with the claimed peer.
        w.ensure_session(&claimed, &st.to)?;
        let sid = w.session_mut(&st.to, &claimed).id;
        Session::new(sid, [0; 32], 1, 1).sign_next(&signer, &text, now, Carrier::ZeroWidth)
    } else {
        w.ensure_session(&st.from, &st.to)?;
        w.session_mut(&st.from, &st.to)
            .sign_next(&signer, &text, now, Carrier::ZeroWidth)
    };
    Ok(Sent {
        to: st.to.clone(),
        claimed,
        signed,
        lite,
    })
}

/// Runs a scenario and returns the verdict code of every step (`-` for held steps).
/// The first step whose verdict differs from `expect` aborts with `Mismatch`.
pub fn run(s: &Scenario) -> Result<Vec<String>, SimError> {
    let names: HashSet<&str> = s.agents.iter().map(|a| a.name.as_str()).collect();
    let mut w = World::default();
    let mut sent: HashMap<usize, Sent> = HashMap::new();
    let mut results = Vec::new();

    for (i, st) in s.steps.iter().enumerate() {
        let now = BASE_TIME + i as u64;
        need(&names, &st.from, i)?;
        let msg = match st.kind.as_str() {
            "send" | "inject" => {
                need(&names, &st.to, i)?;
                if let Some(c) = &st.claim {
                    need(&names, c, i)?;
                }
                let m = sign_step(&mut w, st, i, now)?;
                sent.insert(i, m.clone());
                if st.hold {
                    check(i, "-", &st.expect)?;
                    results.push("-".to_string());
                    continue;
                }
                m
            }
            "deliver" => {
                let of = st
                    .of
                    .ok_or_else(|| SimError::Config(format!("step {i}: 'of' missing")))?;
                sent.get(&of)
                    .cloned()
                    .ok_or_else(|| SimError::Config(format!("step {i}: step {of} sent nothing")))?
            }
            other => {
                return Err(SimError::Config(format!(
                    "step {i}: unknown kind '{other}'"
                )))
            }
        };
        let mut text = msg.signed.clone();
        for t in &st.via {
            text = channel::apply(t, &text).map_err(SimError::Config)?;
        }
        let code = if msg.lite {
            verify_text(
                &text,
                &SingleKey(identity_of(&msg.claimed).identity.public_key.into()),
                now,
            )
            .code()
        } else {
            w.ensure_session(&msg.to, &msg.claimed)?;
            w.session_mut(&msg.to, &msg.claimed)
                .verify_next(&text, now)
                .code()
        };
        check(i, &code, &st.expect)?;
        results.push(code);
    }
    Ok(results)
}
