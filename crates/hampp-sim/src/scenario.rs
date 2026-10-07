use crate::channel;
use hampp_core::{
    try_sign_text, verify_text, Carrier, P256Software, Protection, SignError, SignParams, Signer,
    SigningIdentity, SingleKey,
};
use hampp_session::{accept_auth, initiate_finish, make_hello, respond, Session, Supported};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// An agent and its key. `key` is `ed25519` (default, always protection `software`) or
/// `ecdsa-p256`; `level` is the highest protection that key may claim (`software` by default).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDef {
    pub name: String,
    pub key: Option<String>,
    pub level: Option<String>,
}

fn default_kind() -> String {
    "send".into()
}

/// Step kinds: `send` (sign, deliver unless `hold`), `deliver` (deliver the signed
/// message of step `of` again or late), `inject` (the agent `from` signs with its
/// own key and delivers into the session of the peer named in `claim`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Protection level the sender claims for this message (default `software`).
    pub protection: Option<String>,
    /// Receiver policy: minimum effective protection it requires.
    pub min_protection: Option<String>,
    pub expect: String,
    /// Effective protection level the receiver should see (checked when set).
    pub expect_level: Option<String>,
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

type Signers = HashMap<String, Box<dyn Signer>>;

fn level_of(s: &str, what: &str) -> Result<Protection, SimError> {
    Protection::parse(s).ok_or_else(|| SimError::Config(format!("{what}: unknown level '{s}'")))
}

/// Deterministic key per agent name, of the type the scenario asks for.
fn signer_of(def: &AgentDef) -> Result<Box<dyn Signer>, SimError> {
    let name = def.name.as_str();
    let mut instance = [0u8; 16];
    instance.copy_from_slice(&seed(name, "instance")[..16]);
    let level = match &def.level {
        Some(l) => level_of(l, &format!("agent '{name}'"))?,
        None => Protection::Software,
    };
    match def.key.as_deref() {
        None | Some("ed25519") => {
            if level != Protection::Software {
                return Err(SimError::Config(format!(
                    "agent '{name}': an Ed25519 key is software only"
                )));
            }
            Ok(Box::new(SigningIdentity::from_seed(
                name,
                seed(name, "key"),
                instance,
            )))
        }
        Some("ecdsa-p256") => {
            let key = P256Software::from_scalar(name, seed(name, "key"), instance)
                .map_err(SimError::Config)?;
            Ok(Box::new(key.claim_level_for_tests(level)))
        }
        Some(other) => Err(SimError::Config(format!(
            "agent '{name}': unknown key type '{other}'"
        ))),
    }
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
    fn ensure_session(&mut self, signers: &Signers, a: &str, b: &str) -> Result<(), SimError> {
        if self.sessions.get(a).is_some_and(|m| m.contains_key(b)) {
            return Ok(());
        }
        let (ia, ib) = (signers[a].as_ref(), signers[b].as_ref());
        let pair = format!("{a}->{b}");
        let hello = make_hello(
            ia,
            &Supported::for_signer(ia),
            vec![],
            seed(&pair, "nonce-a"),
        );
        let resp = respond(
            ib,
            &hello,
            &Supported::for_signer(ib),
            vec![],
            seed(&pair, "nonce-b"),
        )
        .map_err(|e| SimError::Config(e.to_string()))?;
        let (auth, sa) = initiate_finish(ia, &hello, &resp, None)
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

/// Outcome of a signing step: a message, or the signer's refusal (e.g. a level it does not have).
enum Signed {
    Sent(Sent),
    Refused(SignError),
}

fn sign_step(
    w: &mut World,
    signers: &Signers,
    st: &Step,
    i: usize,
    now: u64,
) -> Result<Signed, SimError> {
    let text = st
        .text
        .clone()
        .ok_or_else(|| SimError::Config(format!("step {i}: text missing")))?;
    let lite = st.mode.as_deref() == Some("lite");
    let claimed = st.claim.clone().unwrap_or_else(|| st.from.clone());
    let signer = signers[&st.from].as_ref();
    let protection = match &st.protection {
        Some(p) => level_of(p, &format!("step {i}"))?,
        None => Protection::Software,
    };
    let signed = if lite {
        let params = SignParams::lite(now).with_protection(protection);
        try_sign_text(signer, &text, &params, Carrier::ZeroWidth)
    } else if st.kind == "inject" {
        // Impersonation: signed with the injector's own key, but inside the session id
        // that the receiver shares with the claimed peer.
        w.ensure_session(signers, &claimed, &st.to)?;
        let sid = w.session_mut(&st.to, &claimed).id;
        Session::new(sid, [0u8; 32].into(), 1, signer.suite()).try_sign_next(
            signer,
            &text,
            now,
            Carrier::ZeroWidth,
            protection,
        )
    } else {
        w.ensure_session(signers, &st.from, &st.to)?;
        w.session_mut(&st.from, &st.to).try_sign_next(
            signer,
            &text,
            now,
            Carrier::ZeroWidth,
            protection,
        )
    };
    Ok(match signed {
        Ok(signed) => Signed::Sent(Sent {
            to: st.to.clone(),
            claimed,
            signed,
            lite,
        }),
        Err(e) => Signed::Refused(e),
    })
}

/// Runs a scenario and returns the verdict code of every step (`-` for held steps).
/// The first step whose verdict differs from `expect` aborts with `Mismatch`.
pub fn run(s: &Scenario) -> Result<Vec<String>, SimError> {
    let names: HashSet<&str> = s.agents.iter().map(|a| a.name.as_str()).collect();
    let signers: Signers = s
        .agents
        .iter()
        .map(|a| Ok((a.name.clone(), signer_of(a)?)))
        .collect::<Result<_, SimError>>()?;
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
                let m = match sign_step(&mut w, &signers, st, i, now)? {
                    Signed::Sent(m) => m,
                    Signed::Refused(e) => {
                        // only the honest refusal counts; a backend or suite problem is a bug
                        if !matches!(e, SignError::LevelNotAvailable { .. }) {
                            return Err(SimError::Config(format!("step {i}: {e}")));
                        }
                        check(i, "sign-refused", &st.expect)?;
                        results.push("sign-refused".to_string());
                        continue;
                    }
                };
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
        let verdict = if msg.lite {
            verify_text(&text, &SingleKey(signers[&msg.claimed].public_key()), now)
        } else {
            w.ensure_session(&signers, &msg.to, &msg.claimed)?;
            w.session_mut(&msg.to, &msg.claimed).verify_next(&text, now)
        };
        let min = match &st.min_protection {
            Some(m) => Some(level_of(m, &format!("step {i}"))?),
            None => None,
        };
        let verdict = verdict.with_min_protection(min);
        let code = verdict.code();
        check(i, &code, &st.expect)?;
        if let Some(want) = &st.expect_level {
            let got = verdict.protection.map_or("none", |p| p.level.as_str());
            check(i, got, want)?;
        }
        results.push(code);
    }
    Ok(results)
}
