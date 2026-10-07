use hampp_sim::scenario::{load, run};
use std::path::PathBuf;

fn scenarios_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios")
}

#[test]
fn all_scenarios_pass() {
    let mut count = 0;
    for entry in std::fs::read_dir(scenarios_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let s = load(&path).unwrap();
        run(&s).unwrap_or_else(|e| panic!("scenario {} failed: {e:?}", path.display()));
        count += 1;
    }
    assert!(count >= 19, "expected at least 19 scenarios, found {count}");
}

#[test]
fn a_wrong_expectation_is_reported_as_mismatch() {
    let s: hampp_sim::scenario::Scenario = toml::from_str(
        r#"
name = "bad"
[[agents]]
name = "alice"
[[agents]]
name = "bob"
[[steps]]
from = "alice"
to = "bob"
text = "x"
expect = "invalid:replay"
"#,
    )
    .unwrap();
    assert!(matches!(
        run(&s),
        Err(hampp_sim::scenario::SimError::Mismatch { step: 0, .. })
    ));
}

#[test]
fn unknown_agent_is_a_config_error() {
    let s: hampp_sim::scenario::Scenario = toml::from_str(
        r#"
name = "bad"
[[agents]]
name = "alice"
[[steps]]
from = "alice"
to = "nobody"
text = "x"
expect = "authenticated:registered-instance"
"#,
    )
    .unwrap();
    assert!(matches!(
        run(&s),
        Err(hampp_sim::scenario::SimError::Config(_))
    ));
}

#[test]
fn a_typo_in_a_scenario_is_a_parse_error_not_a_silent_pass() {
    let bad = toml::from_str::<hampp_sim::scenario::Scenario>(
        r#"
name = "bad"
[[agents]]
name = "alice"
kye = "ecdsa-p256"
[[steps]]
from = "alice"
to = "alice"
text = "x"
expect = "authenticated:registered-instance"
"#,
    );
    assert!(bad.is_err());
}

#[test]
fn ed25519_and_p256_agents_cannot_open_a_session() {
    let s: hampp_sim::scenario::Scenario = toml::from_str(
        r#"
name = "mixed key types"
[[agents]]
name = "alice"
[[agents]]
name = "bob"
key = "ecdsa-p256"
[[steps]]
from = "alice"
to = "bob"
text = "x"
expect = "authenticated:registered-instance"
"#,
    )
    .unwrap();
    match run(&s) {
        Err(hampp_sim::scenario::SimError::Config(m)) => {
            assert!(m.contains("no common signature suite"), "{m}")
        }
        other => panic!("expected a handshake config error, got {other:?}"),
    }
}

#[test]
fn an_unknown_key_type_is_a_config_error() {
    let s: hampp_sim::scenario::Scenario = toml::from_str(
        r#"
name = "bad"
[[agents]]
name = "alice"
key = "rsa"
[[steps]]
from = "alice"
to = "alice"
text = "x"
expect = "x"
"#,
    )
    .unwrap();
    assert!(matches!(
        run(&s),
        Err(hampp_sim::scenario::SimError::Config(_))
    ));
}
