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
    assert!(count >= 12, "expected at least 12 scenarios, found {count}");
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
