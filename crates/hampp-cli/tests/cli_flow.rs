use assert_cmd::Command;
use std::path::Path;

fn hampp() -> Command {
    let mut c = Command::cargo_bin("hampp").unwrap();
    c.env("HAMPP_NOW", "1791000000");
    c
}

fn keygen(dir: &Path, name: &str) -> (String, String) {
    let key = dir.join(format!("{name}.json")).display().to_string();
    hampp()
        .args(["keygen", "--agent", name, "--key", &key])
        .assert()
        .success();
    let out = hampp()
        .args(["identity", "--key", &key, "--public"])
        .output()
        .unwrap();
    (
        key,
        String::from_utf8(out.stdout).unwrap().trim().to_string(),
    )
}

fn sign(key: &str, text: &str, extra: &[&str]) -> String {
    let out = hampp()
        .args(["sign", "--key", key])
        .args(extra)
        .write_stdin(text)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn two_agents_sign_and_verify_with_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let (ka, pa) = keygen(dir.path(), "alice");
    let (_kb, pb) = keygen(dir.path(), "bob");
    let msg = sign(&ka, "Der Auftrag wurde erfolgreich ausgeführt.", &[]);

    hampp()
        .args(["verify", "--pubkey", &pa])
        .write_stdin(msg.clone())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("AUTHENTICATED"));

    // wrong key -> unverified (exit 10)
    hampp()
        .args(["verify", "--pubkey", &pb])
        .write_stdin(msg.clone())
        .assert()
        .code(10)
        .stdout(predicates::str::contains("unknown-key"));

    // tampered -> invalid (exit 20)
    hampp()
        .args(["verify", "--pubkey", &pa])
        .write_stdin(msg.replace("erfolgreich", "erfolglos"))
        .assert()
        .code(20);

    // strip -> text unchanged, then verify says unverified (exit 10)
    let stripped = hampp()
        .arg("strip")
        .write_stdin(msg.clone())
        .output()
        .unwrap()
        .stdout;
    assert_eq!(
        String::from_utf8(stripped.clone()).unwrap(),
        "Der Auftrag wurde erfolgreich ausgeführt."
    );
    hampp()
        .args(["verify", "--pubkey", &pa])
        .write_stdin(stripped)
        .assert()
        .code(10)
        .stdout(predicates::str::contains("envelope-missing"));
}

#[test]
fn json_output_and_annotate() {
    let dir = tempfile::tempdir().unwrap();
    let (ka, pa) = keygen(dir.path(), "alice");
    let msg = sign(&ka, "Hallo", &[]);
    let out = hampp()
        .args(["verify", "--pubkey", &pa, "--json"])
        .write_stdin(msg.clone())
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["code"], "authenticated:signed-by-agent");
    let ann = hampp()
        .args(["annotate", "--pubkey", &pa])
        .write_stdin(msg)
        .output()
        .unwrap();
    let text = String::from_utf8(ann.stdout).unwrap();
    assert!(text.starts_with("[HAMPP:v1 AUTHENTICATED signed-by-agent key="));
    assert!(text.trim_end().ends_with("Hallo"));
}

#[test]
fn inspect_needs_no_key_and_claims_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (ka, _) = keygen(dir.path(), "alice");
    let msg = sign(&ka, "Hallo", &[]);
    hampp()
        .arg("inspect")
        .write_stdin(msg)
        .assert()
        .code(0)
        .stdout(predicates::str::contains("Protocol:"))
        .stdout(predicates::str::contains("Protection:   SOFTWARE"))
        .stdout(predicates::str::contains("not verified"));
    hampp()
        .arg("inspect")
        .write_stdin("kein Envelope")
        .assert()
        .code(10)
        .stdout(predicates::str::contains("envelope-missing"));
}

#[test]
fn visible_fallback_carrier_works_through_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let (ka, pa) = keygen(dir.path(), "alice");
    let msg = sign(&ka, "Hallo", &["--visible"]);
    assert!(msg.contains("[hampp1:"));
    hampp()
        .args(["verify", "--pubkey", &pa])
        .write_stdin(msg)
        .assert()
        .code(0);
}

#[test]
fn keygen_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let (ka, _) = keygen(dir.path(), "alice");
    hampp()
        .args(["keygen", "--agent", "alice", "--key", &ka])
        .assert()
        .code(2);
}

#[test]
fn registry_trust_and_revoke_flow() {
    let dir = tempfile::tempdir().unwrap();
    let (ka, pa) = keygen(dir.path(), "alice");
    let reg = dir.path().join("reg.json").display().to_string();
    hampp()
        .args([
            "registry", "add", "--file", &reg, "--pubkey", &pa, "--agent", "alice", "--trust",
            "trusted",
        ])
        .assert()
        .success();
    let msg = sign(&ka, "Hallo", &[]);
    hampp()
        .args(["verify", "--registry", &reg])
        .write_stdin(msg.clone())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("alice"));
    let kid = hampp()
        .args(["registry", "list", "--file", &reg])
        .output()
        .unwrap();
    assert!(String::from_utf8(kid.stdout).unwrap().contains("TRUSTED"));
    hampp()
        .args(["registry", "revoke", "--file", &reg, "--pubkey", &pa])
        .assert()
        .success();
    hampp()
        .args(["verify", "--registry", &reg])
        .write_stdin(msg)
        .assert()
        .code(20)
        .stdout(predicates::str::contains("key-revoked"));
}

#[test]
fn handshake_over_files_then_session_messages_with_replay_protection() {
    let dir = tempfile::tempdir().unwrap();
    let (ka, _) = keygen(dir.path(), "alice");
    let (kb, _) = keygen(dir.path(), "bob");
    let p = |n: &str| dir.path().join(n).display().to_string();
    let run = |args: &[&str]| -> String {
        let out = hampp().args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    std::fs::write(p("hello.json"), run(&["handshake", "hello", "--key", &ka])).unwrap();
    std::fs::write(
        p("resp.json"),
        run(&[
            "handshake",
            "respond",
            "--key",
            &kb,
            "--hello",
            &p("hello.json"),
        ]),
    )
    .unwrap();
    std::fs::write(
        p("auth.json"),
        run(&[
            "handshake",
            "auth",
            "--key",
            &ka,
            "--hello",
            &p("hello.json"),
            "--response",
            &p("resp.json"),
            "--session-out",
            &p("a.session"),
        ]),
    )
    .unwrap();
    run(&[
        "handshake",
        "accept",
        "--hello",
        &p("hello.json"),
        "--response",
        &p("resp.json"),
        "--auth",
        &p("auth.json"),
        "--session-out",
        &p("b.session"),
    ]);

    let m1 = sign(&ka, "Hallo Bob", &["--session", &p("a.session")]);
    let v = hampp()
        .args(["verify", "--session", &p("b.session")])
        .write_stdin(m1.clone())
        .assert()
        .code(0);
    v.stdout(predicates::str::contains("registered-instance"));
    // replay of the same message: state was persisted -> invalid (exit 20)
    hampp()
        .args(["verify", "--session", &p("b.session")])
        .write_stdin(m1)
        .assert()
        .code(20)
        .stdout(predicates::str::contains("replay"));
}

#[test]
fn probe_detects_survival_and_stripping() {
    let dir = tempfile::tempdir().unwrap();
    let (ka, _) = keygen(dir.path(), "alice");
    let sent = hampp()
        .args(["probe", "generate", "--key", &ka])
        .output()
        .unwrap()
        .stdout;
    let sent_path = dir.path().join("sent.txt");
    std::fs::write(&sent_path, &sent).unwrap();
    let ok = dir.path().join("ok.txt");
    std::fs::write(&ok, &sent).unwrap();
    hampp()
        .args([
            "probe",
            "check",
            "--sent",
            sent_path.to_str().unwrap(),
            "--received",
            ok.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stdout(predicates::str::contains("SURVIVED"));
    let stripped = hampp()
        .arg("strip")
        .write_stdin(sent.clone())
        .output()
        .unwrap()
        .stdout;
    let sp = dir.path().join("stripped.txt");
    std::fs::write(&sp, stripped).unwrap();
    hampp()
        .args([
            "probe",
            "check",
            "--sent",
            sent_path.to_str().unwrap(),
            "--received",
            sp.to_str().unwrap(),
        ])
        .assert()
        .code(10)
        .stdout(predicates::str::contains("STRIPPED"));
}

#[test]
fn missing_files_are_reported_with_their_path() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nothing-here.json").display().to_string();
    for args in [
        vec!["sign", "--key", missing.as_str()],
        vec!["verify", "--session", missing.as_str()],
        vec![
            "handshake",
            "respond",
            "--key",
            missing.as_str(),
            "--hello",
            missing.as_str(),
        ],
        vec!["verify", "--pubkey-file", missing.as_str()],
        vec!["registry", "list", "--file", dir.path().to_str().unwrap()],
    ] {
        let out = hampp().args(&args).write_stdin("x").output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        let named = if args[0] == "registry" {
            dir.path().to_str().unwrap().to_string()
        } else {
            "nothing-here.json".to_string()
        };
        assert!(err.contains(&named), "{args:?}: stderr was: {err}");
    }
}

#[test]
fn session_state_files_are_written_atomically_without_leftovers() {
    let dir = tempfile::tempdir().unwrap();
    let (ka, _) = keygen(dir.path(), "alice");
    let (kb, _) = keygen(dir.path(), "bob");
    let p = |n: &str| dir.path().join(n).display().to_string();
    let run = |args: &[&str]| -> String {
        let out = hampp().args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    std::fs::write(p("hello.json"), run(&["handshake", "hello", "--key", &ka])).unwrap();
    std::fs::write(
        p("resp.json"),
        run(&[
            "handshake",
            "respond",
            "--key",
            &kb,
            "--hello",
            &p("hello.json"),
        ]),
    )
    .unwrap();
    std::fs::write(
        p("auth.json"),
        run(&[
            "handshake",
            "auth",
            "--key",
            &ka,
            "--hello",
            &p("hello.json"),
            "--response",
            &p("resp.json"),
            "--session-out",
            &p("a.session"),
        ]),
    )
    .unwrap();
    let _ = sign(&ka, "eins", &["--session", &p("a.session")]);
    let _ = sign(&ka, "zwei", &["--session", &p("a.session")]);
    let leftovers: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
    let s: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(p("a.session")).unwrap()).unwrap();
    assert_eq!(s["out_seq"], 2);
}

#[test]
fn capabilities_json_reports_software_only_build() {
    let out = hampp().args(["capabilities", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["protocol_versions"], serde_json::json!([1]));
    assert_eq!(v["suites"], serde_json::json!([1, 2]));
    // the default build has no TPM support; a build with the `tpm` feature has its own test
    if !cfg!(feature = "tpm") {
        assert_eq!(v["key_protection"], serde_json::json!(["software"]));
        assert_eq!(v["protection"]["bound"]["available"], false);
    }
    assert_eq!(v["protection"]["software"]["available"], true);
    assert_eq!(v["protection"]["attested"]["available"], false);
    assert!(v["protection"]["attested"]["reason"].is_string());
    assert_eq!(v["attestation"], serde_json::json!([]));
}

#[test]
fn identity_json_states_software_protection_and_no_attestation() {
    let dir = tempfile::tempdir().unwrap();
    let (key, public) = keygen(dir.path(), "alice");
    let out = hampp()
        .args(["identity", "--key", &key, "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["public_key"], public);
    assert_eq!(v["key_protection"], "software");
    assert_eq!(v["attestation"], "none");
    assert!(
        v.get("secret").is_none(),
        "the JSON must never contain the secret"
    );
}

#[test]
fn skill_frontmatter_is_portable_across_harnesses() {
    // name must equal the directory name; OpenClaw only parses single-line frontmatter keys.
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skills/hampp/SKILL.md");
    let s = std::fs::read_to_string(p).unwrap();
    let fm: Vec<&str> = s
        .strip_prefix("---\n")
        .and_then(|r| r.split("\n---\n").next())
        .expect("frontmatter")
        .lines()
        .collect();
    assert_eq!(fm.len(), 2, "only name and description: {fm:?}");
    assert_eq!(fm[0], "name: hampp");
    let d = fm[1].strip_prefix("description: ").expect("description");
    assert!(!d.is_empty() && d.len() <= 1024);
}

fn keygen_p256(dir: &Path, name: &str) -> (String, String) {
    let key = dir.join(format!("{name}.json")).display().to_string();
    hampp()
        .args([
            "keygen",
            "--agent",
            name,
            "--key",
            &key,
            "--alg",
            "ecdsa-p256",
        ])
        .assert()
        .success();
    let out = hampp()
        .args(["identity", "--key", &key, "--public"])
        .output()
        .unwrap();
    (
        key,
        String::from_utf8(out.stdout).unwrap().trim().to_string(),
    )
}

#[test]
fn p256_software_key_signs_and_verifies_with_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let (key, public) = keygen_p256(dir.path(), "pat");
    assert_eq!(public.len(), 66, "compressed P-256 point as hex");
    let msg = sign(&key, "hallo", &[]);
    hampp()
        .args(["verify", "--pubkey", &public, "--json"])
        .write_stdin(msg.clone())
        .assert()
        .code(0)
        .stdout(predicates::str::contains("authenticated:signed-by-agent"));
    hampp()
        .args(["verify", "--pubkey", &public])
        .write_stdin(msg.replace("hallo", "hullo"))
        .assert()
        .code(20);
    let id = hampp()
        .args(["identity", "--key", &key, "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&id.stdout).unwrap();
    assert_eq!(v["suite"], 2);
    assert_eq!(v["max_protection"], "software");
    assert_eq!(v["key_protection"], "software");
}

#[test]
fn sign_above_key_protection_fails_without_output() {
    let dir = tempfile::tempdir().unwrap();
    let (key, _) = keygen(dir.path(), "alice");
    hampp()
        .args(["sign", "--key", &key, "--protection", "bound"])
        .write_stdin("hi")
        .assert()
        .code(2)
        .stdout("")
        .stderr(predicates::str::contains("not available"));
}

#[test]
fn min_protection_gives_exit_10_and_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let (key, public) = keygen(dir.path(), "alice");
    let msg = sign(&key, "hi", &[]);
    hampp()
        .args([
            "verify",
            "--pubkey",
            &public,
            "--min-protection",
            "bound",
            "--json",
        ])
        .write_stdin(msg.clone())
        .assert()
        .code(10)
        .stdout(predicates::str::contains("unverified:protection-too-low"));
    hampp()
        .args([
            "verify",
            "--pubkey",
            &public,
            "--min-protection",
            "software",
        ])
        .write_stdin(msg)
        .assert()
        .code(0)
        .stdout(predicates::str::contains("Protection:   SOFTWARE"));
}

#[test]
fn registry_add_protection_roundtrips_and_old_registry_loads() {
    let dir = tempfile::tempdir().unwrap();
    let (_k, public) = keygen_p256(dir.path(), "pat");
    let reg = dir.path().join("reg.json").display().to_string();
    hampp()
        .args([
            "registry", "add", "--file", &reg, "--pubkey", &public, "--agent", "pat",
        ])
        .args(["--trust", "trusted", "--protection", "bound"])
        .assert()
        .success();
    hampp()
        .args(["registry", "list", "--file", &reg])
        .assert()
        .success()
        .stdout(predicates::str::contains("bound"));
    // an old-format registry (no protection field, Ed25519 key) still loads
    let old = dir.path().join("old.json");
    std::fs::write(
        &old,
        r#"{"entries":[{"agent_id":"a","instance_id":"00000000000000000000000000000000",
        "key_id":"0000000000000000","public_key":"0909090909090909090909090909090909090909090909090909090909090909",
        "trust":"TRUSTED","first_seen":1,"expires":null}]}"#,
    )
    .unwrap();
    hampp()
        .args(["registry", "list", "--file", &old.display().to_string()])
        .assert()
        .success()
        .stdout(predicates::str::ends_with("-\n"));
}

#[test]
fn registry_caps_what_a_sender_claims_in_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let (_k, public) = keygen_p256(dir.path(), "pat");
    let reg = dir.path().join("reg.json").display().to_string();
    hampp()
        .args([
            "registry", "add", "--file", &reg, "--pubkey", &public, "--agent", "pat",
        ])
        .args(["--trust", "trusted", "--protection", "software"])
        .assert()
        .success();
    // a software key can only claim software, so the cap shows as "registry-known" (not claimed)
    let key = dir.path().join("pat.json").display().to_string();
    let msg = sign(&key, "hi", &[]);
    hampp()
        .args(["verify", "--registry", &reg, "--json"])
        .write_stdin(msg)
        .assert()
        .code(0)
        .stdout(predicates::str::contains("\"protection_claimed\": false"));
}

#[test]
fn sessions_refuse_p256_keys_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let (key, _) = keygen_p256(dir.path(), "pat");
    let session = dir.path().join("s.session").display().to_string();
    hampp()
        .args(["sign", "--key", &key, "--session", &session])
        .write_stdin("hi")
        .assert()
        .code(2)
        .stderr(predicates::str::contains("Ed25519 keys only"));
}

#[test]
fn tpm_key_file_without_tpm_support_gives_a_clear_error() {
    if cfg!(feature = "tpm") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("t.json");
    std::fs::write(&key, r#"{"alg":"ecdsa-p256-tpm","agent_id":"t"}"#).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    hampp()
        .args(["sign", "--key", &key.display().to_string()])
        .write_stdin("hi")
        .assert()
        .code(2)
        .stdout("")
        .stderr(predicates::str::contains("without tpm support"));
}
