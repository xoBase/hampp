//! CLI flow with a TPM-backed key, against swtpm. Only built with `--features tpm`; skipped when
//! `swtpm` is not installed.
#![cfg(feature = "tpm")]
use assert_cmd::Command;
use std::net::{TcpListener, TcpStream};
use std::process::Command as Proc;
use std::time::{Duration, Instant};

struct Swtpm {
    pid_file: std::path::PathBuf,
    _dir: tempfile::TempDir,
    tcti: String,
}

fn free_pair() -> u16 {
    loop {
        let a = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if a < u16::MAX && TcpListener::bind(("127.0.0.1", a + 1)).is_ok() {
            return a;
        }
    }
}

impl Swtpm {
    fn start() -> Option<Swtpm> {
        if Proc::new("swtpm").arg("--version").output().is_err() {
            eprintln!("skipped: swtpm not found");
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let port = free_pair();
        let pid_file = dir.path().join("pid");
        assert!(Proc::new("swtpm")
            .args(["socket", "--tpm2", "--tpmstate"])
            .arg(format!("dir={}", dir.path().display()))
            .arg("--server")
            .arg(format!("type=tcp,port={port}"))
            .arg("--ctrl")
            .arg(format!("type=tcp,port={}", port + 1))
            .args([
                "--flags",
                "not-need-init,startup-clear",
                "--daemon",
                "--pid"
            ])
            .arg(format!("file={}", pid_file.display()))
            .status()
            .unwrap()
            .success());
        let t = Instant::now();
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(t.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(50));
        }
        Some(Swtpm {
            pid_file,
            _dir: dir,
            tcti: format!("swtpm:host=127.0.0.1,port={port}"),
        })
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        if let Ok(pid) = std::fs::read_to_string(&self.pid_file) {
            let _ = Proc::new("kill").arg(pid.trim()).status();
        }
    }
}

fn hampp(tcti: &str) -> Command {
    let mut c = Command::cargo_bin("hampp").unwrap();
    c.env("HAMPP_NOW", "1791000000").env("HAMPP_TCTI", tcti);
    c
}

#[test]
fn bound_key_signs_at_protection_bound_and_the_receiver_can_require_it() {
    let Some(tpm) = Swtpm::start() else { return };
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("t.json").display().to_string();
    hampp(&tpm.tcti)
        .args([
            "keygen",
            "--agent",
            "tpm-agent",
            "--key",
            &key,
            "--protection",
            "bound",
        ])
        .assert()
        .success();
    let id = hampp(&tpm.tcti)
        .args(["identity", "--key", &key, "--json"])
        .output()
        .unwrap();
    assert!(
        id.status.success(),
        "{}",
        String::from_utf8_lossy(&id.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&id.stdout).unwrap();
    assert_eq!(v["key_protection"], "tpm");
    assert_eq!(v["max_protection"], "bound");
    assert_eq!(v["attestation"], "none");
    assert_eq!(v["suite"], 2);
    let public = v["public_key"].as_str().unwrap().to_string();
    let file = std::fs::read_to_string(&key).unwrap();
    assert!(!file.contains("secret"));

    // default protection = the key's own level
    let out = hampp(&tpm.tcti)
        .args(["sign", "--key", &key])
        .write_stdin("Deploy freigegeben")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let msg = String::from_utf8(out.stdout).unwrap();
    hampp(&tpm.tcti)
        .args(["verify", "--pubkey", &public, "--min-protection", "bound"])
        .write_stdin(msg.clone())
        .assert()
        .code(0)
        .stdout(predicates::str::contains(
            "HARDWARE_BOUND (claimed, not verified)",
        ));
    hampp(&tpm.tcti)
        .args([
            "verify",
            "--pubkey",
            &public,
            "--min-protection",
            "attested",
        ])
        .write_stdin(msg)
        .assert()
        .code(10)
        .stdout(predicates::str::contains("protection-too-low"));
    // the agent may choose less than the key offers
    let low = hampp(&tpm.tcti)
        .args(["sign", "--key", &key, "--protection", "software"])
        .write_stdin("Routine")
        .output()
        .unwrap();
    hampp(&tpm.tcti)
        .args(["verify", "--pubkey", &public, "--min-protection", "bound"])
        .write_stdin(low.stdout)
        .assert()
        .code(10);
}

#[test]
fn capabilities_reports_bound_as_available_when_a_tpm_answers() {
    let Some(tpm) = Swtpm::start() else { return };
    let out = hampp(&tpm.tcti)
        .args(["capabilities", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["protection"]["bound"]["available"], true);
    assert_eq!(v["protection"]["attested"]["available"], false);
    assert_eq!(v["key_protection"], serde_json::json!(["software", "tpm"]));
}

#[test]
fn unreachable_tpm_fails_without_output_and_without_a_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let dead = format!("swtpm:host=127.0.0.1,port={}", free_pair());
    let key = dir.path().join("t.json");
    hampp(&dead)
        .args([
            "keygen",
            "--agent",
            "a",
            "--key",
            &key.display().to_string(),
            "--protection",
            "bound",
        ])
        .assert()
        .code(2);
    assert!(!key.exists(), "no key file may be left behind");
    let caps = hampp(&dead)
        .args(["capabilities", "--json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&caps.stdout).unwrap();
    assert_eq!(v["protection"]["bound"]["available"], false);
    assert!(v["protection"]["bound"]["reason"]
        .as_str()
        .unwrap()
        .contains("TPM"));
}

#[test]
fn a_tpm_key_that_lost_its_tpm_never_signs() {
    let Some(tpm) = Swtpm::start() else { return };
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("t.json").display().to_string();
    hampp(&tpm.tcti)
        .args([
            "keygen",
            "--agent",
            "a",
            "--key",
            &key,
            "--protection",
            "bound",
        ])
        .assert()
        .success();
    let dead = format!("swtpm:host=127.0.0.1,port={}", free_pair());
    hampp(&dead)
        .args(["sign", "--key", &key])
        .write_stdin("hi")
        .assert()
        .code(2)
        .stdout("");
}
