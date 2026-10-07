//! Tests against a software TPM (`swtpm`), which needs no root and no hardware. Every test starts
//! its own swtpm (own state directory and ports). Skipped when `swtpm` is not installed.
use hampp_core::*;
use hampp_tpm::{probe, TpmError, TpmSigner};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

struct Swtpm {
    pid_file: std::path::PathBuf,
    _dir: tempfile::TempDir,
    tcti: String,
}

/// The swtpm TCTI talks to `port` and to the control channel on `port + 1`.
fn free_port_pair() -> u16 {
    loop {
        let a = free_port();
        if a < u16::MAX && TcpListener::bind(("127.0.0.1", a + 1)).is_ok() {
            return a;
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Swtpm {
    fn start() -> Option<Swtpm> {
        if Command::new("swtpm").arg("--version").output().is_err() {
            eprintln!("skipped: swtpm not found");
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let (port, ctrl) = {
            let p = free_port_pair();
            (p, p + 1)
        };
        let pid_file = dir.path().join("pid");
        let status = Command::new("swtpm")
            .args(["socket", "--tpm2", "--tpmstate"])
            .arg(format!("dir={}", dir.path().display()))
            .arg("--server")
            .arg(format!("type=tcp,port={port}"))
            .arg("--ctrl")
            .arg(format!("type=tcp,port={ctrl}"))
            .args([
                "--flags",
                "not-need-init,startup-clear",
                "--daemon",
                "--pid",
            ])
            .arg(format!("file={}", pid_file.display()))
            .status()
            .unwrap();
        assert!(status.success(), "swtpm failed to start");
        let t = Instant::now();
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                t.elapsed() < Duration::from_secs(10),
                "swtpm did not come up"
            );
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
            let _ = Command::new("kill").arg(pid.trim()).status();
        }
    }
}

const NOW: u64 = 1_791_000_000;

fn bound_params() -> SignParams {
    SignParams::lite(NOW).with_protection(Protection::Bound)
}

#[test]
fn create_sign_verify_roundtrip_with_protection_bound() {
    let Some(tpm) = Swtpm::start() else { return };
    let (signer, _file) = TpmSigner::create("tpm-agent", Some(&tpm.tcti)).unwrap();
    assert_eq!(signer.level(), Protection::Bound);
    assert_eq!(signer.suite(), SUITE_ECDSA_P256_SHA256);
    // 24 signatures: about half come out of the TPM with a high s, all must verify (low-s enforced)
    for i in 0..24 {
        let text = format!("Nachricht {i}");
        let msg = try_sign_text(&signer, &text, &bound_params(), Carrier::ZeroWidth).unwrap();
        let v = verify_text(&msg, &SingleKey(signer.public_key()), NOW);
        assert_eq!(v.code(), "authenticated:signed-by-agent", "message {i}");
        let h = v.header.unwrap();
        assert_eq!(h.protection(), Protection::Bound);
        assert_eq!(h.suite, 2);
        assert!(v.protection.unwrap().claimed);
    }
}

#[test]
fn key_file_roundtrip_gives_the_same_key_and_still_signs() {
    let Some(tpm) = Swtpm::start() else { return };
    let (a, file) = TpmSigner::create("tpm-agent", Some(&tpm.tcti)).unwrap();
    let json = serde_json::to_string(&file).unwrap();
    assert!(!json.contains("secret"), "a TPM key file holds no secret");
    let back = TpmSigner::load(&serde_json::from_str(&json).unwrap(), Some(&tpm.tcti)).unwrap();
    assert_eq!(a.public_key(), back.public_key());
    let msg = try_sign_text(&back, "hi", &bound_params(), Carrier::Visible).unwrap();
    assert_eq!(
        verify_text(&msg, &SingleKey(a.public_key()), NOW).code(),
        "authenticated:signed-by-agent"
    );
}

#[test]
fn no_fallback_when_the_tpm_is_unreachable() {
    let Some(tpm) = Swtpm::start() else { return };
    let (signer, file) = TpmSigner::create("tpm-agent", Some(&tpm.tcti)).unwrap();
    let dead = format!("swtpm:host=127.0.0.1,port={}", free_port());
    assert!(matches!(
        TpmSigner::create("x", Some(&dead)),
        Err(TpmError::Unavailable(_))
    ));
    assert!(matches!(
        TpmSigner::load(&file, Some(&dead)),
        Err(TpmError::Unavailable(_))
    ));
    assert!(probe(Some(&dead)).is_err());
    assert!(probe(Some(&tpm.tcti)).is_ok());
    // a signer whose TPM went away fails; it does not sign with anything else
    drop(tpm);
    let err = try_sign_text(&signer, "hi", &bound_params(), Carrier::ZeroWidth).unwrap_err();
    assert!(matches!(err, SignError::Backend(_)), "{err}");
}

#[test]
fn key_blob_from_another_tpm_is_not_loadable() {
    let (Some(a), Some(b)) = (Swtpm::start(), Swtpm::start()) else {
        return;
    };
    let (_s, file) = TpmSigner::create("tpm-agent", Some(&a.tcti)).unwrap();
    let err = TpmSigner::load(&file, Some(&b.tcti))
        .err()
        .expect("must not load");
    assert!(matches!(err, TpmError::NotLoadable(_)), "{err}");
}

fn tpm2_getcap(tcti: &str, what: &str) -> Option<String> {
    let out = Command::new("tpm2_getcap")
        .arg(what)
        .env("TPM2TOOLS_TCTI", tcti)
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

#[test]
fn no_transient_handles_left_and_persistent_handles_untouched() {
    let Some(tpm) = Swtpm::start() else { return };
    let Some(persistent_before) = tpm2_getcap(&tpm.tcti, "handles-persistent") else {
        eprintln!("skipped: tpm2_getcap not found");
        return;
    };
    let (signer, file) = TpmSigner::create("tpm-agent", Some(&tpm.tcti)).unwrap();
    for i in 0..20 {
        try_sign_text(
            &signer,
            &format!("m{i}"),
            &bound_params(),
            Carrier::ZeroWidth,
        )
        .unwrap();
    }
    TpmSigner::load(&file, Some(&tpm.tcti)).unwrap();
    assert_eq!(
        tpm2_getcap(&tpm.tcti, "handles-transient").unwrap().trim(),
        ""
    );
    assert_eq!(
        tpm2_getcap(&tpm.tcti, "handles-persistent").unwrap(),
        persistent_before
    );
}
