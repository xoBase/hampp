//! Smoke test against the machine's real TPM (`/dev/tpmrm0`). Not run by default: it needs
//! access to the device (group `tss` or an ACL).
//!
//!     cargo test -p hampp-tpm --test real_tpm -- --ignored --nocapture
//!
//! It creates one transient key, signs with it, and checks that afterwards no transient handle is
//! left and the set of persistent handles is exactly what it was before.
use hampp_core::*;
use hampp_tpm::{probe, TpmSigner};
use std::process::Command;

fn handles(kind: &str) -> String {
    let out = Command::new("tpm2_getcap")
        .arg(kind)
        .output()
        .expect("tpm2_getcap (tpm2-tools) is needed for this test");
    assert!(
        out.status.success(),
        "tpm2_getcap {kind}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
#[ignore = "needs access to the real TPM"]
fn real_tpm_creates_signs_and_leaves_no_handles_behind() {
    probe(None).expect("a real TPM is reachable");
    let (persistent, transient) = (handles("handles-persistent"), handles("handles-transient"));

    let (signer, file) = TpmSigner::create("real-tpm-smoke", None).unwrap();
    assert!(!serde_json::to_string(&file).unwrap().contains("secret"));
    let params = SignParams::lite(1_791_000_000).with_protection(Protection::Bound);
    for i in 0..6 {
        let msg =
            try_sign_text(&signer, &format!("smoke {i}"), &params, Carrier::ZeroWidth).unwrap();
        let v = verify_text(&msg, &SingleKey(signer.public_key()), 1_791_000_000);
        assert_eq!(v.code(), "authenticated:signed-by-agent", "message {i}");
        assert_eq!(v.header.unwrap().protection(), Protection::Bound);
    }
    // the key file loads again on the same TPM
    let again = TpmSigner::load(&file, None).unwrap();
    assert_eq!(again.public_key(), signer.public_key());

    assert_eq!(
        handles("handles-persistent"),
        persistent,
        "persistent handles changed"
    );
    assert_eq!(
        handles("handles-transient"),
        transient,
        "transient handles left behind"
    );
    eprintln!(
        "real TPM ok: key id {}",
        hex::encode(signer.public_key().key_id())
    );
}
