use hampp_core::{
    annotate as core_annotate, key_alg, load_signer, save_p256_software, try_sign_text,
    verify_text, Carrier, FileKeyStore, KeyMeta, KeyStore, P256Software, Protection, PublicKey,
    SignParams, Signer, SigningIdentity, SingleKey, ALG_P256_TPM,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn err<E: std::fmt::Display>(e: E) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// An Ed25519 key (64 hex characters) or a compressed P-256 point (66 hex characters).
fn pubkey(h: &str) -> PyResult<PublicKey> {
    PublicKey::from_hex(h).map_err(err)
}

fn level(name: &str) -> PyResult<Protection> {
    Protection::parse(name).ok_or_else(|| {
        err(format!(
            "unknown protection '{name}' (use software, bound or attested)"
        ))
    })
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Creates a key file (never overwrites) and returns the public key as hex.
/// `alg` is `ed25519` (default) or `ecdsa-p256`; a TPM key needs the command line tool.
#[pyfunction]
#[pyo3(signature = (agent_id, path, alg="ed25519"))]
fn generate_key(agent_id: &str, path: &str, alg: &str) -> PyResult<String> {
    match alg {
        "ed25519" => {
            let id = SigningIdentity::generate(agent_id);
            FileKeyStore { path: path.into() }.save(&id).map_err(err)?;
            Ok(hex::encode(id.identity.public_key))
        }
        "ecdsa-p256" => {
            let key = P256Software::generate(agent_id);
            save_p256_software(path.as_ref(), &key).map_err(err)?;
            Ok(key.public_key().to_hex())
        }
        other => Err(err(format!(
            "unknown key algorithm '{other}' (use ed25519 or ecdsa-p256)"
        ))),
    }
}

/// Loads an Ed25519 or software P-256 key file. A TPM key is valid but belongs to the command
/// line tool, so it gets its own message instead of "invalid key file".
fn load(path: &str) -> PyResult<(Box<dyn Signer>, KeyMeta)> {
    let path = std::path::Path::new(path);
    if key_alg(path).map_err(err)? == ALG_P256_TPM {
        return Err(err(
            "this is a TPM key; Python cannot use it, use the hampp command line tool built with the `tpm` feature",
        ));
    }
    load_signer(path).map_err(err)
}

#[pyfunction]
fn public_key(path: &str) -> PyResult<String> {
    let (_, meta) = load(path)?;
    Ok(meta.public_key.to_hex())
}

/// Signs `text` in the Lite profile (one message, no session). `protection` is the level to
/// claim; by default the highest this key offers. Claiming more than the key offers is an error.
#[pyfunction]
#[pyo3(signature = (text, key_path, visible=false, protection=None))]
fn sign(text: &str, key_path: &str, visible: bool, protection: Option<&str>) -> PyResult<String> {
    let (signer, _) = load(key_path)?;
    let carrier = if visible {
        Carrier::Visible
    } else {
        Carrier::ZeroWidth
    };
    let claimed = match protection {
        Some(p) => level(p)?,
        None => signer.level(),
    };
    let params = SignParams::lite(now()).with_protection(claimed);
    try_sign_text(signer.as_ref(), text, &params, carrier).map_err(err)
}

/// Verdict as JSON. `min_protection` is a receiver policy: weaker messages become
/// `unverified:protection-too-low`.
#[pyfunction]
#[pyo3(signature = (text, public_key_hex, min_protection=None))]
fn verify_json(text: &str, public_key_hex: &str, min_protection: Option<&str>) -> PyResult<String> {
    let min = min_protection.map(level).transpose()?;
    let v = verify_text(text, &SingleKey(pubkey(public_key_hex)?), now()).with_min_protection(min);
    let mut j = v.to_json();
    j["visible"] = serde_json::Value::String(v.visible.clone());
    Ok(j.to_string())
}

#[pyfunction]
fn annotate(text: &str, public_key_hex: &str) -> PyResult<String> {
    Ok(core_annotate(&verify_text(
        text,
        &SingleKey(pubkey(public_key_hex)?),
        now(),
    )))
}

#[pyfunction]
fn strip(text: &str) -> String {
    let ex = hampp_envelope::extract_any(text);
    let base = if ex.envelope == hampp_envelope::Envelope::Missing {
        text.to_string()
    } else {
        ex.visible
    };
    hampp_envelope::strip_all(&hampp_envelope::DEFAULT, &base)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(public_key, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify_json, m)?)?;
    m.add_function(wrap_pyfunction!(annotate, m)?)?;
    m.add_function(wrap_pyfunction!(strip, m)?)?;
    Ok(())
}
