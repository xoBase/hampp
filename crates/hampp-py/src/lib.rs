use hampp_core::{
    annotate as core_annotate, sign_text, verify_text, Carrier, FileKeyStore, KeyStore, SignParams,
    SigningIdentity, SingleKey,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn err<E: std::fmt::Display>(e: E) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn pubkey(h: &str) -> PyResult<[u8; 32]> {
    let v = hex::decode(h.trim()).map_err(err)?;
    <[u8; 32]>::try_from(v).map_err(|_| err("public key must be 32 bytes (64 hex characters)"))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[pyfunction]
fn generate_key(agent_id: &str, path: &str) -> PyResult<String> {
    let id = SigningIdentity::generate(agent_id);
    FileKeyStore { path: path.into() }.save(&id).map_err(err)?;
    Ok(hex::encode(id.identity.public_key))
}

#[pyfunction]
fn public_key(path: &str) -> PyResult<String> {
    let id = FileKeyStore { path: path.into() }.load().map_err(err)?;
    Ok(hex::encode(id.identity.public_key))
}

#[pyfunction]
#[pyo3(signature = (text, key_path, visible=false))]
fn sign(text: &str, key_path: &str, visible: bool) -> PyResult<String> {
    let id = FileKeyStore {
        path: key_path.into(),
    }
    .load()
    .map_err(err)?;
    let carrier = if visible {
        Carrier::Visible
    } else {
        Carrier::ZeroWidth
    };
    Ok(sign_text(&id, text, &SignParams::lite(now()), carrier))
}

#[pyfunction]
fn verify_json(text: &str, public_key_hex: &str) -> PyResult<String> {
    let v = verify_text(text, &SingleKey(pubkey(public_key_hex)?), now());
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
