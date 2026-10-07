//! Vectors for suite 2 and protection levels (`spec/vectors/protection.json`). The file is
//! generated here and verified independently by `spec/vectors/verify_vectors.py --protection`.
use hampp_core::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Vector {
    name: String,
    suite: u8,
    public_key_hex: String,
    /// `false`: the key bytes are not a valid HAMPP key (spec/PROTOCOL.md section 2) and a
    /// verifier must reject them as a key, with no verdict (`expected` is `key-rejected`).
    #[serde(skip_serializing_if = "is_true", default = "yes")]
    key_valid: bool,
    signed_text_hex: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    registry_protection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    min_protection: Option<String>,
    expected: String,
    expected_protection: Option<String>,
    expected_notes: Vec<String>,
}

fn yes() -> bool {
    true
}
fn is_true(b: &bool) -> bool {
    *b
}

const TS: u64 = 1_791_000_000;
const TEXT: &str = "Der Auftrag wurde erfolgreich ausgeführt.";

fn ed() -> SigningIdentity {
    SigningIdentity::from_seed("agent-ed", [0x11; 32], [0xA5; 16])
}
fn p256(scalar: u8, level: Protection) -> P256Software {
    P256Software::from_scalar("agent-p256", [scalar; 32], [0xA6; 16])
        .unwrap()
        .claim_level_for_tests(level)
}
fn params(p: Protection) -> SignParams {
    SignParams::lite(TS).with_protection(p)
}
fn header_of(text: &str) -> (String, Header) {
    let ex = hampp_envelope::extract_any(text);
    let hampp_envelope::Envelope::Present(bytes) = ex.envelope else {
        panic!("envelope expected")
    };
    (ex.visible, Header::decode(&bytes).unwrap())
}

/// Key bytes that are not a valid HAMPP key, paired with a message that key's owner signed.
fn mk_bad_key(name: &str, key_bytes: &[u8], signed: &str) -> Vector {
    Vector {
        name: name.into(),
        suite: 2,
        public_key_hex: hex::encode(key_bytes),
        key_valid: false,
        signed_text_hex: hex::encode(signed.as_bytes()),
        registry_protection: None,
        min_protection: None,
        expected: "key-rejected".into(),
        expected_protection: None,
        expected_notes: vec![],
    }
}

#[allow(clippy::too_many_arguments)]
fn mk(
    name: &str,
    key: &PublicKey,
    signed: String,
    registry: Option<Protection>,
    min: Option<Protection>,
    expected: &str,
    protection: Option<Protection>,
    notes: &[&str],
) -> Vector {
    Vector {
        name: name.into(),
        suite: key.suite(),
        public_key_hex: key.to_hex(),
        key_valid: true,
        signed_text_hex: hex::encode(signed.as_bytes()),
        registry_protection: registry.map(|p| p.as_str().into()),
        min_protection: min.map(|p| p.as_str().into()),
        expected: expected.into(),
        expected_protection: protection.map(|p| p.as_str().into()),
        expected_notes: notes.iter().map(|s| s.to_string()).collect(),
    }
}

fn build() -> Vec<Vector> {
    use Protection::*;
    let ok = "authenticated:signed-by-agent";
    let edk = ed().public_key();
    let sw = p256(0x33, Software);
    let swk = sw.public_key();
    let bound = p256(0x33, Bound);
    let attested = p256(0x33, Attested);
    let sign =
        |s: &dyn Signer, p: Protection, c: Carrier| try_sign_text(s, TEXT, &params(p), c).unwrap();
    let m_ed = sign(&ed(), Software, Carrier::ZeroWidth);
    let m_sw = sign(&sw, Software, Carrier::ZeroWidth);
    let m_bound = sign(&bound, Bound, Carrier::ZeroWidth);
    let m_att = sign(&attested, Attested, Carrier::ZeroWidth);

    // the sender signed `software`, someone flips the protection bits to `bound`
    let (vis, mut h) = header_of(&m_sw);
    h.flags = flags_for(false, Bound);
    let flipped = render(&vis, &h, Carrier::ZeroWidth);
    // reserved protection value 3 and a set reserved flag bit
    let (vis, h) = header_of(&m_sw);
    let mut raw = h.encode();
    raw[3] = 0b0000_0110;
    let reserved3 = hampp_envelope::embed(&vis, &raw).unwrap();
    let mut raw = h.encode();
    raw[3] = 0b0000_1000;
    let bit3 = hampp_envelope::embed(&vis, &raw).unwrap();
    // valid signature with a high s
    let (vis, mut h) = header_of(&m_sw);
    h.signature = flip_s(&h.signature);
    let high_s = render(&vis, &h, Carrier::ZeroWidth);
    // unknown suite
    let (vis, mut h) = header_of(&m_sw);
    h.suite = 3;
    let suite3 = render(&vis, &h, Carrier::ZeroWidth);

    // the same P-256 point in spellings that are not valid keys: SEC1 tag 0x05 ("compact"), the
    // uncompressed form, and an x coordinate that is not on the curve
    let compressed = swk.as_bytes().to_vec();
    let mut tag5 = compressed.clone();
    tag5[0] = 0x05;
    let uncompressed = {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        p256::PublicKey::from_sec1_bytes(&compressed)
            .unwrap()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    };
    let mut off_curve = vec![0x02];
    off_curve.extend([0u8; 31]);
    off_curve.push(1);

    vec![
        mk("p0-suite1", &edk, m_ed, None, None, ok, Some(Software), &[]),
        mk(
            "p0-suite2",
            &swk,
            m_sw.clone(),
            None,
            None,
            ok,
            Some(Software),
            &[],
        ),
        mk(
            "p1-bound-claimed",
            &swk,
            m_bound.clone(),
            None,
            None,
            ok,
            Some(Bound),
            &[],
        ),
        mk(
            "p1-bound-visible-carrier",
            &swk,
            sign(&bound, Bound, Carrier::Visible),
            None,
            None,
            ok,
            Some(Bound),
            &[],
        ),
        mk(
            "p2-treated-as-bound",
            &swk,
            m_att,
            None,
            None,
            ok,
            Some(Bound),
            &["attestation-not-verified"],
        ),
        mk(
            "policy-too-low",
            &swk,
            m_sw.clone(),
            None,
            Some(Bound),
            "unverified:protection-too-low",
            Some(Software),
            &[],
        ),
        mk(
            "policy-satisfied",
            &swk,
            m_bound.clone(),
            None,
            Some(Bound),
            ok,
            Some(Bound),
            &[],
        ),
        mk(
            "registry-caps-to-software",
            &swk,
            m_bound.clone(),
            Some(Software),
            None,
            ok,
            Some(Software),
            &["protection-capped"],
        ),
        mk(
            "registry-lower-header-stands",
            &swk,
            m_sw,
            Some(Bound),
            None,
            ok,
            Some(Software),
            &[],
        ),
        mk(
            "neg-flipped-protection-bit",
            &swk,
            flipped,
            None,
            None,
            "invalid:signature-invalid",
            None,
            &[],
        ),
        mk(
            "neg-protection-value-3",
            &swk,
            reserved3,
            None,
            None,
            "unverified:envelope-corrupt",
            None,
            &[],
        ),
        mk(
            "neg-reserved-flag-bit-3",
            &swk,
            bit3,
            None,
            None,
            "unverified:envelope-corrupt",
            None,
            &[],
        ),
        mk(
            "neg-high-s",
            &swk,
            high_s,
            None,
            None,
            "invalid:signature-invalid",
            None,
            &[],
        ),
        mk(
            "neg-suite-3",
            &swk,
            suite3,
            None,
            None,
            "invalid:unsupported-suite",
            None,
            &[],
        ),
        mk_bad_key("neg-key-tag-05-alias", &tag5, &m_bound),
        mk_bad_key("neg-key-uncompressed", &uncompressed, &m_bound),
        mk_bad_key("neg-key-not-on-curve", &off_curve, &m_bound),
        mk(
            "neg-wrong-signer-suite2",
            &p256(0x44, Software).public_key(),
            m_bound,
            None,
            None,
            "unverified:unknown-key",
            None,
            &[],
        ),
    ]
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors/protection.json")
}

#[test]
fn protection_vectors_file_is_current() {
    let built = build();
    if std::env::var("HAMPP_UPDATE_VECTORS").is_ok() {
        std::fs::write(path(), serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    let on_disk: Vec<Vector> = serde_json::from_str(
        &std::fs::read_to_string(path()).expect("run with HAMPP_UPDATE_VECTORS=1 once"),
    )
    .unwrap();
    assert_eq!(
        on_disk, built,
        "vectors differ; regenerate with HAMPP_UPDATE_VECTORS=1 and review the diff"
    );
}

#[test]
fn every_protection_vector_yields_its_expected_verdict() {
    let on_disk: Vec<Vector> =
        serde_json::from_str(&std::fs::read_to_string(path()).unwrap()).unwrap();
    assert!(on_disk.len() >= 18);
    for v in on_disk {
        let text = String::from_utf8(hex::decode(&v.signed_text_hex).unwrap()).unwrap();
        if !v.key_valid {
            assert_eq!(v.expected, "key-rejected", "vector {}", v.name);
            assert!(
                PublicKey::from_hex(&v.public_key_hex).is_err(),
                "vector {}: an invalid key must be rejected",
                v.name
            );
            continue;
        }
        let key = PublicKey::from_hex(&v.public_key_hex).unwrap();
        let min = v
            .min_protection
            .as_deref()
            .map(|s| Protection::parse(s).unwrap());
        let opts = VerifyOptions {
            min_protection: min,
        };
        let verdict = match v.registry_protection.as_deref() {
            Some(p) => {
                let mut r = Registry::default();
                r.add_key("a", [0; 16], key.clone(), TrustState::Trusted, 0, None)
                    .unwrap();
                r.set_protection(&key.key_id(), Protection::parse(p));
                verify_text_with(&text, &r, TS, &opts)
            }
            None => verify_text_with(&text, &SingleKey(key), TS, &opts),
        };
        assert_eq!(verdict.code(), v.expected, "vector {}", v.name);
        assert_eq!(
            verdict.protection.map(|p| p.level.as_str().to_string()),
            v.expected_protection,
            "protection of {}",
            v.name
        );
        assert_eq!(verdict.notes, v.expected_notes, "notes of {}", v.name);
    }
}
