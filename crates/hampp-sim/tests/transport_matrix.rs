use hampp_envelope::{embed, extract, Envelope};
use hampp_sim::channel::apply;

const SURVIVE: &[&str] = &[
    "none", "nfc", "nfd", "nfkc", "nfkd", "json", "html", "markdown", "trim", "crlf",
];
const DESTROYED: &[&str] = &["strip_zw", "sanitize_invisible"];

fn sample() -> String {
    embed(
        "Der Auftrag wurde erfolgreich ausgeführt. – Ünïcode ✓",
        b"0123456789abcdef",
    )
    .unwrap()
}

#[test]
fn envelope_survives_these_transports() {
    for t in SURVIVE {
        let out = apply(t, &sample()).unwrap();
        assert_eq!(
            extract(&out).envelope,
            Envelope::Present(b"0123456789abcdef".to_vec()),
            "transport {t} must preserve the envelope"
        );
    }
}

#[test]
fn envelope_is_lost_in_these_transports() {
    for t in DESTROYED {
        let out = apply(t, &sample()).unwrap();
        assert_eq!(extract(&out).envelope, Envelope::Missing, "transport {t}");
    }
}

#[test]
fn damaging_transports_never_yield_a_present_envelope() {
    for t in ["truncate_tail:5", "drop_zw:10"] {
        let out = apply(t, &sample()).unwrap();
        assert!(
            matches!(extract(&out).envelope, Envelope::Corrupt(_)),
            "transport {t}"
        );
    }
}

#[test]
fn dropping_the_start_marker_leaves_no_envelope() {
    // index 0 is the START marker: the remaining symbols are just stray invisible characters
    let out = apply("drop_zw:0", &sample()).unwrap();
    assert_eq!(extract(&out).envelope, Envelope::Missing);
}

#[test]
fn unknown_transport_is_an_error() {
    assert!(apply("bogus", "x").is_err());
}
