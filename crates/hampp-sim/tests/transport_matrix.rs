use hampp_envelope::{embed, embed_visible, embed_visible_b64, extract, extract_any, Envelope};
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

/// The visible lines through the text transports. base64url bodies contain `_` and `-`, which
/// Markdown renderers may read as emphasis; the markdown transport (pulldown-cmark text
/// extraction) is measured over many payloads so a loss shows up as a count. A header always
/// starts with the bytes `HP 01`, i.e. the body starts with `SFA`, so a `_` can never open an
/// emphasis span right after the colon.
#[test]
fn visible_lines_survive_the_text_transports() {
    let payloads: Vec<Vec<u8>> = (0u32..400)
        .map(|i| {
            (0..24u32)
                .map(|k| {
                    (i.wrapping_mul(2654435761)
                        .wrapping_add(k.wrapping_mul(40503))
                        >> 3) as u8
                })
                .collect()
        })
        .collect();
    for t in ["none", "nfc", "nfkc", "json", "html", "trim", "crlf"] {
        for p in &payloads {
            for signed in [
                embed_visible("Hallo – Welt", p),
                embed_visible_b64("Hallo – Welt", p),
            ] {
                let out = apply(t, &signed).unwrap();
                assert_eq!(
                    extract_any(&out).envelope,
                    Envelope::Present(p.clone()),
                    "{t}"
                );
            }
        }
    }
}

#[test]
fn markdown_rendering_of_visible_lines_is_measured() {
    let mut lost = [0usize; 2]; // hex, base64url
    let mut never_wrong = true;
    let n = 400u32;
    for i in 0..n {
        let p: Vec<u8> = (0..24u32)
            .map(|k| {
                (i.wrapping_mul(2654435761)
                    .wrapping_add(k.wrapping_mul(40503))
                    >> 3) as u8
            })
            .collect();
        for (slot, signed) in [embed_visible("Hallo", &p), embed_visible_b64("Hallo", &p)]
            .into_iter()
            .enumerate()
        {
            match extract_any(&apply("markdown", &signed).unwrap()).envelope {
                Envelope::Present(got) => never_wrong &= got == p,
                _ => lost[slot] += 1,
            }
        }
    }
    eprintln!(
        "markdown: hex lost {} of {n}, base64url lost {} of {n}",
        lost[0], lost[1]
    );
    assert!(
        never_wrong,
        "a damaged line must never yield a different payload"
    );
    assert_eq!(lost[0], 0, "hex lines contain no Markdown syntax");
}
