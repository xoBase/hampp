use serde::{Deserialize, Serialize};

/// How well the signing key is protected (`spec/PROTOCOL.md`, section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protection {
    Software = 0,
    Bound = 1,
    Attested = 2,
}

impl Protection {
    /// Decodes the two header bits; `3` is reserved.
    pub fn from_bits(v: u8) -> Option<Protection> {
        match v {
            0 => Some(Protection::Software),
            1 => Some(Protection::Bound),
            2 => Some(Protection::Attested),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Protection::Software => "software",
            Protection::Bound => "bound",
            Protection::Attested => "attested",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Protection::Software => "SOFTWARE",
            Protection::Bound => "HARDWARE_BOUND",
            Protection::Attested => "HARDWARE_ATTESTED",
        }
    }

    pub fn parse(s: &str) -> Option<Protection> {
        [
            Protection::Software,
            Protection::Bound,
            Protection::Attested,
        ]
        .into_iter()
        .find(|p| p.as_str() == s)
    }
}

/// The protection a receiver attributes to a message after it has checked the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveProtection {
    pub level: Protection,
    /// `true` while the level rests on the sender's header alone (no registry knowledge).
    pub claimed: bool,
}

/// Effective protection from the header claim and what the receiver's registry records for the
/// key. Returns the result and whether the header was capped (`protection-capped`).
/// `attested` counts as `bound` here: this version defines no evidence format.
pub fn effective_protection(
    header: Protection,
    registry: Option<Protection>,
) -> (EffectiveProtection, bool) {
    let header = header.min(Protection::Bound);
    match registry {
        Some(known) => {
            let level = header.min(known.min(Protection::Bound));
            (
                EffectiveProtection {
                    level,
                    claimed: false,
                },
                header > known,
            )
        }
        None => (
            EffectiveProtection {
                level: header,
                claimed: true,
            },
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn order_names_and_parsing() {
        assert!(
            Protection::Software < Protection::Bound && Protection::Bound < Protection::Attested
        );
        for p in [
            Protection::Software,
            Protection::Bound,
            Protection::Attested,
        ] {
            assert_eq!(Protection::parse(p.as_str()), Some(p));
            assert_eq!(Protection::from_bits(p as u8), Some(p));
        }
        assert_eq!(Protection::from_bits(3), None);
        assert_eq!(Protection::parse("hardware"), None);
        assert_eq!(Protection::Bound.label(), "HARDWARE_BOUND");
    }

    #[test]
    fn effective_protection_matrix() {
        use Protection::*;
        // (header, registry, effective, claimed, capped)
        let cases = [
            (Software, None, Software, true, false),
            (Bound, None, Bound, true, false),
            (Attested, None, Bound, true, false), // no evidence format yet
            (Bound, Some(Software), Software, false, true), // capped
            (Software, Some(Bound), Software, false, false), // sender chose lower
            (Bound, Some(Bound), Bound, false, false),
            (Attested, Some(Attested), Bound, false, false), // still no evidence
            (Attested, Some(Software), Software, false, true),
        ];
        for (h, r, want, claimed, capped) in cases {
            let (e, c) = effective_protection(h, r);
            assert_eq!(
                (e.level, e.claimed, c),
                (want, claimed, capped),
                "{h:?}/{r:?}"
            );
        }
    }
}
