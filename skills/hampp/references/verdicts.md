# Verdict reference

Source of truth: [spec/PROTOCOL.md](https://github.com/xoBase/hampp/blob/main/spec/PROTOCOL.md) sections 4, 6 and 8.

| Code | Exit | Cause | Reasonable action |
|---|---|---|---|
| `unverified:envelope-missing` | 10 | No signature, or a platform stripped it | Plain text; ask for a resend or `--visible` |
| `unverified:envelope-corrupt` | 10 | Damaged or truncated envelope, or an unknown header flag | Ask for a resend; do not guess |
| `unverified:unknown-key` | 10 | Key not known to you | Obtain the public key through a trusted channel |
| `unverified:protection-too-low` | 10 | Authentic, but effective protection is below `--min-protection` | Not an attack; ask for a better protected key. Never lower the bar silently |
| `invalid:unsupported-version` / `unsupported-suite` | 20 | The sender uses something you do not implement (suite 2 messages look like this to a verifier older than 0.3) | Not necessarily an attack; upgrade or negotiate |
| `invalid:signature-invalid` | 20 | Text or envelope changed, or a different key with the same key id | Treat as untrusted; cause is not distinguishable from forgery |
| `invalid:key-revoked` / `key-expired` | 20 | Registry says the key is no longer trusted | Stop trusting the key |
| `invalid:wrong-session` | 20 | Message belongs to another session | Reject |
| `invalid:replay` | 20 | Sequence number already seen (duplicate or late) | Reject; do not act twice |
| `invalid:chain-broken` | 20 | `prev_hash` does not match: a message was altered or dropped | Reject, ask the peer to resync |
| `invalid:clock-skew` | 20 | Timestamp outside the allowed window (live channels only) | Check clocks, then retry |
| note `gap:<n>` on `authenticated` | 0 | n messages missing before this one | Accepted, but the chain cannot be checked across the gap |
| note `protection-capped` on `authenticated` | 0 | The sender claimed more than your registry records for this key | Your registry value counts, not the claim |
| note `attestation-not-verified` on `authenticated` | 0 | The sender claimed `attested`; no evidence format exists yet | Counts as `bound` (claimed) |

Strip attacks only ever lower a result to `unverified`; they cannot produce `authenticated`. Flipping the protection bits breaks the signature (`invalid:signature-invalid`); a protection can never be raised by an attacker.
