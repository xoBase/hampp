# Try to break HAMPP

HAMPP is an experiment. Do not trust it; attack it. A reproducible attack is worth more than agreement.
Everything below can be checked against the code in this repository.

## What counts as a finding

A **vulnerability** is any input for which an implementation here:

- reports `authenticated:*` although the message was not signed by the key that was checked, was altered, or (in the Full profile) was replayed, reordered into acceptance, or injected into another session;
- panics, hangs, or uses unbounded time or memory on any text input (the decoder must fail closed);
- claims more than it proved (for example a protection level shown as verified although no evidence was checked: `bound` and `attested` are always reported as `claimed` unless the receiver's registry records the key);
- lets a message text forge the sidecar status line produced by `hampp annotate`.

A **known limitation** is not a vulnerability, but a better answer to one is very welcome (see `spec/THREAT_MODEL.md`):
Lite messages can be replayed; a copied private key is indistinguishable from the original agent; there is no confidentiality;
an attacker can always strip the envelope (the result is then `unverified`, by design); real platforms may strip invisible characters.

## Challenges

| Question | Where it is tested today | You succeed if |
|---|---|---|
| Can you break the handshake (downgrade, reflection, unknown-key-share)? | `crates/hampp-session/src/handshake.rs` tests | a handshake completes with parties or parameters that did not sign the transcript |
| Can you forge a message? | `crates/hampp-core/tests/verify.rs`, `robustness.rs` | any non-signer text verifies as `authenticated` |
| Can you replay an authenticated message? | `scenarios/10_replay_duplicate.toml`, `11_reorder_gap.toml` | the Full profile accepts a message twice, or a late one |
| Can you strip the envelope and still get `authenticated`? | `scenarios/04_strip_zw.toml`, `05_sanitizer.toml` | any output other than `unverified:envelope-missing` for a stripped message |
| Can Unicode normalisation destroy provenance silently? | `scenarios/06_normalisation.toml`, `crates/hampp-sim/tests/transport_matrix.rs` | a transform changes the verdict in a way the verifier does not report |
| Can you make a message claim a protection level its key does not have, or lower a receiver's `--min-protection` policy? | `scenarios/16_*`, `19_*`, `crates/hampp-core/tests/protection_vectors.rs` | a `bound` message or a policy pass that should have been refused or downgraded |
| Can an instance be cloned? | not preventable at present | a way to detect or limit it without hardware attestation |
| Can a copied key be told from the original agent? | not preventable at present | same as above |
| Can you reduce the overhead? | measured: **446 invisible characters (1338 bytes UTF-8) per message**, independent of the text length | a smaller encoding that survives the same transports |
| Can you design a better encoding? | `spec/UNICODE_ENCODING.md` | one that passes `spec/vectors/` or a documented successor to them |

## How to submit an attack

Make it reproducible, then open an issue (template "Attack report") or a pull request.
The best form is a scenario file in `scenarios/` that states the **secure** outcome you expect and fails today.
This is the existing replay scenario, as a template:

```toml
name = "replayed message is rejected"
[[agents]]
name = "alice"
[[agents]]
name = "bob"
[[steps]]
from = "alice"
to = "bob"
text = "Zahle 100 Euro"
expect = "authenticated:registered-instance"
[[steps]]
kind = "deliver"       # deliver the message of step 0 again
from = "alice"
of = 0
expect = "invalid:replay"
```

Steps can send, hold, deliver late, inject (`kind = "inject"` with `claim`), and pass messages through transports
(`via = ["nfkc", "json", "replace:old=new", "truncate_tail:5", "drop_zw:10", ...]`, see `crates/hampp-sim/src/channel.rs`).
Agents can use ECDSA P-256 keys (`key = "ecdsa-p256"`, with `level = "bound"` to let the key claim a hardware level), a step can claim a
level (`protection = "bound"`), a receiver can require one (`min_protection = "bound"`), and `expect_level` checks what the receiver sees;
see `scenarios/13_*` to `19_*`. Unknown fields are an error, so a typo cannot make a scenario pass silently.
Run it with `cargo test -p hampp-sim`. If your attack needs something the simulator cannot express, describe it precisely
and a failing test in any language is fine.

Vulnerabilities that could harm users should be reported privately first, see `.github/SECURITY.md`.
