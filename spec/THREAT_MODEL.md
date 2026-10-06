# Threat model

Scenario files live in `scenarios/` and run in `cargo test -p hampp-sim`.

| Threat | Detected by | Outcome | Residual risk |
|---|---|---|---|
| Replay | Session state (`seq`) | `invalid:replay` (`scenarios/10_replay_duplicate.toml`) | **Lite messages can be replayed**; use the Full profile when this matters. |
| Message modification | Signature over the payload hash | `invalid:signature-invalid` (`08_tamper_mitm`) | none for signed text |
| Signature stripping | Missing envelope | `unverified:envelope-missing` (`04_strip_zw`) | An attacker can always downgrade a message to unsigned; receivers decide what to do with unsigned text. |
| Zero-width stripping | Same as above | `unverified:envelope-missing` (`04`, `05_sanitizer`) | Some platforms strip invisible characters; use `--visible` there (`hampp probe`). |
| Unicode normalisation | Envelope survives NFC/NFD/NFKC/NFKD (`06_normalisation`) | verifies | Normalising the *visible* characters changes the hash: `invalid:signature-invalid`; cause not distinguishable from forgery. |
| Agent cloning | Not detected | clone is indistinguishable | Only hardware attestation (future) can bind a key to a device. Doubled `seq` values may reveal clones in a session. |
| Private-key theft | Not prevented | attacker can sign as the victim | Revoke the key in the registry; keys are stored 0600. |
| Hardware-ID spoofing | No hardware claim in v0.1 | nothing to spoof | Future levels `BOUND`/`ATTESTED` will make this explicit. |
| Key replacement | Registry key-id conflict; peer pinning in the handshake | `KeyIdConflict`, `PeerKeyMismatch` | First contact without a pinned key is trust on first use. |
| Session hijacking | Session id bound to both keys and nonces | `invalid:wrong-session` | No encryption: an eavesdropper can read, not forge. |
| Man in the middle | Pinned peer key (`--expect-peer`, registry) | handshake fails (`PeerKeyMismatch`) | Without pinning, the handshake authenticates whichever key answers. |
| Reordering | Sequence numbers | gap note / `invalid:replay` for late messages (`11_reorder_gap`) | Strict: late messages are rejected, not queued. |
| Message injection | Unknown key / invalid signature | `unverified:unknown-key` (`12_impersonation`) | none for unknown keys |
| Truncated messages | Envelope framing and CRC | `unverified:envelope-corrupt` (`09a_truncate`, `09b_bitloss`) | none |
| Copy / paste | Envelope is part of the text | verifies if the clipboard keeps invisible characters | Retyping a message loses the envelope. |
| Gateway / proxy transformation | Transport matrix (`07_formats`, `crates/hampp-sim/tests/transport_matrix.rs`) | JSON, HTML, Markdown, newline and CRLF pass | Real platforms are not tested; see `PLATFORMS.md`. |
| Forged status line (sidecar) | `annotate` neutralises `[HAMPP:` in message text | only the first line is a status | The operator must show the first line, not the model-visible text. |
