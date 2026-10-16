# Changelog

All notable changes. The protocol stays HAMPP/1 (header version byte 1); the crate and tool version is what changes.
Releases before 0.5.0 are listed briefly for orientation.

## 0.5.0 (unreleased)

Smaller signatures, all **opt-in** and additive. Existing messages stay valid and the tools still sign in the old format by default.

### Added
- **Compact Lite header** (flag bit 3, `hampp sign --compact`, `hampp.sign(compact=True)`): sessionless messages omit `session_id`, `seq` and `prev_hash`
  (all zero) on the wire, 82 instead of 107 header bytes. The signing input keeps its layout; its flags byte includes bit 3, so a message has exactly one spelling.
  Bit 3 together with the session bit is a decode failure. See `spec/PROTOCOL.md` section 2.
- **Base64url visible line** `[hampp1u:<b64url>]` (`--visible-b64`, `visible_b64=True`, `Carrier::VisibleB64`): RFC 4648 section 5, no padding, strict decoding.
  The last tag at the end of the text wins when both kinds occur.
- **Detached signatures**, Lite only (`hampp sign --detach`, `hampp verify|annotate --sig/--sig-file`, `sign_detached`/`verify_detached` in Rust and Python):
  only the envelope line is produced, to be stored next to the text; the text is verified literally. With the hex line and the long header, `text + "\n" + line` is also a valid 0.4.0 message.
- `hampp capabilities --json`: carrier `visible-b64` and `features` (`compact-header`, `detached`). `hampp inspect` shows the header form and reads a bare signature line.
- New vector set `spec/vectors/detached.json` (verified by `verify_vectors.py --detached`); compact and base64url vectors in `lite.json` and `protection.json`.

### Changed
- The visible hex line now has exactly one spelling: lower-case `0-9a-f`, no whitespace (before, Rust accepted upper case and the Python reference verifier accepted spaces).
  Signers never produced the other spellings; such a line is now `unverified:envelope-corrupt`.
- Flag bits 4-7 are still reserved; bit 3 is now defined. The old reserved-bit vector uses bit 4.

### Fixed
- The Python reference verifier (`spec/vectors/verify_vectors.py`) did not check the header flags in its Lite path: a header with a reserved flag bit and a valid signature
  came out as authenticated, against the specification. Its header parser is now strict (reserved bits, protection value 3, truncation, non-canonical varint, trailing bytes).
  The Rust implementation was not affected.

### Compatibility
- A verifier older than 0.5 reports a compact message as `unverified:envelope-corrupt` and a `[hampp1u:` line as `unverified:envelope-missing`. Neither is ever `authenticated`.
  Verified against a 0.4.0 binary (Ed25519 and P-256, both carriers).
- New verifiers accept everything signed by 0.4.0 (except visible lines with upper-case or spaced hex, which no signer produced).

## 0.4.0 (2026-10-07)
Protection levels (`software`, `bound`, `attested`), Suite 2 (ECDSA P-256), TPM backend, handshake and sessions with Suite 2, Agent Skill, Python bindings with P-256.

## 0.1.1 (2026-10-06)
First public version: Lite and Full profile, zero-width envelope and visible fallback, registry, sidecar mode.
