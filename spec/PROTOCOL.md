# HAMPP/1 protocol

Normative description. The test vectors in `vectors/` and the reference verifier
`vectors/verify_vectors.py` implement exactly this text.

## 1. Canonicalisation and payload hash

`canonicalize(text)`: replace every `\r\n` by `\n`, then remove trailing whitespace, meaning exactly the Unicode
`White_Space` characters U+0009..U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000..U+200A, U+2028, U+2029, U+202F,
U+205F and U+3000 (not other control characters such as U+001F, and not the zero-width characters). `payload_hash = SHA-256(UTF-8(canonicalize(visible_text)))`.
`visible_text` is the message with its envelope removed (section 3).

## 2. Header (the signed record)

Binary layout, big-endian where fixed width:

```
magic "HP" (2) | version (1) = 1 | flags (1) | suite (1) | key_id (8) | session_id (8) |
seq (varint) | timestamp (varint) | prev_hash (16) | signature (64)
```

- `flags`: bit 0 = session message; bits 1-2 = `protection` (0 software, 1 bound, 2 attested; 3 is reserved); bits 3-7 MUST be 0.
  A reserved protection value or a set bit 3-7 is a decode failure (section 4, step 2).
- `suite`: 1 = Ed25519 + SHA-256; 2 = ECDSA P-256 + SHA-256. Other values: `unsupported-suite`.
- `key_id`: suite 1 = first 8 bytes of SHA-256(public key, 32 bytes); suite 2 = first 8 bytes of SHA-256(SEC1 compressed point, 33 bytes).
  The input lengths differ, so a key id never collides across suites. `session_id` is 8 zero bytes for sessionless (Lite) messages.
- Suite 2 public key: the 33-byte SEC1 *compressed* point (first byte 0x02 or 0x03) and no other spelling. A key with another tag (for example 0x05, or an
  uncompressed point) is not a valid HAMPP key, so a key has exactly one hex form and one `key_id`.
- Suite 2 signature: raw `r || s`, each 32 bytes big-endian, 64 bytes in total (same size as suite 1). `s` MUST be low (`s <= n/2`);
  signers normalise `s -> n - s` and verifiers MUST reject a high `s` (the signature feeds `prev_hash`, so its form must be unique).
- `varint`: unsigned LEB128, at most 10 bytes, canonical form only (no redundant trailing zero group).
- `timestamp`: unix seconds. `seq`: 0 for Lite, starting at 1 within a session.
- No trailing bytes are allowed after `signature`.

Signing input (Ed25519 strict verification, or ECDSA P-256 over SHA-256 of this input):

```
"HAMPP/1 msg" || version(1) || flags(1) || suite(1) || key_id(8) || session_id(8) ||
seq (u64 BE) || timestamp (u64 BE) || payload_hash (32) || prev_hash (16)
```

`payload_hash` is not transmitted; the verifier recomputes it from the visible text.

## 3. Carriers

**Zero-width (default).** Appended to the visible text: `START symbols END`. Alphabet:
symbols U+200B, U+200C, U+200D, U+2060 encode the bit pairs `00 01 10 11`
(most significant pair first); START = U+2064, END = U+2063.
The symbol stream is the bytes `len (u16 BE) | header | crc16 (u16 BE)`; `len` is the header length,
CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) covers `len | header`.
The verifier uses the LAST START in the text and the first END after it; everything before START
and after END is the visible text (so quoted older envelopes stay part of the text). No START: no
envelope. START without END, wrong symbols, length or CRC: corrupt envelope.

**Visible fallback.** The text, trailing whitespace removed, then `"\n[hampp1:" || hex(header || crc16(header)) || "]"`
at the very end. The zero-width carrier is tried first.

## 4. Verification algorithm (in this order)

1. Extract the envelope: missing -> `unverified:envelope-missing`; corrupt -> `unverified:envelope-corrupt`.
2. Decode the header: bad version -> `invalid:unsupported-version`; any other decode failure -> `unverified:envelope-corrupt`.
3. Suite not 1 or 2 -> `invalid:unsupported-suite`.
4. Resolve the public key by `key_id` (single known key or registry): none -> `unverified:unknown-key`.
5. Verify the signature over the signing input: failure -> `invalid:signature-invalid`
   (changed text, changed envelope, or a different key with the same key id; the cause is not distinguishable).
6. Registry trust: `REVOKED` -> `invalid:key-revoked`; `EXPIRED` -> `invalid:key-expired`.
7. Otherwise `authenticated:signed-by-agent`, then the protection rules of section 8 apply.

Verdict codes: `authenticated:signed-by-agent`, `authenticated:registered-instance`, `unverified:<reason>`, `invalid:<reason>`.
Reasons: `envelope-missing`, `envelope-corrupt`, `unknown-key`, `unsupported-version`, `unsupported-suite`,
`signature-invalid`, `key-revoked`, `key-expired`, `wrong-session`, `replay`, `chain-broken`, `clock-skew`, `protection-too-low`
(`unverified`, see section 8).

## 5. Handshake (Full profile)

JSON objects with byte fields as lower-case hex. Fields: `HELLO` = versions, suites, caps, agent_id, instance_id (16),
public_key (32 bytes for suite 1, 33 bytes for suite 2), nonce (32); `HELLO_RESPONSE` = version, suite, caps, agent_id, instance_id, public_key, nonce, signature (64);
`AUTH_RESPONSE` = signature (64). Capabilities: `{tag, critical, value}`.

Transcript hash = SHA-256 of `"HAMPP/1 transcript"` followed by, using `put(b) = u32 BE length || b`:
HELLO: `put(versions) put(suites) caps put(agent_id) put(instance_id) put(public_key) put(nonce)`,
then RESPONSE: `put([version, suite]) caps put(agent_id) put(instance_id) put(public_key) put(nonce)`;
`caps = put(u32 BE count) { put([tag, critical 0|1]) put(value) }*`.

- B signs `"HAMPP/1 hs B" || transcript`, A signs `"HAMPP/1 hs A" || transcript`, both with the signature algorithm of the chosen suite
  (suite 2: ECDSA P-256 over SHA-256 of that input, raw `r || s`, low `s`, as in section 2).
- **One key, one suite.** Each party has one key and offers only the suite of that key in `suites`. The chosen suite MUST be the suite of both
  public keys: B fails with no common suite (different key types) or with a key-does-not-match-suite error (a public key whose length or type
  does not fit the chosen suite); A rejects a response and B rejects an AUTH_RESPONSE in the same way. A session therefore exists only between two
  keys of the same suite.
- B chooses the highest version and suite offered by A that B supports; the choice is inside the signed transcript
  (downgrade attempts break the signature). The initiator rejects a choice that was not offered.
- An unknown capability with `critical = true` aborts the handshake; unknown non-critical capabilities are ignored.
- `session_id = SHA-256("HAMPP/1 session" || pkA || pkB || nonceA || nonceB || version || suite)[..8]`. Both keys have the length of the chosen
  suite (32 or 33 bytes), so the concatenation is unambiguous.
- Capability tags: 1 = Lite profile, 2 = Full profile, 3 = verify-only, 4 = visible fallback.
- The handshake authenticates; it exchanges no key and encrypts nothing. Pin the peer key (registry or `--expect-peer`) to defeat
  an active man in the middle.

## 6. Session rules

Per direction, `seq` starts at 1 and `prev_hash` of message n is the first 16 bytes of
`SHA-256(payload_hash(n-1) || signature(n-1))` (16 zero bytes for n = 1). The receiver, after a valid signature:

- `session_id` differs (or message is sessionless) -> `invalid:wrong-session`.
- optional skew window (off by default, for live channels only): `|now - timestamp| > max_skew` -> `invalid:clock-skew`.
- `seq <= last accepted` -> `invalid:replay` (duplicates and late messages).
- `seq == last + 1` and `prev_hash` differs -> `invalid:chain-broken`.
- `seq > last + 1` -> accepted with note `gap:<missing count>` (the chain cannot be checked across a gap).
- State advances only for accepted messages. Success is `authenticated:registered-instance`.
- A session message carries its own `protection` field (section 8). The session binds one key per side, so the highest level a side can claim is the level of
  that key; a sender may claim less per message. The receiver applies section 8 to each message (the peer key comes from the handshake, so the level is a
  claim unless the receiver's registry records one). A sender whose signature fails (for example a TPM that is unreachable) MUST NOT advance its own
  sequence number or chain.

## 7. Versioning and profiles

Header version 1. A verifier that does not know a version reports `unsupported-version` and must not guess.
Profiles: Lite (sessionless), Full (handshake + session), verify-only (no own key). A Lite sender and a Full receiver meet at the
smaller level `signed-by-agent`.

## 8. Protection levels

The `protection` field says how well the signing key is protected. It is about the strength of the statement "this key signed this text",
not about secrecy of the text: HAMPP encrypts nothing.

| Value | Level | Meaning | Verifiable by a remote party |
|---|---|---|---|
| 0 | `software` | key in a file | nothing about hardware |
| 1 | `bound` | non-exportable key in a hardware store (for example a TPM) | no: reported as `claimed` |
| 2 | `attested` | like `bound`, plus evidence (certificate chain) | only with verified evidence |

After step 7 of section 4 the receiver computes the **effective protection**:

1. With a registry entry that records a protection for the key: `min(header, entry)`; the result is not `claimed`. If the header is higher, the entry wins and the
   note `protection-capped` is added. A lower header value stands (the sender chose less).
2. Without such an entry (single key, unknown level): the header value, reported as `claimed`.
3. `attested` without verified evidence counts as `bound` (note `attestation-not-verified`). This version defines no evidence format.
4. If the receiver requires a minimum protection and the effective protection is lower, a result that would be `authenticated` becomes
   `unverified:protection-too-low`. `invalid:*` results and `unverified:unknown-key` take precedence. In a session the state (sequence, chain) advances as for any
   authenticated message; only the verdict changes.

Compatibility: a message with protection >= 1 is a decode failure for a version-1 verifier that predates this section
(`unverified:envelope-corrupt`); every suite 2 message is `invalid:unsupported-suite` for such a verifier. Neither is ever `authenticated`.
Messages with protection 0 and suite 1 are unchanged.
