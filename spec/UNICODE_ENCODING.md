# HAMPP/1 Unicode encoding (zero-width carrier)

## Alphabet

| Role | Code point | Name | Category |
|---|---|---|---|
| symbol 0 (bits `00`) | U+200B | ZERO WIDTH SPACE | Cf |
| symbol 1 (bits `01`) | U+200C | ZERO WIDTH NON-JOINER | Cf |
| symbol 2 (bits `10`) | U+200D | ZERO WIDTH JOINER | Cf |
| symbol 3 (bits `11`) | U+2060 | WORD JOINER | Cf |
| start marker | U+2064 | INVISIBLE PLUS | Cf |
| end marker | U+2063 | INVISIBLE SEPARATOR | Cf |

Each byte becomes four symbols, most significant bit pair first. The carrier is
`START symbols(len(u16 BE) | payload | crc16(u16 BE)) END`, appended to the visible text.
A ~110 byte header therefore costs about 460 invisible characters.

## Size overhead

Measured on 2026-10-06 with `hampp` 0.1.1, Lite profile (no session). The overhead is constant: it does not depend on
the length of the text.

| Carrier | Added characters | Added bytes (UTF-8) | 42-byte text becomes | 1074-byte text becomes |
|---|---|---|---|---|
| zero-width (default) | 446 | 1338 | 1381 bytes | 2413 bytes |
| `--visible` | 227 | 227 | 270 bytes | 1302 bytes |

ECDSA P-256 signatures (suite 2) are also 64 bytes, so the overhead is identical: checked on 2026-10-07 with `hampp` 0.4.0, a 1-byte
text becomes 1339 bytes (zero-width) with either suite.

Each zero-width character takes 3 bytes in UTF-8 and carries 2 bits, so the default carrier costs about 12 bytes
per payload byte; the visible fallback costs 2 (hex). Token cost was **not measured**: some tokenizers may split
zero-width characters into several tokens each, so the real cost for an LLM can be higher than the byte count
suggests. Measure it with your own tokenizer before relying on it. Overhead with a session (Full profile) is also not
measured yet.
CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) covers `len | payload`.

## Measured offline

Checked on 2026-10-06 with Python `unicodedata`: all six code points are unchanged by
NFC, NFD, NFKC and NFKD. `crates/hampp-sim/tests/transport_matrix.rs` re-measures the
following transports on every test run:

| Transport | Envelope |
|---|---|
| none, NFC, NFD, NFKC, NFKD | survives |
| JSON string round trip | survives |
| HTML escape / unescape | survives |
| Markdown text extraction (pulldown-cmark) | survives |
| appended `\n`, CRLF line endings | survives (see canonicalisation) |
| strip zero-width characters | lost -> `unverified:envelope-missing` |
| strip all invisible format characters (sanitizer) | lost -> `unverified:envelope-missing` |
| truncation, one dropped symbol | `unverified:envelope-corrupt` |
| dropped START marker | stray invisible characters, treated as no envelope |

## Not measurable offline

Real platforms (forums, chat tools, databases behind them) are not tested here. See
`PLATFORMS.md` and `hampp probe`. Where invisible characters are stripped, use the
visible fallback (`hampp sign --visible`, line `[hampp1:<hex>]`).

## Canonicalisation

The signed payload hash is `SHA-256(utf8(canonicalize(visible)))` with
`canonicalize`: replace `\r\n` by `\n`, then remove trailing whitespace. A transport that
appends a newline or converts line endings therefore does not break verification.
Anything else that changes the text (including Unicode normalisation of the visible
characters) changes the hash; the verifier reports `invalid:signature-invalid` and cannot
tell normalisation from forgery.

## Short messages

The envelope is invisible, so a three character message such as "Ja." carries the same
~460 invisible characters as a long one. Decision: sign every message, no padding.
Bundling several messages and a separate channel are out of scope for v0.1; the visible
fallback covers platforms that cannot carry the invisible envelope.

## Error correction

v0.1 uses CRC-16 and fails closed. The realistic damage is stripping or deleting symbols,
which loses alignment and which Reed-Solomon over symbols does not repair without
position information. Revisit only if probes show bit-level corruption.
