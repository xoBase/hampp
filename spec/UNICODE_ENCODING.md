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

## Smaller signatures (0.5)

Three opt-in options, measured on 2026-10-16 with the 0.5 code (Lite, Ed25519 and P-256 give identical sizes; timestamp of 2026, a 5-byte varint).
The first rows repeat the figures above for comparison (the visible line is 228 bytes including its newline; the 227 above is the line without it).

| Carrier / option | Header | Added characters | Added bytes (UTF-8) |
|---|---|---|---|
| zero-width, long header (default) | 107 B | 446 | 1338 |
| zero-width, `--compact` | 82 B | 346 | 1038 |
| `--visible` (hex line, inline) | 107 B | 228 | 228 |
| `--visible --compact` | 82 B | 178 | 178 |
| `--visible-b64` (base64url line, inline) | 107 B | 157 | 157 |
| `--visible-b64 --compact` | 82 B | 123 | 123 |
| `--detach` (b64 line alone, long header) | 107 B | 156 | 156 |
| `--detach --compact` (b64 line alone) | 82 B | 122 | 122 |
| `--detach --visible --compact` (hex line alone) | 82 B | 177 | 177 |

For comparison, a bare Ed25519 signature in base64 is 88 characters and carries no key id, suite, timestamp or protection level.

**Token estimates (not Claude's tokenizer).** Counted with llama.cpp's tokenizer on five open vocabularies (Llama 3, Qwen2, GPT-2, Gemma 4, DeepSeek LLM), mean over
50 real signatures (25 Ed25519 and 25 P-256), the signature string only. They show the direction, not the cost for any given model; measure with your own tokenizer.

| Tokenizer | zero-width long | zero-width compact | hex line long | hex line compact | b64url line long | b64url line compact |
|---|---|---|---|---|---|---|
| Llama 3 | 440 | 388 | 119 | 102 | 94 | 86 |
| Qwen2 | 538 | 488 | 207 | 156 | 98 | 89 |
| GPT-2 | 623 | 574 | 112 | 107 | 101 | 93 |
| Gemma 4 | 327 | 302 | 208 | 156 | 92 | 85 |
| DeepSeek LLM | 498 | 484 | 208 | 157 | 97 | 90 |

Zero-width characters are the most expensive carrier by far. Some tokenizers (Qwen2, Gemma, DeepSeek in this run) split hex nearly digit by digit, so base64url saves 14 to 46 percent
of the tokens of the compact hex line. Base64url bodies contain `_` and `-`; a header always starts with `HP` 0x01, i.e. the body starts with `SFA`, so a `_` cannot open Markdown emphasis
right after the colon (`transport_matrix.rs` passes 400 signatures through a Markdown text extractor without loss, for both bodies).

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
