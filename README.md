# HAMPP: Hardware-Bound Agent Message Provenance Protocol

HAMPP lets agents sign their messages so that others can verify which key wrote them. The signature is an **invisible
zero-width envelope** appended to the normal text: the wording and the LLM's token sampling are never touched. It is an
open research project; the reference implementation is Rust with Python bindings.

> **Status: experimental, not audited, no confidentiality.** Messages are signed, not encrypted.
> See [spec/SECURITY.md](spec/SECURITY.md) and [spec/THREAT_MODEL.md](spec/THREAT_MODEL.md).

## Why invisible characters, and what that costs

Plain text is what agents exchange on forums and chat platforms, so the proof travels inside the text. The price: a platform
that strips invisible characters also strips the proof (the message then verifies as `unverified`, never as forged).
Test a platform with `hampp probe`; if it strips, use the visible fallback `hampp sign --visible`.
Measurements: [spec/UNICODE_ENCODING.md](spec/UNICODE_ENCODING.md), platform list: [spec/PLATFORMS.md](spec/PLATFORMS.md).

## Quick start (shell)

```bash
hampp keygen --agent alice --key alice.json               # once; never overwrites
hampp identity --key alice.json --public                  # share this public key, never the file
echo "Der Auftrag wurde erfolgreich ausgeführt." | hampp sign --key alice.json > signed.txt
hampp verify signed.txt --pubkey <alice-public-key-hex>   # exit 0 authenticated, 10 unverified, 20 invalid
```

Other ways to use it, depending on what an agent can do (no code, shell, Python, spec only): [AGENTS.md](AGENTS.md).
Python: `pip install hampp`, then `hampp.sign(text, "alice.json")` and `hampp.verify(text, pubkey_hex)["code"]`.

## Full example: handshake, session, signed message

```bash
hampp keygen --agent alice --key alice.json
hampp keygen --agent bob   --key bob.json

# Agent A -> Agent B: HELLO; B answers; A authenticates; B accepts
hampp handshake hello   --key alice.json > hello.json
hampp handshake respond --key bob.json --hello hello.json > response.json
hampp handshake auth    --key alice.json --hello hello.json --response response.json \
                        --session-out alice.session > auth.json
hampp handshake accept  --hello hello.json --response response.json --auth auth.json \
                        --session-out bob.session

# Agent A: the LLM writes normal text, HAMPP signs it inside the session
echo "Der Auftrag wurde erfolgreich ausgeführt." | hampp sign --key alice.json --session alice.session > msg.txt

# Agent B verifies it (the session file keeps the sequence state, so a replay is rejected)
hampp verify msg.txt --session bob.session      # Result: AUTHENTICATED (registered-instance)
hampp verify msg.txt --session bob.session      # second time: INVALID (replay), exit 20
```

The handshake authenticates the peers but does not exchange a key or encrypt anything. Pin the peer's key
(`hampp handshake auth --expect-peer <hex>` or a registry) to defeat an active man in the middle.

## Development tools (not needed to use HAMPP)

- `hampp inspect <file>`: show envelope fields without any key; it claims nothing.
- `hampp-sim`: simulated agents plus attack and transport scenarios in [`scenarios/`](scenarios/); `cargo test -p hampp-sim`.
- Test vectors in [`spec/vectors/`](spec/vectors/) and an independent Python verifier that does not use the Rust code:
  `uv run --with cryptography python spec/vectors/verify_vectors.py spec/vectors/lite.json`.

## Status and limits

Experimental and **not audited**. Implemented in v0.1: Ed25519 signatures over messages, the zero-width envelope and a
visible fallback, a signed handshake, sessions with replay and ordering checks, a trust registry, the `hampp` CLI with
sidecar mode, and Python bindings.

Not part of v0.1 (so please do not assume it): confidentiality (messages are signed, not encrypted); hardware-bound or
attested keys (the inspector prints `SOFTWARE_ONLY`); authorisation or permissions; key rotation and federation;
replay protection for the sessionless Lite profile; detection of a copied private key; tested compatibility data for real
platforms. Details: [spec/SECURITY.md](spec/SECURITY.md), [spec/THREAT_MODEL.md](spec/THREAT_MODEL.md).

## Try to break it

Do not trust the protocol; attack it. [CHALLENGES.md](CHALLENGES.md) lists concrete questions, what counts as a finding and how
to submit a reproducible attack (a scenario file is enough). Security reports: [.github/SECURITY.md](.github/SECURITY.md).

## Build another implementation

[spec/PROTOCOL.md](spec/PROTOCOL.md) is normative; [spec/vectors/](spec/vectors/) is the conformance suite, and
`spec/vectors/verify_vectors.py` is a complete independent verifier in about 150 lines. An implementation that passes the vectors
interoperates with HAMPP/1. A different design is just as welcome, but please give an incompatible protocol its own label rather
than "HAMPP/1".

## Install

```bash
cargo install --git https://github.com/xoBase/hampp hampp-cli --locked    # builds the `hampp` binary
curl -fsSL https://raw.githubusercontent.com/xoBase/hampp/main/install.sh | sh    # prebuilt binary, checksum verified
pip install hampp                                                      # Python bindings
```

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
