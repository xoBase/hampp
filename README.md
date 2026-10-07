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

The envelope has a fixed size, whatever the text length. In Lite mode it adds 1338 bytes (zero-width) or 227 bytes
(`--visible`) per message, so it hurts most on short messages (a 42-byte message becomes 1381 bytes). Token cost for an
LLM is not measured yet. See [size overhead](spec/UNICODE_ENCODING.md#size-overhead).

## Quick start (shell)

```bash
hampp keygen --agent alice --key alice.json               # once; never overwrites
hampp identity --key alice.json --public                  # share this public key, never the file
echo "Der Auftrag wurde erfolgreich ausgeführt." | hampp sign --key alice.json > signed.txt
hampp verify signed.txt --pubkey <alice-public-key-hex>   # exit 0 authenticated, 10 unverified, 20 invalid
```

Other ways to use it, depending on what an agent can do (no code, shell, Python, spec only): [AGENTS.md](AGENTS.md).
Python bindings (Lite profile; Ed25519 and ECDSA P-256 software keys, no sessions and no TPM keys; not on PyPI yet): build them with
`cd crates/hampp-py && maturin develop`, then `hampp.generate_key("alice", "alice.json", alg="ecdsa-p256")` (default `ed25519`),
`hampp.sign(text, "alice.json")` and `hampp.verify(text, pubkey_hex)["code"]`. `verify(..., min_protection="bound")` applies a receiver policy.

## Protection levels

A sender can choose per message how well its signing key is protected: the more consequential the statement, the closer to hardware.
The level is about the strength of "this key signed this text", **not** about secrecy: HAMPP encrypts nothing.

| Level | Key | A receiver can check |
|---|---|---|
| `software` | in a file (Ed25519, or ECDSA P-256 with `--alg ecdsa-p256`) | nothing about hardware |
| `bound` | non-exportable key inside a TPM 2.0 (ECDSA P-256) | nothing: shown as `claimed, not verified` |
| `attested` | `bound` plus verified evidence | not available yet: such a claim counts as `bound` |

```bash
hampp capabilities --json                                  # what this installation can really offer, with reasons
hampp keygen --agent alice --key tpm.json --protection bound     # needs a build with --features tpm and a TPM
echo "Deploy freigegeben" | hampp sign --key tpm.json            # signs at the highest level the key offers
echo "Routine" | hampp sign --key tpm.json --protection software # an agent may always choose less, never more
hampp verify msg.txt --pubkey <hex> --min-protection bound       # lower results become unverified:protection-too-low (exit 10)
hampp registry add --file reg.json --pubkey <hex> --agent alice --trust trusted --protection bound
```

- Nothing falls back silently: if the TPM is missing, signing at `bound` fails instead of using a software key.
- A receiver trusts a level only as far as it knows the key: the effective level is the minimum of the header and what its registry
  records for that key (`protection-capped`). `--min-protection` applies to that effective level.
- TPM support is an optional build (`cargo install --git https://github.com/xoBase/hampp hampp-cli --locked --features tpm`, needs
  `libtss2`); the prebuilt binaries do not include it.
- Sessions work with both key types, so the most consequential messages can run in a session with replay protection: `bound` messages are
  not re-postable there. A session binds one key per side and both keys must have the same type (two Ed25519 keys or two P-256 keys, including
  TPM keys); an Ed25519 agent and a P-256 agent cannot open a session with each other. Inside a session the protection is still chosen per message
  (at most what the key offers). If signing fails (for example the TPM is gone), the session does not advance.
- Limits: a TPM protects against stealing the key, not against misuse by a compromised local agent; without attestation a remote
  party cannot tell a TPM key from a software key. Details: [spec/HARDWARE_BINDING.md](spec/HARDWARE_BINDING.md).

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

## Agent skill

[`skills/hampp/`](skills/hampp/SKILL.md) is one canonical [Agent Skill](https://agentskills.io) (`SKILL.md` plus a detection script
and a verdict reference) that teaches an agent when and how to sign and verify. It needs the `hampp` CLI but degrades
cleanly without it. Copy or symlink the folder into the skills directory of your harness:

| Harness | Skills directory (project / user) |
|---|---|
| Claude Code | `.claude/skills/hampp` / `~/.claude/skills/hampp` |
| GitHub Copilot | `.github/skills/hampp`, `.claude/skills/hampp` or `.agents/skills/hampp` / `~/.copilot/skills/hampp` |
| OpenClaw | `<workspace>/skills/hampp` / `~/.openclaw/skills/hampp` |
| Hermes | `~/.hermes/skills/hampp` |

Paths follow each harness's documentation; compatibility has not been tested in all four yet. A skill is trusted
instruction text for your agent: install only a copy you have reviewed (pin a release tag).
`hampp capabilities --json` and `hampp identity --json` tell an agent what the installation supports.

## Development tools (not needed to use HAMPP)

- `hampp inspect <file>`: show envelope fields without any key; it claims nothing.
- `hampp-sim`: simulated agents plus attack and transport scenarios in [`scenarios/`](scenarios/); `cargo test -p hampp-sim`.
- Test vectors in [`spec/vectors/`](spec/vectors/) and an independent Python verifier that does not use the Rust code:
  `uv run --with cryptography python spec/vectors/verify_vectors.py spec/vectors/lite.json`
  (also `--handshake spec/vectors/handshake.json`, `--handshake-p256 spec/vectors/handshake_p256.json` and
  `--protection spec/vectors/protection.json`).

## Status and limits

Experimental and **not audited**. Implemented: Ed25519 and ECDSA P-256 signatures over messages, the zero-width envelope and a
visible fallback, per-message protection levels (with TPM-backed keys as an optional build), a signed handshake, sessions with replay
and ordering checks, a trust registry, the `hampp` CLI with sidecar mode, and Python bindings.

Not implemented (so please do not assume it): confidentiality (messages are signed, not encrypted); verified hardware attestation
(`bound` is only a claim; `attested` is not available); sessions between an Ed25519 key and a P-256 key; authorisation or permissions; key rotation and federation;
replay protection for the sessionless Lite profile; detection of a copied private key; tested compatibility data for real
platforms. Details: [spec/SECURITY.md](spec/SECURITY.md), [spec/THREAT_MODEL.md](spec/THREAT_MODEL.md).

## Try to break it

Do not trust the protocol; attack it. [CHALLENGES.md](CHALLENGES.md) lists concrete questions, what counts as a finding and how
to submit a reproducible attack (a scenario file is enough). Security reports: [.github/SECURITY.md](.github/SECURITY.md).

## Build another implementation

[spec/PROTOCOL.md](spec/PROTOCOL.md) is normative; [spec/vectors/](spec/vectors/) is the conformance suite, and
`spec/vectors/verify_vectors.py` is a complete independent verifier in about 350 lines. An implementation that passes the vectors
interoperates with HAMPP/1. A different design is just as welcome, but please give an incompatible protocol its own label rather
than "HAMPP/1".

## Install

```bash
cargo install --git https://github.com/xoBase/hampp hampp-cli --locked    # builds the `hampp` binary
curl -fsSL https://raw.githubusercontent.com/xoBase/hampp/main/install.sh | sh    # prebuilt binary, checksum verified
# Python bindings: not on PyPI yet, see "Quick start" (maturin develop)
```

## Licence

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
