# Architecture

```
hampp-envelope  bytes <-> invisible characters, CRC, visible fallback   (no crypto)
      ^
hampp-core      identity, key store, header, sign/verify (Ed25519 and
      ^         ECDSA P-256), protection levels, verdicts, registry,
      ^         annotate                                                (no network)
hampp-session   handshake, session state, replay/chain checks
      ^
hampp-tpm       TPM 2.0 `Signer` (optional, feature `tpm` of the CLI)
      ^
hampp-cli       `hampp` binary          hampp-py   Python bindings
hampp-sim       scenarios + channel transforms (development tool, not needed to use HAMPP)
```

| Crate | Purpose | Depends on |
|---|---|---|
| hampp-envelope | Carrier codec | none |
| hampp-core | Everything needed to sign and verify one message | hampp-envelope |
| hampp-session | Full profile: handshake and session | hampp-core |
| hampp-tpm | TPM-backed ECDSA P-256 key (`bound`); needs `libtss2` to build | core |
| hampp-cli | Command line, sidecar mode (`annotate`), `probe`; TPM keys with `--features tpm` | core, session, envelope; tpm optional |
| hampp-py | `import hampp` (Lite profile, Ed25519 and software P-256 keys) | core, envelope |
| hampp-sim | Attack and transport scenarios, transport matrix | core, session, envelope |

Using HAMPP needs `hampp-core` (and `hampp-envelope`); `hampp-sim` and `hampp inspect` only help to check implementations.
`spec/PROTOCOL.md` plus `spec/vectors/` are the source of truth: any implementation that passes the vectors interoperates.
