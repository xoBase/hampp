# Architecture

```
hampp-envelope  bytes <-> invisible characters, CRC, visible fallback   (no crypto)
      ^
hampp-core      identity, key store, header, sign/verify, verdicts,
      ^         registry, annotate                                      (no network)
hampp-session   handshake, session state, replay/chain checks
      ^
hampp-cli       `hampp` binary          hampp-py   Python bindings
hampp-sim       scenarios + channel transforms (development tool, not needed to use HAMPP)
```

| Crate | Purpose | Depends on |
|---|---|---|
| hampp-envelope | Carrier codec | none |
| hampp-core | Everything needed to sign and verify one message | hampp-envelope |
| hampp-session | Full profile: handshake and session | hampp-core |
| hampp-cli | Command line, sidecar mode (`annotate`), `probe` | all of the above |
| hampp-py | `import hampp` | core, envelope |
| hampp-sim | Attack and transport scenarios, transport matrix | core, session, envelope |

Using HAMPP needs `hampp-core` (and `hampp-envelope`); `hampp-sim` and `hampp inspect` only help to check implementations.
`spec/PROTOCOL.md` plus `spec/vectors/` are the source of truth: any implementation that passes the vectors interoperates.
