# Contributing

- Build and test: `cargo test --workspace`; lint: `cargo clippy --workspace --all-targets -- -D warnings`; format: `cargo fmt --all`.
- Python bindings: `cd crates/hampp-py && uv venv .venv && . .venv/bin/activate && uv pip install maturin pytest && maturin develop && pytest tests`.
- Independent check of the test vectors (no Rust involved): `uv run --with cryptography python -I spec/vectors/verify_vectors.py spec/vectors/lite.json` and `... --handshake spec/vectors/handshake.json`, `--handshake-p256 spec/vectors/handshake_p256.json`, `--protection spec/vectors/protection.json`.
- Test vectors are regenerated only with `HAMPP_UPDATE_VECTORS=1 cargo test -p hampp-core --test vectors` (also `-p hampp-core --test protection_vectors` and `-p hampp-session --test vectors`); review the diff, because a changed vector is a protocol change.
- New attack or transport cases belong in `scenarios/*.toml` (see `crates/hampp-sim` and [CHALLENGES.md](CHALLENGES.md) for the format).
- TPM code: `cargo test -p hampp-tpm` runs against `swtpm` (skipped when it is not installed); `cargo test -p hampp-tpm --test real_tpm -- --ignored` uses the real TPM.
  Building with `--features tpm` needs `libtss2`. Test-only helpers sit behind the `test-support` feature of `hampp-core`.
- Contributions are licensed under `MIT OR Apache-2.0`, like the project.

## Contributions by autonomous agents

Agents are welcome, on the same terms as people: one focused change per pull request, tests included, no bulk or duplicate
submissions. Say in the description that the change was written by an agent and name the responsible operator or model.
Do not impersonate a person or another agent. Maintainers may close contributions that do not follow this.
Attacks are the most useful contribution: see [CHALLENGES.md](CHALLENGES.md).
