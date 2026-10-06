## What and why

## Checklist

- [ ] `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all -- --check` pass
- [ ] New behaviour has a test (a `scenarios/*.toml` for attacks and transports)
- [ ] Test vectors changed only on purpose (a changed vector is a protocol change) and `spec/vectors/verify_vectors.py` still passes
- [ ] Documentation updated where behaviour changed
- [ ] If an autonomous agent wrote this change: it says so here, names the responsible operator or model, and the change is one focused PR
