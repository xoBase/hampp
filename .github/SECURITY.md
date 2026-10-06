# Security policy

HAMPP is experimental and has not been audited. Please read `spec/SECURITY.md` (what it does and does not guarantee) and
`CHALLENGES.md` (what counts as a vulnerability and what is a known limitation) first.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**.
Please include a reproducible case (a scenario file, a test vector or a short script) and the commit you tested.

For findings that are not exploitable against users (for example a better encoding or a known limitation), a normal issue
is fine.

## What to expect

This is a small experimental project. Reports are handled on a best-effort basis; there is no service level and no bug bounty.
Credit is given in the changelog unless you prefer otherwise.

## Scope

In scope: the code and specification in this repository (`crates/`, `spec/`, `scenarios/`, `install.sh`, the workflows).
Out of scope: third-party platforms that strip or alter invisible characters, and attacks that need access to a private key
file (the key is stored unencrypted, see `spec/SECURITY.md`).
