# Hardware binding and protection levels

The envelope carries a **protection level** (`spec/PROTOCOL.md`, section 8). It says how well the signing key is protected. It does not make the
text secret, and it does not say anything about who may do what. A sender chooses the level per message and can only choose a level its key can honestly
claim; a receiver can require a minimum level and never has to believe a level it cannot verify.

| Level | Meaning | What a remote verifier can check |
|---|---|---|
| `software` | Key lives in a file | nothing about hardware |
| `bound` | Key is held in a non-exportable hardware store (for example a TPM, `fixedTPM` + `fixedParent`) | **not checkable** without evidence; always reported as `claimed` |
| `attested` | `bound`, plus a certificate chain or quote that proves the key lives in the device | the only verifiable level |

This version defines no evidence format, so a message that claims `attested` is treated as `bound (claimed)` until a later version specifies and verifies evidence.

## What is deliberately not a level

- **Hardware identified** (the agent states a serial number or a GPU model): freely readable and spoofable, it proves nothing.
  A hardware id is never a secret and never a key.
- **Sealed at rest** (a software key whose file is encrypted by a TPM): while signing, the key is in process memory, so a compromised process can copy it exactly as with a
  key file, and a receiver cannot tell the two apart. It protects a stolen key file, which is a local property of the key store, not a statement a receiver can use.

## Rules

- The sender can never claim more than its key offers: asking for a higher level than the key's own fails, and nothing falls back to a weaker key silently.
- The receiver trusts a level only as far as it knows the key: the effective level is the minimum of the header and what the receiver's registry records for that key.
- Only evidence can lift a claim to `attested`. A signature alone never does.
- The inspector prints the level that was claimed and says whether it was verified.

## Limits (TPM-backed keys)

- Protection against exfiltration, not against misuse: a local root user or a compromised agent can ask the TPM to sign anything.
- A TPM clear creates a new identity; key rotation is not part of this version.
- A TPM key blob is only useful on the TPM that created it; copying the key file to another machine does not give the signing ability.
- The TPM's endorsement key and its certificate never appear in the protocol (privacy).

## Implementation notes

- TPM-backed keys are ECDSA P-256 (suite 2): TPMs commonly offer NIST P-256/P-384 and no EdDSA. The measured TPM of the development machine lists P-256, P-384 and BN-P256 only.
- The `Signer` trait is the extension point: a signer reports its suite, public key, the highest level it may claim, and signs bytes without exposing key material.
