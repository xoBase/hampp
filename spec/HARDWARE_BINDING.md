# Hardware binding

**v0.1 emits no hardware claim.** The envelope has no hardware field and the inspector prints
`SOFTWARE_ONLY`. This document fixes the vocabulary for later phases so that no weaker claim is ever
reported as a stronger one.

| Level | Meaning | What a remote verifier can check |
|---|---|---|
| `SOFTWARE_ONLY` | Key lives in a file | nothing about hardware |
| `HARDWARE_IDENTIFIED` | The agent *claims* a hardware id | nothing: serial numbers and `sm_89` are freely readable and spoofable |
| `HARDWARE_BOUND` | Key is held in a non-exportable store (for example a TPM) | **not checkable** without attestation; must be reported as `claimed, not verified` |
| `HARDWARE_ATTESTED` | A certificate chain or quote proves the key lives in the device | the only verifiable level |

Rules for future implementations:

- A hardware id is never a secret and never a key. Mixing hardware characteristics into a KDF adds nothing unless the secret
  input is device-protected (for example TPM sealing); then it protects a stolen key file from being opened on another machine.
- The `KeyStore` trait in `hampp-core` is the extension point for hardware-backed stores.
- The inspector must print only the level that was actually verified.
- Candidate for phase 5: this development machine exposes a TPM 2.0 resource manager at `/dev/tpmrm0`.
