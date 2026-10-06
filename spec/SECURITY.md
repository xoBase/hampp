# Security model

**Status: experimental, not audited, not encryption.**

| Property | HAMPP/1 v0.1 | Notes |
|---|---|---|
| Authenticity | yes, per key | The signature proves that the holder of a private key signed exactly this text. |
| Integrity | yes | Any change to the visible text or the envelope makes verification fail (`invalid:signature-invalid`). |
| Provenance | partial | Binds a message to a key. Binding a key to an agent needs the registry or an out-of-band exchange. |
| Replay protection | Full profile only | Lite messages carry a signed timestamp, but the verifier keeps no state; anyone can re-post a Lite message. |
| Ordering / gaps | Full profile only | Sequence numbers and the hash chain. A stateless verifier (`hampp verify --pubkey`) cannot check the chain. |
| Confidentiality | **no** | Messages are signed, not encrypted. The text is public wherever it is posted. |
| Anonymity | **no** | The envelope contains a key id that links all messages of a key. |
| Agent identity | via registry | `agent_id` is a label until a registry entry or a trusted exchange binds it to a key. |
| Instance identity | via registry/handshake | `instance_id` comes from the handshake or registry, not from the envelope. |
| Hardware identity | **none in v0.1** | No hardware claim is emitted; the inspector prints `SOFTWARE_ONLY`. See `HARDWARE_BINDING.md`. |

## What a result means

- `authenticated:signed-by-agent`: some key you hold or trust signed this text.
- `authenticated:registered-instance`: additionally, the message belongs to a live session with a peer whose key was authenticated in
  the handshake, in order and not replayed. It is only as strong as your trust in that peer key.
- `unverified:*`: no usable proof (envelope stripped, corrupt, or key unknown). It is not evidence of forgery.
- `invalid:*`: proof present but wrong, or the key is revoked/expired.

## Key storage (v0.1)

The private key is stored as **plaintext hex in a JSON file** (`hampp keygen`, `FileKeyStore`). There is no passphrase and no
encryption at rest. The only protection is the operating system: the file is created with mode 0600, a key file that is accessible by
group or others is refused, and `keygen` never overwrites an existing key. Anyone who can read the file can sign as that agent, so
keep it out of backups, repositories and shared directories (`hampp-key.json` is in `.gitignore`). Hardware-backed stores (TPM, HSM)
are a future implementation of the `KeyStore` trait; see `HARDWARE_BINDING.md`.

State files (session files, registry) are written atomically (temp file plus rename) and contain no private key material.

## Design rules

- The LLM's token selection is never modified; signing happens after generation.
- Removing the envelope is not an attack on the protocol; it only loses the proof.
- Private keys are stored with mode 0600 and a key file readable by others is refused. Keys are never overwritten by `keygen`.
- The cryptography is Ed25519 and SHA-256 from audited-in-the-wild crates; HAMPP itself has not been audited.
