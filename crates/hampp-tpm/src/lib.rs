//! TPM 2.0 backend for HAMPP: a non-exportable ECDSA P-256 key (`fixedTPM | fixedParent`),
//! protection level `bound`. The key never leaves the TPM; the key file only holds the blob the
//! TPM wrapped under its own primary key, which is useless on any other TPM.
//!
//! No persistent handle is ever used. Every operation recreates the primary, loads the key,
//! works, and flushes everything it loaded, also on errors.
mod keyfile;
mod ops;

pub use keyfile::{KeyFileJson, ALG};
pub use ops::{probe, TpmError, TpmSigner};
