//! HAMPP core. No I/O except the optional file key store.
mod canon;
pub mod hexfmt;
mod identity;
mod keystore;

pub use canon::{canonicalize, payload_hash};
pub use identity::{key_id_of, verify_sig, Identity, SigningIdentity, SUITE_ED25519_SHA256};
pub use keystore::{FileKeyStore, KeyStore, KeyStoreError};
mod header;
mod message;
mod verdict;

pub use header::{Header, HeaderError, FLAG_SESSION, MAGIC, VERSION};
pub use message::{message_hash, render, sign_header, sign_text, verify_text, Carrier, SignParams};
pub use verdict::{
    KeyResolver, Level, Reason, ResolvedKey, SingleKey, Status, TrustState, Verdict,
};
mod registry;
pub use registry::{Entry, Registry, RegistryError};
mod annotate;
pub use annotate::{annotate, neutralize};
mod fsutil;
pub use fsutil::{io_ctx, write_atomic};
