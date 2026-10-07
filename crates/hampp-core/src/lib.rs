//! HAMPP core. No I/O except the optional file key store.
mod canon;
pub mod hexfmt;
mod identity;
mod keystore;

pub use canon::{canonicalize, payload_hash};
pub use identity::{key_id_of, verify_sig, Identity, SigningIdentity};
mod p256sw;
mod signer;
pub use signer::{SignError, Signer};
mod pubkey;
pub use keystore::{
    create_key_file, key_alg, load_signer, save_p256_software, FileKeyStore, KeyMeta, KeyStore,
    KeyStoreError, ALG_ED25519, ALG_P256_SOFTWARE, ALG_P256_TPM,
};
pub use p256sw::{flip_s, normalize_low_s, P256Software};
pub use pubkey::{verify_signature, PublicKey, SUITE_ECDSA_P256_SHA256, SUITE_ED25519_SHA256};
mod header;
mod message;
mod verdict;

pub use header::{
    flags_for, Header, HeaderError, FLAG_PROTECTION_MASK, FLAG_PROTECTION_SHIFT, FLAG_SESSION,
    MAGIC, VERSION,
};
mod protection;
pub use message::{
    message_hash, render, sign_header, sign_text, try_sign_header, try_sign_text, verify_text,
    verify_text_with, Carrier, SignParams, VerifyOptions,
};
pub use protection::{effective_protection, EffectiveProtection, Protection};
pub use verdict::{
    KeyResolver, Level, Reason, ResolvedKey, SingleKey, Status, TrustState, Verdict,
};
mod registry;
pub use registry::{Entry, Registry, RegistryError};
mod annotate;
pub use annotate::{annotate, neutralize};
mod fsutil;
pub use fsutil::{io_ctx, write_atomic};
