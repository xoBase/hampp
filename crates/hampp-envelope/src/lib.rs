//! Zero-width transport layer for HAMPP. Knows only bytes <-> invisible characters.
mod alphabet;
mod crc;
mod frame;

pub use alphabet::{Alphabet, DEFAULT};
pub use frame::{
    embed, embed_with, extract, extract_with, strip_all, Envelope, EnvelopeError, Extracted,
};
mod visible;
pub use visible::{embed_visible, extract_any, extract_visible};
