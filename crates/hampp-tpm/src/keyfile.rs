use serde::{Deserialize, Serialize};

pub const ALG: &str = hampp_core::ALG_P256_TPM;

/// Key file of a TPM-backed key. Holds no secret: `tpm_private` is encrypted by this TPM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFileJson {
    pub alg: String,
    pub agent_id: String,
    pub instance_id: String,
    /// SEC1 compressed P-256 point, hex (what verifiers pin).
    pub public: String,
    /// Marshalled TPM2B_PUBLIC, hex.
    pub tpm_public: String,
    /// Marshalled TPM2B_PRIVATE (wrapped by the TPM), hex.
    pub tpm_private: String,
}
