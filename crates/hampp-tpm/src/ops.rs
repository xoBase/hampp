use crate::keyfile::{KeyFileJson, ALG};
use hampp_core::{
    normalize_low_s, Protection, PublicKey, SignError, Signer, SUITE_ECDSA_P256_SHA256,
};
use sha2::{Digest as _, Sha256};
use std::str::FromStr;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, Private, Public, PublicBuilder,
    PublicEccParametersBuilder, Signature, SignatureScheme, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::Context;

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("TPM unavailable ({0})")]
    Unavailable(String),
    #[error("TPM operation failed: {0}")]
    Tpm(String),
    #[error("key not loadable on this TPM: {0}")]
    NotLoadable(String),
    #[error("invalid key file: {0}")]
    Format(String),
}

impl From<tss_esapi::Error> for TpmError {
    fn from(e: tss_esapi::Error) -> Self {
        TpmError::Tpm(e.to_string())
    }
}

fn open(tcti: Option<&str>) -> Result<Context, TpmError> {
    let conf = match tcti
        .map(str::to_string)
        .or_else(|| std::env::var("HAMPP_TCTI").ok())
    {
        Some(s) => TctiNameConf::from_str(&s)
            .map_err(|e| TpmError::Unavailable(format!("bad TCTI {s:?}: {e}")))?,
        None => TctiNameConf::from_str("device:/dev/tpmrm0")
            .map_err(|e| TpmError::Unavailable(e.to_string()))?,
    };
    Context::new(conf).map_err(|e| TpmError::Unavailable(e.to_string()))
}

/// Standard ECC storage primary (the "SRK" template, P-256), recreated deterministically from the
/// TPM's owner seed, so the wrapped key blob can be loaded again later.
fn primary_template() -> Result<Public, TpmError> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;
    let ecc = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_key_derivation_function_scheme(
            tss_esapi::structures::KeyDerivationFunctionScheme::Null,
        )
        .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?)
}

fn signing_template() -> Result<Public, TpmError> {
    Ok(tss_esapi::utils::create_unrestricted_signing_ecc_public(
        EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
        EccCurve::NistP256,
    )?)
}

/// Runs `f` with the primary loaded and flushes it afterwards, whatever `f` returns.
fn with_primary<T>(
    ctx: &mut Context,
    f: impl FnOnce(&mut Context, KeyHandle) -> Result<T, TpmError>,
) -> Result<T, TpmError> {
    let template = primary_template()?;
    ctx.execute_with_nullauth_session(|ctx| {
        let primary = ctx
            .create_primary(Hierarchy::Owner, template, None, None, None, None)
            .map_err(|e| TpmError::Unavailable(format!("cannot create the primary key: {e}")))?
            .key_handle;
        let r = f(ctx, primary);
        let _ = ctx.flush_context(primary.into());
        r
    })
}

fn pad32(b: &[u8]) -> Result<[u8; 32], TpmError> {
    if b.len() > 32 {
        return Err(TpmError::Tpm("ECC parameter longer than 32 bytes".into()));
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Ok(out)
}

fn compressed_point(public: &Public) -> Result<PublicKey, TpmError> {
    let Public::Ecc { unique, .. } = public else {
        return Err(TpmError::Format("not an ECC key".into()));
    };
    let x = pad32(unique.x().value())?;
    let y = pad32(unique.y().value())?;
    let mut point = [0u8; 33];
    point[0] = if y[31] & 1 == 0 { 0x02 } else { 0x03 };
    point[1..].copy_from_slice(&x);
    PublicKey::from_slice(&point)
        .ok_or_else(|| TpmError::Format("TPM returned an invalid point".into()))
}

fn null_ticket() -> Result<HashcheckTicket, TpmError> {
    use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
    use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
    Ok(HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    })?)
}

/// A signer whose key lives in a TPM.
pub struct TpmSigner {
    pub agent_id: String,
    pub instance_id: [u8; 16],
    public: PublicKey,
    tpm_public: Public,
    tpm_private: Private,
    tcti: Option<String>,
}

impl TpmSigner {
    /// Creates a new key inside the TPM. The returned key file holds only the wrapped blob.
    pub fn create(
        agent_id: &str,
        tcti: Option<&str>,
    ) -> Result<(TpmSigner, KeyFileJson), TpmError> {
        let mut ctx = open(tcti)?;
        let (tpm_public, tpm_private) = with_primary(&mut ctx, |ctx, primary| {
            let r = ctx.create(primary, signing_template()?, None, None, None, None)?;
            Ok((r.out_public, r.out_private))
        })?;
        let mut instance_id = [0u8; 16];
        // The instance id only needs to be unique; derive it from the new key's public point.
        instance_id
            .copy_from_slice(&Sha256::digest(compressed_point(&tpm_public)?.as_bytes())[..16]);
        let signer = TpmSigner {
            agent_id: agent_id.to_string(),
            instance_id,
            public: compressed_point(&tpm_public)?,
            tpm_public,
            tpm_private,
            tcti: tcti.map(str::to_string),
        };
        let file = signer.to_key_file()?;
        Ok((signer, file))
    }

    /// Loads a key file. Fails with `NotLoadable` when this TPM did not create the blob.
    pub fn load(file: &KeyFileJson, tcti: Option<&str>) -> Result<TpmSigner, TpmError> {
        if file.alg != ALG {
            return Err(TpmError::Format(format!(
                "unexpected key algorithm {:?}",
                file.alg
            )));
        }
        let unhex = |s: &str, what: &str| {
            hex::decode(s).map_err(|e| TpmError::Format(format!("{what}: {e}")))
        };
        let tpm_public = Public::unmarshall(&unhex(&file.tpm_public, "tpm_public")?)
            .map_err(|e| TpmError::Format(format!("tpm_public: {e}")))?;
        let tpm_private = Private::try_from(unhex(&file.tpm_private, "tpm_private")?)
            .map_err(|e| TpmError::Format(format!("tpm_private: {e}")))?;
        let public = compressed_point(&tpm_public)?;
        if public.to_hex() != file.public {
            return Err(TpmError::Format(
                "public key does not match the TPM public area".into(),
            ));
        }
        let instance_id: [u8; 16] = unhex(&file.instance_id, "instance_id")?
            .try_into()
            .map_err(|_| TpmError::Format("instance_id must be 16 bytes".into()))?;
        let signer = TpmSigner {
            agent_id: file.agent_id.clone(),
            instance_id,
            public,
            tpm_public,
            tpm_private,
            tcti: tcti.map(str::to_string),
        };
        // Prove now that this TPM can load the blob, instead of failing at the first signature.
        let mut ctx = open(tcti)?;
        with_primary(&mut ctx, |ctx, primary| {
            let key = ctx
                .load(
                    primary,
                    signer.tpm_private.clone(),
                    signer.tpm_public.clone(),
                )
                .map_err(|e| TpmError::NotLoadable(e.to_string()))?;
            let _ = ctx.flush_context(key.into());
            Ok(())
        })?;
        Ok(signer)
    }

    pub fn to_key_file(&self) -> Result<KeyFileJson, TpmError> {
        Ok(KeyFileJson {
            alg: ALG.to_string(),
            agent_id: self.agent_id.clone(),
            instance_id: hex::encode(self.instance_id),
            public: self.public.to_hex(),
            tpm_public: hex::encode(self.tpm_public.marshall()?),
            tpm_private: hex::encode(self.tpm_private.to_vec()),
        })
    }

    fn sign_inner(&self, msg: &[u8]) -> Result<[u8; 64], TpmError> {
        let digest = Digest::try_from(Sha256::digest(msg).to_vec())?;
        let mut ctx = open(self.tcti.as_deref())?;
        with_primary(&mut ctx, |ctx, primary| {
            let key = ctx
                .load(primary, self.tpm_private.clone(), self.tpm_public.clone())
                .map_err(|e| TpmError::NotLoadable(e.to_string()))?;
            let sig = ctx.sign(
                key,
                digest,
                SignatureScheme::EcDsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                null_ticket()?,
            );
            let _ = ctx.flush_context(key.into());
            let Signature::EcDsa(sig) = sig? else {
                return Err(TpmError::Tpm("TPM returned a non-ECDSA signature".into()));
            };
            let mut raw = [0u8; 64];
            raw[..32].copy_from_slice(&pad32(sig.signature_r().value())?);
            raw[32..].copy_from_slice(&pad32(sig.signature_s().value())?);
            // About half of all TPM signatures have a high s; the protocol requires a low one.
            normalize_low_s(&raw)
                .ok_or_else(|| TpmError::Tpm("TPM returned an invalid signature".into()))
        })
    }
}

impl Signer for TpmSigner {
    fn suite(&self) -> u8 {
        SUITE_ECDSA_P256_SHA256
    }
    fn public_key(&self) -> PublicKey {
        self.public.clone()
    }
    fn level(&self) -> Protection {
        Protection::Bound
    }
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], SignError> {
        self.sign_inner(msg)
            .map_err(|e| SignError::Backend(e.to_string()))
    }
}

/// Checks that a TPM is reachable and can create the primary key this crate needs.
pub fn probe(tcti: Option<&str>) -> Result<(), TpmError> {
    let mut ctx = open(tcti)?;
    with_primary(&mut ctx, |_, _| Ok(()))
}
