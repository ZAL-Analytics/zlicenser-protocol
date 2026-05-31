use tss_esapi::{
    abstraction::{ek, AsymmetricAlgorithmSelection},
    interface_types::key_bits::RsaKeyBits,
    Context, TctiNameConf,
};

use crate::{
    error::Error,
    fingerprint::identifier::{HardwareIdentifier, IdentifierKind},
};

/// TPM 2.0 EK cert from NV storage, fused at manufacture, requires manufacturer-provisioned cert.
pub fn endorsement_key() -> crate::Result<HardwareIdentifier> {
    let tcti = TctiNameConf::from_environment_variable()
        .unwrap_or_else(|_| TctiNameConf::Device(Default::default()));

    let mut ctx = Context::new(tcti).map_err(|e| Error::Collection(format!("TPM context: {e}")))?;

    // raw DER bytes from NV storage, exactly what we need
    let ek_cert = ek::retrieve_ek_pubcert(
        &mut ctx,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
    )
    .map_err(|e| Error::Collection(format!("TPM EK cert: {e}")))?;

    Ok(HardwareIdentifier::new(
        IdentifierKind::TpmEndorsementKey,
        ek_cert,
    ))
}
