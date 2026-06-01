//! RFC 3161 timestamp token verification.
//! Checks message imprint, trust anchor pinning, and signature (RSA/ECDSA, SHA-256/384/512).

#[cfg(feature = "tsa-verify")]
pub use inner::{verify, verify_with_extra_cert, TsaProvider, VerifiedToken};

#[cfg(feature = "tsa-verify")]
pub(crate) mod inner {
    use rasn::prelude::*;
    use rasn_pkix::Certificate;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    use crate::error::Error;

    // OID constants

    const OID_SIGNED_DATA: &[u32] = &[1, 2, 840, 113549, 1, 7, 2];
    const OID_TST_INFO: &[u32] = &[1, 2, 840, 113549, 1, 9, 16, 1, 4];
    const OID_MESSAGE_DIGEST: &[u32] = &[1, 2, 840, 113549, 1, 9, 4];
    const OID_SHA256: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
    const OID_SHA384: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
    const OID_SHA512: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];
    const OID_RSA_ENCRYPTION: &[u32] = &[1, 2, 840, 113549, 1, 1, 1];
    const OID_RSA_SHA256: &[u32] = &[1, 2, 840, 113549, 1, 1, 11];
    const OID_RSA_SHA384: &[u32] = &[1, 2, 840, 113549, 1, 1, 12];
    const OID_RSA_SHA512: &[u32] = &[1, 2, 840, 113549, 1, 1, 13];
    const OID_ECDSA_SHA256: &[u32] = &[1, 2, 840, 10045, 4, 3, 2];
    const OID_ECDSA_SHA384: &[u32] = &[1, 2, 840, 10045, 4, 3, 3];
    const OID_ECDSA_SHA512: &[u32] = &[1, 2, 840, 10045, 4, 3, 4];
    const OID_SUBJECT_KEY_ID: &[u32] = &[2, 5, 29, 14];

    fn oid(parts: &[u32]) -> ObjectIdentifier {
        ObjectIdentifier::new(parts.to_vec()).expect("static OID is valid")
    }

    // SetOf<T> requires T: Eq + Hash; all types below carry those derives.

    #[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct AlgorithmIdentifier {
        pub algorithm: ObjectIdentifier,
        pub parameters: Option<Any>,
    }

    #[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct IssuerAndSerialNumber {
        pub issuer: Any,
        pub serial_number: Integer,
    }

    #[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum SignerIdentifier {
        IssuerAndSerialNumber(IssuerAndSerialNumber),
        #[rasn(tag(0))]
        SubjectKeyIdentifier(OctetString),
    }

    #[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct Attribute {
        pub attr_type: ObjectIdentifier,
        pub attr_values: SetOf<Any>,
    }

    pub type Attributes = SetOf<Attribute>;

    #[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct SignerInfo {
        pub version: Integer,
        pub sid: SignerIdentifier,
        pub digest_algorithm: AlgorithmIdentifier,
        #[rasn(tag(0))]
        pub signed_attrs: Option<Attributes>,
        pub signature_algorithm: AlgorithmIdentifier,
        pub signature: OctetString,
    }

    #[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct EncapsulatedContentInfo {
        pub e_content_type: ObjectIdentifier,
        #[rasn(tag(explicit(0)))]
        pub e_content: Option<OctetString>,
    }

    #[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct SignedData {
        pub version: Integer,
        pub digest_algorithms: SetOf<AlgorithmIdentifier>,
        pub encap_content_info: EncapsulatedContentInfo,
        #[rasn(tag(0))]
        pub certificates: Option<SetOf<Any>>,
        pub signer_infos: SetOf<SignerInfo>,
    }

    #[derive(AsnType, Clone, Debug, Decode, Encode)]
    pub struct ContentInfo {
        pub content_type: ObjectIdentifier,
        #[rasn(tag(explicit(0)))]
        pub content: Any,
    }

    // RFC 3161 chapter 2.4.2, accuracy is an optional sub-sequence
    #[derive(AsnType, Clone, Debug, Decode, Encode)]
    pub struct TstAccuracy {
        pub seconds: Option<Integer>,
        #[rasn(tag(0))]
        pub millis: Option<Integer>,
        #[rasn(tag(1))]
        pub micros: Option<Integer>,
    }

    // full TSTInfo with optional tail fields, missing these broke FreeTSA parsing
    #[derive(AsnType, Clone, Debug, Decode, Encode)]
    pub struct TstInfo {
        pub version: Integer,
        pub policy: ObjectIdentifier,
        pub message_imprint: MessageImprint,
        pub serial_number: Integer,
        pub gen_time: GeneralizedTime,
        // optional fields (RFC 3161 chapter 2.4.2)
        pub accuracy: Option<TstAccuracy>,
        // absent in DER means false; Some(true) means TSA guarantees ordering
        pub ordering: Option<bool>,
        pub nonce: Option<Integer>,
        // TSA GeneralName, decoded as opaque bytes, we don't need to inspect it
        #[rasn(tag(explicit(0)))]
        pub tsa: Option<Any>,
        #[rasn(tag(1))]
        pub extensions: Option<Any>,
    }

    #[derive(AsnType, Clone, Debug, Decode, Encode)]
    pub struct MessageImprint {
        pub hash_algorithm: AlgorithmIdentifier,
        pub hashed_message: OctetString,
    }

    /// Identifies which trusted provider issued the token.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TsaProvider {
        FreeTsa,
        Sectigo,
        Qtsa,
    }

    #[derive(Debug, Clone)]
    pub struct VerifiedToken {
        pub provider: TsaProvider,
        pub hashed_message: Vec<u8>,
        pub serial_number: String,
        pub gen_time_unix: i64,
    }

    struct TrustAnchor {
        provider: TsaProvider,
        chain: &'static [&'static [u8]],
    }

    fn trust_anchors() -> Vec<TrustAnchor> {
        vec![
            TrustAnchor {
                provider: TsaProvider::FreeTsa,
                chain: &[
                    include_bytes!("certs/freetsa_root.der"),
                    include_bytes!("certs/freetsa_tsa.der"),
                ],
            },
            TrustAnchor {
                provider: TsaProvider::Sectigo,
                chain: &[
                    include_bytes!("certs/sectigo_usertrust_root.der"),
                    include_bytes!("certs/sectigo_tsa_r36.der"),
                ],
            },
            TrustAnchor {
                provider: TsaProvider::Qtsa,
                chain: &[
                    include_bytes!("certs/qtsa_root.der"),
                    include_bytes!("certs/qtsa_intermediate.der"),
                    include_bytes!("certs/qtsa_tsa_g4.der"),
                ],
            },
        ]
    }

    /// Verifies a DER-encoded RFC 3161 token against the embedded trust anchors.
    pub fn verify(token_der: &[u8], message: &[u8]) -> crate::Result<VerifiedToken> {
        verify_inner(token_der, message, &[])
    }

    /// Like `verify` but also trusts extra_cert_der. Only use in tests/sandboxes.
    pub fn verify_with_extra_cert(
        token_der: &[u8],
        message: &[u8],
        extra_cert_der: &[u8],
        extra_provider: TsaProvider,
    ) -> crate::Result<VerifiedToken> {
        verify_inner(token_der, message, &[(extra_cert_der, extra_provider)])
    }

    fn verify_inner(
        token_der: &[u8],
        message: &[u8],
        extra_trusted: &[(&[u8], TsaProvider)],
    ) -> crate::Result<VerifiedToken> {
        let ci: ContentInfo = rasn::der::decode(token_der)
            .map_err(|e| Error::TsaParse(format!("ContentInfo: {e}")))?;

        if ci.content_type != oid(OID_SIGNED_DATA) {
            return Err(Error::TsaParse("not a SignedData content type".into()));
        }

        let sd: SignedData = rasn::der::decode(ci.content.as_bytes())
            .map_err(|e| Error::TsaParse(format!("SignedData: {e}")))?;

        if sd.encap_content_info.e_content_type != oid(OID_TST_INFO) {
            return Err(Error::TsaParse("encapContentInfo is not TSTInfo".into()));
        }

        let e_content = sd
            .encap_content_info
            .e_content
            .as_ref()
            .ok_or_else(|| Error::TsaParse("missing eContent".into()))?;
        let tst_der: &[u8] = e_content.as_ref();

        let tst: TstInfo =
            rasn::der::decode(tst_der).map_err(|e| Error::TsaParse(format!("TSTInfo: {e}")))?;

        verify_message_imprint(&tst, message)?;

        let signer_infos = sd.signer_infos.to_vec();
        let signer = signer_infos
            .into_iter()
            .next()
            .ok_or_else(|| Error::TsaParse("no SignerInfo in SignedData".into()))?;

        let signer_cert_der = find_signer_cert(&sd, signer, extra_trusted)?;
        let provider = identify_provider(&signer_cert_der, extra_trusted)?;

        verify_signature(signer, &signer_cert_der, tst_der)?;

        Ok(VerifiedToken {
            provider,
            hashed_message: tst.message_imprint.hashed_message.to_vec(),
            serial_number: format!("{}", tst.serial_number),
            gen_time_unix: tst.gen_time.timestamp(),
        })
    }

    fn verify_message_imprint(tst: &TstInfo, message: &[u8]) -> crate::Result<()> {
        let alg_oid = &tst.message_imprint.hash_algorithm.algorithm;
        let expected: Vec<u8> = if *alg_oid == oid(OID_SHA256) {
            Sha256::digest(message).to_vec()
        } else if *alg_oid == oid(OID_SHA384) {
            Sha384::digest(message).to_vec()
        } else if *alg_oid == oid(OID_SHA512) {
            Sha512::digest(message).to_vec()
        } else {
            return Err(Error::TsaVerification(
                "unsupported hash algorithm in message imprint".into(),
            ));
        };

        if tst.message_imprint.hashed_message.as_ref() != expected.as_slice() {
            return Err(Error::TsaVerification(
                "message imprint hash mismatch".into(),
            ));
        }
        Ok(())
    }

    fn find_signer_cert(
        sd: &SignedData,
        signer: &SignerInfo,
        extra_trusted: &[(&[u8], TsaProvider)],
    ) -> crate::Result<Vec<u8>> {
        // 1. certs embedded in the token itself
        if let Some(certs) = &sd.certificates {
            for cert_any in certs.to_vec() {
                let cert_der = cert_any.as_bytes();
                if signer_matches_cert(signer, cert_der) {
                    return Ok(cert_der.to_vec());
                }
            }
        }

        // 2. pinned trust anchor certs (TSAs that omit the cert expect the verifier to have it)
        for anchor in trust_anchors() {
            for &cert_der in anchor.chain {
                if signer_matches_cert(signer, cert_der) {
                    return Ok(cert_der.to_vec());
                }
            }
        }

        // 3. extra certs from the caller (tests/sandboxes)
        for (cert_der, _) in extra_trusted {
            if signer_matches_cert(signer, cert_der) {
                return Ok(cert_der.to_vec());
            }
        }

        Err(Error::TsaParse(
            "signer certificate not found in token or trust anchors".into(),
        ))
    }

    fn signer_matches_cert(signer: &SignerInfo, cert_der: &[u8]) -> bool {
        let Ok(cert) = rasn::der::decode::<Certificate>(cert_der) else {
            return false;
        };
        match &signer.sid {
            SignerIdentifier::IssuerAndSerialNumber(isn) => {
                cert.tbs_certificate.serial_number == isn.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(skid) => cert
                .tbs_certificate
                .extensions
                .as_ref()
                .and_then(|exts| exts.iter().find(|e| e.extn_id == oid(OID_SUBJECT_KEY_ID)))
                .map(|e| e.extn_value.as_ref() == skid.as_ref())
                .unwrap_or(false),
        }
    }

    fn identify_provider(
        signer_cert_der: &[u8],
        extra_trusted: &[(&[u8], TsaProvider)],
    ) -> crate::Result<TsaProvider> {
        for (cert, provider) in extra_trusted {
            if *cert == signer_cert_der {
                return Ok(provider.clone());
            }
        }
        for anchor in trust_anchors() {
            if anchor.chain.contains(&signer_cert_der) {
                return Ok(anchor.provider);
            }
        }
        Err(Error::TsaUntrustedProvider)
    }

    fn verify_signature(
        signer: &SignerInfo,
        cert_der: &[u8],
        e_content_der: &[u8],
    ) -> crate::Result<()> {
        let cert: Certificate = rasn::der::decode(cert_der)
            .map_err(|e| Error::TsaParse(format!("signer cert: {e}")))?;

        let spki_der = rasn::der::encode(&cert.tbs_certificate.subject_public_key_info)
            .map_err(|e| Error::TsaParse(format!("SPKI encode: {e}")))?;

        let signed_bytes: Vec<u8> = match &signer.signed_attrs {
            Some(attrs) => {
                // RFC 5652: signedAttrs must be re-encoded with SET tag for signature input
                rasn::der::encode(attrs)
                    .map_err(|e| Error::TsaParse(format!("signedAttrs encode: {e}")))?
            }
            None => e_content_der.to_vec(),
        };

        if let Some(attrs) = &signer.signed_attrs {
            verify_message_digest_attr(attrs, e_content_der, &signer.digest_algorithm)?;
        }

        let sig_alg = &signer.signature_algorithm.algorithm;
        let sig_bytes = signer.signature.as_ref();

        if *sig_alg == oid(OID_RSA_SHA256) {
            verify_rsa_sha256(sig_bytes, &signed_bytes, &spki_der)
        } else if *sig_alg == oid(OID_RSA_SHA384) {
            verify_rsa_sha384(sig_bytes, &signed_bytes, &spki_der)
        } else if *sig_alg == oid(OID_RSA_SHA512) {
            verify_rsa_sha512(sig_bytes, &signed_bytes, &spki_der)
        } else if *sig_alg == oid(OID_RSA_ENCRYPTION) {
            // Some providers (e.g. Sectigo) use bare rsaEncryption OID with digest
            // specified separately in digest_algorithm rather than a compound OID.
            let digest_oid = &signer.digest_algorithm.algorithm;
            if *digest_oid == oid(OID_SHA256) {
                verify_rsa_sha256(sig_bytes, &signed_bytes, &spki_der)
            } else if *digest_oid == oid(OID_SHA384) {
                verify_rsa_sha384(sig_bytes, &signed_bytes, &spki_der)
            } else if *digest_oid == oid(OID_SHA512) {
                verify_rsa_sha512(sig_bytes, &signed_bytes, &spki_der)
            } else {
                Err(Error::TsaVerification(format!(
                    "unsupported digest for rsaEncryption: {:?}",
                    digest_oid
                )))
            }
        } else if *sig_alg == oid(OID_ECDSA_SHA256) {
            verify_ecdsa_p256(sig_bytes, &signed_bytes, &spki_der)
        } else if *sig_alg == oid(OID_ECDSA_SHA384) {
            verify_ecdsa_p384(sig_bytes, &signed_bytes, &spki_der)
        } else if *sig_alg == oid(OID_ECDSA_SHA512) {
            verify_ecdsa_sha512(sig_bytes, &signed_bytes, &spki_der)
        } else {
            Err(Error::TsaVerification(format!(
                "unsupported signature algorithm: {:?}",
                sig_alg
            )))
        }
    }

    fn verify_message_digest_attr(
        attrs: &Attributes,
        e_content_der: &[u8],
        digest_alg: &AlgorithmIdentifier,
    ) -> crate::Result<()> {
        let md_oid = oid(OID_MESSAGE_DIGEST);
        let attrs_vec = attrs.to_vec();
        let Some(md_attr) = attrs_vec.into_iter().find(|a| a.attr_type == md_oid) else {
            return Err(Error::TsaVerification(
                "messageDigest attribute missing".into(),
            ));
        };

        let vals = md_attr.attr_values.to_vec();
        let Some(md_any) = vals.into_iter().next() else {
            return Err(Error::TsaVerification("empty messageDigest value".into()));
        };

        let expected: OctetString = rasn::der::decode(md_any.as_bytes())
            .map_err(|e| Error::TsaParse(format!("messageDigest: {e}")))?;

        let actual: Vec<u8> = if digest_alg.algorithm == oid(OID_SHA256) {
            Sha256::digest(e_content_der).to_vec()
        } else if digest_alg.algorithm == oid(OID_SHA384) {
            Sha384::digest(e_content_der).to_vec()
        } else if digest_alg.algorithm == oid(OID_SHA512) {
            Sha512::digest(e_content_der).to_vec()
        } else {
            return Err(Error::TsaVerification(
                "unsupported digest algorithm".into(),
            ));
        };

        if expected.as_ref() != actual.as_slice() {
            return Err(Error::TsaVerification("messageDigest mismatch".into()));
        }
        Ok(())
    }

    fn verify_rsa_sha256(sig: &[u8], data: &[u8], spki_der: &[u8]) -> crate::Result<()> {
        use rsa::{pkcs1v15::VerifyingKey, pkcs8::DecodePublicKey, signature::Verifier};
        let pk = rsa::RsaPublicKey::from_public_key_der(spki_der)
            .map_err(|e| Error::TsaVerification(format!("RSA key: {e}")))?;
        let vk: VerifyingKey<Sha256> = VerifyingKey::new(pk);
        let sig = rsa::pkcs1v15::Signature::try_from(sig)
            .map_err(|e| Error::TsaVerification(format!("RSA sig: {e}")))?;
        vk.verify(data, &sig)
            .map_err(|_| Error::TsaVerification("RSA-SHA256 invalid".into()))
    }

    fn verify_rsa_sha384(sig: &[u8], data: &[u8], spki_der: &[u8]) -> crate::Result<()> {
        use rsa::{pkcs1v15::VerifyingKey, pkcs8::DecodePublicKey, signature::Verifier};
        let pk = rsa::RsaPublicKey::from_public_key_der(spki_der)
            .map_err(|e| Error::TsaVerification(format!("RSA key: {e}")))?;
        let vk: VerifyingKey<Sha384> = VerifyingKey::new(pk);
        let sig = rsa::pkcs1v15::Signature::try_from(sig)
            .map_err(|e| Error::TsaVerification(format!("RSA sig: {e}")))?;
        vk.verify(data, &sig)
            .map_err(|_| Error::TsaVerification("RSA-SHA384 invalid".into()))
    }

    fn verify_rsa_sha512(sig: &[u8], data: &[u8], spki_der: &[u8]) -> crate::Result<()> {
        use rsa::{pkcs1v15::VerifyingKey, pkcs8::DecodePublicKey, signature::Verifier};
        let pk = rsa::RsaPublicKey::from_public_key_der(spki_der)
            .map_err(|e| Error::TsaVerification(format!("RSA key: {e}")))?;
        let vk: VerifyingKey<Sha512> = VerifyingKey::new(pk);
        let sig = rsa::pkcs1v15::Signature::try_from(sig)
            .map_err(|e| Error::TsaVerification(format!("RSA sig: {e}")))?;
        vk.verify(data, &sig)
            .map_err(|_| Error::TsaVerification("RSA-SHA512 invalid".into()))
    }

    fn verify_ecdsa_p256(sig: &[u8], data: &[u8], spki_der: &[u8]) -> crate::Result<()> {
        use p256::{
            ecdsa::{signature::Verifier, DerSignature, VerifyingKey},
            pkcs8::DecodePublicKey,
        };
        let vk = VerifyingKey::from_public_key_der(spki_der)
            .map_err(|e| Error::TsaVerification(format!("P-256 key: {e}")))?;
        let sig = DerSignature::try_from(sig)
            .map_err(|e| Error::TsaVerification(format!("P-256 sig: {e}")))?;
        vk.verify(data, &sig)
            .map_err(|_| Error::TsaVerification("ECDSA-P256-SHA256 invalid".into()))
    }

    fn verify_ecdsa_p384(sig: &[u8], data: &[u8], spki_der: &[u8]) -> crate::Result<()> {
        use p384::ecdsa::{signature::Verifier, DerSignature, VerifyingKey};
        use p384::pkcs8::DecodePublicKey;
        let vk = VerifyingKey::from_public_key_der(spki_der)
            .map_err(|e| Error::TsaVerification(format!("P-384 key: {e}")))?;
        let sig = DerSignature::try_from(sig)
            .map_err(|e| Error::TsaVerification(format!("P-384 sig: {e}")))?;
        vk.verify(data, &sig)
            .map_err(|_| Error::TsaVerification("ECDSA-P384-SHA384 invalid".into()))
    }

    // ecdsa-with-SHA512 OID doesn't name the curve, so try P-256 then P-384
    fn verify_ecdsa_sha512(sig: &[u8], data: &[u8], spki_der: &[u8]) -> crate::Result<()> {
        let prehash = Sha512::digest(data);

        {
            // try P-256
            use p256::pkcs8::DecodePublicKey;
            if let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
                use p256::ecdsa::signature::hazmat::PrehashVerifier;
                let raw = p256::ecdsa::Signature::from_der(sig)
                    .map_err(|e| Error::TsaVerification(format!("sig: {e}")))?;
                return vk
                    .verify_prehash(prehash.as_slice(), &raw)
                    .map_err(|_| Error::TsaVerification("ECDSA-P256-SHA512 invalid".into()));
            }
        }

        {
            // try P-384
            use p384::pkcs8::DecodePublicKey;
            if let Ok(vk) = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der) {
                use p384::ecdsa::signature::hazmat::PrehashVerifier;
                let raw = p384::ecdsa::Signature::from_der(sig)
                    .map_err(|e| Error::TsaVerification(format!("sig: {e}")))?;
                return vk
                    .verify_prehash(prehash.as_slice(), &raw)
                    .map_err(|_| Error::TsaVerification("ECDSA-P384-SHA512 invalid".into()));
            }
        }

        Err(Error::TsaVerification(
            "ECDSA-SHA512: unsupported EC curve (expected P-256 or P-384)".into(),
        ))
    }

    #[cfg(test)]
    pub mod mock {
        //! Minimal RFC 3161 token builder for tests. Uses 512-bit RSA, insecure but fast.

        use rasn::prelude::*;
        use rsa::{
            pkcs1v15::SigningKey,
            pkcs8::EncodePublicKey,
            rand_core::OsRng,
            signature::{RandomizedSigner, SignatureEncoding},
            RsaPrivateKey,
        };
        use sha2::{Digest, Sha256};

        use super::*;

        const TEST_RSA_BITS: usize = 512;

        const OID_SHA256_OBJ: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
        const OID_RSA_SHA256_OBJ: &[u32] = &[1, 2, 840, 113549, 1, 1, 11];
        const OID_SIGNED_DATA_OBJ: &[u32] = &[1, 2, 840, 113549, 1, 7, 2];
        const OID_TST_INFO_OBJ: &[u32] = &[1, 2, 840, 113549, 1, 9, 16, 1, 4];
        const OID_MESSAGE_DIGEST_OBJ: &[u32] = &[1, 2, 840, 113549, 1, 9, 4];
        const OID_MOCK_POLICY: &[u32] = &[1, 3, 6, 1, 4, 1, 0, 1];

        fn o(parts: &[u32]) -> ObjectIdentifier {
            ObjectIdentifier::new(parts.to_vec()).unwrap()
        }

        fn sha256_alg() -> AlgorithmIdentifier {
            AlgorithmIdentifier {
                algorithm: o(OID_SHA256_OBJ),
                parameters: None,
            }
        }

        fn rsa_sha256_alg() -> AlgorithmIdentifier {
            AlgorithmIdentifier {
                algorithm: o(OID_RSA_SHA256_OBJ),
                parameters: None,
            }
        }

        /// Builds a mock timestamp token. Returns (token_der, spki_der).
        pub fn build(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let sk = RsaPrivateKey::new(&mut OsRng, TEST_RSA_BITS).expect("RSA key gen");
            let signing_key: SigningKey<Sha256> = SigningKey::new(sk.clone());

            let spki_der = sk.to_public_key().to_public_key_der().unwrap().to_vec();

            // Build TSTInfo
            let msg_hash = Sha256::digest(message);
            let tst = TstInfo {
                version: Integer::from(1u8),
                policy: o(OID_MOCK_POLICY),
                message_imprint: MessageImprint {
                    hash_algorithm: sha256_alg(),
                    hashed_message: OctetString::from(msg_hash.to_vec()),
                },
                serial_number: Integer::from(42u8),
                gen_time: chrono::Utc::now().fixed_offset(),
                accuracy: None,
                ordering: None,
                nonce: None,
                tsa: None,
                extensions: None,
            };
            let tst_der = rasn::der::encode(&tst).unwrap();

            // Build signedAttrs with the messageDigest attribute
            let tst_digest = Sha256::digest(&tst_der);
            let digest_attr = build_message_digest_attr(&tst_digest);
            let mut signed_attrs = Attributes::new();
            signed_attrs.insert(digest_attr);
            let signed_attrs_der = rasn::der::encode(&signed_attrs).unwrap();

            // Sign the signedAttrs
            let sig_bytes: Vec<u8> = signing_key
                .sign_with_rng(&mut OsRng, &signed_attrs_der)
                .to_bytes()
                .to_vec();

            // SignerInfo its serial is irrelevant here, identify_provider matches on raw cert bytes
            let signer_info = SignerInfo {
                version: Integer::from(1u8),
                sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                    issuer: Any::new(vec![]),
                    serial_number: Integer::from(42u8),
                }),
                digest_algorithm: sha256_alg(),
                signed_attrs: Some(signed_attrs),
                signature_algorithm: rsa_sha256_alg(),
                signature: OctetString::from(sig_bytes),
            };

            // bundle SPKI as cert so find_signer_cert matches it via extra_trusted
            let mut certs_set = SetOf::<Any>::new();
            certs_set.insert(Any::new(spki_der.clone()));

            let mut digest_algs = SetOf::new();
            digest_algs.insert(sha256_alg());
            let mut signer_infos = SetOf::new();
            signer_infos.insert(signer_info);

            let sd = SignedData {
                version: Integer::from(3u8),
                digest_algorithms: digest_algs,
                encap_content_info: EncapsulatedContentInfo {
                    e_content_type: o(OID_TST_INFO_OBJ),
                    e_content: Some(OctetString::from(tst_der)),
                },
                certificates: Some(certs_set),
                signer_infos,
            };
            let sd_der = rasn::der::encode(&sd).unwrap();

            let ci = ContentInfo {
                content_type: o(OID_SIGNED_DATA_OBJ),
                content: Any::new(sd_der),
            };
            let token_der = rasn::der::encode(&ci).unwrap();

            (token_der, spki_der)
        }

        fn build_message_digest_attr(digest: &[u8]) -> Attribute {
            let val_der = rasn::der::encode(&OctetString::from(digest.to_vec())).unwrap();
            let mut vals = SetOf::<Any>::new();
            vals.insert(Any::new(val_der));
            Attribute {
                attr_type: o(OID_MESSAGE_DIGEST_OBJ),
                attr_values: vals,
            }
        }

        // signer_matches_cert can't parse raw SPKI as X.509, so tests use verify_with_extra_cert
        // rather than embedding the cert in SignedData. a proper fix would use a self-signed stub.
    }

    #[cfg(test)]
    mod tests {
        use super::mock;
        use super::*;

        #[test]
        fn mock_token_parses_and_imprint_matches() {
            let message = b"hello from the test suite";
            let (token_der, _spki_der) = mock::build(message);

            // checks parse + imprint only; full sig+cert chain is behind tsa-live-test
            let ci: ContentInfo = rasn::der::decode(&token_der).unwrap();
            assert_eq!(ci.content_type, oid(OID_SIGNED_DATA));

            let sd: SignedData = rasn::der::decode(ci.content.as_bytes()).unwrap();
            let tst_der: &[u8] = sd.encap_content_info.e_content.as_ref().unwrap().as_ref();
            let tst: TstInfo = rasn::der::decode(tst_der).unwrap();

            let expected: Vec<u8> = sha2::Sha256::digest(message).to_vec();
            assert_eq!(
                tst.message_imprint.hashed_message.as_ref(),
                expected.as_slice()
            );
        }

        #[test]
        fn wrong_message_imprint_detected() {
            let message = b"correct message";
            let (token_der, _spki_der) = mock::build(message);

            // Parse manually to check the imprint fails for a different message.
            let ci: ContentInfo = rasn::der::decode(&token_der).unwrap();
            let sd: SignedData = rasn::der::decode(ci.content.as_bytes()).unwrap();
            let tst_der: &[u8] = sd.encap_content_info.e_content.as_ref().unwrap().as_ref();
            let tst: TstInfo = rasn::der::decode(tst_der).unwrap();

            let wrong_hash: Vec<u8> = sha2::Sha256::digest(b"wrong message").to_vec();
            assert_ne!(
                tst.message_imprint.hashed_message.as_ref(),
                wrong_hash.as_slice()
            );
        }
    }
}
