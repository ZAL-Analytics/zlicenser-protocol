//! In-process mock RFC 3161 TSA server for integration testing.
//! Binds to a random port, signs requests with a fresh P-256 cert.
//! Only compiled with the `tsa-test-utils` feature.

use std::sync::Arc;

use chrono::offset::Utc;
use p256::{
    ecdsa::{signature::RandomizedSigner, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use rand::rngs::OsRng;
use rasn::prelude::*;
use rasn_pkix::Certificate;
use sha2::{Digest, Sha256};

use crate::tsa::verify::inner::{
    AlgorithmIdentifier, Attribute, Attributes, CertificateSet, ContentInfo,
    EncapsulatedContentInfo, IssuerAndSerialNumber, MessageImprint, SignedData, SignerIdentifier,
    SignerInfo, TstInfo,
};

// OIDs used when building mock tokens
const OID_SHA256: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_ECDSA_SHA256: &[u32] = &[1, 2, 840, 10045, 4, 3, 2];
const OID_SIGNED_DATA: &[u32] = &[1, 2, 840, 113549, 1, 7, 2];
const OID_TST_INFO: &[u32] = &[1, 2, 840, 113549, 1, 9, 16, 1, 4];
const OID_MESSAGE_DIGEST: &[u32] = &[1, 2, 840, 113549, 1, 9, 4];
const OID_MOCK_POLICY: &[u32] = &[1, 3, 6, 1, 4, 1, 0, 1];

fn oid(parts: &[u32]) -> ObjectIdentifier {
    ObjectIdentifier::new(parts.to_vec()).unwrap()
}

/// Self-signed P-256 test certificate and its private key.
pub struct TestCert {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl TestCert {
    pub fn generate() -> Self {
        use rcgen::{CertificateParams, KeyPair};
        let key = KeyPair::generate().expect("rcgen key gen");
        let params =
            CertificateParams::new(vec!["mock-tsa.local".to_string()]).expect("rcgen params");
        let cert = params.self_signed(&key).expect("rcgen self_signed");
        Self {
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }
}

/// In-process HTTP TSA server on a random local port. Dropped when shut down.
pub struct MockTsaServer {
    addr: std::net::SocketAddr,
    _shutdown: tokio::sync::oneshot::Sender<()>,
    pub test_cert: TestCert,
}

impl MockTsaServer {
    /// Starts the server in the background and returns immediately.
    pub async fn start() -> Self {
        use tokio::net::TcpListener;

        let cert = TestCert::generate();
        let cert_arc = Arc::new(cert.cert_der.clone());
        let key_arc = Arc::new(cert.key_der.clone());

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock TSA: bind");
        let addr = listener.local_addr().expect("mock TSA: local_addr");

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(serve_loop(listener, cert_arc, key_arc, shutdown_rx));

        Self {
            addr,
            _shutdown: shutdown_tx,
            test_cert: cert,
        }
    }

    /// URL to use with `request_token_to()` in tests.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

async fn serve_loop(
    listener: tokio::net::TcpListener,
    cert_der: Arc<Vec<u8>>,
    key_der: Arc<Vec<u8>>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                if let Ok((stream, _)) = result {
                    tokio::spawn(handle(stream, Arc::clone(&cert_der), Arc::clone(&key_der)));
                }
            }
            _ = &mut shutdown => break,
        }
    }
}

async fn handle(mut stream: tokio::net::TcpStream, cert_der: Arc<Vec<u8>>, key_der: Arc<Vec<u8>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n == 0 {
        return;
    }
    let raw = &buf[..n];

    let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return;
    };

    let headers = std::str::from_utf8(&raw[..header_end]).unwrap_or("");
    let content_length: usize = headers
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split_once(':').map(|x| x.1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    let body_start = header_end + 4;
    let body = &raw[body_start..(body_start + content_length).min(n)];

    let tsr = build_tsr_response(body, &cert_der, &key_der);

    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        tsr.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(&tsr).await;
}

fn build_tsr_response(ts_req_body: &[u8], cert_der: &[u8], key_der: &[u8]) -> Vec<u8> {
    let hash =
        extract_hash_from_req(ts_req_body).unwrap_or_else(|| Sha256::digest(b"fallback").to_vec());

    let token = build_token_for_hash(&hash, cert_der, key_der);

    // TimeStampResp = SEQUENCE { PKIStatusInfo(granted=0), TimeStampToken }
    let status: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x00];
    wrap_sequence(&[status, &token].concat())
}

/// Builds an RFC 3161 TimeStampToken for the given pre-hashed message.
/// Can be called directly in unit tests without a full HTTP server.
pub fn build_token_for_hash(hashed_message: &[u8], cert_der: &[u8], key_der: &[u8]) -> Vec<u8> {
    let sha256_alg = AlgorithmIdentifier {
        algorithm: oid(OID_SHA256),
        parameters: None,
    };

    let tst = TstInfo {
        version: Integer::from(1u8),
        policy: oid(OID_MOCK_POLICY),
        message_imprint: MessageImprint {
            hash_algorithm: sha256_alg.clone(),
            hashed_message: OctetString::from(hashed_message.to_vec()),
        },
        serial_number: Integer::from(1u8),
        gen_time: Utc::now().fixed_offset(),
        accuracy: None,
        ordering: None,
        nonce: None,
        tsa: None,
        extensions: None,
    };
    let tst_der = rasn::der::encode(&tst).expect("encode TstInfo");

    // signedAttrs: messageDigest = SHA-256(tst_der)
    let tst_digest = Sha256::digest(&tst_der);
    let md_val = rasn::der::encode(&OctetString::from(tst_digest.to_vec())).unwrap();
    let mut md_vals = SetOf::<Any>::new();
    md_vals.insert(Any::new(md_val));
    let mut attrs = Attributes::new();
    attrs.insert(Attribute {
        attr_type: oid(OID_MESSAGE_DIGEST),
        attr_values: md_vals,
    });
    let attrs_der = rasn::der::encode(&attrs).expect("encode signedAttrs");

    // Sign the signedAttrs DER with ECDSA-P256-SHA256
    let sk = SigningKey::from_pkcs8_der(key_der).expect("p256 from pkcs8");
    let sig: Signature = sk.sign_with_rng(&mut OsRng, &attrs_der);
    let sig_bytes = sig.to_der().as_bytes().to_vec();

    // match cert serial so signer_matches_cert succeeds
    let cert_parsed: Certificate = rasn::der::decode(cert_der).expect("decode cert");
    let serial = cert_parsed.tbs_certificate.serial_number.clone();

    let signer_info = SignerInfo {
        version: Integer::from(1u8),
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            // issuer content isn't checked during matching; only serial is
            issuer: Any::new(vec![0x30, 0x00]),
            serial_number: serial,
        }),
        digest_algorithm: sha256_alg.clone(),
        signed_attrs: Some(attrs),
        signature_algorithm: AlgorithmIdentifier {
            algorithm: oid(OID_ECDSA_SHA256),
            parameters: None,
        },
        signature: OctetString::from(sig_bytes),
    };

    let mut cert_set = SetOf::<Any>::new();
    cert_set.insert(Any::new(cert_der.to_vec()));

    let mut digest_algs = SetOf::new();
    digest_algs.insert(sha256_alg);
    let mut signer_infos = SetOf::new();
    signer_infos.insert(signer_info);

    let sd = SignedData {
        version: Integer::from(3u8),
        digest_algorithms: digest_algs,
        encap_content_info: EncapsulatedContentInfo {
            e_content_type: oid(OID_TST_INFO),
            e_content: Some(OctetString::from(tst_der)),
        },
        certificates: Some(CertificateSet(cert_set)),
        signer_infos,
    };

    let ci = ContentInfo {
        content_type: oid(OID_SIGNED_DATA),
        content: Any::new(rasn::der::encode(&sd).expect("encode SignedData")),
    };
    rasn::der::encode(&ci).expect("encode ContentInfo")
}

/// Parses a `TimeStampReq` DER and extracts the `hashedMessage` bytes.
fn extract_hash_from_req(req_der: &[u8]) -> Option<Vec<u8>> {
    // SEQUENCE { INTEGER(version), SEQUENCE { SEQUENCE(AlgID), OCTET_STRING(hash) }, ... }
    let inner = unwrap_seq(req_der)?; // outer SEQUENCE
    let (_, rest) = next_elem(inner)?; // skip version INTEGER
    let (imprint, _) = next_elem(rest)?; // messageImprint SEQUENCE
    let imp_inner = unwrap_seq(imprint)?; // unwrap messageImprint
    let (_, after_alg) = next_elem(imp_inner)?; // skip AlgorithmIdentifier

    // OCTET STRING: 04 <len> <hash>
    if after_alg.first()? != &0x04 {
        return None;
    }
    let (len, off) = der_length(&after_alg[1..])?;
    Some(after_alg[1 + off..1 + off + len].to_vec())
}

fn wrap_sequence(inner: &[u8]) -> Vec<u8> {
    der_tlv(0x30, inner)
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xFF) as u8]);
    }
    out.extend_from_slice(value);
    out
}

fn unwrap_seq(data: &[u8]) -> Option<&[u8]> {
    if data.first()? != &0x30 {
        return None;
    }
    let (len, off) = der_length(&data[1..])?;
    Some(&data[1 + off..1 + off + len])
}

fn next_elem(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }
    let (len, off) = der_length(&data[1..])?;
    let end = 1 + off + len;
    Some((&data[..end], &data[end..]))
}

fn der_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()? as usize;
    if first < 0x80 {
        Some((first, 1))
    } else if first == 0x81 {
        Some((*data.get(1)? as usize, 2))
    } else if first == 0x82 {
        Some((((*data.get(1)? as usize) << 8) | *data.get(2)? as usize, 3))
    } else {
        None
    }
}
