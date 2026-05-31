pub mod evidency;
pub mod freetsa;
pub mod qtsa;

// Shared DER helpers used by all provider request builders.
pub(super) mod ts_request {
    use sha2::{Digest, Sha256};

    /// Builds a minimal DER `TimeStampReq` for a SHA-256 hash of `message`.
    pub fn build(message: &[u8]) -> Vec<u8> {
        let hash = Sha256::digest(message);
        build_from_hash(hash.as_slice())
    }

    /// Builds a `TimeStampReq` from a pre-computed SHA-256 hash.
    pub fn build_from_hash(hash: &[u8]) -> Vec<u8> {
        // SHA-256 OID: 2.16.840.1.101.3.4.2.1
        let sha256_oid: &[u8] = &[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        let null: &[u8] = &[0x05, 0x00];
        let alg_inner = [sha256_oid, null].concat();
        let alg = sequence(&alg_inner);

        let hashed = octet_string(hash);
        let imprint = sequence(&[alg.as_slice(), hashed.as_slice()].concat());

        let version: &[u8] = &[0x02, 0x01, 0x01]; // INTEGER 1
        let cert_req: &[u8] = &[0x01, 0x01, 0xff]; // BOOLEAN TRUE
        sequence(&[version, imprint.as_slice(), cert_req].concat())
    }

    /// Extracts the `TimeStampToken` from a `TimeStampResp`.
    /// A `TimeStampResp` is: SEQUENCE { PKIStatusInfo, TimeStampToken OPTIONAL }.
    pub fn extract_token(resp_der: &[u8]) -> crate::Result<Vec<u8>> {
        use crate::error::Error;

        let inner = unwrap_sequence(resp_der)
            .ok_or_else(|| Error::TsaParse("malformed TimeStampResp".into()))?;

        let (_, token_start) =
            next_element(inner).ok_or_else(|| Error::TsaParse("missing PKIStatusInfo".into()))?;

        if token_start.is_empty() {
            return Err(Error::TsaVerification(
                "TSA returned no token (request rejected)".into(),
            ));
        }

        Ok(token_start.to_vec())
    }

    // ---- minimal DER utilities --------------------------------------------------

    fn sequence(inner: &[u8]) -> Vec<u8> {
        tlv(0x30, inner)
    }

    fn octet_string(data: &[u8]) -> Vec<u8> {
        tlv(0x04, data)
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
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

    fn unwrap_sequence(data: &[u8]) -> Option<&[u8]> {
        if data.first()? != &0x30 {
            return None;
        }
        let (len, off) = length(&data[1..])?;
        Some(&data[1 + off..1 + off + len])
    }

    fn next_element(data: &[u8]) -> Option<(&[u8], &[u8])> {
        if data.is_empty() {
            return None;
        }
        let (len, off) = length(&data[1..])?;
        let end = 1 + off + len;
        Some((&data[..end], &data[end..]))
    }

    fn length(data: &[u8]) -> Option<(usize, usize)> {
        let first = *data.first()? as usize;
        if first < 0x80 {
            Some((first, 1))
        } else if first == 0x81 {
            Some((*data.get(1)? as usize, 2))
        } else if first == 0x82 {
            Some(((*data.get(1)? as usize) << 8 | *data.get(2)? as usize, 3))
        } else {
            None
        }
    }
}
