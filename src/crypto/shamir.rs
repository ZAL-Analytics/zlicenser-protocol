use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use vsss_rs::Gf256;

use crate::error::Error;

/// An opaque Shamir share. First byte is the x-coordinate (share identifier).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share(Vec<u8>);


pub fn split(secret: &[u8; 32], threshold: u8, count: u8) -> Result<Vec<Share>, Error> {
    Gf256::split_array(threshold as usize, count as usize, secret.as_slice(), OsRng)
        .map(|shares| shares.into_iter().map(Share).collect())
        .map_err(|e| Error::Shamir(e.to_string()))
}

pub fn combine(shares: &[Share]) -> Result<[u8; 32], Error> {
    let raw: Vec<Vec<u8>> = shares.iter().map(|s| s.0.clone()).collect();
    let bytes = Gf256::combine_array(&raw).map_err(|e| Error::Shamir(e.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| Error::Shamir("reconstructed secret has wrong length".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shamir_roundtrip_3_of_5() {
        let secret = [0x42u8; 32];
        let shares = split(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // Every combination of any 3 shares must reconstruct the secret.
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                for k in (j + 1)..shares.len() {
                    let trio = [shares[i].clone(), shares[j].clone(), shares[k].clone()];
                    assert_eq!(combine(&trio).unwrap(), secret);
                }
            }
        }
    }

    #[test]
    fn shamir_below_threshold_fails_or_wrong() {
        let secret = [0x42u8; 32];
        let shares = split(&secret, 3, 5).unwrap();
        let result = combine(&shares[..2]);
        // vsss-rs may succeed but reconstruct the wrong value when below threshold.
        assert!(result.is_err() || result.unwrap() != secret);
    }

    #[test]
    fn shamir_2_of_3() {
        let secret = [0xdeu8; 32];
        let shares = split(&secret, 2, 3).unwrap();
        assert_eq!(combine(&shares[0..2]).unwrap(), secret);
        assert_eq!(combine(&shares[1..3]).unwrap(), secret);
    }
}
