use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    crypto::{
        aead::{self, AeadKey, Nonce},
        hash, shamir,
    },
    error::Error,
    fingerprint::identifier::{HardwareIdentifier, IdentifierKind},
};

// Domain separation constant so identifier hashes can't be confused with other BLAKE3 hashes.
const IDENTIFIER_KEY_DOMAIN: &[u8; 32] = b"zlicenser-v1-hw-identifier-key--";

/// The reconstructed 32-byte secret that is stable for matching hardware.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSecret([u8; 32]);

impl MasterSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSecret([REDACTED])")
    }
}

// real impl is in linux/ (collect-linux feature); tests use MockCollector
pub trait HardwareCollector {
    fn collect(&self) -> crate::Result<Vec<HardwareIdentifier>>;
}

/// Mock collector for tests and platforms without real hardware collection.
pub struct MockCollector {
    identifiers: Vec<HardwareIdentifier>,
}

impl MockCollector {
    pub fn new(identifiers: Vec<HardwareIdentifier>) -> Self {
        Self { identifiers }
    }

    /// Creates a fixture with a realistic spread of identifier kinds.
    pub fn default_fixture() -> Self {
        use crate::fingerprint::identifier::IdentifierKind::{
            CpuVendorAndModel, DiskSerial, MacAddress, MachineId, PciSignature, SmbiosBoardUuid,
            SmbiosSystemSerial,
        };
        let entries = [
            (SmbiosBoardUuid, b"mock-board-uuid-0000".as_slice()),
            (SmbiosSystemSerial, b"mock-system-serial-00"),
            (CpuVendorAndModel, b"GenuineIntel|Intel(R) Core(TM) i7"),
            (MachineId, b"aabbccddeeff00112233445566778899"),
            (DiskSerial { index: 0 }, b"MOCK_DISK_0_SERIAL"),
            (MacAddress { index: 0 }, b"\x00\x11\x22\x33\x44\x55"),
            (PciSignature { index: 0 }, b"8086:1234"),
        ];
        Self {
            identifiers: entries
                .iter()
                .map(|(kind, val)| HardwareIdentifier::new(kind.clone(), val.to_vec()))
                .collect(),
        }
    }
}

impl HardwareCollector for MockCollector {
    fn collect(&self) -> crate::Result<Vec<HardwareIdentifier>> {
        Ok(self.identifiers.clone())
    }
}

/// One AEAD-encrypted Shamir share tied to a specific hardware identifier kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedShare {
    pub kind: IdentifierKind,
    #[serde(with = "crate::wire::bytes::nonce_bytes")]
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Persisted after enrollment alongside the license. Needs the master secret to decrypt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    pub shares: Vec<EncryptedShare>,
    pub threshold: u8,
}

/// Stable hash of the given identifiers, sorted by kind so collection order doesn't matter.
pub fn compute_commitment(identifiers: &[HardwareIdentifier]) -> [u8; 32] {
    let mut sorted: Vec<&HardwareIdentifier> = identifiers.iter().collect();
    sorted.sort_by(|a, b| {
        let ka = format!("{:?}", a.kind);
        let kb = format!("{:?}", b.kind);
        ka.cmp(&kb)
    });
    let mut combined = Vec::new();
    for id in &sorted {
        let key_repr = format!("{:?}", id.kind);
        combined.extend_from_slice(key_repr.as_bytes());
        combined.push(b':');
        combined.extend_from_slice(&id.value);
        combined.push(b'\n');
    }
    *hash::hash(&combined).as_bytes()
}

pub struct FuzzyExtractor;

impl FuzzyExtractor {
    /// Enrolls identifiers. Returns the master secret (never stored, keep it!) and the enrollment record.
    /// threshold must be >= 1 and <= identifiers.len().
    pub fn enroll(
        identifiers: &[HardwareIdentifier],
        threshold: u8,
    ) -> crate::Result<(MasterSecret, EnrollmentRecord)> {
        let n = identifiers.len();
        if n == 0 {
            return Err(Error::Collection("no hardware identifiers provided".into()));
        }
        if threshold as usize > n {
            return Err(Error::Collection(
                "threshold exceeds number of identifiers".into(),
            ));
        }
        if threshold == 0 {
            return Err(Error::Collection("threshold must be at least 1".into()));
        }

        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);

        let n_u8 = u8::try_from(n)
            .map_err(|_| Error::Collection("too many hardware identifiers (max 255)".into()))?;
        let shares = shamir::split(&secret, threshold, n_u8)?;

        let encrypted: crate::Result<Vec<EncryptedShare>> = identifiers
            .iter()
            .zip(shares.iter())
            .map(|(id, share)| {
                let key = derive_identifier_key(&id.value);
                let nonce = Nonce::random();
                let ciphertext = aead::encrypt(&key, &nonce, &share_to_bytes(share), &[])?;
                Ok(EncryptedShare {
                    kind: id.kind.clone(),
                    nonce: *nonce.as_bytes(),
                    ciphertext,
                })
            })
            .collect();
        let encrypted = encrypted?;

        Ok((
            MasterSecret(secret),
            EnrollmentRecord {
                shares: encrypted,
                threshold,
            },
        ))
    }

    /// Reconstructs the master secret. Needs at least record.threshold identifiers to still match.
    pub fn reconstruct(
        identifiers: &[HardwareIdentifier],
        record: &EnrollmentRecord,
    ) -> crate::Result<MasterSecret> {
        let mut recovered = Vec::new();

        for stored in &record.shares {
            let Some(current) = identifiers.iter().find(|id| id.kind == stored.kind) else {
                continue;
            };

            let key = derive_identifier_key(&current.value);
            let nonce = Nonce::from_bytes(stored.nonce);
            let Ok(plaintext) = aead::decrypt(&key, &nonce, &stored.ciphertext, &[]) else {
                continue; // identifier changed, skip this share
            };

            if let Some(share) = bytes_to_share(&plaintext) {
                recovered.push(share);
            }
        }

        if recovered.len() < record.threshold as usize {
            return Err(Error::InsufficientIdentifiers {
                recovered: recovered.len(),
                threshold: record.threshold as usize,
            });
        }

        let secret = shamir::combine(&recovered)?;
        Ok(MasterSecret(secret))
    }
}

fn derive_identifier_key(identifier_value: &[u8]) -> AeadKey {
    let h = hash::keyed_hash(IDENTIFIER_KEY_DOMAIN, identifier_value);
    AeadKey::from_bytes(h.as_bytes())
}

fn share_to_bytes(share: &shamir::Share) -> Vec<u8> {
    // ciborium for consistency with the rest of the wire format
    crate::wire::encode(share).expect("share serialisation should never fail")
}

fn bytes_to_share(bytes: &[u8]) -> Option<shamir::Share> {
    crate::wire::decode(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_identifiers() -> Vec<HardwareIdentifier> {
        MockCollector::default_fixture().collect().unwrap()
    }

    #[test]
    fn enroll_and_reconstruct_exact_match() {
        let ids = fixture_identifiers();
        let (secret, record) = FuzzyExtractor::enroll(&ids, 5).unwrap();
        let recovered = FuzzyExtractor::reconstruct(&ids, &record).unwrap();
        assert_eq!(secret.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn reconstruct_tolerates_missing_identifiers() {
        let ids = fixture_identifiers();
        let threshold = 4u8;
        let (secret, record) = FuzzyExtractor::enroll(&ids, threshold).unwrap();

        // Drop two identifiers so only 5 of 7 are present (threshold = 4, should still work).
        let partial: Vec<_> = ids.iter().take(5).cloned().collect();
        let recovered = FuzzyExtractor::reconstruct(&partial, &record).unwrap();
        assert_eq!(secret.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn reconstruct_fails_below_threshold() {
        let ids = fixture_identifiers();
        let threshold = 5u8;
        let (_secret, record) = FuzzyExtractor::enroll(&ids, threshold).unwrap();

        // Provide only 3 correct identifiers.
        let partial: Vec<_> = ids.iter().take(3).cloned().collect();
        let result = FuzzyExtractor::reconstruct(&partial, &record);
        assert!(matches!(
            result,
            Err(Error::InsufficientIdentifiers {
                recovered: 3,
                threshold: 5
            })
        ));
    }

    #[test]
    fn reconstruct_fails_when_identifier_value_changed() {
        let ids = fixture_identifiers();
        let (_secret, record) = FuzzyExtractor::enroll(&ids, 7).unwrap();

        // Replace all values with different bytes, none should decrypt.
        let tampered: Vec<_> = ids
            .iter()
            .map(|id| HardwareIdentifier::new(id.kind.clone(), b"wrong-value".to_vec()))
            .collect();
        let result = FuzzyExtractor::reconstruct(&tampered, &record);
        assert!(result.is_err());
    }

    #[test]
    fn commitment_is_stable() {
        let ids = fixture_identifiers();
        assert_eq!(compute_commitment(&ids), compute_commitment(&ids));
    }

    #[test]
    fn commitment_changes_when_value_changes() {
        let ids = fixture_identifiers();
        let mut modified = ids.clone();
        modified[0].value = b"different".to_vec();
        assert_ne!(compute_commitment(&ids), compute_commitment(&modified));
    }

    #[test]
    fn enroll_rejects_zero_threshold() {
        let ids = fixture_identifiers();
        assert!(FuzzyExtractor::enroll(&ids, 0).is_err());
    }

    #[test]
    fn enroll_rejects_threshold_above_count() {
        let ids = fixture_identifiers();
        let too_high = u8::try_from(ids.len()).unwrap() + 1;
        assert!(FuzzyExtractor::enroll(&ids, too_high).is_err());
    }

    // proptest: any subset >= threshold reconstructs correctly
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_reconstruct_with_any_threshold_subset(
            drop_count in 0usize..3,
        ) {
            let ids = fixture_identifiers(); // 7 identifiers
            let threshold = u8::try_from(ids.len() - drop_count).unwrap();
            if threshold == 0 { return Ok(()); }
            let (secret, record) = FuzzyExtractor::enroll(&ids, threshold).unwrap();

            // Keep exactly `threshold` identifiers.
            let subset: Vec<_> = ids.iter().take(threshold as usize).cloned().collect();
            let recovered = FuzzyExtractor::reconstruct(&subset, &record).unwrap();
            prop_assert_eq!(secret.as_bytes(), recovered.as_bytes());
        }
    }
}
