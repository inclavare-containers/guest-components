// Copyright (c) 2024 Alibaba Cloud
// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Hash algorithms used to calculate runtime/init data binding
#[derive(
    EnumString, AsRefStr, Serialize, Deserialize, Clone, Debug, Display, Copy, PartialEq, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    #[default]
    #[strum(serialize = "sha256")]
    Sha256,

    #[strum(serialize = "sha384")]
    Sha384,

    #[strum(serialize = "sha512")]
    Sha512,
}

fn hash_reportdata<D: Digest>(material: &[u8]) -> Vec<u8> {
    D::new().chain_update(material).finalize().to_vec()
}

impl HashAlgorithm {
    /// Return the hash value length in bytes
    pub fn digest_len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    pub fn digest(&self, material: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha256 => hash_reportdata::<Sha256>(material),
            HashAlgorithm::Sha384 => hash_reportdata::<Sha384>(material),
            HashAlgorithm::Sha512 => hash_reportdata::<Sha512>(material),
        }
    }

    /// Return a list of all supported hash algorithms.
    pub fn list_all() -> Vec<Self> {
        vec![
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_list_all() {
        let algorithms = HashAlgorithm::list_all();
        assert_eq!(algorithms.len(), 3);
        assert_eq!(algorithms[0], HashAlgorithm::Sha256);
        assert_eq!(algorithms[1], HashAlgorithm::Sha384);
        assert_eq!(algorithms[2], HashAlgorithm::Sha512);
    }

    #[test]
    fn test_hash_algorithm_from_str() {
        assert_eq!(
            "sha256".parse::<HashAlgorithm>().unwrap(),
            HashAlgorithm::Sha256
        );
        assert_eq!(
            "sha384".parse::<HashAlgorithm>().unwrap(),
            HashAlgorithm::Sha384
        );
        assert_eq!(
            "sha512".parse::<HashAlgorithm>().unwrap(),
            HashAlgorithm::Sha512
        );
    }

    #[test]
    fn test_hash_algorithm_from_str_error() {
        assert!("sha256-384".parse::<HashAlgorithm>().is_err());
        assert!("sha384-512".parse::<HashAlgorithm>().is_err());
        assert!("sha512-384".parse::<HashAlgorithm>().is_err());
    }

    #[test]
    fn test_hash_algorithm_length() {
        assert_eq!(HashAlgorithm::Sha256.digest_len(), 32);
        assert_eq!(HashAlgorithm::Sha384.digest_len(), 48);
        assert_eq!(HashAlgorithm::Sha512.digest_len(), 64);
    }
}
