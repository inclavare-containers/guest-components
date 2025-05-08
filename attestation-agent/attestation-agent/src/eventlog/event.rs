// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use crypto::HashAlgorithm;
use sha2::{digest::FixedOutput, Digest, Sha256, Sha384, Sha512};

#[derive(Clone)]
pub struct AAEventlog {
    pub hash_algorithm: HashAlgorithm,
    pub init_state: Vec<u8>,
    pub events: Vec<String>,
}

impl FromStr for AAEventlog {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let all_lines = input.lines().collect::<Vec<&str>>();

        let (initline, eventlines) = all_lines
            .split_first()
            .ok_or(anyhow!("at least one line should be included in AAEL"))?;

        // Init line looks like
        // INIT sha256/0000000000000000000000000000000000000000000000000000000000000000
        let init_line_items = initline.split_ascii_whitespace().collect::<Vec<&str>>();
        if init_line_items.len() != 2 {
            bail!("Illegal INIT event record.");
        }

        if init_line_items[0] != "INIT" {
            bail!("INIT event should start with `INIT` key word");
        }

        let (hash_algorithm, init_state) = init_line_items[1].split_once('/').ok_or(anyhow!(
            "INIT event should have `<sha-algorithm>/<init-PCR-value>` as content after `INIT`"
        ))?;

        let hash_algorithm = HashAlgorithm::from_str(hash_algorithm)
            .context("parse Hash Algorithm in INIT entry")?;
        let init_state = hex::decode(init_state).context("parse init state in INIT entry")?;

        let events = eventlines
            .iter()
            .map(|line| line.trim_end().to_string())
            .collect();

        Ok(Self {
            events,
            hash_algorithm,
            init_state,
        })
    }
}

impl AAEventlog {
    fn accumulate_hash<D: Digest + FixedOutput>(&self) -> Vec<u8> {
        let mut state = self.init_state.clone();

        let mut init_event_hasher = D::new();
        let init_event = format!(
            "INIT {}/{}",
            self.hash_algorithm.as_ref(),
            hex::encode(&self.init_state)
        );
        Digest::update(&mut init_event_hasher, init_event.as_bytes());
        let init_event_hash = init_event_hasher.finalize();

        let mut hasher = D::new();
        Digest::update(&mut hasher, &state);

        Digest::update(&mut hasher, init_event_hash);
        state = hasher.finalize().to_vec();

        self.events.iter().for_each(|event| {
            let mut event_hasher = D::new();
            Digest::update(&mut event_hasher, event);
            let event_hash = event_hasher.finalize();

            let mut hasher = D::new();
            Digest::update(&mut hasher, &state);
            Digest::update(&mut hasher, event_hash);
            state = hasher.finalize().to_vec();
        });

        state
    }

    /// Check the integrity of the AAEL, and gets a digest. Return whether the rtmr is the same as the digest.
    pub fn integrity_check(&self, rtmr: &[u8]) -> bool {
        let result = match self.hash_algorithm {
            HashAlgorithm::Sha256 => self.accumulate_hash::<Sha256>(),
            HashAlgorithm::Sha384 => self.accumulate_hash::<Sha384>(),
            HashAlgorithm::Sha512 => self.accumulate_hash::<Sha512>(),
        };

        rtmr == result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aa_eventlog_sha256() {
        let aael = r#"INIT sha256/0000000000000000000000000000000000000000000000000000000000000000
domain event operation
domain event2 operation"#;
        let aael = AAEventlog::from_str(aael).unwrap();
        assert_eq!(
            aael.events,
            vec![
                "domain event operation".to_string(),
                "domain event2 operation".to_string()
            ]
        );
        assert_eq!(
            aael.hash_algorithm,
            HashAlgorithm::from_str("sha256").unwrap()
        );
        assert_eq!(
            aael.init_state,
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );
        assert!(aael.integrity_check(
            &hex::decode("e3f24e31c29b371c521ead351f6fed0865695cf512cfcb0df658090217f6f678")
                .unwrap()
        ));
    }

    #[test]
    fn test_aa_eventlog_sha384() {
        let aael = r#"INIT sha384/00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
domain event operation
domain event2 operation"#;
        let aael = AAEventlog::from_str(aael).unwrap();
        assert_eq!(
            aael.events,
            vec![
                "domain event operation".to_string(),
                "domain event2 operation".to_string()
            ]
        );
        assert_eq!(
            aael.hash_algorithm,
            HashAlgorithm::from_str("sha384").unwrap()
        );
        assert_eq!(
            aael.init_state,
            hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );
        assert!(aael.integrity_check(
            &hex::decode("34f0b32ab53b0c41d4617d63666388fa824da49467544232dde0fd1332b734a9230a3928f1aafffc8dc7fd367669d68e")
                .unwrap()
        ));
    }

    #[test]
    fn test_aa_eventlog_sha512() {
        let aael = r#"INIT sha512/00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
domain event operation
domain event2 operation"#;
        let aael = AAEventlog::from_str(aael).unwrap();
        assert_eq!(
            aael.events,
            vec![
                "domain event operation".to_string(),
                "domain event2 operation".to_string()
            ]
        );
        assert_eq!(
            aael.hash_algorithm,
            HashAlgorithm::from_str("sha512").unwrap()
        );
        assert_eq!(
            aael.init_state,
            hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );
        assert!(aael.integrity_check(
            &hex::decode("841f9a2b8b20b144ad9d077cf2a18940a6dee908a808487fad0e43da6878ac3d87ffd75d2514405e8beb2f1b467523f81e81498dbb877782898e00af900eed6c")
                .unwrap()
        ));
    }
}
