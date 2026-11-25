// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use openssl::rand::rand_bytes;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    rand_bytes(&mut bytes).unwrap();
    bytes
}

pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new() -> Self {
        let suffix = u128::from_ne_bytes(random_bytes());
        let path = std::env::temp_dir().join(format!("ocicrypt-test-{suffix:032x}"));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    pub fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
