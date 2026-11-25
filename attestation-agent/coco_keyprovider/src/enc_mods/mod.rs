// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use jwt_simple::prelude::Ed25519KeyPair;
use log::{debug, info, warn};
use rand::TryRngCore;
use reqwest::Url;
use resource_uri::ResourceUri;
use serde::{Deserialize, Serialize};
use tokio::fs;

use self::kbs::register_kek;

mod crypto;
mod kbs;

/// `AnnotationPacket` is what a encrypted image layer's
/// `org.opencontainers.image.enc.keys.provider.attestation-agent`
/// annotation should contain when it is encrypted by CoCo's
/// encryption modules. Please refer to issue
/// <https://github.com/confidential-containers/attestation-agent/issues/113>
#[derive(Serialize, Deserialize)]
pub struct AnnotationPacket {
    // Key ID to manage multiple keys
    pub kid: String,
    // Encrypted key to unwrap (base64-encoded)
    pub wrapped_data: String,
    // Initialisation vector (base64-encoded)
    pub iv: String,
    // Wrap type to specify encryption algorithm and mode
    pub wrap_type: String,
}

struct InputParams {
    /// Whether this image is encrypted by sample key provider.
    /// By default `false`.
    /// If `sample` is enabled, the `keypath` field will be ignored.
    sample: bool,

    /// Specify the KEK of this image. keyid field will be
    /// included in AnnotationPacket. For example:
    /// `kbs:///default/key/test-tag`
    keyid: Option<String>,

    /// Specify the KEK to encrypted the image in local
    /// filesystem. This key will be read from fs and then
    /// used to encrypt the image. This key's length must
    /// be 32 bytes
    keypath: Option<String>,
}

const HARD_CODED_KEYID: &str = "kbs:///default/test-key/1";

const WRAP_TYPE: &str = "A256GCM";

/// When a KEK is randomly generated, a new kid will be generated
/// with this prefix.
const DEFAULT_KEY_REPO_PATH: &str = "/default/image-kek";

const KBS_RESOURCE_URL_PREFIX: &str = "kbs://";

fn parse_input_params(input: &str) -> InputParams {
    let map: HashMap<&str, &str> = input
        .split("::")
        .filter_map(|field| field.split_once('='))
        .collect();
    if map.get("algorithm") == Some(&"A256CTR") {
        warn!("A256CTR is a deprecated key wrapping option. The key is wrapped with {WRAP_TYPE}.");
    }
    let sample = map
        .get("sample")
        .map(|sa| sa.parse::<bool>().unwrap_or(false))
        .unwrap_or(false);
    let keyid = map.get("keyid").map(|id| id.to_string());
    let keypath = map.get("keypath").map(|p| p.to_string());
    InputParams {
        sample,
        keyid,
        keypath,
    }
}

/// This function will generate (key, iv, keyid) for given `InputParams`
async fn generate_key_parameters(input_params: &InputParams) -> Result<(Vec<u8>, Vec<u8>, String)> {
    let sample_flag = input_params.sample;
    match sample_flag {
        true => {
            info!("Use the sample keyprovider");
            let key_path = std::env::var_os("COCO_SAMPLE_KEY_FILE")
                .context("COCO_SAMPLE_KEY_FILE must point to a raw 32-byte key")?;
            let key = fs::read(key_path)
                .await
                .context("read sample keyprovider key")?;
            anyhow::ensure!(
                key.len() == 32,
                "sample keyprovider key must be exactly 32 bytes"
            );
            let mut iv = [0; 12];
            rand::rngs::OsRng.try_fill_bytes(&mut iv)?;
            Ok((key, iv.to_vec(), HARD_CODED_KEYID.into()))
        }
        // use input key and randomly generated iv
        false => match &input_params.keypath {
            Some(kpath) => {
                debug!("use given key from: {kpath}");
                let key = fs::read(kpath).await.context("read Key file failed")?;
                let mut iv = [0; 12];
                rand::rngs::OsRng.try_fill_bytes(&mut iv)?;
                let kid = match &input_params.keyid {
                    Some(kid) => kid.to_string(),
                    None => {
                        debug!("no kid input, generate a random kid");
                        let tag = uuid::Uuid::new_v4().to_string();
                        format!("{DEFAULT_KEY_REPO_PATH}/{tag}")
                    }
                };

                Ok((key.to_vec(), iv.to_vec(), kid))
            }
            None => {
                debug!("no key input, generate a random key");

                let mut iv = [0; 12];
                rand::rngs::OsRng.try_fill_bytes(&mut iv)?;

                let mut key = [0; 32];
                rand::rngs::OsRng.try_fill_bytes(&mut key)?;

                let kid = match &input_params.keyid {
                    Some(kid) => kid.to_string(),
                    None => {
                        debug!("no kid input, generate a random kid");
                        let tag = uuid::Uuid::new_v4().to_string();
                        format!("{DEFAULT_KEY_REPO_PATH}/{tag}")
                    }
                };
                Ok((key.to_vec(), iv.to_vec(), kid))
            }
        },
    }
}

/// Normalize the given keyid into (kbs addr, key path), s.t.
/// converting `kbs://...` or `../..` to `(<kbs-addr>, <repository>/<type>/<tag>)`.
fn normalize_path(key_id: &str) -> Result<(String, String)> {
    debug!("normalize key id {key_id}");

    if let Ok(resource_uri) = ResourceUri::try_from(key_id) {
        return Ok((
            resource_uri.kbs_address.clone(),
            resource_uri.resource_path(),
        ));
    }

    let values: Vec<&str> = key_id.split('/').collect();
    if values.len() == 4 {
        return Ok((
            values[0].to_string(),
            format!("{}/{}/{}", values[1], values[2], values[3]),
        ));
    }

    bail!(
        "Resource path {key_id} must follow one of the following formats:
                'kbs:///<repository>/<type>/<tag>'
                'kbs://<kbs-addr>/<repository>/<type>/<tag>'
                'kbs+<plugin>:///<path>'
                'kbs+<plugin>://<kbs-addr>/<path>'
                '<kbs-addr>/<repository>/<type>/<tag>'
                '/<repository>/<type>/<tag>'
            "
    )
}

fn normalized_annotation_kid(key_id: &str, kbs_address: &str, key_path: &str) -> String {
    match ResourceUri::try_from(key_id) {
        Ok(resource_uri) => resource_uri.whole_uri(),
        Err(_) => format!("{KBS_RESOURCE_URL_PREFIX}{kbs_address}/{key_path}"),
    }
}

/// The input parameters are encoded in the following format:
/// ```plaintext
/// <key1>=<value1>::<key2>=<value2>::...
/// ```
///
/// That is, a set of key-value pairs separated by double colons.
/// Now the supported key-value pairs are
/// | Key       |             Value                    | Usage                                                                                            |
/// |-----------|--------------------------------------|--------------------------------------------------------------------------------------------------|
/// | sample    | `true` or `false`                    | Whether this image is encrypted by sample key provider. By default `false`                       |
/// | keyid     | a KBS Resource URI, s.t. `kbs://..`  | Specify the KEK of this image. keyid field will be included in AnnotationPacket                  |
/// | keypath   | path to the KEK, e.g. `/home/key`    | Specify the KEK to encrypted the image in local filesystem                                       |
/// | algorithm | `A256GCM`                          | The provider always wraps layer key parameters with `A256GCM`. |
pub async fn enc_optsdata_gen_anno(
    kbs_parameter: (&Option<Url>, &Option<Ed25519KeyPair>),
    optsdata: &[u8],
    params: &str,
) -> Result<String> {
    let input_params = parse_input_params(params);
    let (key, iv, kid) = generate_key_parameters(&input_params)
        .await
        .context("generating key params")?;

    let (kbs_addr, k_path) = normalize_path(&kid)?;
    let annotation_kid = normalized_annotation_kid(&kid, &kbs_addr, &k_path);

    let encrypt_optsdata = crypto::encrypt(optsdata, &key, &iv).context("encrypt key options")?;

    if let (Some(addr), Some(private_key)) = kbs_parameter {
        if !input_params.sample {
            // We do not register KEK for sample kbc
            register_kek(private_key, addr, key, &k_path)
                .await
                .context("register KEK failed")?;
            info!("register KEK succeeded.");
        }
    }

    let engine = base64::engine::general_purpose::STANDARD;
    let annotation = AnnotationPacket {
        kid: annotation_kid,
        wrapped_data: engine.encode(encrypt_optsdata),
        iv: engine.encode(iv),
        wrap_type: WRAP_TYPE.to_string(),
    };

    serde_json::to_string(&annotation).map_err(|_| anyhow!("Serialize annotation failed"))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    #[rstest]
    #[case("kbs://a/b/c/d", ("a", "b/c/d"))]
    #[case("kbs:///b/c/d", ("", "b/c/d"))]
    #[case("kbs+pkcs11://a/slot/key/label", ("a", "slot/key/label"))]
    #[case("kbs+pkcs11:///slot/key/label/version", ("", "slot/key/label/version"))]
    #[case("a/b/c/d", ("a", "b/c/d"))]
    #[case("/b/c/d", ("", "b/c/d"))]
    fn test_normalize_keypath(#[case] input: &str, #[case] expected: (&str, &str)) {
        let res = crate::enc_mods::normalize_path(input).expect("normalize failed");
        assert_eq!(res.0, expected.0);
        assert_eq!(res.1, expected.1);
    }

    #[rstest]
    #[case(
        "kbs+pkcs11:///slot/key/label/version",
        "",
        "slot/key/label/version",
        "kbs+pkcs11:///slot/key/label/version"
    )]
    #[case(
        "kbs+resource:///repo/type/tag",
        "",
        "repo/type/tag",
        "kbs:///repo/type/tag"
    )]
    #[case("/repo/type/tag", "", "repo/type/tag", "kbs:///repo/type/tag")]
    fn annotation_keeps_plugin_and_canonicalizes_legacy_paths(
        #[case] input: &str,
        #[case] address: &str,
        #[case] path: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(
            crate::enc_mods::normalized_annotation_kid(input, address, path),
            expected
        );
    }
}
