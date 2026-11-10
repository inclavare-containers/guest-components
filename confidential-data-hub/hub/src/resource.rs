// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

//! Backend selection is a deployment choice, never inferred from a resource URI.
use tokio::sync::OnceCell;

use crate::{kms, CdhConfig, GetResourceOptions, KbcConfig};
use kms::{Annotations, Getter, ProviderSettings};

pub(crate) struct ResourceResolver {
    backend: Backend,
    kbs: OnceCell<Box<dyn Getter>>,
}

enum Backend {
    Kbs,
    #[cfg(feature = "aliyun")]
    AliyunKms(Box<kms::plugins::aliyun::AutomaticKmsClient>),
}

impl Backend {
    fn resource_type(&self) -> &str {
        match self {
            Self::Kbs => "kbs",
            #[cfg(feature = "aliyun")]
            Self::AliyunKms(_) => "aliyun_kms",
        }
    }
}

impl ResourceResolver {
    pub(crate) fn new(config: &CdhConfig) -> anyhow::Result<Self> {
        config.kbc.validate()?;
        let backend = match &config.kbc {
            #[cfg(feature = "aliyun")]
            KbcConfig::AliyunKms(kms) => {
                Backend::AliyunKms(Box::new(kms::plugins::aliyun::AutomaticKmsClient::new(
                    kms.clone(),
                    config.aa_socket.clone(),
                )?))
            }
            #[cfg(not(feature = "aliyun"))]
            KbcConfig::AliyunKms(_) => anyhow::bail!("aliyun_kms_kbc requires the aliyun feature"),
            KbcConfig::Cc(_) | KbcConfig::OfflineFs(_) | KbcConfig::OnlineSev(_) => Backend::Kbs,
        };
        Ok(Self {
            backend,
            kbs: OnceCell::new(),
        })
    }

    pub(crate) async fn get_resource(
        &self,
        uri: &str,
        options: &GetResourceOptions,
    ) -> kms::Result<Vec<u8>> {
        // Business validation lives here for REST, ttRPC and gRPC callers alike.
        // No request may select a backend outside the deployment configuration.
        validate_options(options, self.backend.resource_type())?;
        match &self.backend {
            Backend::Kbs => {
                let getter = self
                    .kbs
                    .get_or_try_init(|| async {
                        kms::new_getter("kbs", ProviderSettings::default()).await
                    })
                    .await?;
                getter.get_secret(uri, &Annotations::default()).await
            }
            #[cfg(feature = "aliyun")]
            Backend::AliyunKms(client) => {
                let name =
                    kms_secret_name(uri).map_err(|e| kms::Error::AliyunKmsError(e.to_string()))?;
                client
                    .get_secret_with_options(
                        name,
                        &Annotations::default(),
                        options.options.get("kms_id").map(String::as_str),
                        options.options.get("sts").map(String::as_str),
                        options.options.get("region_id").map(String::as_str),
                    )
                    .await
            }
        }
    }
}

fn validate_options(options: &GetResourceOptions, configured_type: &str) -> kms::Result<()> {
    use kms::Error::InvalidResourceOptions;
    if options
        .resource_type
        .as_deref()
        .is_some_and(|t| t != configured_type)
    {
        return Err(InvalidResourceOptions(
            "resource type does not match the configured backend",
        ));
    }
    if options.options.len() > 16
        || options
            .options
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
            > 20 * 1024
    {
        return Err(InvalidResourceOptions("resource options are too large"));
    }
    match configured_type {
        "kbs" if !options.options.is_empty() => Err(InvalidResourceOptions(
            "the KBS backend does not accept resource options",
        )),
        "aliyun_kms"
            if options
                .options
                .keys()
                .any(|k| !matches!(k.as_str(), "sts" | "kms_id" | "region_id")) =>
        {
            Err(InvalidResourceOptions("unsupported KMS resource option"))
        }
        _ => Ok(()),
    }
}

#[cfg(any(feature = "aliyun", test))]
fn kms_secret_name(uri: &str) -> anyhow::Result<&str> {
    let name = uri.strip_prefix("kbs:///").ok_or_else(|| {
        anyhow::anyhow!("KMS resources must use kbs:/// followed by a secret name")
    })?;
    anyhow::ensure!(
        !name.is_empty()
            && !name.starts_with('/')
            && !name.ends_with('/')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_+=.@-".contains(&b))
            && !name
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == ".."),
        "invalid KMS secret name; use an ASCII name without URL encoding or path traversal"
    );
    Ok(name)
}

