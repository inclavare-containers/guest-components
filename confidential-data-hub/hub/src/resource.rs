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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_options_are_validated_in_cdh_without_changing_defaults() {
        use std::collections::HashMap;
        for entries in [
            vec![],
            vec![("sts", "YWJj")],
            vec![("kms_id", "kst-test")],
            vec![("region_id", "cn-beijing")],
            vec![
                ("sts", "YWJj"),
                ("kms_id", "kst-test"),
                ("region_id", "cn-beijing"),
            ],
        ] {
            let options = GetResourceOptions {
                resource_type: None,
                options: entries
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            };
            assert!(validate_options(&options, "aliyun_kms").is_ok());
        }
        assert!(validate_options(&GetResourceOptions::default(), "kbs").is_ok());
        for (configured, requested, key) in [
            ("kbs", None, Some("sts")),
            ("aliyun_kms", Some("kbs"), None),
            ("kbs", Some("aliyun_kms"), None),
            ("aliyun_kms", Some(""), None),
            ("aliyun_kms", Some("private-marker"), None),
            ("aliyun_kms", None, Some("private-marker")),
        ] {
            let options = GetResourceOptions {
                resource_type: requested.map(str::to_owned),
                options: key
                    .map(|k| HashMap::from([(k.into(), "private-marker".into())]))
                    .unwrap_or_default(),
            };
            let error = validate_options(&options, configured).unwrap_err();
            assert!(!error.to_string().contains("private-marker"));
            assert!(!format!("{options:?}").contains("private-marker"));
        }
        for backend in ["kbs", "aliyun_kms"] {
            assert!(validate_options(
                &GetResourceOptions {
                    resource_type: Some(backend.into()),
                    ..Default::default()
                },
                backend
            )
            .is_ok());
        }
        let oversized = GetResourceOptions {
            options: HashMap::from([("sts".into(), "x".repeat(20 * 1024 + 1))]),
            ..Default::default()
        };
        assert!(validate_options(&oversized, "aliyun_kms").is_err());
    }

    #[cfg(feature = "aliyun")]
    #[tokio::test]
    async fn malformed_kms_options_are_rejected_by_cdh_before_network_access() {
        let config:CdhConfig=toml::from_str("[kbc]\nname='aliyun_kms_kbc'\ninstance_id='kst-test'\necs_ram_role_name='product-role'\nregion_id='cn-beijing'").unwrap();
        let resolver = ResourceResolver::new(&config).unwrap();
        for (key, value) in [
            ("sts", ""),
            ("sts", "not-base64!"),
            ("kms_id", ""),
            ("kms_id", "https://kms.example"),
            ("region_id", ""),
            ("region_id", "cn/beijing"),
            ("region_id", "cn_beijing"),
            ("unknown", "private-marker"),
        ] {
            let options = GetResourceOptions {
                options: std::collections::HashMap::from([(key.into(), value.into())]),
                ..Default::default()
            };
            assert!(matches!(
                resolver.get_resource("kbs:///secret", &options).await,
                Err(kms::Error::InvalidResourceOptions(_))
            ));
        }
    }

    #[cfg(feature = "aliyun")]
    #[test]
    fn backend_is_selected_by_configuration_variant_not_url() {
        let config: CdhConfig = toml::from_str(
            r#"
[kbc]
name = "cc_kbc"
url = "https://trustee.example/api"
"#,
        )
        .unwrap();
        assert!(matches!(
            ResourceResolver::new(&config).unwrap().backend,
            Backend::Kbs
        ));
        let mut config = config;
        config.kbc = KbcConfig::Cc(crate::KbsConfig {
            url: "kst-test".into(),
            kbs_cert: None,
        });
        assert!(ResourceResolver::new(&config).is_err());
        config = toml::from_str("[kbc]\nname='aliyun_kms_kbc'\ninstance_id='kst-test'\necs_ram_role_name='product-role'").unwrap();
        assert!(matches!(
            ResourceResolver::new(&config).unwrap().backend,
            Backend::AliyunKms(_)
        ));
    }

    #[test]
    fn accepts_single_component_and_preserves_nested_names() {
        for name in ["my-secret", "my-repo/my-type/my-data", "app/secret_v1"] {
            assert_eq!(kms_secret_name(&format!("kbs:///{name}")).unwrap(), name);
        }
    }

    #[test]
    fn rejects_authority_query_encoding_and_traversal() {
        for uri in [
            "my-secret",
            "kbs://host/secret",
            "https://host/x",
            "kbs:///",
            "kbs:////x",
            "kbs:///a/../b",
            "kbs:///./x",
            "kbs:///a//b",
            "kbs:///a%2Fb",
            "kbs:///x?query",
            "kbs:///x#frag",
        ] {
            assert!(kms_secret_name(uri).is_err(), "{uri}");
        }
    }
}
