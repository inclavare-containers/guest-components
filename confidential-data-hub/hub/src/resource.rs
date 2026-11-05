// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

//! Backend selection is a deployment choice, never inferred from a resource URI.
use tokio::sync::OnceCell;

use crate::{kms, CdhConfig, KbcConfig};
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

    pub(crate) async fn get_resource(&self, uri: &str) -> kms::Result<Vec<u8>> {
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
                client.get_secret(name, &Annotations::default()).await
            }
        }
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
