// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Resource URI parsing for resources obtained from Trustee.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const RESOURCE_ID_ERROR_INFO: &str =
    "invalid KBS resource URI, expected kbs[+plugin]://<kbs-address>/<path>";

const SCHEME: &str = "kbs";
pub const DEFAULT_RESOURCE_PLUGIN: &str = "resource";

/// Identifies a resource exposed by a Trustee plugin.
///
/// The default `kbs://` scheme addresses the `resource` plugin. Other plugins
/// use `kbs+<plugin>://`, and their resource paths may contain any positive
/// number of segments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceUri {
    pub kbs_address: String,
    pub plugin: String,
    pub path: Vec<String>,
    pub query: Option<String>,
}

/// The three-segment path required by Trustee's default `resource` plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourcePluginPath {
    pub repo: String,
    pub r#type: String,
    pub tag: String,
}

impl TryFrom<&str> for ResourceUri {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let url = url::Url::try_from(value).map_err(|_| RESOURCE_ID_ERROR_INFO)?;
        Self::try_from(url)
    }
}

impl TryFrom<url::Url> for ResourceUri {
    type Error = &'static str;

    fn try_from(value: url::Url) -> Result<Self, Self::Error> {
        let mut kbs_address = value.host_str().unwrap_or_default().to_string();

        if !kbs_address.is_empty() {
            if let Some(port) = value.port() {
                kbs_address.push(':');
                kbs_address.push_str(&port.to_string());
            }
        }

        let plugin = match value.scheme() {
            SCHEME => DEFAULT_RESOURCE_PLUGIN.to_string(),
            scheme if scheme.starts_with("kbs+") => {
                let plugin = scheme.trim_start_matches("kbs+");
                if plugin.is_empty() {
                    return Err("scheme kbs+ requires a plugin name, e.g. kbs+pkcs11");
                }
                plugin.to_string()
            }
            _ => return Err("scheme must be kbs or kbs+<plugin>"),
        };

        let path = value.path().strip_prefix('/').unwrap_or(value.path());
        let path = parse_path(path)?;

        Ok(Self {
            kbs_address,
            plugin,
            path,
            query: value.query().map(ToString::to_string),
        })
    }
}

impl From<ResourceUri> for url::Url {
    fn from(value: ResourceUri) -> Self {
        url::Url::try_from(value.whole_uri().as_str()).expect("unexpected resource URI parse")
    }
}

impl TryFrom<ResourceUri> for ResourcePluginPath {
    type Error = anyhow::Error;

    fn try_from(value: ResourceUri) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&ResourceUri> for ResourcePluginPath {
    type Error = anyhow::Error;

    fn try_from(value: &ResourceUri) -> Result<Self, Self::Error> {
        if value.plugin != DEFAULT_RESOURCE_PLUGIN {
            bail!(
                "resource URI plugin must be {DEFAULT_RESOURCE_PLUGIN} instead of {}",
                value.plugin
            );
        }

        if value.path.len() != 3 {
            bail!(
                "resource URI path must contain 3 segments instead of {}",
                value.path.len()
            );
        }

        Ok(Self {
            repo: value.path[0].clone(),
            r#type: value.path[1].clone(),
            tag: value.path[2].clone(),
        })
    }
}

impl ResourceUri {
    pub fn new(
        kbs_uri: &str,
        resource_path: &str,
        plugin: Option<&str>,
        query: Option<&str>,
    ) -> Result<Self> {
        let kbs_address = match url::Url::parse(kbs_uri) {
            Ok(url) => {
                let host = url
                    .host_str()
                    .ok_or_else(|| anyhow!("Invalid URL: {url}"))?;

                match url.port() {
                    Some(port) => format!("{host}:{port}"),
                    None => host.to_string(),
                }
            }
            Err(_) => kbs_uri.to_string(),
        };

        let path = resource_path
            .strip_prefix('/')
            .ok_or_else(|| anyhow!("Resource path {resource_path} must start with '/'"))?;

        Ok(Self {
            kbs_address,
            plugin: plugin.unwrap_or(DEFAULT_RESOURCE_PLUGIN).to_string(),
            path: parse_path(path).map_err(anyhow::Error::msg)?,
            query: query.map(ToString::to_string),
        })
    }

    pub fn whole_uri(&self) -> String {
        let scheme = match self.plugin.as_str() {
            DEFAULT_RESOURCE_PLUGIN => SCHEME.to_string(),
            plugin => format!("{SCHEME}+{plugin}"),
        };
        let uri = format!("{scheme}://{}/{}", self.kbs_address, self.resource_path());

        match &self.query {
            Some(query) => format!("{uri}?{query}"),
            None => uri,
        }
    }

    /// Returns the Trustee plugin name. `kbs://` maps to `resource`.
    pub fn plugin(&self) -> &str {
        &self.plugin
    }

    /// Returns the slash-separated path sent to the Trustee plugin.
    pub fn resource_path(&self) -> String {
        self.path.join("/")
    }
}

fn parse_path(path: &str) -> std::result::Result<Vec<String>, &'static str> {
    if path.is_empty() {
        return Err(RESOURCE_ID_ERROR_INFO);
    }

    let segments: Vec<String> = path.split('/').map(ToString::to_string).collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return Err("resource URI path must not contain empty segments");
    }

    Ok(segments)
}

impl Serialize for ResourceUri {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.whole_uri())
    }
}

impl<'de> Deserialize<'de> for ResourceUri {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value: &str = Deserialize::deserialize(deserializer)?;
        value
            .try_into()
            .map_err(|error| serde::de::Error::custom(format!("{error:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::{ResourcePluginPath, ResourceUri, DEFAULT_RESOURCE_PLUGIN};
    use rstest::rstest;

    #[rstest]
    #[case(
        "kbs:///alice/cosign-key/213",
        "",
        "resource",
        "alice/cosign-key/213",
        None
    )]
    #[case(
        "kbs:///repo/type/tag?param1=value1&param2=value2",
        "",
        "resource",
        "repo/type/tag",
        Some("param1=value1&param2=value2")
    )]
    #[case("kbs+pkcs11:///slot/key/label", "", "pkcs11", "slot/key/label", None)]
    #[case(
        "kbs+custom://example.com:8080/a/b/c/d/e",
        "example.com:8080",
        "custom",
        "a/b/c/d/e",
        None
    )]
    fn serialization_round_trip(
        #[case] uri: &str,
        #[case] address: &str,
        #[case] plugin: &str,
        #[case] path: &str,
        #[case] query: Option<&str>,
    ) {
        let parsed: ResourceUri = uri.try_into().expect("parse resource URI");
        assert_eq!(parsed.kbs_address, address);
        assert_eq!(parsed.plugin(), plugin);
        assert_eq!(parsed.resource_path(), path);
        assert_eq!(parsed.query.as_deref(), query);
        assert_eq!(parsed.whole_uri(), uri);
        assert_eq!(
            serde_json::to_string(&parsed).unwrap(),
            format!("\"{uri}\"")
        );

        let as_url: url::Url = parsed.clone().into();
        let from_url = ResourceUri::try_from(as_url).expect("parse URL");
        assert_eq!(from_url, parsed);
    }

    #[test]
    fn default_resource_plugin_has_canonical_short_form() {
        let shorthand: ResourceUri = "kbs:///repo/type/tag".try_into().unwrap();
        let explicit: ResourceUri = "kbs+resource:///repo/type/tag".try_into().unwrap();

        assert_eq!(shorthand, explicit);
        assert_eq!(explicit.plugin(), DEFAULT_RESOURCE_PLUGIN);
        assert_eq!(explicit.whole_uri(), "kbs:///repo/type/tag");
    }

    #[rstest]
    #[case("http:///repo/type/tag", "scheme must be kbs")]
    #[case("kbs+:///repo/type/tag", "requires a plugin name")]
    #[case("kbs://example.com", "expected kbs")]
    #[case("kbs:///repo//tag", "empty segments")]
    fn rejects_invalid_uri(#[case] uri: &str, #[case] expected: &str) {
        let error = ResourceUri::try_from(uri).unwrap_err();
        assert!(error.contains(expected), "unexpected error: {error}");
    }

    #[test]
    fn constructor_keeps_one_path_separator() {
        let uri = ResourceUri::new(
            "https://kbs.example.com:8443/",
            "/repo/type/tag",
            Some("pkcs11"),
            Some("slot=1"),
        )
        .unwrap();

        assert_eq!(
            uri.whole_uri(),
            "kbs+pkcs11://kbs.example.com:8443/repo/type/tag?slot=1"
        );
    }

    #[test]
    fn converts_only_default_three_segment_resource_paths() {
        let uri: ResourceUri = "kbs:///repo/type/tag".try_into().unwrap();
        assert_eq!(
            ResourcePluginPath::try_from(&uri).unwrap(),
            ResourcePluginPath {
                repo: "repo".into(),
                r#type: "type".into(),
                tag: "tag".into(),
            }
        );

        let plugin_uri: ResourceUri = "kbs+pkcs11:///repo/type/tag".try_into().unwrap();
        assert!(ResourcePluginPath::try_from(plugin_uri).is_err());

        let long_uri: ResourceUri = "kbs:///repo/type/tag/extra".try_into().unwrap();
        assert!(ResourcePluginPath::try_from(long_uri).is_err());
    }
}
