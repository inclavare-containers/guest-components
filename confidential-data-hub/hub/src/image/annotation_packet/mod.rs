// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod v1;
pub mod v2;

pub use v2::AnnotationPacketV2 as AnnotationPacket;

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};

    use super::AnnotationPacket;

    #[test]
    fn compatiblity_with_old_packets() {
        let v1_raw = serde_json::json!({
            "kid": "kbs:///default/key/test",
            "wrapped_data": STANDARD.encode(rand::random::<[u8; 32]>()),
            "iv": STANDARD.encode(rand::random::<[u8; 12]>()),
            "wrap_type": "A256GCM",
        })
        .to_string();
        let _: AnnotationPacket =
            serde_json::from_str(&v1_raw).expect("unable to parse V1 with V2");
    }
}
