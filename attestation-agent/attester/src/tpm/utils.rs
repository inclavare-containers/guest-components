// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use base64::Engine;
use openssl::x509::X509;
use rsa as rust_rsa;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tss_esapi::abstraction::{
    ak::{create_ak, load_ak},
    ek::{create_ek_object, retrieve_ek_pubcert},
    pcr,
    public::DecodedKey,
    DefaultKey,
};
use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::interface_types::algorithm::{
    AsymmetricAlgorithm, HashingAlgorithm, SignatureSchemeAlgorithm,
};
use tss_esapi::structures::{
    pcr_selection_list::PcrSelectionListBuilder, pcr_slot::PcrSlot, AttestInfo, Private, Public,
    Signature, SignatureScheme, SymmetricDefinition,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::Marshall;
use tss_esapi::Context;

const TPM_QUOTE_PCR_SLOTS: [PcrSlot; 24] = [
    PcrSlot::Slot0,
    PcrSlot::Slot1,
    PcrSlot::Slot2,
    PcrSlot::Slot3,
    PcrSlot::Slot4,
    PcrSlot::Slot5,
    PcrSlot::Slot6,
    PcrSlot::Slot7,
    PcrSlot::Slot8,
    PcrSlot::Slot9,
    PcrSlot::Slot10,
    PcrSlot::Slot11,
    PcrSlot::Slot12,
    PcrSlot::Slot13,
    PcrSlot::Slot14,
    PcrSlot::Slot15,
    PcrSlot::Slot16,
    PcrSlot::Slot17,
    PcrSlot::Slot18,
    PcrSlot::Slot19,
    PcrSlot::Slot20,
    PcrSlot::Slot21,
    PcrSlot::Slot22,
    PcrSlot::Slot23,
];

pub fn create_tcti() -> Result<TctiNameConf> {
    match std::env::var("TEST_TCTI") {
        std::result::Result::Err(_) => Ok(TctiNameConf::Device(DeviceConfig::default())),
        std::result::Result::Ok(tctistr) => Ok(TctiNameConf::from_str(&tctistr)?),
    }
}

pub fn create_ctx_without_session() -> Result<Context> {
    let tcti = create_tcti()?;
    let ctx = Context::new(tcti)?;
    Ok(ctx)
}

pub fn create_ctx_with_session() -> Result<Context> {
    let mut ctx = create_ctx_without_session()?;
    let session = ctx.start_auth_session(
        None,
        None,
        None,
        SessionType::Hmac,
        SymmetricDefinition::AES_256_CFB,
        HashingAlgorithm::Sha256,
    )?;
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    ctx.tr_sess_set_attributes(
        session.unwrap(),
        session_attributes,
        session_attributes_mask,
    )?;
    ctx.set_sessions((session, None, None));

    Ok(ctx)
}

pub fn dump_ek_cert_pem() -> Result<String> {
    let mut context = create_ctx_without_session()?;

    let ek_cert_bytes = retrieve_ek_pubcert(&mut context, AsymmetricAlgorithm::Rsa)?;
    let ek_cert_x509 = X509::from_der(&ek_cert_bytes)?;
    let ek_cert_pem_bytes = ek_cert_x509.to_pem()?;
    let ek_cert = String::from_utf8(ek_cert_pem_bytes)?;

    Ok(ek_cert)
}

pub fn dump_pcr_sha256_digests() -> Result<Vec<String>> {
    let mut context = create_ctx_without_session()?;
    let selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &TPM_QUOTE_PCR_SLOTS)
        .build()?;
    let pcr_data = pcr::read_all(&mut context, selection_list)?;
    let pcr_bank = pcr_data
        .pcr_bank(HashingAlgorithm::Sha256)
        .ok_or(anyhow!("PCR bank not found"))?;
    let pcrs: Result<Vec<String>, _> = pcr_bank
        .into_iter()
        .map(|(_, digest)| {
            hex::encode(digest.value())
                .try_into()
                .map_err(|_| anyhow!("Invalid PCR digest"))
        })
        .collect();
    let pcrs = pcrs?;
    Ok(pcrs)
}

#[derive(Clone)]
pub struct AttestationKey {
    pub ak_private: Private,
    pub ak_public: Public,
}

pub fn generate_rsa_ak() -> Result<AttestationKey> {
    let mut context = create_ctx_without_session()?;

    let ek_handle = create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, DefaultKey)?;

    let ak = create_ak(
        &mut context,
        ek_handle,
        HashingAlgorithm::Sha256,
        SignatureSchemeAlgorithm::RsaSsa,
        None,
        DefaultKey,
    )?;

    Ok(AttestationKey {
        ak_private: ak.out_private,
        ak_public: ak.out_public,
    })
}

pub fn get_ak_pub(ak: AttestationKey) -> Result<rust_rsa::RsaPublicKey> {
    let mut context = create_ctx_without_session()?;
    let ek_handle = create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, DefaultKey)?;
    let key_handle = load_ak(
        &mut context,
        ek_handle,
        None,
        ak.clone().ak_private,
        ak.clone().ak_public,
    )?;
    let (pk, _, _) = context.read_public(key_handle.into())?;

    let decoded_key: DecodedKey = pk.try_into()?;
    let DecodedKey::RsaPublicKey(rsa_pk) = decoded_key else {
        bail!("unexpected key type");
    };

    let bytes = rsa_pk.modulus.as_unsigned_bytes_be();
    let n = rust_rsa::BigUint::from_bytes_be(bytes);
    let bytes = rsa_pk.public_exponent.as_unsigned_bytes_be();
    let e = rust_rsa::BigUint::from_bytes_be(bytes);

    let pkey = rust_rsa::RsaPublicKey::new(n, e)?;
    Ok(pkey)
}

#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct TpmQuote {
    // Base64 encoded
    attest_body: String,
    // Base64 encoded
    attest_sig: String,
}

pub fn get_quote(attest_key: AttestationKey, report_data: &[u8]) -> Result<TpmQuote> {
    let mut context = create_ctx_with_session()?;
    let ek_handle = create_ek_object(&mut context, AsymmetricAlgorithm::Rsa, DefaultKey)?;
    let ak_handle = load_ak(
        &mut context,
        ek_handle,
        None,
        attest_key.ak_private,
        attest_key.ak_public,
    )?;
    let selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &TPM_QUOTE_PCR_SLOTS)
        .build()?;
    let (attest, signature) = context.quote(
        ak_handle.into(),
        report_data.to_vec().try_into()?,
        SignatureScheme::Null,
        selection_list.clone(),
    )?;
    let AttestInfo::Quote { .. } = attest.attested() else {
        return Err(anyhow!("Get Quote failed"));
    };
    let Signature::RsaSsa(rsa_sig) = signature.clone() else {
        return Err(anyhow!("Wrong Signature"));
    };

    let engine = base64::engine::general_purpose::STANDARD;

    Ok(TpmQuote {
        attest_body: engine.encode(attest.marshall()?),
        attest_sig: engine.encode(rsa_sig.signature().to_vec()),
    })
}
