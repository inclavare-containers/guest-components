// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
use anyhow::*;
use num_traits::cast::FromPrimitive;
use openssl::x509::X509;
use std::str::FromStr;
use tss_esapi::abstraction::{ek::retrieve_ek_pubcert, pcr, AsymmetricAlgorithmSelection};
use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::PcrHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::digest_values::DigestValues;
use tss_esapi::structures::{
    pcr_selection_list::PcrSelectionListBuilder, pcr_slot::PcrSlot, SymmetricDefinition,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
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
        SymmetricDefinition::Xor {
            hashing_algorithm: HashingAlgorithm::Sha256,
        },
        HashingAlgorithm::Sha256,
    )?;
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    let valid_session = session.ok_or(anyhow!("Failed to start auth session"))?;

    ctx.tr_sess_set_attributes(valid_session, session_attributes, session_attributes_mask)?;
    ctx.set_sessions((session, None, None));

    Ok(ctx)
}

pub fn pcr_extend(digest: Vec<u8>, index: u64) -> Result<()> {
    let mut ctx = create_ctx_with_session()?;

    if index >= TPM_QUOTE_PCR_SLOTS.len() as u64 {
        bail!("Register index out of bounds");
    }

    // Must be SHA-256 digest
    if digest.len() != 32 {
        bail!("Event digest length is not 32 bytes (SHA-256)");
    }

    let pcr_handle = PcrHandle::from_u64(index).ok_or_else(|| anyhow!("Invalid pcr index"))?;
    let mut digest_values = DigestValues::new();
    digest_values.set(
        HashingAlgorithm::Sha256,
        digest
            .try_into()
            .map_err(|_| anyhow!("Failed to convert digest"))?,
    );

    ctx.pcr_extend(pcr_handle, digest_values)?;

    Ok(())
}

pub fn dump_ek_cert_pem() -> Result<String> {
    let mut context = create_ctx_without_session()?;

    let ek_cert_bytes = retrieve_ek_pubcert(
        &mut context,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
    )?;
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
        .map(|(_, digest)| Ok(hex::encode(digest.value())))
        .collect();
    let pcrs = pcrs?;

    Ok(pcrs)
}

pub fn dump_pcr_sha1_digests() -> Result<Vec<String>> {
    let mut context = create_ctx_without_session()?;

    let selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha1, &TPM_QUOTE_PCR_SLOTS)
        .build()?;

    let pcr_data = pcr::read_all(&mut context, selection_list)?;
    let pcr_bank = pcr_data
        .pcr_bank(HashingAlgorithm::Sha1)
        .ok_or(anyhow!("PCR bank not found"))?;
    let pcrs: Result<Vec<String>, _> = pcr_bank
        .into_iter()
        .map(|(_, digest)| Ok(hex::encode(digest.value())))
        .collect();
    let pcrs = pcrs?;

    Ok(pcrs)
}
