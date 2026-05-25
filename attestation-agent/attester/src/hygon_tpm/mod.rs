// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

use crate::utils::read_eventlog;
use crate::{Attester, TeeEvidence};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use kbs_types::HashAlgorithm;
use num_traits::FromPrimitive;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use tss_esapi::abstraction::{
    ak::{create_ak, load_ak},
    ek::{create_ek_object_2, retrieve_ek_pubcert},
    pcr, AsymmetricAlgorithmSelection, DefaultKey,
};
use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{KeyHandle, PcrHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::structures::digest_values::DigestValues;
use tss_esapi::structures::{
    pcr_selection_list::PcrSelectionListBuilder, pcr_slot::PcrSlot, AttestInfo, PcrSelectionList,
    Private, Public, Signature, SignatureScheme, SymmetricDefinition,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::Context as TssContext;

const TPM_EVENTLOG_FILE_PATH: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
const TPM_REPORT_DATA_SIZE: usize = 32;
const PCR_BANK_SM3: &str = "SM3";
const HYGON_CPU_VENDOR: &str = "HygonGenuine";
const KEYLIME_AGENT_UUID_ENV: &str = "KEYLIME_AGENT_UUID";
const KEYLIME_AGENT_DATA_PATH: &str = "/var/lib/keylime/agent_data.json";

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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HygonSm2PublicKey {
    pub x: String,
    pub y: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HygonTpmQuote {
    pub attest_body: String,
    pub attest_sig: String,
    pub pcrs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HygonTpmEvidence {
    pub ek_cert: Option<String>,
    pub ak_pubkey: HygonSm2PublicKey,
    pub keylime_agent_uuid: Option<String>,
    pub quote: HashMap<String, HygonTpmQuote>,
    pub eventlog: Option<String>,
    pub aa_eventlog: Option<String>,
}

#[derive(Clone)]
struct AttestationKey {
    ak_private: Private,
    ak_public: Public,
}

#[derive(serde::Deserialize)]
struct AgentDataFile {
    ak_hash_alg: String,
    ak_sign_alg: String,
    ak_public: Vec<u8>,
    ak_private: Vec<u8>,
    #[allow(dead_code)]
    ek_hash: Vec<u8>,
}

fn try_get_keylime_uuid() -> Option<String> {
    match env::var(KEYLIME_AGENT_UUID_ENV) {
        Result::Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

fn is_sm3_algorithm(name: &str) -> bool {
    let normalized = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    normalized == "sm3" || normalized == "sm3256"
}

fn is_sm2_algorithm(name: &str) -> bool {
    let normalized = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    normalized == "sm2" || normalized == "sm2p256"
}

pub fn detect_platform() -> bool {
    if !Path::new("/dev/tpm0").exists() {
        return false;
    }

    std::fs::read_to_string("/proc/cpuinfo")
        .map(|content| content.contains(HYGON_CPU_VENDOR))
        .unwrap_or(false)
}

fn create_tcti() -> Result<TctiNameConf> {
    if let Result::Ok(tctistr) = std::env::var("TEST_TCTI") {
        return Ok(TctiNameConf::from_str(&tctistr)?);
    }

    // Prefer the kernel TPM resource manager (/dev/tpmrm0) over the direct
    // device (/dev/tpm0) so AA can coexist with other TPM consumers such as
    // keylime-agent. /dev/tpm0 only allows a single exclusive opener; the
    // resource manager multiplexes access.
    let tpmrm_path = "/dev/tpmrm0";
    if Path::new(tpmrm_path).exists() {
        return Ok(TctiNameConf::Device(DeviceConfig::from_str(tpmrm_path)?));
    }
    Ok(TctiNameConf::Device(DeviceConfig::default()))
}

fn create_ctx_without_session() -> Result<TssContext> {
    let tcti = create_tcti()?;
    let ctx = TssContext::new(tcti)?;
    Ok(ctx)
}

fn create_ctx_with_session() -> Result<TssContext> {
    let mut ctx = create_ctx_without_session()?;
    start_encrypted_hmac_session(&mut ctx)?;
    Ok(ctx)
}

fn start_encrypted_hmac_session(ctx: &mut TssContext) -> Result<()> {
    let session = ctx.start_auth_session(
        None,
        None,
        None,
        SessionType::Hmac,
        SymmetricDefinition::Xor {
            hashing_algorithm: HashingAlgorithm::Sm3_256,
        },
        HashingAlgorithm::Sm3_256,
    )?;
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    let valid_session = session.ok_or_else(|| anyhow!("Failed to start auth session"))?;

    ctx.tr_sess_set_attributes(valid_session, session_attributes, session_attributes_mask)?;
    ctx.set_sessions((session, None, None));

    Ok(())
}

fn create_pcr_selection_list(algorithm: &str) -> Result<PcrSelectionList> {
    match algorithm {
        PCR_BANK_SM3 => PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sm3_256, &TPM_QUOTE_PCR_SLOTS)
            .build()
            .context("Build PCR selection list failed"),
        _ => bail!("Unsupported PCR algorithm of Hygon TPM attester"),
    }
}

fn dump_ek_cert_pem() -> Result<String> {
    let mut context = create_ctx_without_session()?;
    let ek_cert_bytes = retrieve_ek_pubcert(
        &mut context,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::Sm2P256),
    )?;
    let ek_cert_x509 = X509::from_der(&ek_cert_bytes)?;
    let ek_cert_pem_bytes = ek_cert_x509.to_pem()?;
    let ek_cert = String::from_utf8(ek_cert_pem_bytes)?;
    Ok(ek_cert)
}

fn dump_pcrs(algorithm: &str) -> Result<Vec<String>> {
    let mut context = create_ctx_without_session()?;
    let selection_list = create_pcr_selection_list(algorithm)?;
    let pcr_data = pcr::read_all(&mut context, selection_list)?;

    let pcr_bank = match algorithm {
        PCR_BANK_SM3 => pcr_data
            .pcr_bank(HashingAlgorithm::Sm3_256)
            .ok_or_else(|| anyhow!("PCR bank not found"))?,
        _ => bail!("Unsupported PCR algorithm of Hygon TPM attester"),
    };

    let pcrs: Vec<String> = pcr_bank
        .into_iter()
        .map(|(_, digest)| hex::encode(digest.value()))
        .collect();
    Ok(pcrs)
}

fn generate_sm2_ak() -> Result<AttestationKey> {
    let mut context = create_ctx_without_session()?;
    let ek_handle = create_ek_object_2(
        &mut context,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::Sm2P256),
        DefaultKey,
    )?;

    let ak = create_ak(
        &mut context,
        ek_handle,
        HashingAlgorithm::Sm3_256,
        SignatureSchemeAlgorithm::Sm2,
        None,
        DefaultKey,
    )?;

    Ok(AttestationKey {
        ak_private: ak.out_private,
        ak_public: ak.out_public,
    })
}

fn import_ak_handle(ctx: &mut TssContext, ak: AttestationKey) -> Result<KeyHandle> {
    let ek_handle = create_ek_object_2(
        ctx,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::Sm2P256),
        DefaultKey,
    )?;
    let ak_handle = load_ak(ctx, ek_handle, None, ak.ak_private, ak.ak_public)?;
    Ok(ak_handle)
}

fn get_ak_pub(ak: AttestationKey) -> Result<HygonSm2PublicKey> {
    let mut context = create_ctx_without_session()?;
    let ek_handle = create_ek_object_2(
        &mut context,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::Sm2P256),
        DefaultKey,
    )?;
    let key_handle = load_ak(
        &mut context,
        ek_handle,
        None,
        ak.clone().ak_private,
        ak.clone().ak_public,
    )?;
    let (pk, _, _) = context.read_public(key_handle)?;

    let Public::Ecc { unique, .. } = pk else {
        bail!("unexpected key type");
    };

    Ok(HygonSm2PublicKey {
        x: hex::encode(unique.x().value()),
        y: hex::encode(unique.y().value()),
    })
}

fn get_quote(ak: AttestationKey, report_data: &[u8], pcr_algorithm: &str) -> Result<HygonTpmQuote> {
    // EK/AK loading must run without an encrypt+decrypt session active, because
    // the SM2 EK template's policy uses TPM2_PolicyOR which rejects those
    // session attributes ("inconsistent attributes"). Start the HMAC session
    // only after EK/AK are loaded, just for the quote call.
    let mut context = create_ctx_without_session()?;
    let ak_handle = import_ak_handle(&mut context, ak)?;
    start_encrypted_hmac_session(&mut context)?;
    let selection_list = create_pcr_selection_list(pcr_algorithm)?;

    let (attest, signature) = context
        .quote(
            ak_handle,
            report_data.to_vec().try_into()?,
            SignatureScheme::Null,
            selection_list,
        )
        .context("Call TPM Quote API failed")?;

    let AttestInfo::Quote { .. } = attest.attested() else {
        bail!("Get Quote failed");
    };

    let Signature::Sm2(_) = &signature else {
        bail!("Wrong signature type from Hygon TPM quote");
    };

    let engine = base64::engine::general_purpose::STANDARD;

    Ok(HygonTpmQuote {
        attest_body: engine.encode(attest.marshall()?),
        attest_sig: engine.encode(signature.marshall()?),
        pcrs: dump_pcrs(pcr_algorithm)?,
    })
}

fn pcr_extend(digest: Vec<u8>, index: u64) -> Result<()> {
    let mut ctx = create_ctx_with_session()?;

    if index >= TPM_QUOTE_PCR_SLOTS.len() as u64 {
        bail!("Register index out of bounds");
    }

    if digest.len() != TPM_REPORT_DATA_SIZE {
        bail!("Event digest length is not 32 bytes (SM3)");
    }

    let pcr_handle = PcrHandle::from_u64(index).ok_or_else(|| anyhow!("Invalid pcr index"))?;
    let mut digest_values = DigestValues::new();
    digest_values.set(
        HashingAlgorithm::Sm3_256,
        digest
            .try_into()
            .map_err(|_| anyhow!("Failed to convert digest"))?,
    );

    ctx.pcr_extend(pcr_handle, digest_values)?;
    Ok(())
}

#[derive(Debug, Default)]
pub struct HygonTpmAttester {}

#[async_trait::async_trait]
impl Attester for HygonTpmAttester {
    async fn get_evidence(&self, mut report_data: Vec<u8>) -> Result<TeeEvidence> {
        if report_data.len() > TPM_REPORT_DATA_SIZE {
            log::warn!(
                "Hygon TPM Attester: report data truncated from {} to {} bytes",
                report_data.len(),
                TPM_REPORT_DATA_SIZE
            );
            report_data.truncate(TPM_REPORT_DATA_SIZE);
        }
        report_data.resize(TPM_REPORT_DATA_SIZE, 0);

        let mut keylime_uuid: Option<String> = None;
        let mut quote = HashMap::new();
        let mut ak_pubkey: Option<HygonSm2PublicKey> = None;

        if let Some(uuid) = try_get_keylime_uuid() {
            match File::open(KEYLIME_AGENT_DATA_PATH)
                .map_err(|e| anyhow!("Open agent_data.json failed: {e}"))
                .and_then(|f| {
                    serde_json::from_reader::<_, AgentDataFile>(f)
                        .map_err(|e| anyhow!("Parse agent_data.json failed: {e}"))
                }) {
                Result::Ok(ad) => {
                    if !is_sm3_algorithm(&ad.ak_hash_alg) || !is_sm2_algorithm(&ad.ak_sign_alg) {
                        log::warn!(
                            "Unexpected Hygon AK params hash/sign: {}/{}; fallback to new AK",
                            ad.ak_hash_alg,
                            ad.ak_sign_alg
                        );
                    } else if let (Result::Ok(public), Result::Ok(private)) = (
                        Public::unmarshall(&ad.ak_public),
                        Private::try_from(ad.ak_private.clone()),
                    ) {
                        let ak = AttestationKey {
                            ak_private: private,
                            ak_public: public,
                        };
                        quote.insert(
                            PCR_BANK_SM3.to_string(),
                            get_quote(ak.clone(), &report_data, PCR_BANK_SM3)?,
                        );
                        ak_pubkey = Some(get_ak_pub(ak)?);
                        keylime_uuid = Some(uuid);
                    } else {
                        log::warn!("Unmarshall Hygon AK public/private failed; fallback to new AK");
                    }
                }
                Result::Err(e) => {
                    log::warn!("{}; fallback to new AK", e);
                }
            }
        }

        if ak_pubkey.is_none() {
            let attestation_key = generate_sm2_ak()?;
            quote.insert(
                PCR_BANK_SM3.to_string(),
                get_quote(attestation_key.clone(), &report_data, PCR_BANK_SM3)?,
            );
            ak_pubkey = Some(get_ak_pub(attestation_key)?);
        }

        let engine = base64::engine::general_purpose::STANDARD;
        let eventlog = match std::fs::read(TPM_EVENTLOG_FILE_PATH) {
            Result::Ok(el) => Some(engine.encode(el)),
            Result::Err(e) => {
                log::warn!("Read TPM eventlog failed: {:?}", e);
                None
            }
        };

        let aa_eventlog = read_eventlog().await?;
        let evidence = HygonTpmEvidence {
            ek_cert: dump_ek_cert_pem().ok(),
            ak_pubkey: ak_pubkey.ok_or_else(|| anyhow!("AK pubkey must be set"))?,
            keylime_agent_uuid: keylime_uuid,
            quote,
            eventlog,
            aa_eventlog,
        };

        serde_json::to_value(evidence)
            .map_err(|e| anyhow!("Serialize Hygon TPM evidence failed: {:?}", e))
    }

    async fn extend_runtime_measurement(&self, digest: Vec<u8>, index: u64) -> Result<()> {
        pcr_extend(digest, index)
    }

    async fn get_runtime_measurement(&self, index: u64) -> Result<Vec<u8>> {
        let pcr_index = index as usize;
        let pcrs = dump_pcrs(PCR_BANK_SM3)?;
        let target_pcr = pcrs
            .get(pcr_index)
            .ok_or_else(|| anyhow!("Register index out of bounds"))?;
        let pcr_value = hex::decode(target_pcr)?;
        Ok(pcr_value)
    }

    fn pcr_to_ccmr(&self, pcr_index: u64) -> u64 {
        pcr_index
    }

    fn ccel_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sm3
    }
}
