//! Browser binding for one locally approved Orchard payment.

mod finalized;

use core::str::FromStr;

use kaspa_shielded_core::payment_check::PaymentOutputIntent;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;
use zkas_sdk::{DeviceSignature, Network, PreparedPaymentMulti, PreparedPaymentMultiEnvelope, ShieldedAddress, SoftwareSigner};
use zkas_signer::BatchIntent;
use zkas_wallet_engine::max_payees_per_tx;

const MAX_INTENT_JSON: usize = 64 * 1024;
const MAX_PREPARED_JSON: usize = 512 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovedOutput {
    recipient: String,
    amount_sompi: String,
    memo_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovedIntent {
    account: String,
    outputs: Vec<ApprovedOutput>,
    max_fee_sompi: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionSignature {
    action_index: usize,
    signature_hex: String,
}

struct SignedPrepared {
    envelope: PreparedPaymentMultiEnvelope,
    payment: PreparedPaymentMulti,
    signatures: Vec<DeviceSignature>,
    response: String,
    verified: Option<finalized::VerifiedFinalized>,
}

fn exact_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')) {
        return Err("expected lowercase fixed-width hex".into());
    }
    hex::decode(value).map_err(|_| "invalid hex".to_string())?.try_into().map_err(|_| "invalid hex length".to_string())
}

fn decimal_sompi(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("expected canonical decimal sompi string".into());
    }
    value.parse().map_err(|_| "sompi value exceeds u64".into())
}

fn network(name: &str) -> Result<Network, String> {
    match name {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet),
        "devnet" => Ok(Network::Devnet),
        "simnet" => Ok(Network::Simnet),
        _ => Err("unsupported network".into()),
    }
}

fn canonical_address(network: &Network, value: &str) -> Result<[u8; 43], String> {
    if value.len() > 120 {
        return Err("address too long".into());
    }
    let parsed = ShieldedAddress::from_str(value).map_err(|_| "invalid shielded address".to_string())?;
    let canonical = ShieldedAddress::from_raw(network, parsed.raw()).map_err(|_| "unsupported address network".to_string())?;
    if canonical.to_string() != value {
        return Err("noncanonical or wrong-network address".into());
    }
    Ok(parsed.raw())
}

fn parse_intent(network: &Network, json: &str, account: [u8; 43]) -> Result<BatchIntent, String> {
    if json.len() > MAX_INTENT_JSON {
        return Err("approved intent too large".into());
    }
    let approved: ApprovedIntent = serde_json::from_str(json).map_err(|_| "invalid approved intent".to_string())?;
    if canonical_address(network, &approved.account)? != account {
        return Err("approved account differs from signer".into());
    }
    if approved.outputs.is_empty() || approved.outputs.len() > max_payees_per_tx() {
        return Err("unsupported output count".into());
    }
    let max_fee = decimal_sompi(&approved.max_fee_sompi)?;
    if max_fee == 0 || max_fee > i64::MAX as u64 {
        return Err("invalid fee ceiling".into());
    }
    let mut outputs: Vec<PaymentOutputIntent> = Vec::with_capacity(approved.outputs.len());
    let mut total = 0u64;
    for output in approved.outputs {
        let recipient = canonical_address(network, &output.recipient)?;
        if recipient == account || outputs.iter().any(|prior| prior.recipient == recipient) {
            return Err("repeated or automatic-change recipient".into());
        }
        let amount = decimal_sompi(&output.amount_sompi)?;
        if amount == 0 {
            return Err("zero output amount".into());
        }
        total = total.checked_add(amount).ok_or("output total overflow")?;
        let memo = exact_hex::<512>(&output.memo_hex)?;
        outputs.push(PaymentOutputIntent { recipient, amount, memo });
    }
    if total.checked_add(max_fee).is_none_or(|sum| sum > i64::MAX as u64) {
        return Err("payment and fee exceed supported amount".into());
    }
    Ok(BatchIntent { account, outputs, max_fee })
}

/// Construct only inside the wallet's private approval context. The constructor
/// clears its caller-provided seed buffer; the retained seed zeroizes on drop.
#[wasm_bindgen]
pub struct PrivateAccountSigner {
    signer: SoftwareSigner,
    approved: BatchIntent,
    network: Network,
    genesis: [u8; 32],
    account_address: String,
    signed: Option<SignedPrepared>,
}

#[wasm_bindgen]
impl PrivateAccountSigner {
    #[wasm_bindgen(constructor)]
    pub fn new(account_seed: &mut [u8], network_name: &str, genesis_hex: &str, approved_intent_json: &str) -> Result<Self, String> {
        let result = Self::construct(account_seed, network_name, genesis_hex, approved_intent_json);
        account_seed.fill(0);
        result
    }

    /// Return only the public address retained with the wallet's approved intent.
    pub fn approved_account(&self) -> String {
        self.account_address.clone()
    }

    /// Sign exactly the approved version-3 payment. No raw signing entry point is exposed.
    pub fn sign_prepared_v3(&mut self, prepared_json: &str) -> Result<String, String> {
        if prepared_json.len() > MAX_PREPARED_JSON {
            return Err("prepared envelope too large".into());
        }
        let envelope: PreparedPaymentMultiEnvelope =
            serde_json::from_str(prepared_json).map_err(|_| "invalid prepared envelope".to_string())?;
        let prepared = envelope.to_typed().map_err(|_| "invalid prepared payment".to_string())?;
        let canonical =
            PreparedPaymentMultiEnvelope::from_typed(&prepared, &self.network).map_err(|_| "invalid prepared payment".to_string())?;
        if envelope != canonical {
            return Err("noncanonical prepared envelope".into());
        }
        if let Some(signed) = &self.signed {
            return if envelope == signed.envelope {
                Ok(signed.response.clone())
            } else {
                Err("a different prepared payment was already signed".into())
            };
        }
        let signatures = self
            .signer
            .verify_and_sign_multi(&self.genesis, &self.approved, &prepared)
            .map_err(|_| "prepared payment differs from local approval".to_string())?;
        let reply: Vec<ActionSignature> = signatures
            .iter()
            .map(|signature| ActionSignature { action_index: signature.action_index, signature_hex: hex::encode(signature.signature) })
            .collect();
        let response = serde_json::to_string(&reply).map_err(|_| "signature encoding failed".to_string())?;
        self.signed = Some(SignedPrepared { envelope, payment: prepared, signatures, response: response.clone(), verified: None });
        Ok(response)
    }

    /// Verify complete signed bytes against this handle's one retained V3 payment.
    pub fn verify_finalized_v3(&mut self, transaction_hex: &str) -> Result<String, String> {
        let signed = self.signed.as_mut().ok_or("no prepared payment was signed by this handle")?;
        if let Some(verified) = &signed.verified {
            return if transaction_hex == verified.transaction_hex {
                serde_json::to_string(verified).map_err(|_| "verified payment encoding failed".into())
            } else {
                Err("a different finalized transaction was already verified".into())
            };
        }
        let verified =
            finalized::verify(transaction_hex, &self.genesis, &signed.payment, &signed.signatures).map_err(str::to_owned)?;
        let response = serde_json::to_string(&verified).map_err(|_| "verified payment encoding failed".to_string())?;
        signed.verified = Some(verified);
        Ok(response)
    }
}

impl PrivateAccountSigner {
    fn construct(account_seed: &[u8], network_name: &str, genesis_hex: &str, approved_intent_json: &str) -> Result<Self, String> {
        if account_seed.len() != 32 {
            return Err("account seed must be 32 bytes".into());
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(account_seed);
        let signer = SoftwareSigner::new(*seed).map_err(|_| "invalid account seed".to_string())?;
        let network = network(network_name)?;
        let genesis = exact_hex::<32>(genesis_hex)?;
        let account = signer.address_bytes();
        let approved = parse_intent(&network, approved_intent_json, account)?;
        let account_address =
            ShieldedAddress::from_raw(&network, account).map_err(|_| "unsupported address network".to_string())?.to_string();
        Ok(Self { signer, approved, network, genesis, account_address, signed: None })
    }
}
