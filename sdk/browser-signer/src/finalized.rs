//! Verification of the only full transaction shape this signer authorizes.

use kaspa_hashes::{Hasher, HasherBase, PayloadDigest, TransactionRest, TransactionV1Id};
use kaspa_shielded_core::{
    bundle::ShieldedBundle,
    verify::{BundleVerifyError, sighash, verify_bundle},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zkas_sdk::{DeviceSignature, PreparedPaymentMulti};
use zkas_signer::PAYMENT_TX_CONTEXT;
use zkas_wallet_engine::{
    max_actions_per_tx,
    payment::{STANDARD_TX_MASS_CAP, TRANSIENT_BYTE_TO_MASS_FACTOR},
};

const MAX_FINALIZED_BYTES: usize = (STANDARD_TX_MASS_CAP / TRANSIENT_BYTE_TO_MASS_FACTOR) as usize;
const FIXED_BORSH_LEN: usize = 2 + 4 + 4 + 8 + 20 + 8 + 4 + 8 + 32;
const PAYLOAD_START: usize = 2 + 4 + 4 + 8 + 20 + 8 + 4;
const ESTIMATED_ENVELOPE_BYTES: u64 = 94;
const SHIELDED_MASS_PER_ACTION: u64 = 1_000;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VerifiedFinalized {
    pub transaction_hex: String,
    pub txid: String,
    pub sha256: String,
}

fn canonical_payment_payload(bytes: &[u8]) -> Result<&[u8], &'static str> {
    if bytes.len() < FIXED_BORSH_LEN || bytes.len() > MAX_FINALIZED_BYTES {
        return Err("unsupported transaction length");
    }
    if bytes[..2] != [2, 0] || bytes[2..10] != [0; 8] || bytes[10..18] != [0; 8] || bytes[18..38] != [0; 20] || bytes[38..46] != [0; 8]
    {
        return Err("noncanonical payment transaction");
    }
    let length = u32::from_le_bytes(bytes[46..50].try_into().map_err(|_| "invalid payload length")?) as usize;
    let end = PAYLOAD_START.checked_add(length).ok_or("payload length overflow")?;
    if end.checked_add(40) != Some(bytes.len()) || bytes[end..end + 8] != [0; 8] {
        return Err("noncanonical payment transaction length or mass");
    }
    Ok(&bytes[PAYLOAD_START..end])
}

fn recomputed_txid(payload: &[u8]) -> [u8; 32] {
    // Consensus v1+ transaction ID: digest the payload and the remaining normal
    // payment fields separately, excluding the cached Borsh ID and storage mass.
    let payload_digest = PayloadDigest::hash(payload);
    let mut rest = [0u8; 62];
    rest[..2].copy_from_slice(&2u16.to_le_bytes());
    let rest_digest = TransactionRest::hash(rest);
    let mut id = TransactionV1Id::new();
    id.update(payload_digest).update(rest_digest);
    id.finalize().as_bytes()
}

pub(crate) fn verify(
    transaction_hex: &str,
    genesis: &[u8; 32],
    prepared: &PreparedPaymentMulti,
    signatures: &[DeviceSignature],
) -> Result<VerifiedFinalized, &'static str> {
    if transaction_hex.len() > 2 * MAX_FINALIZED_BYTES
        || !transaction_hex.len().is_multiple_of(2)
        || !transaction_hex.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err("expected bounded lowercase transaction hex");
    }
    let bytes = hex::decode(transaction_hex).map_err(|_| "invalid transaction hex")?;
    let payload = canonical_payment_payload(&bytes)?;
    let txid = recomputed_txid(payload);
    if bytes[bytes.len() - 32..] != txid {
        return Err("cached transaction ID differs from computed ID");
    }
    let bundle = ShieldedBundle::from_bytes(payload).map_err(|_| "invalid shielded bundle")?;
    if bundle.to_bytes() != payload
        || bundle.flags != 3
        || bundle.burn.is_some()
        || bundle.actions.len() < 2
        || bundle.actions.len() > max_actions_per_tx()
        || bundle.value_balance != prepared.claimed_fee as i64
    {
        return Err("noncanonical payment bundle");
    }
    let estimated_size = (payload.len() as u64).checked_add(ESTIMATED_ENVELOPE_BYTES).ok_or("payment mass overflow")?;
    let compute_mass =
        estimated_size.checked_add((bundle.actions.len() as u64) * SHIELDED_MASS_PER_ACTION).ok_or("payment mass overflow")?;
    let transient_mass = estimated_size.checked_mul(TRANSIENT_BYTE_TO_MASS_FACTOR).ok_or("payment mass overflow")?;
    if compute_mass > STANDARD_TX_MASS_CAP || transient_mass > STANDARD_TX_MASS_CAP {
        return Err("payment exceeds mass limit");
    }
    let mut unsigned = bundle.clone();
    unsigned.proof.clear();
    unsigned.binding_sig = [0; 64];
    for action in &mut unsigned.actions {
        action.spend_auth_sig = [0; 64];
    }
    if unsigned != prepared.bundle || prepared.network_domain != *genesis || prepared.tx_context != PAYMENT_TX_CONTEXT {
        return Err("finalized effects differ from signed payment");
    }
    if signatures.len() != prepared.spend_auth.len() {
        return Err("incomplete spend authorization");
    }
    verify_bundle(&bundle, &sighash(&bundle, genesis, &PAYMENT_TX_CONTEXT)).map_err(|error| match error {
        BundleVerifyError::ProofInvalid | BundleVerifyError::BadProofLength { .. } => "completed payment proof invalid",
        BundleVerifyError::BindingSigInvalid => "completed payment binding signature invalid",
        BundleVerifyError::SpendAuthSigInvalid(_) => "completed payment spend authorization invalid",
        _ => "completed payment bundle invalid",
    })?;
    for (signature, request) in signatures.iter().zip(&prepared.spend_auth) {
        if signature.action_index != request.action_index
            || bundle.actions.get(signature.action_index).map(|action| action.spend_auth_sig) != Some(signature.signature)
        {
            return Err("spend authorization differs from signed payment");
        }
    }
    Ok(VerifiedFinalized {
        transaction_hex: transaction_hex.to_owned(),
        txid: hex::encode(txid),
        sha256: hex::encode(Sha256::digest(&bytes)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::{
        config::params::{DEVNET_PARAMS, MAINNET_PARAMS, SIMNET_PARAMS, TESTNET_PARAMS},
        mass::MassCalculator,
        tx::Transaction,
    };
    use kaspa_shielded_wallet::tx::payment_tx;

    #[test]
    fn normal_payment_decoder_recomputes_native_transaction_id_and_mass() {
        use kaspa_consensus_core::mass::transaction_estimated_serialized_size;
        let fixture: serde_json::Value = serde_json::from_str(include_str!("../tests/fixtures/v3-finalized.json")).unwrap();
        let bytes = hex::decode(fixture["transactionHex"].as_str().unwrap()).unwrap();
        let tx: Transaction = borsh::from_slice(&bytes).unwrap();
        let payload = canonical_payment_payload(&bytes).unwrap();
        assert_eq!(payload, tx.payload);
        assert_eq!(recomputed_txid(payload), tx.id().as_bytes());
        let estimated = transaction_estimated_serialized_size(&tx);
        assert_eq!(estimated, tx.payload.len() as u64 + ESTIMATED_ENVELOPE_BYTES);
        for params in [&MAINNET_PARAMS, &TESTNET_PARAMS, &SIMNET_PARAMS, &DEVNET_PARAMS] {
            assert_eq!(params.mass_per_tx_byte, 1);
            let mass = MassCalculator::new_with_consensus_params(params).calc_non_contextual_masses(&tx);
            assert_eq!(mass.compute_mass, estimated * params.mass_per_tx_byte + 2 * SHIELDED_MASS_PER_ACTION);
            assert_eq!(mass.transient_mass, estimated * TRANSIENT_BYTE_TO_MASS_FACTOR);
        }
    }

    #[test]
    fn bounded_borsh_decoder_and_id_match_native_at_length_boundaries() {
        for size in [0, 1, 127, 128, 16_383, 16_384, MAX_FINALIZED_BYTES - FIXED_BORSH_LEN] {
            let tx = payment_tx(vec![7; size]);
            let bytes = borsh::to_vec(&tx).unwrap();
            assert_eq!(canonical_payment_payload(&bytes).unwrap(), tx.payload);
            assert_eq!(recomputed_txid(&tx.payload), tx.id().as_bytes());
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(canonical_payment_payload(&trailing).is_err());
        }
    }

    #[test]
    fn mass_formula_matches_native_for_bounded_action_counts() {
        use kaspa_consensus_core::mass::transaction_estimated_serialized_size;
        let fixture: serde_json::Value = serde_json::from_str(include_str!("../tests/fixtures/v3-finalized.json")).unwrap();
        let bytes = hex::decode(fixture["transactionHex"].as_str().unwrap()).unwrap();
        let tx: Transaction = borsh::from_slice(&bytes).unwrap();
        let original = ShieldedBundle::from_bytes(&tx.payload).unwrap();
        for count in [2, 3, max_actions_per_tx()] {
            let mut bundle = original.clone();
            bundle.actions = vec![original.actions[0].clone(); count];
            bundle.proof = vec![0; kaspa_shielded_core::bundle::expected_proof_len(count)];
            let tx = payment_tx(bundle.to_bytes());
            let serialized = borsh::to_vec(&tx).unwrap();
            assert_eq!(canonical_payment_payload(&serialized).unwrap(), tx.payload);
            let size = transaction_estimated_serialized_size(&tx);
            assert_eq!(size, tx.payload.len() as u64 + ESTIMATED_ENVELOPE_BYTES);
            for params in [&MAINNET_PARAMS, &TESTNET_PARAMS, &SIMNET_PARAMS, &DEVNET_PARAMS] {
                assert_eq!(params.mass_per_tx_byte, 1);
                let mass = MassCalculator::new_with_consensus_params(params).calc_non_contextual_masses(&tx);
                assert_eq!(mass.compute_mass, size * params.mass_per_tx_byte + count as u64 * SHIELDED_MASS_PER_ACTION);
                assert_eq!(mass.transient_mass, size * TRANSIENT_BYTE_TO_MASS_FACTOR);
            }
        }
    }
}
