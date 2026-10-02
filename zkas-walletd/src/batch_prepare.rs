//! Scoped preparation of one exact multi-output watch-only payment.

use super::*;
use kaspa_shielded_core::payment_check::PaymentOutputIntent;
use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};
use sha2::Digest;
use zkas_sdk::BatchIntent;

const GRANT_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);
const MAX_ACTIVE_GRANTS: usize = 64;
type BatchHttpError = (StatusCode, Json<serde_json::Value>);

fn supported_profile(allow_custodial: bool, enable_multiparty: bool, network: &str) -> bool {
    !allow_custodial && !enable_multiparty && matches!(network, "mainnet" | "testnet" | "devnet" | "simnet")
}

fn legacy_reservation_exists(
    fvk: &[u8; 96],
    active: &HashMap<String, (std::time::Instant, bool)>,
    pending: impl Iterator<Item = ([u8; 96], std::time::Instant)>,
    now: std::time::Instant,
) -> bool {
    active.contains_key(&hex(fvk))
        || pending.into_iter().any(|(owner, created)| owner == *fvk && now.saturating_duration_since(created) < PREPARED_TTL)
}

struct BatchRecord {
    // Kept only in memory so an identical logical request can receive the same
    // random grant. This registry does not persist or log either value.
    capability: [u8; 32],
    token: String,
    origin: String,
    logical_id: [u8; 32],
    intent: BatchIntent,
    capability_expires: std::time::Instant,
    capability_expires_unix: u64,
    expires: std::time::Instant,
    session: Option<String>,
    phase: BatchPhase,
}

enum BatchPhase {
    Issued,
    Proving,
    Ready(Box<BatchPrepared>),
    Finalizing,
    Finalized(Box<BatchFinalized>),
    Failed,
}

struct BatchPrepared {
    payment: PreparedPayment,
    positions: Vec<u64>,
    amount: u64,
    fee: u64,
    response: BatchPrepareResp,
}

struct BatchFinalized {
    response: BatchFinalizeResp,
    signatures: Vec<(usize, [u8; 64])>,
    positions: Vec<u64>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BatchFinalizeResp {
    status: &'static str,
    logical_id: String,
    transaction_hex: String,
    txid: String,
    sha256: String,
}

impl BatchFinalized {
    fn new(bytes: Vec<u8>, txid: String, logical_id: [u8; 32], signatures: Vec<(usize, [u8; 64])>, positions: Vec<u64>) -> Self {
        Self {
            response: BatchFinalizeResp {
                status: "finalized",
                logical_id: hex(&logical_id),
                transaction_hex: hex(&bytes),
                txid,
                sha256: hex(&sha2::Sha256::digest(&bytes)),
            },
            signatures,
            positions,
        }
    }

    fn retry(&self, signatures: &[(usize, [u8; 64])]) -> Result<&BatchFinalizeResp, &'static str> {
        if self.signatures == signatures { Ok(&self.response) } else { Err("finalized signatures differ") }
    }
}

enum BatchFinalizeStart {
    New(Box<BatchPrepared>, BatchIntent, String),
    InProgress,
    Ready(BatchFinalizeResp),
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BatchPrepareResp {
    status: &'static str,
    logical_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prepared_payment: Option<zkas_sdk::PreparedPaymentMultiEnvelope>,
}

pub(super) struct BatchJob {
    fvk: [u8; 96],
    token: String,
    intent: BatchIntent,
    logical_id: [u8; 32],
}

pub(super) enum BatchStart {
    New(BatchJob),
    InProgress,
    Ready(BatchPrepareResp),
    Failed,
}

impl BatchRecord {
    fn active(&self, now: std::time::Instant) -> bool {
        matches!(self.phase, BatchPhase::Proving | BatchPhase::Finalizing) || self.expires > now
    }
}

#[derive(Default)]
pub(super) struct BatchRegistry {
    records: HashMap<[u8; 96], BatchRecord>,
}

impl BatchRegistry {
    pub fn authorize(&self, capability: &[u8; 32], origin: &str, now: std::time::Instant) -> Result<[u8; 96], &'static str> {
        self.records
            .iter()
            .find(|(_, record)| {
                record.capability == *capability && record.origin == origin && record.capability_expires > now && record.active(now)
            })
            .map(|(fvk, _)| *fvk)
            .ok_or("invalid, expired or origin-mismatched capability")
    }

    pub fn reserves(&self, fvk: &[u8; 96], now: std::time::Instant) -> bool {
        self.records.get(fvk).is_some_and(|record| record.active(now))
    }

    pub fn issue(
        &mut self,
        fvk: [u8; 96],
        token: &str,
        origin: &str,
        logical_id: [u8; 32],
        intent: BatchIntent,
        now: std::time::Instant,
    ) -> Result<[u8; 32], &'static str> {
        self.records.retain(|_, record| record.active(now));
        if let Some(record) = self.records.get(&fvk) {
            return if record.capability_expires > now
                && record.token == token
                && record.origin == origin
                && record.logical_id == logical_id
                && record.intent.account == intent.account
                && record.intent.max_fee == intent.max_fee
                && record.intent.outputs == intent.outputs
            {
                Ok(record.capability)
            } else {
                Err("wallet already has an unresolved preparation")
            };
        }
        if self.records.len() >= MAX_ACTIVE_GRANTS {
            return Err("preparation capacity reached");
        }
        let mut capability = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut capability);
        self.records.insert(
            fvk,
            BatchRecord {
                capability,
                token: token.to_owned(),
                origin: origin.to_owned(),
                logical_id,
                intent,
                capability_expires: now + GRANT_TTL,
                capability_expires_unix: now_unix() + GRANT_TTL.as_secs(),
                expires: now + GRANT_TTL,
                session: None,
                phase: BatchPhase::Issued,
            },
        );
        Ok(capability)
    }

    fn capability_expires_unix(&self, fvk: &[u8; 96]) -> Option<u64> {
        self.records.get(fvk).map(|record| record.capability_expires_unix)
    }

    pub fn start(&mut self, capability: &[u8; 32], origin: &str, now: std::time::Instant) -> Result<BatchStart, &'static str> {
        let fvk = self.authorize(capability, origin, now)?;
        let record = self.records.get_mut(&fvk).ok_or("missing capability")?;
        match record.phase {
            BatchPhase::Issued => {
                record.phase = BatchPhase::Proving;
                Ok(BatchStart::New(BatchJob {
                    fvk,
                    token: record.token.clone(),
                    intent: record.intent.clone(),
                    logical_id: record.logical_id,
                }))
            }
            BatchPhase::Proving => Ok(BatchStart::InProgress),
            BatchPhase::Ready(ref prepared) => Ok(BatchStart::Ready(prepared.response.clone())),
            BatchPhase::Finalizing => Ok(BatchStart::InProgress),
            BatchPhase::Finalized(_) => Ok(BatchStart::Ready(BatchPrepareResp::finalized(record.logical_id))),
            BatchPhase::Failed => Ok(BatchStart::Failed),
        }
    }

    pub fn finish_failure(&mut self, fvk: &[u8; 96], now: std::time::Instant) {
        match self.records.get_mut(fvk) {
            Some(record) if matches!(record.phase, BatchPhase::Proving) => {
                record.phase = BatchPhase::Failed;
                record.expires = now + GRANT_TTL;
            }
            _ => {}
        }
    }

    fn finish_success(&mut self, fvk: &[u8; 96], prepared: BatchPrepared, now: std::time::Instant) {
        match self.records.get_mut(fvk) {
            Some(record) if matches!(record.phase, BatchPhase::Proving) => {
                record.session = prepared.response.session.clone();
                record.phase = BatchPhase::Ready(Box::new(prepared));
                record.expires = now + GRANT_TTL;
            }
            _ => {}
        }
    }

    fn credentialed_view(
        &self,
        fvk: &[u8; 96],
        token: &str,
        logical_id: &[u8; 32],
        now: std::time::Instant,
    ) -> Result<BatchPrepareResp, &'static str> {
        let record = self.records.get(fvk).ok_or("unknown preparation")?;
        if record.token != token || &record.logical_id != logical_id || !record.active(now) {
            return Err("unknown preparation");
        }
        Ok(match &record.phase {
            BatchPhase::Issued | BatchPhase::Proving => BatchPrepareResp::pending(record.logical_id),
            BatchPhase::Ready(prepared) => prepared.response.clone(),
            BatchPhase::Finalizing => BatchPrepareResp::pending(record.logical_id),
            BatchPhase::Finalized(_) => BatchPrepareResp::finalized(record.logical_id),
            BatchPhase::Failed => BatchPrepareResp::failed(record.logical_id),
        })
    }

    fn begin_finalize(
        &mut self,
        fvk: &[u8; 96],
        token: &str,
        logical_id: [u8; 32],
        session: &str,
        account: [u8; 43],
        genesis: &[u8; 32],
        signatures: &[(usize, [u8; 64])],
        now: std::time::Instant,
    ) -> Result<BatchFinalizeStart, &'static str> {
        let record = self.records.get_mut(fvk).ok_or("unknown preparation")?;
        if !record.active(now)
            || record.token != token
            || record.logical_id != logical_id
            || record.intent.account != account
            || record.session.as_deref() != Some(session)
        {
            return Err("unknown preparation");
        }
        match &record.phase {
            BatchPhase::Ready(prepared) => {
                validate_spend_signatures(&prepared.payment, signatures, genesis)?;
                let phase = std::mem::replace(&mut record.phase, BatchPhase::Finalizing);
                match phase {
                    BatchPhase::Ready(prepared) => Ok(BatchFinalizeStart::New(prepared, record.intent.clone(), record.origin.clone())),
                    _ => unreachable!(),
                }
            }
            BatchPhase::Finalizing => Ok(BatchFinalizeStart::InProgress),
            BatchPhase::Finalized(finalized) => Ok(BatchFinalizeStart::Ready(finalized.retry(signatures)?.clone())),
            _ => Err("preparation is not ready"),
        }
    }

    fn finish_finalize(&mut self, fvk: &[u8; 96], outcome: Result<BatchFinalized, &'static str>) {
        if let Some(record) = self.records.get_mut(fvk)
            && matches!(record.phase, BatchPhase::Finalizing)
        {
            record.phase = match outcome {
                Ok(finalized) => {
                    record.expires = std::time::Instant::now() + GRANT_TTL;
                    BatchPhase::Finalized(Box::new(finalized))
                }
                Err(_) => BatchPhase::Failed,
            };
        }
    }
}

impl BatchPrepareResp {
    fn pending(logical_id: [u8; 32]) -> Self {
        Self { status: "in_progress", logical_id: hex(&logical_id), session: None, prepared_payment: None }
    }

    fn failed(logical_id: [u8; 32]) -> Self {
        Self { status: "failed", logical_id: hex(&logical_id), session: None, prepared_payment: None }
    }

    fn finalized(logical_id: [u8; 32]) -> Self {
        Self { status: "finalized", logical_id: hex(&logical_id), session: None, prepared_payment: None }
    }

    fn capability_view(&self) -> Self {
        Self { status: self.status, logical_id: self.logical_id.clone(), session: None, prepared_payment: None }
    }
}

fn validate_signature_indices(
    requests: &[(usize, [u8; 32])],
    signatures: &[(usize, [u8; 64])],
    action_count: usize,
) -> Result<(), &'static str> {
    let mut expected: Vec<_> = requests.iter().map(|(index, _)| *index).collect();
    let mut actual: Vec<_> = signatures.iter().map(|(index, _)| *index).collect();
    expected.sort_unstable();
    actual.sort_unstable();
    if expected.is_empty()
        || expected != actual
        || expected.windows(2).any(|pair| pair[0] == pair[1])
        || actual.iter().any(|&index| index >= action_count)
    {
        return Err("incomplete or repeated spend signatures");
    }
    Ok(())
}

fn validate_spend_signatures(
    prepared: &PreparedPayment,
    signatures: &[(usize, [u8; 64])],
    genesis: &[u8; 32],
) -> Result<(), &'static str> {
    validate_signature_indices(&prepared.spend_auth_requests, signatures, prepared.effects.actions.len())?;
    let sighash = kaspa_shielded_core::verify::sighash(&prepared.effects, genesis, &payment_tx_context());
    if sighash != prepared.sighash {
        return Err("prepared payment sighash mismatch");
    }
    for (index, bytes) in signatures {
        let action = &prepared.effects.actions[*index];
        let key = VerificationKey::<SpendAuth>::try_from(action.rk).map_err(|_| "invalid action verification key")?;
        key.verify(&sighash, &Signature::<SpendAuth>::from(*bytes)).map_err(|_| "invalid spend signature")?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchSignatureReq {
    action_index: usize,
    signature_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchFinalizeReq {
    account: String,
    genesis: String,
    logical_id: String,
    session: String,
    signatures: Vec<BatchSignatureReq>,
}

fn lowercase_hex<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')) {
        return Err("invalid lowercase hex field");
    }
    hex::decode(value).map_err(|_| "invalid hex field")?.try_into().map_err(|_| "invalid hex field")
}

pub(super) async fn finalize_many(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BatchFinalizeReq>,
) -> Result<Json<BatchFinalizeResp>, BatchHttpError> {
    if !supported_profile(state.allow_custodial, state.enable_multiparty, &state.network) {
        return Err(err(
            StatusCode::NOT_IMPLEMENTED,
            "batch finalization requires a supported watch-only, single-owner daemon profile",
        ));
    }
    let token = token_from(&headers, false)?;
    let wallet = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no registered wallet"))?;
    let (fvk, account) = {
        let entry = wallet.lock().await;
        if !entry.key.is_watch_only() {
            return Err(err(StatusCode::FORBIDDEN, "batch finalization requires a watch-only wallet"));
        }
        (entry.db.fvk().to_bytes(), entry.db.my_address_bytes())
    };
    let address = Address::try_from(req.account.as_str()).map_err(|_| err(StatusCode::BAD_REQUEST, "invalid account"))?;
    if address.prefix != state.prefix
        || address.version != Version::ShieldedOrchard
        || orchard_recipient_bytes(&address) != Some(account)
    {
        return Err(err(StatusCode::BAD_REQUEST, "account mismatch"));
    }
    if lowercase_hex::<32>(&req.genesis).map_err(|reason| err(StatusCode::BAD_REQUEST, reason))? != state.genesis.as_bytes() {
        return Err(err(StatusCode::BAD_REQUEST, "genesis mismatch"));
    }
    let logical_id = lowercase_hex::<32>(&req.logical_id).map_err(|reason| err(StatusCode::BAD_REQUEST, reason))?;
    lowercase_hex::<24>(&req.session).map_err(|reason| err(StatusCode::BAD_REQUEST, reason))?;
    if req.signatures.is_empty() || req.signatures.len() > max_actions_per_tx() {
        return Err(err(StatusCode::BAD_REQUEST, "invalid signature count"));
    }
    let mut signatures = Vec::with_capacity(req.signatures.len());
    for signature in &req.signatures {
        let bytes = lowercase_hex::<64>(&signature.signature_hex).map_err(|reason| err(StatusCode::BAD_REQUEST, reason))?;
        signatures.push((signature.action_index, bytes));
    }
    signatures.sort_unstable_by_key(|(index, _)| *index);
    let start = {
        let mut registry =
            state.batch_preparations.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "batch tracker poisoned"))?;
        // Authentication, session binding and signature validation precede the
        // state transition, so an invalid signature cannot consume a session.
        registry
            .begin_finalize(
                &fvk,
                &token,
                logical_id,
                &req.session,
                account,
                &state.genesis.as_bytes(),
                &signatures,
                std::time::Instant::now(),
            )
            .map_err(|reason| err(StatusCode::CONFLICT, reason))?
    };
    match start {
        BatchFinalizeStart::Ready(response) => Ok(Json(response)),
        BatchFinalizeStart::InProgress => Err(err(StatusCode::CONFLICT, "finalization in progress; retry the same request")),
        BatchFinalizeStart::New(prepared, intent, origin) => {
            let state_for_job = state.clone();
            let genesis = state.genesis.as_bytes();
            let signatures_for_task = signatures;
            let (sender, receiver) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                let token_for_record = token;
                let outcome = tokio::task::spawn_blocking(move || {
                    let intent_hash = batch_journal::intent_hash(&intent);
                    let finalized = finalize_batch_prepared(
                        *prepared,
                        intent,
                        signatures_for_task,
                        logical_id,
                        fvk,
                        state_for_job.genesis.as_bytes(),
                        &state_for_job.network,
                    )?;
                    let bytes = hex::decode(&finalized.response.transaction_hex).map_err(|_| "invalid finalized bytes")?;
                    let record = batch_journal::JournalRecord::new(
                        fvk, &token_for_record, genesis, account, &origin, logical_id,
                        intent_hash, bytes, finalized.positions.clone(),
                    ).map_err(|_| "journal record failed")?;
                    state_for_job.batch_journal.lock().map_err(|_| "journal unavailable")?
                        .insert(record).map_err(|_| "journal write failed")?;
                    Ok(finalized)
                })
                .await
                .unwrap_or(Err("finalization task failed"));
                let response = outcome.as_ref().map(|finalized| finalized.response.clone()).map_err(|error| *error);
                if let Ok(mut registry) = state.batch_preparations.lock() {
                    registry.finish_finalize(&fvk, outcome);
                }
                let _ = sender.send(response);
            });
            match receiver.await {
                Ok(Ok(response)) => Ok(Json(response)),
                Ok(Err(reason)) => Err(err(StatusCode::BAD_REQUEST, reason)),
                Err(_) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, "finalization task unavailable")),
            }
        }
    }
}

fn finalize_batch_prepared(
    prepared: BatchPrepared,
    intent: BatchIntent,
    signatures: Vec<(usize, [u8; 64])>,
    logical_id: [u8; 32],
    fvk_bytes: [u8; 96],
    genesis: [u8; 32],
    network: &str,
) -> Result<BatchFinalized, &'static str> {
    let positions = prepared.positions.clone();
    let fvk = fvk_from_bytes(&fvk_bytes).ok_or("invalid wallet viewing key")?;
    let typed = prepared
        .response
        .prepared_payment
        .as_ref()
        .ok_or("missing prepared envelope")?
        .to_typed()
        .map_err(|_| "invalid prepared envelope")?;
    let total = intent.outputs.iter().try_fold(0u64, |sum, output| sum.checked_add(output.amount)).ok_or("payment amount overflow")?;
    if prepared.positions.is_empty()
        || prepared.positions.len() != prepared.payment.spend_auth_requests.len()
        || prepared.amount != total
    {
        return Err("prepared payment metadata mismatch");
    }
    let expected_fee = prepared.fee;
    if typed.network_domain != genesis
        || typed.tx_context != payment_tx_context()
        || typed.claimed_account != intent.account
        || typed.claimed_outputs != intent.outputs
        || typed.claimed_fee != expected_fee
        || typed.claimed_fee > intent.max_fee
        || typed.bundle != prepared.payment.effects
    {
        return Err("prepared payment context mismatch");
    }
    kaspa_shielded_core::payment_check::check_prepared_payment_multi_recoverable(
        &prepared.payment.effects,
        &prepared.payment.disclosure,
        &fvk,
        &intent.outputs,
        expected_fee,
        intent.max_fee,
    )
    .map_err(|_| "prepared payment output recovery failed")?;
    validate_spend_signatures(&prepared.payment, &signatures, &genesis)?;
    let bundle = kaspa_shielded_core::wallet::build::finalize_payment_multi(prepared.payment, signatures.clone())
        .map_err(|_| "payment finalization failed")?;
    let sighash = kaspa_shielded_core::verify::sighash(&bundle, &genesis, &payment_tx_context());
    kaspa_shielded_core::verify::verify_bundle(&bundle, &sighash).map_err(|_| "completed payment verification failed")?;
    if bundle.flags != 3
        || bundle.burn.is_some()
        || bundle.value_balance != expected_fee as i64
        || bundle.actions.len() < 2
        || bundle.actions.len() > max_actions_per_tx()
        || expected_fee < min_relay_fee_for_actions(bundle.actions.len())
    {
        return Err("completed payment shape mismatch");
    }
    let wire = bundle.to_bytes();
    if kaspa_shielded_core::bundle::ShieldedBundle::from_bytes(&wire).map_err(|_| "noncanonical bundle")? != bundle {
        return Err("noncanonical bundle");
    }
    let tx = payment_tx(wire);
    if tx.version != TX_VERSION_SHIELDED
        || !tx.inputs.is_empty()
        || !tx.outputs.is_empty()
        || tx.lock_time != 0
        || tx.gas != 0
        || tx.shielded_sighash_context() != payment_tx_context()
    {
        return Err("noncanonical payment transaction");
    }
    let params = kaspa_consensus_core::config::params::Params::from(state_prefix_network(network));
    let mass = kaspa_consensus_core::mass::MassCalculator::new_with_consensus_params(&params).calc_non_contextual_masses(&tx);
    let limits = params.mempool_block_mass_limits().before();
    if mass.compute_mass > limits.compute.min(zkas_wallet_engine::payment::STANDARD_TX_MASS_CAP)
        || mass.transient_mass > limits.transient.min(zkas_wallet_engine::payment::STANDARD_TX_MASS_CAP)
    {
        return Err("completed payment exceeds network mass limit");
    }
    let bytes = borsh::to_vec(&tx).map_err(|_| "transaction serialization failed")?;
    let decoded: Transaction = borsh::from_slice(&bytes).map_err(|_| "transaction roundtrip failed")?;
    if decoded != tx || decoded.id() != tx.id() {
        return Err("transaction roundtrip mismatch");
    }
    Ok(BatchFinalized::new(bytes, hex(&tx.id().as_bytes()), logical_id, signatures, positions))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchStatusQuery {
    account: String,
    genesis: String,
    logical_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchSubmitReq {
    account: String,
    genesis: String,
    logical_id: String,
    txid: String,
    sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BatchSendStatus {
    status: &'static str,
    logical_id: String,
    txid: String,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    included_block: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    included_daa: Option<u64>,
}

impl BatchSendStatus {
    fn from_record(record: &batch_journal::JournalRecord) -> Self {
        let status = match record.phase {
            batch_journal::JournalPhase::Finalized => "finalized_unsent",
            batch_journal::JournalPhase::Unknown => "unknown",
            batch_journal::JournalPhase::Mempool => "mempool",
            batch_journal::JournalPhase::Included => "included",
            batch_journal::JournalPhase::Settled => "settled",
            batch_journal::JournalPhase::Conflicted => "conflicted",
            batch_journal::JournalPhase::ConflictSettled => "conflicted",
        };
        Self {
            status,
            logical_id: hex(&record.logical_id),
            txid: hex(&record.txid),
            sha256: hex(&record.sha256),
            included_block: record.included_block.map(|block| hex(&block)),
            included_daa: record.included_daa,
        }
    }
}

async fn credentialed_record(
    state: &Arc<AppState>, headers: &HeaderMap, account_text: &str, genesis_text: &str, logical_text: &str,
) -> Result<(String, Wallet, [u8; 96], batch_journal::JournalRecord), BatchHttpError> {
    let token = token_from(headers, false)?;
    let wallet = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no registered wallet"))?;
    let (fvk, account) = {
        let entry = wallet.lock().await;
        if !entry.key.is_watch_only() { return Err(err(StatusCode::FORBIDDEN, "watch-only wallet required")); }
        (entry.db.fvk().to_bytes(), entry.db.my_address_bytes())
    };
    let address = Address::try_from(account_text).map_err(|_| err(StatusCode::BAD_REQUEST, "invalid account"))?;
    if address.prefix != state.prefix || orchard_recipient_bytes(&address) != Some(account) {
        return Err(err(StatusCode::BAD_REQUEST, "account mismatch"));
    }
    let genesis = lowercase_hex::<32>(genesis_text).map_err(|reason| err(StatusCode::BAD_REQUEST, reason))?;
    if genesis != state.genesis.as_bytes() { return Err(err(StatusCode::BAD_REQUEST, "genesis mismatch")); }
    let logical_id = lowercase_hex::<32>(logical_text).map_err(|reason| err(StatusCode::BAD_REQUEST, reason))?;
    let record = state.batch_journal.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?
        .get(&batch_journal::fvk_hash(&fvk), &logical_id).cloned()
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown logical payment"))?;
    if !record.authenticate(&token, &account, &genesis) {
        return Err(err(StatusCode::NOT_FOUND, "unknown logical payment"));
    }
    Ok((token, wallet, fvk, record))
}

pub(super) async fn submit_many(
    State(state): State<Arc<AppState>>, headers: HeaderMap, Json(req): Json<BatchSubmitReq>,
) -> Result<Json<BatchSendStatus>, BatchHttpError> {
    if !supported_profile(state.allow_custodial, state.enable_multiparty, &state.network) {
        return Err(err(StatusCode::NOT_IMPLEMENTED, "batch submission requires a watch-only, single-owner daemon profile"));
    }
    let _journal_scope = state.journal_reconcile.lock().await;
    let (token, wallet, fvk, record) = credentialed_record(&state, &headers, &req.account, &req.genesis, &req.logical_id).await?;
    if lowercase_hex::<32>(&req.txid).map_err(|reason| err(StatusCode::BAD_REQUEST, reason))? != record.txid
        || lowercase_hex::<32>(&req.sha256).map_err(|reason| err(StatusCode::BAD_REQUEST, reason))? != record.sha256
    {
        return Err(err(StatusCode::CONFLICT, "signed transaction identity differs from journal"));
    }
    let _submission = SubmissionGuard::new(&state, fvk, false)?;
    let cursor = {
        let entry = wallet.lock().await;
        if record.phase == batch_journal::JournalPhase::Finalized && !entry.caught_up {
            return Err(err(StatusCode::SERVICE_UNAVAILABLE, "wallet is not caught up"));
        }
        entry.low.as_bytes()
    };
    let record = state.batch_journal.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?
        .begin_attempt(&record.fvk_hash, &record.logical_id, cursor)
        .map_err(|_| err(StatusCode::CONFLICT, "payment is not available for exact retry"))?;
    {
        let mut entry = wallet.lock().await;
        for position in &record.positions { entry.db.mark_spent(*position, record.txid, 0); }
        entry.force_checkpoint = true;
    }
    let transaction = record.transaction().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal transaction invalid"))?;
    if let Some(node) = state.request_client().await {
        if let Ok(Ok(accepted)) = tokio::time::timeout(SYNC_RPC_TIMEOUT, node.submit_transaction(RpcTransaction::from(&transaction), false)).await {
            if accepted.as_bytes() == record.txid {
                let mut updated = record.clone();
                updated.phase = batch_journal::JournalPhase::Mempool;
                let _ = state.batch_journal.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?.update(&mut updated);
            }
        }
    }
    let current = state.batch_journal.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?
        .get(&record.fvk_hash, &record.logical_id).cloned().ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?;
    let _ = token;
    Ok(Json(BatchSendStatus::from_record(&current)))
}

pub(super) async fn status_many(
    State(state): State<Arc<AppState>>, headers: HeaderMap, Query(req): Query<BatchStatusQuery>,
) -> Result<Json<BatchSendStatus>, BatchHttpError> {
    let _journal_scope = state.journal_reconcile.lock().await;
    let (_, wallet, _, record) = credentialed_record(&state, &headers, &req.account, &req.genesis, &req.logical_id).await?;
    let record = reconcile_record(&state, &wallet, record).await?;
    Ok(Json(BatchSendStatus::from_record(&record)))
}

pub(super) async fn finalized_many_journal(
    State(state): State<Arc<AppState>>, headers: HeaderMap, Query(req): Query<BatchStatusQuery>,
) -> Result<Json<BatchFinalizeResp>, BatchHttpError> {
    let (_, _, _, record) = credentialed_record(&state, &headers, &req.account, &req.genesis, &req.logical_id).await?;
    Ok(Json(BatchFinalizeResp {
        status: "finalized", logical_id: hex(&record.logical_id),
        transaction_hex: record.transaction_hex, txid: hex(&record.txid), sha256: hex(&record.sha256),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchDiscoveryQuery {
    account: String,
    genesis: String,
    after_logical_id: Option<String>,
    epoch: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchDiscoveryEntry {
    logical_id: String,
    revision: u64,
    status: &'static str,
    txid: String,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    included_block: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    included_daa: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BatchDiscoveryResp {
    inventory_only: bool,
    epoch: String,
    entries: Vec<BatchDiscoveryEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_after_logical_id: Option<String>,
    unlisted_reservation_count: usize,
}

struct DiscoveryCursor {
    after: Option<[u8; 32]>,
    epoch: Option<[u8; 32]>,
}

fn discovery_cursor(req: &BatchDiscoveryQuery) -> Result<DiscoveryCursor, BatchHttpError> {
    let after = req.after_logical_id.as_deref()
        .map(|value| lowercase_hex::<32>(value).map_err(|reason| err(StatusCode::BAD_REQUEST, reason)))
        .transpose()?;
    let epoch = req.epoch.as_deref()
        .map(|value| lowercase_hex::<32>(value).map_err(|reason| err(StatusCode::BAD_REQUEST, reason)))
        .transpose()?;
    if after.is_some() && epoch.is_none() {
        return Err(err(StatusCode::BAD_REQUEST, "discovery cursor requires epoch"));
    }
    Ok(DiscoveryCursor { after, epoch })
}

fn canonical_discovery_account(value: &str) -> Result<Address, BatchHttpError> {
    let address = Address::try_from(value).map_err(|_| err(StatusCode::BAD_REQUEST, "invalid account"))?;
    if address.to_string() != value {
        return Err(err(StatusCode::BAD_REQUEST, "invalid account"));
    }
    Ok(address)
}

pub(super) async fn discover_many_journal(
    State(state): State<Arc<AppState>>, headers: HeaderMap, Query(req): Query<BatchDiscoveryQuery>,
) -> Result<Json<BatchDiscoveryResp>, BatchHttpError> {
    if !state.batch_journal_ready {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "payment journal migration is required"));
    }
    if !supported_profile(state.allow_custodial, state.enable_multiparty, &state.network) {
        return Err(err(StatusCode::NOT_IMPLEMENTED, "journal discovery requires a watch-only, single-owner daemon profile"));
    }
    if req.account.len() > 120 {
        return Err(err(StatusCode::BAD_REQUEST, "invalid account"));
    }
    let cursor = discovery_cursor(&req)?;
    let token = token_from(&headers, false)?;
    let wallet = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no registered wallet"))?;
    let (fvk, account) = {
        let entry = wallet.lock().await;
        if !entry.key.is_watch_only() {
            return Err(err(StatusCode::FORBIDDEN, "watch-only wallet required"));
        }
        (entry.db.fvk().to_bytes(), entry.db.my_address_bytes())
    };
    let address = canonical_discovery_account(&req.account)?;
    if address.prefix != state.prefix || orchard_recipient_bytes(&address) != Some(account) {
        return Err(err(StatusCode::BAD_REQUEST, "account mismatch"));
    }
    let genesis = lowercase_hex::<32>(&req.genesis).map_err(|reason| err(StatusCode::BAD_REQUEST, reason))?;
    if genesis != state.genesis.as_bytes() {
        return Err(err(StatusCode::BAD_REQUEST, "genesis mismatch"));
    }
    let snapshot = state.batch_journal.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?
        .discovery_snapshot(&fvk, &token, &account, &genesis)
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "journal unavailable"))?;
    let page = snapshot.page(cursor.after, cursor.epoch).map_err(|reason| {
        let status = if reason == "discovery inventory changed" { StatusCode::CONFLICT } else { StatusCode::BAD_REQUEST };
        err(status, reason)
    })?;
    Ok(Json(BatchDiscoveryResp {
        inventory_only: true,
        epoch: hex(&page.epoch),
        entries: page.entries.into_iter().map(|entry| BatchDiscoveryEntry {
            logical_id: hex(&entry.logical_id),
            revision: entry.revision,
            status: entry.status_hint(),
            txid: hex(&entry.txid),
            sha256: hex(&entry.sha256),
            included_block: entry.included_block.map(|block| hex(&block)),
            included_daa: entry.included_daa,
        }).collect(),
        next_after_logical_id: page.next_after.map(|cursor| hex(&cursor)),
        unlisted_reservation_count: page.unlisted_reservation_count,
    }))
}

pub(super) async fn legacy_uncertain(
    State(state): State<Arc<AppState>>, headers: HeaderMap,
) -> Result<Json<Vec<BatchSendStatus>>, BatchHttpError> {
    let token = token_from(&headers, false)?;
    let wallet = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no registered wallet"))?;
    let (fvk, account) = {
        let entry = wallet.lock().await;
        (entry.db.fvk().to_bytes(), entry.db.my_address_bytes())
    };
    let mut records: Vec<_> = state.batch_journal.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?
        .unresolved_for_fvk(&fvk).into_iter()
        .filter(|record| record.legacy_for(&token, &account, &state.genesis.as_bytes()))
        .map(|record| {
            let unverified_terminal = !record.reserves();
            let mut status = BatchSendStatus::from_record(&record);
            if unverified_terminal { status.status = "unknown"; }
            (unverified_terminal, status)
        }).collect();
    records.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.logical_id.cmp(&right.1.logical_id)));
    records.truncate(32);
    Ok(Json(records.into_iter().map(|(_, status)| status).collect()))
}

async fn reconcile_record(
    state: &Arc<AppState>, wallet: &Wallet, mut record: batch_journal::JournalRecord,
) -> Result<batch_journal::JournalRecord, BatchHttpError> {
    use batch_journal::{JournalPhase, Observation};
    if record.phase == JournalPhase::Finalized { return Ok(record); }
    let node = state.request_client().await.ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "node unavailable for payment reconciliation"))?;
    let view = tokio::time::timeout(SYNC_RPC_TIMEOUT, node.get_server_info()).await
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "chain status timed out"))?
        .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "chain status unavailable"))?;
    if !view.is_synced || view.network_id.network_type() != state_prefix_network(&state.network) {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "node network is unavailable or not synced"));
    }
    if let (Some(block), Some(daa)) = (record.included_block, record.included_daa) {
        let chain_txid = if matches!(record.phase, JournalPhase::Conflicted | JournalPhase::ConflictSettled) { record.conflicting_txid.unwrap_or(record.txid) } else { record.txid };
        match apply_inclusion_lookup(&mut record, selected_acceptance_at(&node, RpcHash::from_bytes(block), daa).await, chain_txid) {
            Ok(false) => {}
            Ok(true) => {
                // A continuous selected-chain walk passed the old inclusion DAA
                // without its block. The prior cursor may itself be orphaned.
                state.batch_journal.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?
                    .update(&mut record).map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "journal unavailable"))?;
                return Ok(record);
            }
            Err(()) => {
                // Absence of retained acceptance data is not evidence of a
                // replacement. Keep the durable inclusion and reservation.
                return Err(err(StatusCode::SERVICE_UNAVAILABLE, "selected-chain acceptance unavailable"));
            }
        }
    } else if let Some(cursor) = record.scan_cursor {
        match tokio::time::timeout(SYNC_RPC_TIMEOUT, node.get_shielded_blocks(RpcHash::from_bytes(cursor), 512)).await {
            Ok(Ok(page)) if page.reorged => {
                record.invalidate_chain_provenance();
            }
            Ok(Ok(page)) => {
                for block in &page.blocks {
                    match batch_journal::observe_block(&record, block) {
                        Observation::Included(hash, daa) => {
                            record.phase = JournalPhase::Included;
                            record.included_block = Some(hash);
                            record.included_daa = Some(daa);
                            break;
                        }
                        Observation::Conflicted(txid, hash, daa) => {
                            record.phase = JournalPhase::Conflicted;
                            record.conflicting_txid = Some(txid);
                            record.included_block = Some(hash);
                            record.included_daa = Some(daa);
                            break;
                        }
                        Observation::Continue(hash) => record.scan_cursor = Some(hash),
                        Observation::Gap => return Err(err(StatusCode::SERVICE_UNAVAILABLE, "incomplete selected-chain page")),
                    }
                }
            }
            _ => return Err(err(StatusCode::SERVICE_UNAVAILABLE, "selected-chain page unavailable")),
        }
        state.batch_journal.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?
            .update(&mut record).map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "journal unavailable"))?;
    }
    if matches!(record.phase, JournalPhase::Unknown | JournalPhase::Mempool) && record.included_block.is_none() {
        let observed = tokio::time::timeout(SYNC_RPC_TIMEOUT,
            node.get_mempool_entry(RpcHash::from_bytes(record.txid), true, false)).await
            .is_ok_and(|result| result.is_ok());
        let next = if observed { JournalPhase::Mempool } else { JournalPhase::Unknown };
        if record.phase != next {
            record.phase = next;
            state.batch_journal.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?
                .update(&mut record).map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "journal unavailable"))?;
        }
    }
    if matches!(record.phase, JournalPhase::Included | JournalPhase::Conflicted | JournalPhase::Settled | JournalPhase::ConflictSettled) {
        let was_terminal = matches!(record.phase, JournalPhase::Settled | JournalPhase::ConflictSettled);
        let included = record.included_daa.ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "missing inclusion DAA"))?;
        let mature_daa = included.checked_add(DEFAULT_ANCHOR_DEPTH).ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "invalid inclusion DAA"))?;
        if !release_depth_satisfied(included, view.virtual_daa_score, view.virtual_daa_score) {
            return if was_terminal { Err(err(StatusCode::SERVICE_UNAVAILABLE, "settlement needs fresh chain depth")) } else { Ok(record) };
        }
        let block = record.included_block.ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "missing inclusion block"))?;
        let accepted_txid = if matches!(record.phase, JournalPhase::Conflicted | JournalPhase::ConflictSettled) {
            record.conflicting_txid.ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "missing conflicting transaction"))?
        } else { record.txid };
        if !accepted_txids_at(&node, RpcHash::from_bytes(block), included).await
            .is_some_and(|ids| ids.contains(&accepted_txid)) {
            return Err(err(StatusCode::SERVICE_UNAVAILABLE, "selected-chain acceptance unavailable"));
        }
        let entry = wallet.lock().await;
        let wallet_consumed = record.positions.iter().all(|position| {
            !entry.db.notes().iter().any(|note| note.position == *position)
                && !entry.db.pending_spends().iter().any(|pending| pending.note.position == *position)
        });
        if !record.positions.is_empty() && entry.caught_up && entry.blind_below == 0
            && entry.reorged_strikes == 0 && release_depth_satisfied(included, view.virtual_daa_score, entry.scanned as u64)
            && wallet_consumed {
            drop(entry);
            let final_view = tokio::time::timeout(SYNC_RPC_TIMEOUT, node.get_server_info()).await
                .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "chain status timed out"))?
                .map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "chain status unavailable"))?;
            if !final_view.is_synced || final_view.network_id != view.network_id
                || final_view.virtual_daa_score < mature_daa
                || !accepted_txids_at(&node, RpcHash::from_bytes(block), included).await
                    .is_some_and(|ids| ids.contains(&accepted_txid)) {
                return Err(err(StatusCode::SERVICE_UNAVAILABLE, "selected-chain view changed"));
            }
            record.phase = if matches!(record.phase, JournalPhase::Conflicted | JournalPhase::ConflictSettled) { JournalPhase::ConflictSettled } else { JournalPhase::Settled };
            state.batch_journal.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?
                .update(&mut record).map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "journal unavailable"))?;
        } else if was_terminal {
            return Err(err(StatusCode::SERVICE_UNAVAILABLE, "wallet settlement scan is incomplete"));
        }
    }
    Ok(record)
}

/// True only for positive selected-chain replacement. Unavailable history
/// leaves the exact persisted inclusion unchanged for a later retry.
fn apply_inclusion_lookup(
    record: &mut batch_journal::JournalRecord, lookup: AcceptanceLookup, expected_txid: [u8; 32],
) -> Result<bool, ()> {
    match lookup {
        AcceptanceLookup::Found(ids) if ids.contains(&expected_txid) => Ok(false),
        AcceptanceLookup::Replaced => { record.invalidate_chain_provenance(); Ok(true) }
        AcceptanceLookup::Found(_) | AcceptanceLookup::Unavailable => Err(()),
    }
}

fn release_depth_satisfied(included: u64, node_tip: u64, wallet_scanned: u64) -> bool {
    included.checked_add(DEFAULT_ANCHOR_DEPTH)
        .is_some_and(|mature| node_tip >= mature && wallet_scanned >= mature)
}

pub(super) async fn reconcile_wallet_journal(
    state: &Arc<AppState>, wallet: &Wallet, fvk: &[u8; 96],
) -> Result<(), BatchHttpError> {
    let records = state.batch_journal.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?
        .records_for_fvk(fvk);
    for record in records { reconcile_record(state, wallet, record).await?; }
    Ok(())
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchOutputReq {
    pub recipient: String,
    pub amount_sompi: String,
    pub memo_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchGrantReq {
    pub origin: String,
    pub account: String,
    pub genesis: String,
    pub logical_id: String,
    #[serde(deserialize_with = "bounded_batch_outputs")]
    pub outputs: Vec<BatchOutputReq>,
    pub max_fee_sompi: String,
}

fn bounded_batch_outputs<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<BatchOutputReq>, D::Error> {
    struct BoundedOutputs;

    impl<'de> serde::de::Visitor<'de> for BoundedOutputs {
        type Value = Vec<BatchOutputReq>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(formatter, "at most {} payment outputs", max_payees_per_tx())
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            use serde::de::Error;
            let limit = max_payees_per_tx();
            if seq.size_hint().is_some_and(|size| size > limit) {
                return Err(A::Error::custom("too many payment outputs"));
            }
            let mut outputs = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(limit));
            while let Some(output) = seq.next_element::<BatchOutputReq>()? {
                if outputs.len() == limit {
                    return Err(A::Error::custom("too many payment outputs"));
                }
                outputs.push(output);
            }
            Ok(outputs)
        }
    }

    deserializer.deserialize_seq(BoundedOutputs)
}

pub(super) fn parse_batch_intent(
    req: &BatchGrantReq,
    account: [u8; 43],
    genesis: [u8; 32],
    prefix: Prefix,
) -> Result<BatchIntent, &'static str> {
    if !valid_batch_origin(&req.origin)
        || req.account.len() > 120
        || req.genesis.len() != 64
        || req.logical_id.len() != 64
        || !req.logical_id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || req.outputs.is_empty()
        || req.outputs.len() > max_payees_per_tx()
        || !canonical_decimal(&req.max_fee_sompi)
    {
        return Err("invalid batch intent shape");
    }
    let approved_account = Address::try_from(req.account.as_str()).map_err(|_| "invalid account")?;
    if approved_account.prefix != prefix
        || approved_account.version != Version::ShieldedOrchard
        || orchard_recipient_bytes(&approved_account) != Some(account)
        || hex(&genesis) != req.genesis
    {
        return Err("account or genesis mismatch");
    }
    let max_fee: u64 = req.max_fee_sompi.parse().map_err(|_| "invalid fee ceiling")?;
    if max_fee == 0 || max_fee > i64::MAX as u64 {
        return Err("invalid fee ceiling");
    }
    let mut total = 0u64;
    let mut outputs: Vec<PaymentOutputIntent> = Vec::with_capacity(req.outputs.len());
    for output in &req.outputs {
        if output.recipient.len() > 120
            || !canonical_decimal(&output.amount_sompi)
            || output.memo_hex.len() != 1024
            || !output.memo_hex.bytes().all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return Err("invalid output shape");
        }
        let address = Address::try_from(output.recipient.as_str()).map_err(|_| "invalid recipient")?;
        if address.prefix != prefix || address.version != Version::ShieldedOrchard {
            return Err("invalid recipient network or type");
        }
        let recipient = orchard_recipient_bytes(&address).ok_or("invalid recipient")?;
        if recipient == account || outputs.iter().any(|prior| prior.recipient == recipient) {
            return Err("repeated or change recipient");
        }
        let amount: u64 = output.amount_sompi.parse().map_err(|_| "invalid output amount")?;
        if amount == 0 {
            return Err("zero output amount");
        }
        total = total.checked_add(amount).ok_or("payment amount overflow")?;
        let memo: [u8; 512] =
            hex::decode(&output.memo_hex).map_err(|_| "invalid memo hex")?.try_into().map_err(|_| "invalid memo length")?;
        outputs.push(PaymentOutputIntent { recipient, amount, memo });
    }
    if total.checked_add(max_fee).is_none_or(|sum| sum > i64::MAX as u64) {
        return Err("payment plus fee ceiling exceeds supported range");
    }
    Ok(BatchIntent { account, outputs, max_fee })
}

fn canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|b| b.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
}

fn valid_batch_origin(origin: &str) -> bool {
    if let Some(authority) = origin.strip_prefix("http://") {
        let Some((host, port)) = authority.split_once(':') else {
            return false;
        };
        // Browsers omit the default HTTP port from the Origin header.
        return origin.len() <= 200
            && matches!(host, "localhost" | "127.0.0.1")
            && !port.is_empty()
            && !port.starts_with('0')
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|number| number > 0 && number != 80);
    }
    let Some(authority) = origin.strip_prefix("https://") else {
        return false;
    };
    if origin.len() > 200 || authority.is_empty() || authority.contains('@') {
        return false;
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    !host.is_empty()
        && host.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        && port.is_none_or(|port| {
            !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok_and(|number| number > 0)
        })
}

/// Select one complete payment from descending matured note values. Reserve an
/// action for positive change when estimating the fee and mass before proving.
pub(super) fn choose_batch_spends(
    values: &[u64],
    output_total: u64,
    output_count: usize,
    max_fee: u64,
) -> Result<(usize, u64), &'static str> {
    let mut selected = 0u64;
    for (index, value) in values.iter().take(max_actions_per_tx()).enumerate() {
        selected = selected.checked_add(*value).ok_or("input amount overflow")?;
        let actions = (index + 1).max(output_count.saturating_add(1)).max(2);
        if actions > max_actions_per_tx() {
            return Err("payment exceeds standard action budget");
        }
        let fee = DEFAULT_FEE_SOMPI.max(min_relay_fee_for_actions(actions));
        if fee > max_fee {
            return Err("network fee exceeds approved ceiling");
        }
        let needed = output_total.checked_add(fee).ok_or("payment amount overflow")?;
        if selected >= needed {
            return Ok((index + 1, fee));
        }
    }
    Err("insufficient matured funds for one complete payment")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BatchGrantResp {
    capability: String,
    logical_id: String,
    expires_at_unix: u64,
}

pub(super) async fn issue_batch_capability(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BatchGrantReq>,
) -> Result<Json<BatchGrantResp>, (StatusCode, Json<serde_json::Value>)> {
    if !state.batch_journal_ready {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, "payment journal migration is required"));
    }
    if !supported_profile(state.allow_custodial, state.enable_multiparty, &state.network) {
        return Err(err(
            StatusCode::NOT_IMPLEMENTED,
            "batch preparation requires a supported watch-only, single-owner daemon profile",
        ));
    }
    let token = token_from(&headers, false)?;
    let wallet = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no registered wallet"))?;
    let (fvk, account) = {
        let entry = wallet.lock().await;
        if !entry.key.is_watch_only() {
            return Err(err(StatusCode::FORBIDDEN, "batch preparation requires a watch-only wallet"));
        }
        (entry.db.fvk().to_bytes(), entry.db.my_address_bytes())
    };
    let intent = parse_batch_intent(&req, account, state.genesis.as_bytes(), state.prefix)
        .map_err(|reason| err(StatusCode::BAD_REQUEST, reason))?;
    let logical_id: [u8; 32] = hex::decode(&req.logical_id)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid logical id"))?
        .try_into()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid logical id"))?;
    let _journal_scope = state.journal_reconcile.lock().await;
    reconcile_wallet_journal(&state, &wallet, &fvk).await?;
    let now = std::time::Instant::now();
    // Hold the legacy active tracker while examining unsigned legacy sessions and
    // installing the new reservation. A legacy prepare keeps its active marker
    // until after it has inserted its session, so no gap can select the same notes.
    let active = state.preparing.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "prepare tracker poisoned"))?;
    let pending = state.prepared.try_lock().map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "preparation tracker busy"))?;
    if legacy_reservation_exists(&fvk, &active, pending.values().map(|session| (session.fvk, session.created)), now) {
        return Err(err(StatusCode::CONFLICT, "this wallet already has a pending payment preparation"));
    }
    if state.batch_journal.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "journal unavailable"))?.reserves(&fvk) {
        return Err(err(StatusCode::CONFLICT, "this wallet has an unresolved submitted payment"));
    }
    if state.submitting.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "submission tracker unavailable"))?.contains(&fvk) {
        return Err(err(StatusCode::CONFLICT, "this wallet has a submission in progress"));
    }
    let mut registry =
        state.batch_preparations.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "batch tracker poisoned"))?;
    let capability =
        registry.issue(fvk, &token, &req.origin, logical_id, intent, now).map_err(|reason| err(StatusCode::CONFLICT, reason))?;
    Ok(Json(BatchGrantResp {
        capability: hex(&capability),
        logical_id: req.logical_id,
        expires_at_unix: registry
            .capability_expires_unix(&fvk)
            .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "missing capability"))?,
    }))
}

fn capability_headers(headers: &HeaderMap) -> Result<([u8; 32], &str), BatchHttpError> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing preparation origin"))?;
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Batch "))
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing batch capability"))?;
    if supplied.len() != 64 || !supplied.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid batch capability"));
    }
    let capability = hex::decode(supplied)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid batch capability"))?
        .try_into()
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "invalid batch capability"))?;
    Ok((capability, origin))
}

/// The browser can start or observe only the exact preparation named by its
/// single-intent capability. The proof runs independently of this HTTP request.
pub(super) async fn prepare_many(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<BatchPrepareResp>, (StatusCode, Json<serde_json::Value>)> {
    if !supported_profile(state.allow_custodial, state.enable_multiparty, &state.network) {
        return Err(err(
            StatusCode::NOT_IMPLEMENTED,
            "batch preparation requires a supported watch-only, single-owner daemon profile",
        ));
    }
    if !body.is_empty()
        || headers.get(header::CONTENT_LENGTH).is_some_and(|value| value != "0")
        || headers.contains_key(header::TRANSFER_ENCODING)
    {
        return Err(err(StatusCode::BAD_REQUEST, "batch preparation takes no body"));
    }
    let (capability, origin) = capability_headers(&headers)?;
    let now = std::time::Instant::now();
    let outcome = state
        .batch_preparations
        .lock()
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "batch tracker poisoned"))?
        .start(&capability, origin, now)
        .map_err(|reason| err(StatusCode::UNAUTHORIZED, reason))?;
    match outcome {
        BatchStart::New(job) => {
            let logical_id = job.logical_id;
            let fvk = job.fvk;
            let state_for_task = state.clone();
            tokio::spawn(async move {
                let outcome = run_batch_job(state_for_task.clone(), job).await;
                let now = std::time::Instant::now();
                match state_for_task.batch_preparations.lock() {
                    Ok(mut registry) => match outcome {
                        Ok(prepared) => registry.finish_success(&fvk, prepared, now),
                        Err(reason) => {
                            log::warn!("multi-output prepare failed: {reason}");
                            registry.finish_failure(&fvk, now);
                        }
                    },
                    Err(_) => log::error!("batch tracker poisoned after proof"),
                }
            });
            Ok(Json(BatchPrepareResp::pending(logical_id)))
        }
        BatchStart::InProgress => {
            let registry =
                state.batch_preparations.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "batch tracker poisoned"))?;
            let fvk = registry.authorize(&capability, origin, now).map_err(|reason| err(StatusCode::UNAUTHORIZED, reason))?;
            let record = registry.records.get(&fvk).ok_or_else(|| err(StatusCode::NOT_FOUND, "preparation not found"))?;
            Ok(Json(BatchPrepareResp::pending(record.logical_id)))
        }
        BatchStart::Ready(response) => Ok(Json(response.capability_view())),
        BatchStart::Failed => Err(err(StatusCode::CONFLICT, "batch preparation failed; request a new capability after expiry")),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BatchViewQuery {
    logical_id: String,
}

/// A wallet-controlled refetch for the independent signer. A browser capability
/// cannot call this route, and the wallet token is never sent to the browser.
pub(super) async fn prepared_many(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<BatchViewQuery>,
) -> Result<Json<BatchPrepareResp>, (StatusCode, Json<serde_json::Value>)> {
    let token = token_from(&headers, false)?;
    if query.logical_id.len() != 64 || !query.logical_id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid logical id"));
    }
    let logical_id: [u8; 32] = hex::decode(&query.logical_id)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid logical id"))?
        .try_into()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "invalid logical id"))?;
    let wallet = state.get_wallet(&token).await.ok_or_else(|| err(StatusCode::NOT_FOUND, "no registered wallet"))?;
    let fvk = wallet.lock().await.db.fvk().to_bytes();
    let response = state
        .batch_preparations
        .lock()
        .map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "batch tracker poisoned"))?
        .credentialed_view(&fvk, &token, &logical_id, std::time::Instant::now())
        .map_err(|_| err(StatusCode::NOT_FOUND, "preparation not found"))?;
    Ok(Json(response))
}

async fn run_batch_job(state: Arc<AppState>, job: BatchJob) -> Result<BatchPrepared, &'static str> {
    let wallet = state.get_wallet(&job.token).await.ok_or("registered wallet disappeared")?;
    ensure_canonical_checkpoint(&state, &wallet).await.map_err(|_| "wallet checkpoint unavailable")?;
    build_send_cache_off_lock(&state, &job.token, &wallet).await;
    let (fvk, inputs, positions, fee, amount) = {
        let mut entry = wallet.lock().await;
        if !entry.key.is_watch_only() || entry.db.fvk().to_bytes() != job.fvk {
            return Err("registered wallet changed during preparation");
        }
        if entry.reorged_strikes > 0 {
            return Err("wallet checkpoint is being repaired");
        }
        let matured = entry.matured_leaves().ok_or("wallet has no matured anchor")?;
        let shared_covers = state.chain_tree_size.load(std::sync::atomic::Ordering::Relaxed);
        let shared_base = state.chain_tree_base.load(std::sync::atomic::Ordering::Relaxed);
        tokio::task::block_in_place(|| entry.advance_spend_witnesses_bounded(shared_covers, shared_base));
        let (mut candidates, _) = matured_candidates(&entry.db, matured);
        candidates.sort_by_key(|note| std::cmp::Reverse(note.value()));
        let values: Vec<u64> = candidates.iter().map(|note| note.value()).collect();
        let amount =
            job.intent.outputs.iter().try_fold(0u64, |sum, output| sum.checked_add(output.amount)).ok_or("payment amount overflow")?;
        let (take, fee) = choose_batch_spends(&values, amount, job.intent.outputs.len(), job.intent.max_fee)?;
        let selected: Vec<_> = candidates.iter().take(take).cloned().collect();
        let positions: Vec<u64> = selected.iter().map(|note| note.position).collect();
        let paths = tokio::task::block_in_place(|| state.batch_witness_paths(&entry.db, &positions, matured));
        let mut inputs = Vec::with_capacity(take);
        for (note, path) in selected.iter().zip(paths) {
            let path = match path {
                Some(path) => path,
                None => tokio::task::block_in_place(|| entry.db.witness_path_at(note.position, matured))
                    .ok_or("matured note has no witness path")?,
            };
            inputs.push((note.note, path));
        }
        (entry.db.fvk().clone(), inputs, positions, fee, amount)
    };
    let _permit = tokio::time::timeout(PREPARE_QUEUE_WAIT, state.prepare_gate.acquire())
        .await
        .map_err(|_| "proving queue timed out")?
        .map_err(|_| "proving queue closed")?;
    let network = state.genesis.as_bytes();
    let context = payment_tx_context();
    let outputs = job.intent.outputs.clone();
    let payment = tokio::task::spawn_blocking(move || {
        let _proving = ProvingGuard::new();
        kaspa_shielded_core::wallet::build::prepare_payment_multi(&fvk, inputs, &outputs, fee, &network, &context, true)
    })
    .await
    .map_err(|_| "proof task failed")?
    .map_err(|_| "multi-output proof failed")?;
    let fvk = fvk_from_bytes(&job.fvk).ok_or("invalid wallet viewing key")?;
    kaspa_shielded_core::payment_check::check_prepared_payment_multi_recoverable(
        &payment.effects,
        &payment.disclosure,
        &fvk,
        &job.intent.outputs,
        fee,
        job.intent.max_fee,
    )
    .map_err(|_| "prepared payment output recovery failed")?;
    let network_name = match state.network.as_str() {
        "mainnet" => SdkNetwork::Mainnet,
        "testnet" => SdkNetwork::Testnet,
        "devnet" => SdkNetwork::Devnet,
        "simnet" => SdkNetwork::Simnet,
        _ => return Err("unsupported network"),
    };
    let typed = zkas_sdk::PreparedPaymentMulti {
        version: zkas_sdk::PreparedPaymentMulti::VERSION,
        network_domain: network,
        tx_context: payment_tx_context(),
        bundle: payment.effects.clone(),
        disclosure: payment.disclosure.clone(),
        spend_auth: payment
            .spend_auth_requests
            .iter()
            .map(|(action_index, alpha)| zkas_sdk::SpendAuthRequest { action_index: *action_index, alpha: *alpha })
            .collect(),
        claimed_account: job.intent.account,
        claimed_outputs: job.intent.outputs,
        claimed_fee: fee,
    };
    let envelope =
        zkas_sdk::PreparedPaymentMultiEnvelope::from_typed(&typed, &network_name).map_err(|_| "prepared envelope encoding failed")?;
    let mut session_bytes = [0u8; 24];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut session_bytes);
    Ok(BatchPrepared {
        payment,
        positions,
        amount,
        fee,
        response: BatchPrepareResp {
            status: "prepared",
            logical_id: hex(&job.logical_id),
            session: Some(hex(&session_bytes)),
            prepared_payment: Some(envelope),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_query_requires_bounded_cursor_and_wallet_token() {
        let query: BatchDiscoveryQuery = serde_json::from_value(serde_json::json!({
            "account": "zkas:example", "genesis": hex(&[7; 32]),
            "afterLogicalId": hex(&[2; 32]), "epoch": hex(&[3; 32]),
        })).unwrap();
        let cursor = discovery_cursor(&query).unwrap();
        assert_eq!(cursor.after, Some([2; 32]));
        assert_eq!(cursor.epoch, Some([3; 32]));
        let no_epoch = BatchDiscoveryQuery { epoch: None, ..query };
        assert!(discovery_cursor(&no_epoch).is_err());
        let upper = BatchDiscoveryQuery { epoch: Some("AA".repeat(32)), ..no_epoch };
        assert!(discovery_cursor(&upper).is_err());
        assert!(serde_json::from_value::<BatchDiscoveryQuery>(serde_json::json!({
            "account": "zkas:example", "genesis": hex(&[7; 32]), "unknown": true,
        })).is_err());
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Batch {}", hex(&[5; 32]))).unwrap());
        assert!(token_from(&headers, false).is_err());
    }

    #[test]
    fn discovery_account_requires_canonical_address_text() {
        let canonical = "zkas:pxm8d4su40hc95vr0llq7rrf5gqzhmdhh5m3c8qtve2dllfxrqrsh6wlugnyp3krnxe2cgs4fmfwagv";
        let alias = "zkas:pxm8d4su40hc95vr0llq7rrf5gqzhmdhh5m3c8qtve2dllfxrqrsh6wlugnyp3krnxe2cg3x2zzh7md";
        let parsed = Address::try_from(canonical).unwrap();
        assert_eq!(Address::try_from(alias).unwrap(), parsed);
        assert!(canonical_discovery_account(canonical).is_ok());
        assert!(canonical_discovery_account(alias).is_err());
    }

    #[test]
    fn discovery_response_contains_only_bounded_inventory_metadata() {
        let response = BatchDiscoveryResp {
            inventory_only: true,
            epoch: hex(&[4; 32]),
            entries: vec![BatchDiscoveryEntry {
                logical_id: hex(&[2; 32]), revision: 2, status: "unknown", txid: hex(&[3; 32]), sha256: hex(&[5; 32]),
                included_block: None, included_daa: None,
            }],
            next_after_logical_id: None,
            unlisted_reservation_count: 1,
        };
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["inventoryOnly"], true);
        assert_eq!(json["unlistedReservationCount"], 1);
        assert_eq!(json["entries"][0]["status"], "unknown");
        assert_eq!(json["entries"][0]["revision"], 2);
        assert!(json.get("nextAfterLogicalId").is_none());
        let text = json.to_string();
        for private in ["transactionHex", "origin", "intent", "positions", "memo", "fvk", "token", "account"] {
            assert!(!text.contains(private), "exposed {private}");
        }
    }

    #[test]
    fn unavailable_history_preserves_inclusion_for_node_recovery() {
        let tx = payment_tx(vec![1]);
        let mut record = batch_journal::JournalRecord::new(
            [1; 96], "token", [7; 32], [8; 43], "legacy", [2; 32], [3; 32],
            borsh::to_vec(&tx).unwrap(), vec![42],
        ).unwrap();
        record.phase = batch_journal::JournalPhase::Settled;
        record.start_cursor = Some([4; 32]);
        record.scan_cursor = Some([5; 32]);
        record.included_block = Some([6; 32]);
        record.included_daa = Some(100);
        let original = record.clone();
        assert!(apply_inclusion_lookup(&mut record, AcceptanceLookup::Unavailable, tx.id().as_bytes()).is_err());
        assert_eq!(record, original);
        assert_eq!(apply_inclusion_lookup(&mut record, AcceptanceLookup::Found(vec![tx.id().as_bytes()]), tx.id().as_bytes()), Ok(false));
        assert_eq!(record, original);
        assert_eq!(apply_inclusion_lookup(&mut record, AcceptanceLookup::Replaced, tx.id().as_bytes()), Ok(true));
        assert_eq!(record.phase, batch_journal::JournalPhase::Unknown);
        assert!(record.scan_cursor.is_none());
    }

    #[test]
    fn release_requires_six_hundred_daa_on_node_and_wallet() {
        assert!(!release_depth_satisfied(100, 699, 700));
        assert!(!release_depth_satisfied(100, 700, 699));
        assert!(release_depth_satisfied(100, 700, 700));
        assert!(!release_depth_satisfied(u64::MAX, u64::MAX, u64::MAX));
    }

    #[test]
    fn profile_and_legacy_reservation_fail_closed() {
        assert!(supported_profile(false, false, "mainnet"));
        assert!(!supported_profile(true, false, "mainnet"));
        assert!(!supported_profile(false, true, "mainnet"));
        assert!(!supported_profile(false, false, "other"));
        let fvk = [4; 96];
        let now = std::time::Instant::now();
        let mut active = HashMap::new();
        active.insert(hex(&fvk), (now, false));
        assert!(legacy_reservation_exists(&fvk, &active, std::iter::empty(), now));
        active.clear();
        assert!(legacy_reservation_exists(&fvk, &active, std::iter::once((fvk, now)), now));
        assert!(!legacy_reservation_exists(&fvk, &active, std::iter::once((fvk, now)), now + PREPARED_TTL));
        assert!(!legacy_reservation_exists(&fvk, &active, std::iter::once(([3; 96], now)), now));
    }

    #[test]
    fn batch_authorization_header_requires_exact_origin_and_lowercase_capability() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Batch {}", hex(&[7; 32]))).unwrap());
        assert!(capability_headers(&headers).is_err());
        headers.insert(header::ORIGIN, HeaderValue::from_static("https://example.test"));
        assert_eq!(capability_headers(&headers).unwrap().0, [7; 32]);
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer 123"));
        assert!(capability_headers(&headers).is_err());
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Batch {}", "AA".repeat(32))).unwrap());
        assert!(capability_headers(&headers).is_err());
    }

    #[test]
    fn batch_origin_accepts_only_explicit_canonical_loopback_http_ports() {
        for origin in [
            "https://example.test",
            "https://example.test:8443",
            "http://localhost:8765",
            "http://127.0.0.1:1",
            "http://127.0.0.1:65535",
        ] {
            assert!(valid_batch_origin(origin), "rejected {origin}");
        }
        for origin in [
            "http://localhost",
            "http://127.0.0.1",
            "http://localhost:0",
            "http://localhost:00",
            "http://localhost:08080",
            "http://localhost:80",
            "http://localhost:65536",
            "http://LOCALHOST:8765",
            "http://localhost.:8765",
            "http://localhost.evil.test:8765",
            "http://127.0.0.2:8765",
            "http://[::1]:8765",
            "http://100.100.100.100:8765",
            "http://example.test:8765",
            "http://user@localhost:8765",
            "http://localhost:8765/",
            "http://localhost:8765/path",
            "http://localhost:8765?x=1",
            "http://localhost:8765#fragment",
            "http://localhost:8765:*",
            "HTTP://localhost:8765",
        ] {
            assert!(!valid_batch_origin(origin), "accepted {origin}");
        }
    }

    #[test]
    fn loopback_capability_is_bound_to_the_exact_browser_origin() {
        let now = std::time::Instant::now();
        let fvk = [9; 96];
        let intent = BatchIntent { account: [5; 43], outputs: vec![], max_fee: 10 };
        let mut registry = BatchRegistry::default();
        let origin = "http://localhost:8765";
        assert!(valid_batch_origin(origin));
        let capability = registry.issue(fvk, "owner", origin, [7; 32], intent, now).unwrap();
        assert_eq!(registry.authorize(&capability, origin, now).unwrap(), fvk);
        for other in ["http://localhost:8766", "http://127.0.0.1:8765", "https://localhost:8765"] {
            assert!(registry.authorize(&capability, other, now).is_err());
        }
    }

    #[test]
    fn browser_capability_status_excludes_prepared_envelope_and_session() {
        let response = BatchPrepareResp {
            status: "prepared",
            logical_id: hex(&[2; 32]),
            session: Some("secret session".into()),
            prepared_payment: None,
        };
        let json = serde_json::to_value(response.capability_view()).unwrap();
        assert_eq!(json["status"], "prepared");
        assert!(json.get("session").is_none());
        assert!(json.get("preparedPayment").is_none());
    }

    #[test]
    fn finalize_request_rejects_repeated_and_incomplete_signatures_before_consumption() {
        let requests = [(1usize, [3u8; 32]), (3usize, [4u8; 32])];
        assert!(validate_signature_indices(&requests, &[(1, [0u8; 64])], 4).is_err());
        assert!(validate_signature_indices(&requests, &[(1, [0u8; 64]), (1, [0u8; 64])], 4).is_err());
        assert!(validate_signature_indices(&requests, &[(1, [0u8; 64]), (4, [0u8; 64])], 4).is_err());
        assert!(validate_signature_indices(&requests, &[(1, [0u8; 64]), (3, [0u8; 64])], 4).is_ok());
    }

    #[test]
    fn finalized_bytes_are_immutable_for_identical_retry() {
        let first = BatchFinalized::new(vec![1, 2, 3], "abcd".into(), [7; 32], vec![(0, [1; 64])], vec![1]);
        let first_json = serde_json::to_vec(&first.response).unwrap();
        assert_eq!(first.response.transaction_hex, "010203");
        assert_eq!(first.response.sha256, hex(&sha2::Sha256::digest([1, 2, 3])));
        assert_eq!(first.retry(&[(0, [1; 64])]).unwrap().transaction_hex, first.response.transaction_hex);
        assert_eq!(serde_json::to_vec(first.retry(&[(0, [1; 64])]).unwrap()).unwrap(), first_json);
        assert!(first.retry(&[(0, [2; 64])]).is_err());
    }

    #[test]
    fn finalizing_keeps_wallet_reserved_when_unsigned_ttl_passes() {
        let now = std::time::Instant::now();
        let fvk = [9; 96];
        let intent = BatchIntent { account: [5; 43], outputs: vec![], max_fee: 10 };
        let mut registry = BatchRegistry::default();
        registry.issue(fvk, "owner", "https://example.test", [7; 32], intent.clone(), now).unwrap();
        let record = registry.records.get_mut(&fvk).unwrap();
        record.phase = BatchPhase::Finalizing;
        record.expires = now;
        let later = now + GRANT_TTL;
        assert!(registry.reserves(&fvk, later));
        assert!(registry.issue(fvk, "owner", "https://example.test", [8; 32], intent, later).is_err());
    }

    #[test]
    fn real_proof_invalid_signature_preserves_session_then_finalizes_once() {
        use incrementalmerkletree::{Hashable, Level};
        use orchard::{
            keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
            note::{NoteVersion, RandomSeed, Rho},
            tree::{MerkleHashOrchard, MerklePath},
            value::NoteValue,
        };
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes([7; 32])).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let account = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        let recipient = FullViewingKey::from(&Option::<SpendingKey>::from(SpendingKey::from_bytes([8; 32])).unwrap())
            .address_at(0u32, Scope::External)
            .to_raw_address_bytes();
        let mut rho_bytes = [0; 32];
        rho_bytes[0] = 3;
        let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).unwrap();
        let mut seed_bytes = [0; 32];
        seed_bytes[0] = 4;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(seed_bytes, &rho)).unwrap();
        let note = Option::<orchard::Note>::from(orchard::Note::from_parts(
            fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(10_000_000),
            rho,
            rseed,
            NoteVersion::V2,
        ))
        .unwrap();
        let path =
            MerklePath::from_parts(0, core::array::from_fn(|i| <MerkleHashOrchard as Hashable>::empty_root(Level::from(i as u8))));
        let outputs = vec![PaymentOutputIntent { recipient, amount: 2_000_000, memo: [0; 512] }];
        let genesis = [0x55; 32];
        let payment = kaspa_shielded_core::wallet::build::prepare_payment_multi(
            &fvk,
            vec![(note, path)],
            &outputs,
            3_000_000,
            &genesis,
            &payment_tx_context(),
            true,
        )
        .unwrap();
        let expected = zkas_sdk::PreparedPaymentMulti {
            version: 3,
            network_domain: genesis,
            tx_context: payment_tx_context(),
            bundle: payment.effects.clone(),
            disclosure: payment.disclosure.clone(),
            spend_auth: payment
                .spend_auth_requests
                .iter()
                .map(|(action_index, alpha)| zkas_sdk::SpendAuthRequest { action_index: *action_index, alpha: *alpha })
                .collect(),
            claimed_account: account,
            claimed_outputs: outputs.clone(),
            claimed_fee: 3_000_000,
        };
        let envelope = zkas_sdk::PreparedPaymentMultiEnvelope::from_typed(&expected, &SdkNetwork::Simnet).unwrap();
        let ask = SpendAuthorizingKey::from(&sk);
        let signatures: Vec<_> = payment
            .spend_auth_requests
            .iter()
            .map(|(index, alpha)| {
                (*index, kaspa_shielded_core::wallet::build::sign_spend_auth(&ask, *alpha, payment.sighash).unwrap())
            })
            .collect();
        let intent = BatchIntent { account, outputs, max_fee: 3_000_000 };
        let prepared = BatchPrepared {
            payment,
            positions: vec![0],
            amount: 2_000_000,
            fee: 3_000_000,
            response: BatchPrepareResp {
                status: "prepared",
                logical_id: hex(&[1; 32]),
                session: Some(hex(&[2; 24])),
                prepared_payment: Some(envelope),
            },
        };
        let mut registry = BatchRegistry::default();
        let fvk_bytes = fvk.to_bytes();
        let now = std::time::Instant::now();
        registry.issue(fvk_bytes, "owner", "https://example.test", [1; 32], intent, now).unwrap();
        registry.records.get_mut(&fvk_bytes).unwrap().phase = BatchPhase::Proving;
        registry.finish_success(&fvk_bytes, prepared, now);
        let bad = vec![(signatures[0].0, [0; 64])];
        assert!(registry.begin_finalize(&fvk_bytes, "other", [1; 32], &hex(&[2; 24]), account, &genesis, &signatures, now).is_err());
        assert!(registry.begin_finalize(&fvk_bytes, "owner", [9; 32], &hex(&[2; 24]), account, &genesis, &signatures, now).is_err());
        assert!(registry.begin_finalize(&fvk_bytes, "owner", [1; 32], &hex(&[3; 24]), account, &genesis, &signatures, now).is_err());
        assert!(registry.begin_finalize(&fvk_bytes, "owner", [1; 32], &hex(&[2; 24]), [0; 43], &genesis, &signatures, now).is_err());
        let mut other_genesis = genesis;
        other_genesis[0] ^= 1;
        assert!(
            registry.begin_finalize(&fvk_bytes, "owner", [1; 32], &hex(&[2; 24]), account, &other_genesis, &signatures, now).is_err()
        );
        assert!(registry.begin_finalize(&fvk_bytes, "owner", [1; 32], &hex(&[2; 24]), account, &genesis, &bad, now).is_err());
        assert!(matches!(registry.records.get(&fvk_bytes).unwrap().phase, BatchPhase::Ready(_)));
        let (prepared, intent) = match registry
            .begin_finalize(&fvk_bytes, "owner", [1; 32], &hex(&[2; 24]), account, &genesis, &signatures, now)
            .unwrap()
        {
            BatchFinalizeStart::New(prepared, intent, _) => (*prepared, intent),
            _ => panic!("expected one finalization"),
        };
        let finalized = finalize_batch_prepared(prepared, intent, signatures.clone(), [1; 32], fvk_bytes, genesis, "simnet").unwrap();
        let bytes = hex::decode(&finalized.response.transaction_hex).unwrap();
        let tx: Transaction = borsh::from_slice(&bytes).unwrap();
        assert_eq!(finalized.response.txid, hex(&tx.id().as_bytes()));
        registry.finish_finalize(&fvk_bytes, Ok(finalized));
        let again =
            registry.begin_finalize(&fvk_bytes, "owner", [1; 32], &hex(&[2; 24]), account, &genesis, &signatures, now).unwrap();
        assert!(matches!(again, BatchFinalizeStart::Ready(response) if response.transaction_hex == hex(&bytes)));
    }
}
