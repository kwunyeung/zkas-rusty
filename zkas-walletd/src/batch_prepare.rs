//! Scoped preparation of one exact multi-output watch-only payment.

use super::*;
use kaspa_shielded_core::payment_check::PaymentOutputIntent;
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
    phase: BatchPhase,
}

enum BatchPhase {
    Issued,
    Proving,
    Ready(Box<BatchPrepared>),
    Failed,
}

#[allow(dead_code)] // Retained for a separate finalization route; this route only prepares.
struct BatchPrepared {
    payment: PreparedPayment,
    positions: Vec<u64>,
    amount: u64,
    fee: u64,
    response: BatchPrepareResp,
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
        matches!(self.phase, BatchPhase::Proving) || self.expires > now
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
            BatchPhase::Failed => BatchPrepareResp::failed(record.logical_id),
        })
    }
}

impl BatchPrepareResp {
    fn pending(logical_id: [u8; 32]) -> Self {
        Self { status: "in_progress", logical_id: hex(&logical_id), session: None, prepared_payment: None }
    }

    fn failed(logical_id: [u8; 32]) -> Self {
        Self { status: "failed", logical_id: hex(&logical_id), session: None, prepared_payment: None }
    }

    fn capability_view(&self) -> Self {
        Self { status: self.status, logical_id: self.logical_id.clone(), session: None, prepared_payment: None }
    }
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
    let now = std::time::Instant::now();
    // Hold the legacy active tracker while examining unsigned legacy sessions and
    // installing the new reservation. A legacy prepare keeps its active marker
    // until after it has inserted its session, so no gap can select the same notes.
    let active = state.preparing.lock().map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "prepare tracker poisoned"))?;
    let pending = state.prepared.try_lock().map_err(|_| err(StatusCode::SERVICE_UNAVAILABLE, "preparation tracker busy"))?;
    if legacy_reservation_exists(&fvk, &active, pending.values().map(|session| (session.fvk, session.created)), now) {
        return Err(err(StatusCode::CONFLICT, "this wallet already has a pending payment preparation"));
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
}
