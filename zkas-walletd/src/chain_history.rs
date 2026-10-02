use crate::AppState;
use axum::{
    body::Bytes,
    extract::{RawQuery, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{GetShieldedBlocksResponse, RpcHash, api::rpc::RpcApi, notify::mode::NotificationMode};
use serde::Serialize;
use std::collections::HashSet;
use std::future::Future;
use std::io::Write;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, RwLock, Semaphore, watch};

const COMPACT_ACTION_LEN: usize = 148;
const MAX_COMPACT_BYTES: usize = 2_000_000;
const MAX_JSON_BYTES: usize = 6 * 1024 * 1024;
const PAGE_DEADLINE: Duration = Duration::from_secs(20);
const CALL_DEADLINE: Duration = Duration::from_secs(12);

#[derive(Clone)]
pub(crate) struct HistoryConnection {
    pub(crate) generation: u64,
    pub(crate) client: GrpcClient,
}

#[derive(Default)]
pub(crate) struct HistoryRetire {
    latest: AtomicU64,
    notify: Notify,
}

impl HistoryRetire {
    fn request(&self, generation: u64) {
        self.latest.fetch_max(generation, Ordering::AcqRel);
        self.notify.notify_one();
    }

    fn requested(&self, generation: u64) -> bool {
        self.latest.load(Ordering::Acquire) == generation
    }
}

struct HistoryReadGuard {
    retire: Arc<HistoryRetire>,
    generation: u64,
    armed: bool,
}

impl HistoryReadGuard {
    fn new(retire: Arc<HistoryRetire>, generation: u64) -> Self {
        Self { retire, generation, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for HistoryReadGuard {
    fn drop(&mut self) {
        if self.armed {
            self.retire.request(self.generation);
        }
    }
}

fn next_generation(current: u64) -> Option<u64> {
    current.checked_add(1)
}

fn take_matching<T>(slot: &mut Option<T>, generation: u64, key: impl FnOnce(&T) -> u64) -> Option<T> {
    if slot.as_ref().is_some_and(|value| key(value) == generation) { slot.take() } else { None }
}

fn random_generation() -> u64 {
    loop {
        let generation = u64::from_le_bytes(rand::random::<[u8; 8]>());
        if generation != 0 {
            return generation;
        }
    }
}

const RETRY_DELAY: Duration = Duration::from_secs(3);
const DRAIN_DELAY: Duration = Duration::from_secs(5);
static HISTORY_PERMIT: OnceLock<Semaphore> = OnceLock::new();
static HISTORY_RUNS: OnceLock<Mutex<Vec<Arc<HistoryRun>>>> = OnceLock::new();

struct HistoryRun {
    stop: watch::Sender<bool>,
    done: AtomicBool,
    done_notify: Notify,
    handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl HistoryRun {
    fn stop(&self) {
        self.stop.send_replace(true);
    }

    async fn wait_done(&self) {
        loop {
            let notified = self.done_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.done.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

// The registry owns every spawned supervisor until it finishes, even if serve is
// canceled during its soft shutdown wait. One owner may be retiring a channel;
// one more may wait for the process permit. Additional starts remain unavailable.
pub(crate) struct HistorySupervisorLease(Option<Arc<HistoryRun>>);

impl HistorySupervisorLease {
    pub(crate) fn stop(&self) {
        if let Some(run) = &self.0 {
            run.stop();
        }
    }

    pub(crate) async fn drain(&self) {
        self.drain_for(DRAIN_DELAY).await;
    }

    async fn drain_for(&self, delay: Duration) {
        if let Some(run) = &self.0 {
            if tokio::time::timeout(delay, run.wait_done()).await.is_err() {
                log::warn!("history channel retirement pending");
            }
        }
    }
}

impl Drop for HistorySupervisorLease {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(crate) fn start_supervisor(
    slot: Arc<RwLock<Option<HistoryConnection>>>,
    retire: Arc<HistoryRetire>,
    rpc_server: String,
) -> HistorySupervisorLease {
    let registry = HISTORY_RUNS.get_or_init(|| Mutex::new(Vec::with_capacity(2)));
    let mut runs = registry.lock().unwrap_or_else(|e| e.into_inner());
    runs.retain(|run| {
        if run.done.load(Ordering::Acquire) {
            // The completed handle is reaped before this registry slot is reused.
            let _ = run.handle.lock().unwrap_or_else(|e| e.into_inner()).take();
            false
        } else {
            true
        }
    });
    if runs.len() >= 2 {
        return HistorySupervisorLease(None);
    }
    let (stop, stop_rx) = watch::channel(false);
    let run = Arc::new(HistoryRun { stop, done: AtomicBool::new(false), done_notify: Notify::new(), handle: Mutex::new(None) });
    let owned = run.clone();
    let handle = tokio::spawn(async move {
        run_supervisor(slot, retire, rpc_server, stop_rx).await;
        owned.done.store(true, Ordering::Release);
        owned.done_notify.notify_waiters();
    });
    *run.handle.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
    runs.push(run.clone());
    HistorySupervisorLease(Some(run))
}

async fn disconnect_until_complete(client: &GrpcClient) {
    loop {
        if client.disconnect().await.is_ok() {
            return;
        }
        log::warn!("history channel retirement failed; retrying");
        tokio::time::sleep(RETRY_DELAY).await;
    }
}

async fn run_supervisor(
    slot: Arc<RwLock<Option<HistoryConnection>>>,
    retire: Arc<HistoryRetire>,
    rpc_server: String,
    stop: watch::Receiver<bool>,
) {
    run_supervisor_from_generation(slot, retire, rpc_server, stop, random_generation()).await;
}

async fn run_supervisor_from_generation(
    slot: Arc<RwLock<Option<HistoryConnection>>>,
    retire: Arc<HistoryRetire>,
    rpc_server: String,
    mut stop: watch::Receiver<bool>,
    mut generation: u64,
) {
    let gate = HISTORY_PERMIT.get_or_init(|| Semaphore::new(1));
    let _permit = tokio::select! {
        permit = gate.acquire() => match permit { Ok(permit) => permit, Err(_) => return },
        _ = stop.changed() => return,
    };
    if *stop.borrow() {
        return;
    }
    loop {
        if *stop.borrow() {
            return;
        }
        let attempt = GrpcClient::connect_with_args_and_receive_limit(
            NotificationMode::Direct,
            format!("grpc://{rpc_server}"),
            None,
            false,
            None,
            false,
            Some(5_000),
            Default::default(),
            Some(8 * 1024 * 1024),
        );
        let connected = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(8), attempt) => result,
            _ = stop.changed() => return,
        };
        let client = match connected {
            Ok(Ok(client)) => client,
            _ => {
                tokio::select! {
                    _ = tokio::time::sleep(RETRY_DELAY) => {},
                    _ = stop.changed() => return,
                }
                continue;
            }
        };
        let Some(next) = next_generation(generation) else {
            disconnect_until_complete(&client).await;
            return;
        };
        generation = next;
        // The local client remains the cleanup owner even if publication loses
        // a race with shutdown. The slot only lends clones to request handlers.
        let published = tokio::select! {
            mut published = slot.write() => {
                if *stop.borrow() || retire.requested(generation) || published.is_some() {
                    false
                } else {
                    *published = Some(HistoryConnection { generation, client: client.clone() });
                    true
                }
            }
            _ = stop.changed() => false,
        };
        if published {
            loop {
                if *stop.borrow() || retire.requested(generation) || !client.is_connected() {
                    break;
                }
                tokio::select! {
                    _ = retire.notify.notified() => {},
                    _ = tokio::time::sleep(RETRY_DELAY) => {},
                    _ = stop.changed() => {},
                }
            }
            let mut published = slot.write().await;
            let _ = take_matching(&mut published, generation, |current| current.generation);
            drop(published);
        }
        disconnect_until_complete(&client).await;
        if *stop.borrow() {
            return;
        }
    }
}

#[derive(Clone)]
struct Tip {
    hash: RpcHash,
    daa: u64,
    blue: u64,
}

struct Floor {
    checkpoint: RpcHash,
    daa: u64,
    history_from: u64,
    complete: bool,
}

trait HistorySource {
    fn info(&self) -> impl Future<Output = Result<(String, bool), ()>> + Send;
    fn sync_status(&self) -> impl Future<Output = Result<bool, ()>> + Send;
    fn sink(&self) -> impl Future<Output = Result<RpcHash, ()>> + Send;
    fn tip(&self, hash: RpcHash) -> impl Future<Output = Result<Tip, ()>> + Send;
    fn floor(&self) -> impl Future<Output = Result<Floor, ()>> + Send;
    fn page(&self, after: RpcHash, limit: u8) -> impl Future<Output = Result<GetShieldedBlocksResponse, ()>> + Send;
}

impl HistorySource for GrpcClient {
    async fn info(&self) -> Result<(String, bool), ()> {
        let r = self.get_server_info().await.map_err(|_| ())?;
        Ok((r.network_id.to_string(), r.is_synced))
    }
    async fn sync_status(&self) -> Result<bool, ()> {
        self.get_sync_status().await.map_err(|_| ())
    }
    async fn sink(&self) -> Result<RpcHash, ()> {
        Ok(self.get_sink().await.map_err(|_| ())?.sink)
    }
    async fn tip(&self, hash: RpcHash) -> Result<Tip, ()> {
        let block = self.get_block(hash, false).await.map_err(|_| ())?;
        let verbose = block.verbose_data.ok_or(())?;
        if block.header.hash != hash
            || verbose.hash != hash
            || verbose.blue_score != block.header.blue_score
            || !verbose.is_chain_block
            || !block.transactions.is_empty()
        {
            return Err(());
        }
        Ok(Tip { hash, daa: block.header.daa_score, blue: block.header.blue_score })
    }
    async fn floor(&self) -> Result<Floor, ()> {
        let r = self.get_shielded_tree_state(None).await.map_err(|_| ())?;
        Ok(Floor { checkpoint: r.block_hash, daa: r.daa_score, history_from: r.history_from_daa_score, complete: r.history_complete })
    }
    async fn page(&self, after: RpcHash, limit: u8) -> Result<GetShieldedBlocksResponse, ()> {
        self.get_shielded_blocks(after, u64::from(limit)).await.map_err(|_| ())
    }
}

async fn call<T>(future: impl Future<Output = Result<T, ()>>) -> Result<T, ()> {
    tokio::time::timeout(CALL_DEADLINE, future).await.map_err(|_| ())?
}

struct Snapshot {
    observed_network: String,
    before: Tip,
    after: Tip,
    floor: Floor,
    page: GetShieldedBlocksResponse,
    has_ids: bool,
}

async fn read_snapshot<S: HistorySource>(source: &S, query: HistoryQuery, expected_network: &str) -> Result<Snapshot, ()> {
    let (network, synced) = call(source.info()).await?;
    if !synced || network != expected_network || !call(source.sync_status()).await? {
        return Err(());
    }
    let before_hash = call(source.sink()).await?;
    let before = call(source.tip(before_hash)).await?;
    let floor = call(source.floor()).await?;
    let page = call(source.page(query.after, query.limit)).await?;
    let has_ids = validate_page(&page, query.limit, query.after, before.hash)?;
    let after_hash = call(source.sink()).await?;
    let after = call(source.tip(after_hash)).await?;
    let (network_after, synced_after) = call(source.info()).await?;
    if !synced_after || network_after != network || !call(source.sync_status()).await? {
        return Err(());
    }
    Ok(Snapshot { observed_network: network, before, after, floor, page, has_ids })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonTip {
    hash: String,
    daa: String,
    blue_score: String,
}
impl From<Tip> for JsonTip {
    fn from(t: Tip) -> Self {
        Self { hash: t.hash.to_string(), daa: t.daa.to_string(), blue_score: t.blue.to_string() }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonFloor {
    served_checkpoint_hash: String,
    served_checkpoint_daa: String,
    history_from_daa: String,
    history_complete: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonOutput {
    script_hex: String,
    value_sompi: String,
    commitment_hex: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonBlock {
    hash: String,
    daa: String,
    blue_score: String,
    timestamp_ms: String,
    coinbase_txid: String,
    coinbase_outputs: Vec<JsonOutput>,
    accepted_txids: Vec<String>,
    accepted_compact_hex: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonSource {
    generation: String,
    configured_network: String,
    observed_network: String,
    configured_genesis: String,
    sync_before: bool,
    sync_after: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonRequest {
    after: String,
    limit: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonPage {
    reorged: bool,
    sink_blue_score: String,
    protocol_evidence: &'static str,
    blocks: Vec<JsonBlock>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonResponse {
    version: u8,
    encoding: &'static str,
    request: JsonRequest,
    source: JsonSource,
    tip_before: JsonTip,
    floor: JsonFloor,
    page: JsonPage,
    tip_after: JsonTip,
}

fn response_dto(snapshot: Snapshot, query: HistoryQuery, generation: u64, network: &str, genesis: RpcHash) -> JsonResponse {
    JsonResponse {
        version: 1,
        encoding: "hex-compact-148-v1",
        request: JsonRequest { after: query.after.to_string(), limit: query.limit },
        source: JsonSource {
            generation: generation.to_string(),
            configured_network: network.to_string(),
            observed_network: snapshot.observed_network,
            configured_genesis: genesis.to_string(),
            sync_before: true,
            sync_after: true,
        },
        tip_before: snapshot.before.into(),
        floor: JsonFloor {
            served_checkpoint_hash: snapshot.floor.checkpoint.to_string(),
            served_checkpoint_daa: snapshot.floor.daa.to_string(),
            history_from_daa: snapshot.floor.history_from.to_string(),
            history_complete: snapshot.floor.complete,
        },
        page: JsonPage {
            reorged: snapshot.page.reorged,
            sink_blue_score: snapshot.page.sink_blue_score.to_string(),
            protocol_evidence: if snapshot.has_ids { "id-bearing-actions-observed" } else { "unknown" },
            blocks: snapshot
                .page
                .blocks
                .into_iter()
                .map(|b| JsonBlock {
                    hash: b.hash.to_string(),
                    daa: b.daa_score.to_string(),
                    blue_score: b.blue_score.to_string(),
                    timestamp_ms: b.timestamp.to_string(),
                    coinbase_txid: b.coinbase_txid.to_string(),
                    coinbase_outputs: b
                        .coinbase_outputs
                        .into_iter()
                        .map(|o| JsonOutput {
                            script_hex: hex::encode(o.script_public_key),
                            value_sompi: o.value.to_string(),
                            commitment_hex: o.commitment.map(hex::encode),
                        })
                        .collect(),
                    accepted_txids: b.accepted_txids.into_iter().map(|id| id.to_string()).collect(),
                    accepted_compact_hex: b.accepted_actions.into_iter().map(hex::encode).collect(),
                })
                .collect(),
        },
        tip_after: snapshot.after.into(),
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
}
impl Write for BoundedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().checked_add(buf.len()).is_none_or(|n| n > MAX_JSON_BYTES) {
            return Err(std::io::Error::other("history response limit"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialize_response(response: &JsonResponse) -> Result<Vec<u8>, ()> {
    let mut writer = BoundedWriter { bytes: Vec::new() };
    serde_json::to_writer(&mut writer, response).map_err(|_| ())?;
    Ok(writer.bytes)
}

fn fixed_error(status: StatusCode, message: &'static str) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], format!("{{\"error\":\"{message}\"}}")).into_response()
}

pub(crate) async fn shielded_history(State(state): State<Arc<AppState>>, RawQuery(raw): RawQuery, _body: Bytes) -> Response {
    let Ok(query) = raw.as_deref().ok_or(()).and_then(parse_query) else {
        return fixed_error(StatusCode::BAD_REQUEST, "invalid history query");
    };
    let Ok(_permit) = state.history_gate.try_acquire() else {
        return fixed_error(StatusCode::SERVICE_UNAVAILABLE, "history busy");
    };
    let Some(connection) = state.history_client.read().await.clone() else {
        return fixed_error(StatusCode::SERVICE_UNAVAILABLE, "history source unavailable");
    };
    let mut read = HistoryReadGuard::new(state.history_retire.clone(), connection.generation);
    let expected_network =
        kaspa_consensus_core::config::params::Params::from(super::state_prefix_network(&state.network)).net.to_string();
    let started = Instant::now();
    let result = tokio::time::timeout(PAGE_DEADLINE, read_snapshot(&connection.client, query, &expected_network)).await;
    let Ok(Ok(snapshot)) = result else {
        return fixed_error(StatusCode::BAD_GATEWAY, "history source unavailable");
    };
    if state.history_client.read().await.as_ref().is_none_or(|current| current.generation != connection.generation)
        || state.history_retire.requested(connection.generation)
        || started.elapsed() >= PAGE_DEADLINE
    {
        return fixed_error(StatusCode::BAD_GATEWAY, "history source changed");
    }
    let response = response_dto(snapshot, query, connection.generation, &expected_network, state.genesis);
    let Ok(bytes) = serialize_response(&response) else {
        return fixed_error(StatusCode::BAD_GATEWAY, "history response unavailable");
    };
    let response = (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], bytes).into_response();
    if state.history_client.read().await.as_ref().is_none_or(|current| current.generation != connection.generation)
        || state.history_retire.requested(connection.generation)
        || started.elapsed() >= PAGE_DEADLINE
    {
        return fixed_error(StatusCode::BAD_GATEWAY, "history source changed");
    }
    read.disarm();
    response
}

fn validate_page(page: &GetShieldedBlocksResponse, limit: u8, after: RpcHash, tip_before: RpcHash) -> Result<bool, ()> {
    if page.blocks.len() > usize::from(limit) || (page.reorged && !page.blocks.is_empty()) {
        return Err(());
    }
    if page.blocks.is_empty() {
        return if page.reorged || after == tip_before { Ok(false) } else { Err(()) };
    }
    let mut block_ids = HashSet::from([after]);
    let mut tx_ids = HashSet::new();
    let mut tx_count = 0usize;
    let mut output_count = 0usize;
    let mut compact_bytes = 0usize;
    let mut last_daa = None;
    let mut last_blue = None;
    let mut observed_ids = false;
    for block in &page.blocks {
        if !block_ids.insert(block.hash) || block.coinbase_txid == RpcHash::from_bytes([0; 32]) || block.timestamp == 0 {
            return Err(());
        }
        if last_daa.is_some_and(|daa| block.daa_score < daa) || last_blue.is_some_and(|blue| block.blue_score < blue) {
            return Err(());
        }
        last_daa = Some(block.daa_score);
        last_blue = Some(block.blue_score);
        output_count = output_count.checked_add(block.coinbase_outputs.len()).ok_or(())?;
        if output_count > 2048 || block.coinbase_outputs.iter().any(|out| out.script_public_key.len() > 128) {
            return Err(());
        }
        if block.accepted_actions.len() != block.accepted_txids.len() {
            return Err(());
        }
        tx_count = tx_count.checked_add(block.accepted_txids.len()).ok_or(())?;
        if tx_count > 512 {
            return Err(());
        }
        for (id, actions) in block.accepted_txids.iter().zip(&block.accepted_actions) {
            if *id == RpcHash::from_bytes([0; 32])
                || !tx_ids.insert(*id)
                || actions.is_empty()
                || actions.len() > COMPACT_ACTION_LEN * 512
                || actions.len() % COMPACT_ACTION_LEN != 0
            {
                return Err(());
            }
            observed_ids = true;
            compact_bytes = compact_bytes.checked_add(actions.len()).ok_or(())?;
            if compact_bytes > MAX_COMPACT_BYTES {
                return Err(());
            }
        }
    }
    Ok(observed_ids)
}

#[derive(Clone, Copy)]
struct HistoryQuery {
    after: RpcHash,
    limit: u8,
}

fn parse_query(raw: &str) -> Result<HistoryQuery, ()> {
    if raw.len() > 128 || !raw.is_ascii() {
        return Err(());
    }
    let mut after = None;
    let mut limit = None;
    for part in raw.split('&') {
        let (key, value) = part.split_once('=').ok_or(())?;
        match key {
            "after"
                if after.is_none() && value.len() == 64 && value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) =>
            {
                let bytes: [u8; 32] = hex::decode(value).map_err(|_| ())?.try_into().map_err(|_| ())?;
                after = Some(RpcHash::from_bytes(bytes));
            }
            "limit"
                if limit.is_none()
                    && !value.is_empty()
                    && value.len() <= 2
                    && !value.starts_with('0')
                    && value.bytes().all(|c| c.is_ascii_digit()) =>
            {
                let n: u8 = value.parse().map_err(|_| ())?;
                if !(1..=32).contains(&n) {
                    return Err(());
                }
                limit = Some(n);
            }
            _ => return Err(()),
        }
    }
    Ok(HistoryQuery { after: after.ok_or(())?, limit: limit.ok_or(())? })
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Bytes,
        extract::DefaultBodyLimit,
        http::{HeaderName, HeaderValue, Method, header},
        middleware::from_fn_with_state,
        routing::get,
    };
    use kaspa_rpc_core::{GetShieldedBlocksResponse, RpcHash, RpcShieldedChainBlock};
    use std::sync::Mutex;

    fn block(actions: Vec<Vec<u8>>, ids: Vec<RpcHash>) -> RpcShieldedChainBlock {
        RpcShieldedChainBlock {
            hash: RpcHash::from_bytes([3; 32]),
            blue_score: 3,
            daa_score: 3,
            coinbase_txid: RpcHash::from_bytes([4; 32]),
            coinbase_outputs: vec![],
            accepted_actions: actions,
            accepted_txids: ids,
            timestamp: 1,
        }
    }

    #[test]
    fn action_without_accepted_id_is_unavailable() {
        let page = GetShieldedBlocksResponse { blocks: vec![block(vec![vec![1; 148]], vec![])], reorged: false, sink_blue_score: 4 };
        assert!(super::validate_page(&page, 1, RpcHash::from_bytes([2; 32]), RpcHash::from_bytes([9; 32])).is_err());
    }

    #[test]
    fn actionless_page_does_not_claim_id_support() {
        let page = GetShieldedBlocksResponse { blocks: vec![block(vec![], vec![])], reorged: false, sink_blue_score: 4 };
        assert_eq!(super::validate_page(&page, 1, RpcHash::from_bytes([2; 32]), RpcHash::from_bytes([9; 32])).unwrap(), false);
    }

    #[test]
    fn non_tip_empty_page_is_unavailable() {
        let page = GetShieldedBlocksResponse { blocks: vec![], reorged: false, sink_blue_score: 4 };
        assert!(super::validate_page(&page, 1, RpcHash::from_bytes([2; 32]), RpcHash::from_bytes([9; 32])).is_err());
    }

    struct MockSource {
        page: GetShieldedBlocksResponse,
        calls: Mutex<Vec<&'static str>>,
        network: &'static str,
        network_after: Option<&'static str>,
        synced: bool,
        synced_after: Option<bool>,
    }
    impl MockSource {
        fn new(page: GetShieldedBlocksResponse) -> Self {
            Self { page, calls: Mutex::new(vec![]), network: "mainnet", network_after: None, synced: true, synced_after: None }
        }
        fn called(&self, name: &'static str) {
            self.calls.lock().unwrap().push(name);
        }
    }
    impl super::HistorySource for MockSource {
        async fn info(&self) -> Result<(String, bool), ()> {
            self.called("info");
            let second = self.calls.lock().unwrap().iter().filter(|&&name| name == "info").count() == 2;
            Ok((
                if second { self.network_after.unwrap_or(self.network) } else { self.network }.to_string(),
                if second { self.synced_after.unwrap_or(self.synced) } else { self.synced },
            ))
        }
        async fn sync_status(&self) -> Result<bool, ()> {
            self.called("sync");
            let second = self.calls.lock().unwrap().iter().filter(|&&name| name == "sync").count() == 2;
            Ok(if second { self.synced_after.unwrap_or(self.synced) } else { self.synced })
        }
        async fn sink(&self) -> Result<RpcHash, ()> {
            self.called("sink");
            Ok(RpcHash::from_bytes([9; 32]))
        }
        async fn tip(&self, hash: RpcHash) -> Result<super::Tip, ()> {
            self.called("tip");
            Ok(super::Tip { hash, daa: u64::MAX, blue: 9_007_199_254_740_993 })
        }
        async fn floor(&self) -> Result<super::Floor, ()> {
            self.called("floor");
            Ok(super::Floor { checkpoint: RpcHash::from_bytes([8; 32]), daa: 9_007_199_254_740_993, history_from: 0, complete: false })
        }
        async fn page(&self, _: RpcHash, _: u8) -> Result<GetShieldedBlocksResponse, ()> {
            self.called("page");
            Ok(self.page.clone())
        }
    }

    #[tokio::test]
    async fn read_uses_ten_ordered_calls_and_preserves_large_integers() {
        let mut accepted = block(vec![vec![1; 148]], vec![RpcHash::from_bytes([5; 32])]);
        accepted.coinbase_outputs.push(kaspa_rpc_core::RpcShieldedCoinbaseOutput {
            script_public_key: vec![0xab; 43],
            value: u64::MAX,
            commitment: Some([0xcd; 32]),
        });
        let page = GetShieldedBlocksResponse { blocks: vec![accepted], reorged: false, sink_blue_score: u64::MAX };
        let source = MockSource::new(page);
        let query = super::parse_query(&format!("after={}&limit=1", "02".repeat(32))).unwrap();
        let snapshot = super::read_snapshot(&source, query, "mainnet").await.unwrap();
        assert_eq!(*source.calls.lock().unwrap(), ["info", "sync", "sink", "tip", "floor", "page", "sink", "tip", "info", "sync"]);
        let value = super::response_dto(snapshot, query, 1, "mainnet", RpcHash::from_bytes([7; 32]));
        let json = super::serialize_response(&value).unwrap();
        let json = std::str::from_utf8(&json).unwrap();
        assert!(json.contains("\"daa\":\"18446744073709551615\""));
        assert!(json.contains("\"blueScore\":\"9007199254740993\""));
        assert!(json.contains("\"protocolEvidence\":\"id-bearing-actions-observed\""));
        assert!(json.contains(&format!("\"acceptedCompactHex\":[\"{}\"]", "01".repeat(148))));
        assert!(json.contains("\"valueSompi\":\"18446744073709551615\""));
        assert!(json.contains(&format!("\"scriptHex\":\"{}\"", "ab".repeat(43))));
    }

    #[tokio::test]
    async fn wrong_network_stops_before_page_rpc() {
        let page = GetShieldedBlocksResponse { blocks: vec![], reorged: false, sink_blue_score: 0 };
        let mut source = MockSource::new(page);
        source.network = "testnet-10";
        let query = super::parse_query(&format!("after={}&limit=1", "09".repeat(32))).unwrap();
        assert!(super::read_snapshot(&source, query, "mainnet").await.is_err());
        assert_eq!(*source.calls.lock().unwrap(), ["info"]);
    }

    #[tokio::test]
    async fn source_change_after_page_cannot_return_success() {
        let page = GetShieldedBlocksResponse { blocks: vec![], reorged: false, sink_blue_score: 1 };
        let mut source = MockSource::new(page);
        source.network_after = Some("devnet");
        let query = super::parse_query(&format!("after={}&limit=1", "09".repeat(32))).unwrap();
        assert!(super::read_snapshot(&source, query, "mainnet").await.is_err());
        assert_eq!(source.calls.lock().unwrap().iter().filter(|&&name| name == "page").count(), 1);
    }

    #[tokio::test]
    async fn unsynced_second_observation_cannot_return_success() {
        let page = GetShieldedBlocksResponse { blocks: vec![], reorged: false, sink_blue_score: 1 };
        let mut source = MockSource::new(page);
        source.synced_after = Some(false);
        let query = super::parse_query(&format!("after={}&limit=1", "09".repeat(32))).unwrap();
        assert!(super::read_snapshot(&source, query, "mainnet").await.is_err());
    }

    #[test]
    fn explicit_reorg_is_distinct_from_unavailable_empty_page() {
        let page = GetShieldedBlocksResponse { blocks: vec![], reorged: true, sink_blue_score: 4 };
        assert!(!super::validate_page(&page, 1, RpcHash::from_bytes([2; 32]), RpcHash::from_bytes([9; 32])).unwrap());
    }

    #[test]
    fn old_actionless_block_has_no_valid_timestamp() {
        let mut old = block(vec![], vec![]);
        old.timestamp = 0;
        let page = GetShieldedBlocksResponse { blocks: vec![old], reorged: false, sink_blue_score: 4 };
        assert!(super::validate_page(&page, 1, RpcHash::from_bytes([2; 32]), RpcHash::from_bytes([9; 32])).is_err());
    }

    #[test]
    fn transport_bounds_reject_excess_without_truncation() {
        let after = RpcHash::from_bytes([2; 32]);
        let tip = RpcHash::from_bytes([9; 32]);
        let mut b = block(vec![vec![1; 148 * 513]], vec![RpcHash::from_bytes([5; 32])]);
        let mut page = GetShieldedBlocksResponse { blocks: vec![b.clone()], reorged: false, sink_blue_score: 4 };
        assert!(super::validate_page(&page, 1, after, tip).is_err());
        b.accepted_actions = vec![vec![1; 148 * 512]];
        page.blocks = vec![b.clone()];
        assert!(super::validate_page(&page, 1, after, tip).is_ok());
        b.accepted_actions = vec![vec![1; 149]];
        page.blocks = vec![b.clone()];
        assert!(super::validate_page(&page, 1, after, tip).is_err());
        b.accepted_actions = vec![vec![1; 148]];
        page.blocks = vec![b.clone(), b.clone()];
        assert!(super::validate_page(&page, 2, after, tip).is_err());
        page.blocks = vec![b.clone()];
        assert!(super::validate_page(&page, 0, after, tip).is_err());
        b.accepted_actions = (0..27).map(|_| vec![1; 148 * 512]).collect();
        b.accepted_txids = (0..27)
            .map(|i| {
                let mut raw = [0u8; 32];
                raw[0] = i + 1;
                RpcHash::from_bytes(raw)
            })
            .collect();
        page.blocks = vec![b];
        assert!(super::validate_page(&page, 1, after, tip).is_err());
    }

    #[test]
    fn repeated_accepted_id_and_reversed_daa_fail_closed() {
        let after = RpcHash::from_bytes([2; 32]);
        let tip = RpcHash::from_bytes([9; 32]);
        let id = RpcHash::from_bytes([5; 32]);
        let mut a = block(vec![vec![1; 148]], vec![id]);
        let mut b = block(vec![vec![2; 148]], vec![id]);
        b.hash = RpcHash::from_bytes([6; 32]);
        b.daa_score = 4;
        assert!(
            super::validate_page(
                &GetShieldedBlocksResponse { blocks: vec![a.clone(), b.clone()], reorged: false, sink_blue_score: 5 },
                2,
                after,
                tip
            )
            .is_err()
        );
        b.accepted_txids = vec![RpcHash::from_bytes([7; 32])];
        a.daa_score = 5;
        assert!(
            super::validate_page(&GetShieldedBlocksResponse { blocks: vec![a, b], reorged: false, sink_blue_score: 5 }, 2, after, tip)
                .is_err()
        );
    }

    #[test]
    fn selected_page_must_advance_past_its_cursor() {
        let cursor = RpcHash::from_bytes([3; 32]);
        let page = GetShieldedBlocksResponse { blocks: vec![block(vec![], vec![])], reorged: false, sink_blue_score: 4 };
        assert!(super::validate_page(&page, 1, cursor, RpcHash::from_bytes([9; 32])).is_err());
    }

    #[test]
    fn oversized_and_duplicate_page_never_returns_a_prefix() {
        let id = RpcHash::from_bytes([5; 32]);
        let mut first = block(vec![vec![1; 148]], vec![id]);
        first.coinbase_outputs.push(kaspa_rpc_core::RpcShieldedCoinbaseOutput {
            script_public_key: vec![1; 129],
            value: 1,
            commitment: None,
        });
        let page = GetShieldedBlocksResponse { blocks: vec![first], reorged: false, sink_blue_score: 4 };
        assert!(super::validate_page(&page, 1, RpcHash::from_bytes([2; 32]), RpcHash::from_bytes([9; 32])).is_err());
        let mut writer = super::BoundedWriter { bytes: vec![0; super::MAX_JSON_BYTES] };
        assert!(std::io::Write::write_all(&mut writer, b"x").is_err());
        assert_eq!(writer.bytes.len(), super::MAX_JSON_BYTES);
    }

    #[tokio::test]
    async fn history_route_keeps_global_bearer_and_explicit_cors() {
        let app = Router::new()
            .route("/api/chain/shielded-history", get(|_body: Bytes| async { "ok" }).layer(DefaultBodyLimit::max(0)))
            .layer(from_fn_with_state(std::sync::Arc::new("sentinel-secret".to_string()), super::super::bearer_guard))
            .layer(
                tower_http::cors::CorsLayer::new()
                    .allow_methods([Method::GET, Method::POST])
                    .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, HeaderName::from_static("x-wallet-token")])
                    .allow_origin(vec![HeaderValue::from_static("https://wallet.example")]),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        async fn send(address: std::net::SocketAddr, headers: &str, body: &str) -> String {
            let request = format!(
                "GET /api/chain/shielded-history HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}Content-Length: {}\r\n\r\n{body}",
                body.len()
            );
            tokio::task::spawn_blocking(move || {
                use std::io::{Read, Write};
                let mut stream = std::net::TcpStream::connect(address).unwrap();
                stream.write_all(request.as_bytes()).unwrap();
                let mut response = String::new();
                stream.read_to_string(&mut response).unwrap();
                response
            })
            .await
            .unwrap()
        }
        let missing = send(address, "Origin: https://wallet.example\r\n", "").await;
        assert!(missing.starts_with("HTTP/1.1 401"));
        assert!(missing.to_ascii_lowercase().contains("access-control-allow-origin: https://wallet.example"));
        let allowed = send(address, "Origin: https://wallet.example\r\nAuthorization: Bearer sentinel-secret\r\n", "").await;
        assert!(allowed.starts_with("HTTP/1.1 200"));
        assert!(allowed.to_ascii_lowercase().contains("access-control-allow-origin: https://wallet.example"));
        let refused = send(address, "Origin: https://other.example\r\nAuthorization: Bearer sentinel-secret\r\n", "").await;
        assert!(!refused.to_ascii_lowercase().contains("access-control-allow-origin:"));
        let body = send(address, "Authorization: Bearer sentinel-secret\r\n", "not-empty").await;
        assert!(body.starts_with("HTTP/1.1 413"));
        server.abort();
    }

    #[test]
    fn query_requires_exact_canonical_cursor_and_limit() {
        let cursor = "ab".repeat(32);
        assert!(super::parse_query(&format!("after={cursor}&limit=32")).is_ok());
        for query in [
            format!("after={cursor}&limit=0"),
            format!("after={cursor}&limit=01"),
            format!("after={cursor}&limit=33"),
            format!("after={cursor}&limit=1&url=localhost"),
            format!("limit=1&after={cursor}&after={cursor}"),
            format!("after={}&limit=1", cursor.to_uppercase()),
        ] {
            assert!(super::parse_query(&query).is_err(), "accepted {query}");
        }
    }

    #[test]
    fn dropped_history_read_retires_only_its_generation() {
        let retire = std::sync::Arc::new(super::HistoryRetire::default());
        {
            let _read = super::HistoryReadGuard::new(retire.clone(), 7);
        }
        assert!(retire.requested(7));
        assert!(!retire.requested(8));
        retire.request(8);
        retire.request(7);
        assert!(retire.requested(8));
    }

    #[test]
    fn completed_history_read_does_not_retire_its_generation() {
        let retire = std::sync::Arc::new(super::HistoryRetire::default());
        let mut read = super::HistoryReadGuard::new(retire.clone(), 7);
        read.disarm();
        drop(read);
        assert!(!retire.requested(7));
    }

    #[test]
    fn history_generation_exhaustion_is_not_wrapped_or_reused() {
        assert_eq!(super::next_generation(u64::MAX), None);
        assert_eq!(super::next_generation(0), Some(1));
    }

    #[test]
    fn old_retirement_never_removes_newer_publication() {
        let mut slot = Some((8u64, "new"));
        assert_eq!(super::take_matching(&mut slot, 7, |entry| entry.0), None);
        assert_eq!(slot, Some((8, "new")));
        assert_eq!(super::take_matching(&mut slot, 8, |entry| entry.0), Some((8, "new")));
        assert_eq!(slot, None);
    }

    #[tokio::test]
    async fn stopped_supervisor_waiting_for_process_permit_exits_promptly() {
        let gate = super::HISTORY_PERMIT.get_or_init(|| tokio::sync::Semaphore::new(1));
        let _held = gate.acquire().await.unwrap();
        let slot = std::sync::Arc::new(tokio::sync::RwLock::new(None));
        let retire = std::sync::Arc::new(super::HistoryRetire::default());
        let first = super::start_supervisor(slot.clone(), retire.clone(), "127.0.0.1:1".into());
        let waiting = super::start_supervisor(slot.clone(), retire.clone(), "127.0.0.1:1".into());
        let refused = super::start_supervisor(slot, retire, "127.0.0.1:1".into());
        assert!(first.0.is_some());
        assert!(waiting.0.is_some());
        assert!(refused.0.is_none());
        waiting.stop();
        tokio::time::timeout(std::time::Duration::from_secs(1), waiting.drain()).await.unwrap();
        first.stop();
        tokio::time::timeout(std::time::Duration::from_secs(1), first.drain()).await.unwrap();
    }

    #[tokio::test]
    async fn soft_shutdown_keeps_cleanup_task_owned_until_it_finishes() {
        let (stop, _stop_rx) = tokio::sync::watch::channel(false);
        let run = std::sync::Arc::new(super::HistoryRun {
            stop,
            done: std::sync::atomic::AtomicBool::new(false),
            done_notify: tokio::sync::Notify::new(),
            handle: std::sync::Mutex::new(None),
        });
        let (release, held) = tokio::sync::oneshot::channel::<()>();
        let completed = run.clone();
        let task = tokio::spawn(async move {
            let _ = held.await;
            completed.done.store(true, std::sync::atomic::Ordering::Release);
            completed.done_notify.notify_waiters();
        });
        *run.handle.lock().unwrap() = Some(task);
        let lease = super::HistorySupervisorLease(Some(run.clone()));
        lease.drain_for(std::time::Duration::from_millis(10)).await;
        assert!(!run.done.load(std::sync::atomic::Ordering::Acquire));
        assert!(!run.handle.lock().unwrap().as_ref().unwrap().is_finished());
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), run.wait_done()).await.unwrap();
        assert!(run.handle.lock().unwrap().take().unwrap().await.is_ok());
    }
}
