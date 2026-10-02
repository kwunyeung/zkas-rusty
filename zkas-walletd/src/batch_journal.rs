#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
            let _ = fs::remove_file(self.0.with_extension("manifest"));
            let _ = fs::remove_file(self.0.with_extension("lock"));
        }
    }

    #[test]
    fn attempted_signed_bytes_survive_restart_and_cannot_be_replaced() {
        let dir = std::env::temp_dir().join(format!("zkas-batch-journal-{}", rand::random::<u64>()));
        let _cleanup = TestDir(dir.clone());
        let genesis = [7; 32];
        let mut journal = BatchJournal::open(&dir, genesis).unwrap();
        let bytes = borsh::to_vec(&payment_tx(vec![1, 2, 3])).unwrap();
        let record = JournalRecord::new(
            [1; 96],
            "wallet-token",
            genesis,
            [8; 43],
            "https://wallet.example",
            [2; 32],
            [3; 32],
            bytes.clone(),
            vec![42],
        )
        .unwrap();
        journal.insert(record.clone()).unwrap();
        journal.begin_attempt(&record.fvk_hash, &record.logical_id, [4; 32]).unwrap();
        drop(journal);
        let mut restored = BatchJournal::open(&dir, genesis).unwrap();
        let got = restored.get(&record.fvk_hash, &record.logical_id).unwrap();
        assert_eq!(hex::decode(&got.transaction_hex).unwrap(), bytes);
        assert_eq!(got.phase, JournalPhase::Unknown);
        let altered = JournalRecord::new(
            [1; 96],
            "wallet-token",
            genesis,
            [8; 43],
            "https://wallet.example",
            [2; 32],
            [3; 32],
            borsh::to_vec(&payment_tx(vec![9])).unwrap(),
            vec![42],
        )
        .unwrap();
        assert!(restored.insert(altered).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn selected_chain_page_requires_parallel_acceptance_ids_and_reverts_on_reorg() {
        let tx = payment_tx(vec![1]);
        let record = JournalRecord::new(
            [1; 96],
            "wallet-token",
            [7; 32],
            [8; 43],
            "https://wallet.example",
            [2; 32],
            [3; 32],
            borsh::to_vec(&tx).unwrap(),
            vec![42],
        )
        .unwrap();
        let block = kaspa_rpc_core::RpcShieldedChainBlock {
            hash: RpcHash::from_bytes([9; 32]),
            blue_score: 10,
            daa_score: 11,
            coinbase_txid: RpcHash::default(),
            coinbase_outputs: vec![],
            accepted_actions: vec![vec![0; 148]],
            accepted_txids: vec![],
            timestamp: 0,
        };
        assert_eq!(observe_block(&record, &block), Observation::Gap);
        let mut accepted = block.clone();
        accepted.accepted_txids.push(RpcHash::from_bytes(record.txid));
        assert_eq!(observe_block(&record, &accepted), Observation::Included([9; 32], 11));
        let mut reorged = record.clone();
        reorged.phase = JournalPhase::Settled;
        reorged.included_block = Some([9; 32]);
        reorged.included_daa = Some(11);
        reorged.invalidate_chain_provenance();
        assert!(reorged.reserves());
        assert!(reorged.scan_cursor.is_none());
    }

    #[test]
    fn deleted_journal_inventory_fails_closed() {
        let dir = std::env::temp_dir().join(format!("zkas-batch-inventory-{}", rand::random::<u64>()));
        let _cleanup = TestDir(dir.clone());
        let genesis = [7; 32];
        let mut journal = BatchJournal::open(&dir, genesis).unwrap();
        let record = JournalRecord::new(
            [1; 96],
            "token",
            genesis,
            [8; 43],
            "legacy",
            [2; 32],
            [3; 32],
            borsh::to_vec(&payment_tx(vec![1])).unwrap(),
            vec![42],
        )
        .unwrap();
        journal.insert(record).unwrap();
        drop(journal);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(BatchJournal::open(&dir, genesis).is_err());
    }

    #[test]
    fn deleted_record_cannot_be_silently_forgotten() {
        let dir = std::env::temp_dir().join(format!("zkas-batch-missing-record-{}", rand::random::<u64>()));
        let _cleanup = TestDir(dir.clone());
        let genesis = [7; 32];
        let mut journal = BatchJournal::open(&dir, genesis).unwrap();
        let record = JournalRecord::new(
            [1; 96],
            "token",
            genesis,
            [8; 43],
            "legacy",
            [2; 32],
            [3; 32],
            borsh::to_vec(&payment_tx(vec![1])).unwrap(),
            vec![42],
        )
        .unwrap();
        journal.insert(record.clone()).unwrap();
        std::fs::remove_file(journal.path(&record)).unwrap();
        drop(journal);
        assert!(BatchJournal::open(&dir, genesis).is_err());
    }

    #[test]
    fn second_daemon_cannot_open_same_journal() {
        let dir = std::env::temp_dir().join(format!("zkas-batch-lock-{}", rand::random::<u64>()));
        let _cleanup = TestDir(dir.clone());
        let genesis = [7; 32];
        let first = BatchJournal::open(&dir, genesis).unwrap();
        assert!(BatchJournal::open(&dir, genesis).is_err());
        drop(first);
        assert!(BatchJournal::open(&dir, genesis).is_ok());
    }

    #[test]
    fn stale_observation_cannot_replace_newer_attempt() {
        let dir = std::env::temp_dir().join(format!("zkas-batch-cas-{}", rand::random::<u64>()));
        let _cleanup = TestDir(dir.clone());
        let genesis = [7; 32];
        let mut journal = BatchJournal::open(&dir, genesis).unwrap();
        let record = JournalRecord::new(
            [1; 96],
            "token",
            genesis,
            [8; 43],
            "legacy",
            [2; 32],
            [3; 32],
            borsh::to_vec(&payment_tx(vec![1])).unwrap(),
            vec![42],
        )
        .unwrap();
        journal.insert(record.clone()).unwrap();
        let mut stale = record.clone();
        journal.begin_attempt(&record.fvk_hash, &record.logical_id, [4; 32]).unwrap();
        stale.phase = JournalPhase::Mempool;
        assert!(journal.update(&mut stale).is_err());
        assert_eq!(journal.get(&record.fvk_hash, &record.logical_id).unwrap().phase, JournalPhase::Unknown);
        let mut changed = journal.get(&record.fvk_hash, &record.logical_id).unwrap().clone();
        changed.positions = vec![99];
        assert!(journal.update(&mut changed).is_err());
    }

    #[test]
    fn cached_transaction_id_must_match_recomputed_id() {
        let mut bytes = borsh::to_vec(&payment_tx(vec![1])).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        assert!(JournalRecord::new([1; 96], "token", [7; 32], [8; 43], "legacy", [2; 32], [3; 32], bytes, vec![42]).is_err());
    }

    #[test]
    fn poisoned_journal_rejects_exact_retry_before_rpc() {
        let dir = std::env::temp_dir().join(format!("zkas-batch-poison-{}", rand::random::<u64>()));
        let _cleanup = TestDir(dir.clone());
        let genesis = [7; 32];
        let mut journal = BatchJournal::open(&dir, genesis).unwrap();
        let record = JournalRecord::new(
            [1; 96],
            "token",
            genesis,
            [8; 43],
            "legacy",
            [2; 32],
            [3; 32],
            borsh::to_vec(&payment_tx(vec![1])).unwrap(),
            vec![42],
        )
        .unwrap();
        journal.insert(record.clone()).unwrap();
        journal.begin_attempt(&record.fvk_hash, &record.logical_id, [4; 32]).unwrap();
        journal.poisoned = true;
        assert!(journal.begin_attempt(&record.fvk_hash, &record.logical_id, [4; 32]).is_err());
    }

    #[test]
    fn resolved_record_is_reserved_after_restart_until_fresh_revalidation() {
        let dir = std::env::temp_dir().join(format!("zkas-batch-revalidate-{}", rand::random::<u64>()));
        let _cleanup = TestDir(dir.clone());
        let genesis = [7; 32];
        let mut journal = BatchJournal::open(&dir, genesis).unwrap();
        let record = JournalRecord::new(
            [1; 96],
            "token",
            genesis,
            [8; 43],
            "legacy",
            [2; 32],
            [3; 32],
            borsh::to_vec(&payment_tx(vec![1])).unwrap(),
            vec![42],
        )
        .unwrap();
        journal.insert(record.clone()).unwrap();
        let mut included = journal.begin_attempt(&record.fvk_hash, &record.logical_id, [4; 32]).unwrap();
        included.phase = JournalPhase::Settled;
        included.included_block = Some([5; 32]);
        included.included_daa = Some(100);
        journal.update(&mut included).unwrap();
        assert!(!journal.reserves(&[1; 96]));
        drop(journal);
        let mut reopened = BatchJournal::open(&dir, genesis).unwrap();
        assert!(reopened.reserves(&[1; 96]));
        let mut settled = reopened.get(&record.fvk_hash, &record.logical_id).unwrap().clone();
        reopened.update(&mut settled).unwrap();
        assert!(!reopened.reserves(&[1; 96]));
    }

    #[test]
    fn existing_wallet_needs_explicit_migration_marker() {
        let wallet_dir = std::env::temp_dir().join(format!("zkas-batch-migrate-{}", rand::random::<u64>()));
        let _cleanup = TestDir(wallet_dir.clone());
        std::fs::create_dir(&wallet_dir).unwrap();
        assert!(!migration_ready(&wallet_dir, [7; 32], false).unwrap());
        assert!(migration_ready(&wallet_dir, [7; 32], true).unwrap());
        assert!(migration_ready(&wallet_dir, [7; 32], false).unwrap());
        assert!(migration_ready(&wallet_dir, [8; 32], false).is_err());
        std::fs::remove_dir_all(wallet_dir).unwrap();
    }
}
// Durable identity and exact bytes for submitted watch-only payments.

use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_RECORDS: usize = 4096;

pub(super) fn verify_private_wallet_dir(dir: &Path, newly_created: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if !metadata.file_type().is_dir() {
        return Err("wallet directory is not a directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        // The directory is private to this daemon's OS account. A different
        // local account cannot replace the journal or its external inventory.
        if metadata.uid() != unsafe { geteuid() } {
            return Err("wallet directory has a different owner".into());
        }
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    if newly_created {
        File::open(dir.parent().ok_or("wallet directory has no parent")?)
            .and_then(|parent| parent.sync_all())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub(super) fn migration_ready(wallet_dir: &Path, genesis: [u8; 32], fresh_wallet_dir: bool) -> Result<bool, String> {
    let marker = wallet_dir.join("batch-journal-enabled");
    let expected = format!("zkas-walletd-batch-journal-v1:{}\n", hex::encode(genesis));
    if fresh_wallet_dir {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&marker).map_err(|e| e.to_string())?;
        file.write_all(expected.as_bytes()).and_then(|_| file.sync_all()).map_err(|e| e.to_string())?;
        File::open(wallet_dir).and_then(|dir| dir.sync_all()).map_err(|e| e.to_string())?;
        return Ok(true);
    }
    match fs::symlink_metadata(&marker) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.len() <= 128 => {
            let bytes = fs::read(marker).map_err(|e| e.to_string())?;
            if bytes == expected.as_bytes() { Ok(true) } else { Err("invalid journal migration marker".into()) }
        }
        Ok(_) => Err("invalid journal migration marker".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Observation {
    Included([u8; 32], u64),
    Conflicted([u8; 32], [u8; 32], u64),
    Continue([u8; 32]),
    Gap,
}

pub(super) fn observe_block(record: &JournalRecord, block: &kaspa_rpc_core::RpcShieldedChainBlock) -> Observation {
    if block.accepted_actions.len() != block.accepted_txids.len() {
        return Observation::Gap;
    }
    let target_nullifiers: Vec<[u8; 32]> = record
        .transaction()
        .ok()
        .and_then(|tx| kaspa_shielded_core::bundle::ShieldedBundle::from_bytes(&tx.payload).ok())
        .map(|bundle| bundle.actions.iter().map(|action| action.nullifier).collect())
        .unwrap_or_default();
    for (txid, actions) in block.accepted_txids.iter().zip(&block.accepted_actions) {
        if txid.as_bytes() == record.txid {
            return Observation::Included(block.hash.as_bytes(), block.daa_score);
        }
        if !target_nullifiers.is_empty() {
            if actions.len() % CompactActionRecord::SERIALIZED_LEN != 0 {
                return Observation::Gap;
            }
            if actions
                .chunks_exact(CompactActionRecord::SERIALIZED_LEN)
                .filter_map(CompactActionRecord::from_bytes)
                .any(|action| target_nullifiers.contains(&action.nullifier))
            {
                return Observation::Conflicted(txid.as_bytes(), block.hash.as_bytes(), block.daa_score);
            }
        }
    }
    Observation::Continue(block.hash.as_bytes())
}

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update((*part).len().to_le_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

pub(super) fn fvk_hash(fvk: &[u8; 96]) -> [u8; 32] {
    digest(&[b"zkas.walletd.batch.fvk.v1", fvk])
}

pub(super) fn intent_hash(intent: &zkas_sdk::BatchIntent) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"zkas.walletd.batch.intent.v1");
    hash.update(intent.account);
    hash.update(intent.max_fee.to_le_bytes());
    hash.update((intent.outputs.len() as u64).to_le_bytes());
    for output in &intent.outputs {
        hash.update(output.recipient);
        hash.update(output.amount.to_le_bytes());
        hash.update(output.memo);
    }
    hash.finalize().into()
}

fn token_hash(token: &str) -> [u8; 32] {
    digest(&[b"zkas.walletd.batch.token.v1", token.as_bytes()])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum JournalPhase {
    Finalized,
    Unknown,
    Mempool,
    Included,
    Settled,
    Conflicted,
    ConflictSettled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JournalRecord {
    version: u8,
    genesis: [u8; 32],
    pub(super) fvk_hash: [u8; 32],
    token_hash: [u8; 32],
    account: Vec<u8>,
    origin: String,
    pub(super) logical_id: [u8; 32],
    intent_hash: [u8; 32],
    pub(super) transaction_hex: String,
    pub(super) txid: [u8; 32],
    pub(super) sha256: [u8; 32],
    pub(super) positions: Vec<u64>,
    revision: u64,
    pub(super) phase: JournalPhase,
    pub(super) start_cursor: Option<[u8; 32]>,
    pub(super) scan_cursor: Option<[u8; 32]>,
    pub(super) included_block: Option<[u8; 32]>,
    pub(super) included_daa: Option<u64>,
    pub(super) conflicting_txid: Option<[u8; 32]>,
}

impl JournalRecord {
    pub(super) fn invalidate_chain_provenance(&mut self) {
        self.phase = JournalPhase::Unknown;
        self.scan_cursor = None;
        self.included_block = None;
        self.included_daa = None;
        self.conflicting_txid = None;
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        fvk: [u8; 96],
        token: &str,
        genesis: [u8; 32],
        account: [u8; 43],
        origin: &str,
        logical_id: [u8; 32],
        intent_hash: [u8; 32],
        transaction: Vec<u8>,
        positions: Vec<u64>,
    ) -> Result<Self, String> {
        let tx: Transaction = borsh::from_slice(&transaction).map_err(|_| "invalid finalized transaction")?;
        let mut recomputed = tx.clone();
        recomputed.finalize();
        if borsh::to_vec(&tx).map_err(|_| "invalid transaction encoding")? != transaction || recomputed.id() != tx.id() {
            return Err("invalid finalized transaction metadata".into());
        }
        Ok(Self {
            version: 1,
            genesis,
            fvk_hash: fvk_hash(&fvk),
            token_hash: token_hash(token),
            account: account.to_vec(),
            origin: origin.to_owned(),
            logical_id,
            intent_hash,
            transaction_hex: hex::encode(&transaction),
            txid: tx.id().as_bytes(),
            sha256: Sha256::digest(&transaction).into(),
            positions,
            revision: 0,
            phase: JournalPhase::Finalized,
            start_cursor: None,
            scan_cursor: None,
            included_block: None,
            included_daa: None,
            conflicting_txid: None,
        })
    }

    pub(super) fn authenticate(&self, token: &str, account: &[u8; 43], genesis: &[u8; 32]) -> bool {
        self.token_hash == token_hash(token) && self.account.as_slice() == account && &self.genesis == genesis
    }

    pub(super) fn legacy_for(&self, token: &str, account: &[u8; 43], genesis: &[u8; 32]) -> bool {
        self.origin == "legacy" && self.authenticate(token, account, genesis)
    }

    pub(super) fn transaction(&self) -> Result<Transaction, String> {
        let bytes = hex::decode(&self.transaction_hex).map_err(|_| "invalid journal transaction hex")?;
        let tx: Transaction = borsh::from_slice(&bytes).map_err(|_| "invalid journal transaction")?;
        let mut recomputed = tx.clone();
        recomputed.finalize();
        if borsh::to_vec(&tx).map_err(|_| "invalid journal transaction")? != bytes
            || recomputed.id() != tx.id()
            || tx.id().as_bytes() != self.txid
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != self.sha256
        {
            return Err("journal transaction identity mismatch".into());
        }
        Ok(tx)
    }

    fn validate(&self, genesis: &[u8; 32]) -> Result<(), String> {
        if self.version != 1
            || &self.genesis != genesis
            || self.account.len() != 43
            || self.origin.len() > 256
            || self.positions.is_empty()
            || self.positions.len() > 128
        {
            return Err("journal binding mismatch".into());
        }
        self.transaction()?;
        if self.phase != JournalPhase::Finalized && (self.start_cursor.is_none() || self.revision == 0) {
            return Err("attempted journal lacks chain cursor".into());
        }
        if self.phase == JournalPhase::Finalized && self.revision != 0 {
            return Err("finalized journal revision mismatch".into());
        }
        let included = self.included_block.is_some() && self.included_daa.is_some();
        match self.phase {
            JournalPhase::Finalized
                if self.start_cursor.is_some() || self.scan_cursor.is_some() || included || self.conflicting_txid.is_some() =>
            {
                return Err("invalid finalized journal state".into());
            }
            JournalPhase::Unknown | JournalPhase::Mempool if included || self.conflicting_txid.is_some() => {
                return Err("invalid unresolved journal state".into());
            }
            JournalPhase::Included | JournalPhase::Settled if !included || self.conflicting_txid.is_some() => {
                return Err("invalid included journal state".into());
            }
            JournalPhase::Conflicted | JournalPhase::ConflictSettled if !included || self.conflicting_txid.is_none() => {
                return Err("invalid conflicting journal state".into());
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn reserves(&self) -> bool {
        !matches!(self.phase, JournalPhase::Settled | JournalPhase::ConflictSettled)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    record: JournalRecord,
    checksum: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    version: u8,
    genesis: [u8; 32],
    names: Vec<String>,
}

pub(super) struct BatchJournal {
    dir: PathBuf,
    anchor: PathBuf,
    _lock: File,
    genesis: [u8; 32],
    records: HashMap<([u8; 32], [u8; 32]), JournalRecord>,
    verified_terminals: HashSet<([u8; 32], [u8; 32])>,
    poisoned: bool,
}

impl BatchJournal {
    pub(super) fn open(dir: &Path, genesis: [u8; 32]) -> Result<Self, String> {
        let parent = dir.parent().ok_or("journal has no parent")?;
        let stem = dir.file_name().and_then(|name| name.to_str()).ok_or("invalid journal name")?;
        let anchor = parent.join(format!("{stem}.manifest"));
        let lock_path = parent.join(format!("{stem}.lock"));
        if fs::symlink_metadata(&lock_path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
            return Err("journal lock path is not a regular file".into());
        }
        let mut lock_options = OpenOptions::new();
        lock_options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600);
        }
        let lock = lock_options.open(&lock_path).map_err(|e| e.to_string())?;
        lock.try_lock().map_err(|_| "another daemon owns the payment journal")?;
        let dir_metadata = fs::symlink_metadata(dir).ok();
        let existed = dir_metadata.is_some();
        let anchor_metadata = fs::symlink_metadata(&anchor).ok();
        if existed != anchor_metadata.is_some() {
            return Err("journal directory or inventory anchor is missing".into());
        }
        if anchor_metadata.is_some_and(|metadata| !metadata.file_type().is_file() || metadata.len() > 512 * 1024) {
            return Err("invalid journal inventory file".into());
        }
        if dir_metadata.is_some_and(|metadata| !metadata.file_type().is_dir()) {
            return Err("journal path is not a directory".into());
        }
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        }
        if !existed {
            File::open(parent).and_then(|file| file.sync_all()).map_err(|e| e.to_string())?;
        }
        let mut journal = Self {
            dir: dir.to_owned(),
            anchor,
            _lock: lock,
            genesis,
            records: HashMap::new(),
            verified_terminals: HashSet::new(),
            poisoned: false,
        };
        if !existed {
            journal.write_inventory()?;
        }
        for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                if path.extension().and_then(|e| e.to_str()) == Some("tmp") {
                    continue;
                }
                return Err("unexpected journal file".into());
            }
            if !entry.file_type().map_err(|e| e.to_string())?.is_file()
                || entry.metadata().map_err(|e| e.to_string())?.len() > MAX_RECORD_BYTES
            {
                return Err("invalid journal file".into());
            }
            let bytes = fs::read(&path).map_err(|e| e.to_string())?;
            let stored: Stored = serde_json::from_slice(&bytes).map_err(|_| "invalid journal encoding")?;
            let record_bytes = serde_json::to_vec(&stored.record).map_err(|e| e.to_string())?;
            if <[u8; 32]>::from(Sha256::digest(&record_bytes)) != stored.checksum {
                return Err("journal checksum mismatch".into());
            }
            stored.record.validate(&genesis)?;
            if path != journal.path(&stored.record) {
                return Err("journal filename mismatch".into());
            }
            let key = (stored.record.fvk_hash, stored.record.logical_id);
            if journal.records.insert(key, stored.record).is_some() || journal.records.len() > MAX_RECORDS {
                return Err("duplicate or excess journal record".into());
            }
        }
        let expected: Inventory =
            serde_json::from_slice(&fs::read(&journal.anchor).map_err(|e| e.to_string())?).map_err(|_| "invalid journal inventory")?;
        if expected.version != 1 || expected.genesis != genesis || expected.names != journal.names() {
            return Err("journal inventory mismatch".into());
        }
        Ok(journal)
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<_> =
            self.records.values().map(|record| self.path(record).file_name().unwrap().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    fn write_inventory(&self) -> Result<(), String> {
        let inventory = Inventory { version: 1, genesis: self.genesis, names: self.names() };
        let bytes = serde_json::to_vec(&inventory).map_err(|e| e.to_string())?;
        let tmp = self.anchor.with_extension(format!("manifest-{}.tmp", rand::random::<u64>()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).map_err(|e| e.to_string())?;
        file.write_all(&bytes).and_then(|_| file.sync_all()).map_err(|e| e.to_string())?;
        fs::rename(&tmp, &self.anchor).map_err(|e| e.to_string())?;
        File::open(self.anchor.parent().unwrap()).and_then(|dir| dir.sync_all()).map_err(|e| e.to_string())
    }

    fn path(&self, record: &JournalRecord) -> PathBuf {
        let name = digest(&[b"zkas.walletd.batch.file.v1", &record.fvk_hash, &record.logical_id]);
        self.dir.join(format!("{}.json", hex::encode(name)))
    }

    fn write(&mut self, record: &JournalRecord) -> Result<(), String> {
        if self.poisoned {
            return Err("journal unavailable".into());
        }
        let result = (|| {
            let payload = serde_json::to_vec(record).map_err(|e| e.to_string())?;
            let stored = Stored { record: record.clone(), checksum: Sha256::digest(&payload).into() };
            let bytes = serde_json::to_vec(&stored).map_err(|e| e.to_string())?;
            if bytes.len() as u64 > MAX_RECORD_BYTES {
                return Err("journal record too large".into());
            }
            let path = self.path(record);
            let tmp = self.dir.join(format!(
                "{}.tmp",
                hex::encode(digest(&[&record.fvk_hash, &record.logical_id, &rand::random::<u64>().to_le_bytes()]))
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp).map_err(|e| e.to_string())?;
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
            File::open(&self.dir).and_then(|dir| dir.sync_all()).map_err(|e| e.to_string())?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(super) fn insert(&mut self, record: JournalRecord) -> Result<(), String> {
        record.validate(&self.genesis)?;
        if self.poisoned {
            return Err("journal unavailable".into());
        }
        let key = (record.fvk_hash, record.logical_id);
        if let Some(existing) = self.records.get(&key) {
            return if existing == &record { Ok(()) } else { Err("logical payment already journaled".into()) };
        }
        if self.records.len() >= MAX_RECORDS || self.reserves_hash(&record.fvk_hash) {
            return Err("wallet has unresolved payment".into());
        }
        self.write(&record)?;
        self.records.insert(key, record);
        if let Err(error) = self.write_inventory() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn reserves(&self, fvk: &[u8; 96]) -> bool {
        self.reserves_hash(&fvk_hash(fvk))
    }

    fn reserves_hash(&self, fingerprint: &[u8; 32]) -> bool {
        self.poisoned
            || self
                .records
                .iter()
                .any(|(key, record)| &record.fvk_hash == fingerprint && (record.reserves() || !self.verified_terminals.contains(key)))
    }

    pub(super) fn get(&self, fvk_hash: &[u8; 32], logical_id: &[u8; 32]) -> Option<&JournalRecord> {
        self.records.get(&(*fvk_hash, *logical_id))
    }

    pub(super) fn records_for_fvk(&self, fvk: &[u8; 96]) -> Vec<JournalRecord> {
        let fingerprint = fvk_hash(fvk);
        self.records.values().filter(|record| record.fvk_hash == fingerprint).cloned().collect()
    }

    pub(super) fn unresolved_for_fvk(&self, fvk: &[u8; 96]) -> Vec<JournalRecord> {
        let fingerprint = fvk_hash(fvk);
        self.records
            .iter()
            .filter(|(key, record)| record.fvk_hash == fingerprint && (record.reserves() || !self.verified_terminals.contains(key)))
            .map(|(_, record)| record.clone())
            .collect()
    }

    pub(super) fn begin_attempt(
        &mut self,
        fvk_hash: &[u8; 32],
        logical_id: &[u8; 32],
        cursor: [u8; 32],
    ) -> Result<JournalRecord, String> {
        if self.poisoned {
            return Err("journal unavailable".into());
        }
        let key = (*fvk_hash, *logical_id);
        let mut record = self.records.get(&key).ok_or("unknown journaled payment")?.clone();
        if record.phase == JournalPhase::Finalized {
            record.revision = record.revision.checked_add(1).ok_or("journal revision exhausted")?;
            record.phase = JournalPhase::Unknown;
            record.start_cursor = Some(cursor);
            record.scan_cursor = Some(cursor);
            self.write(&record)?;
            self.records.insert(key, record.clone());
        }
        if !matches!(record.phase, JournalPhase::Unknown | JournalPhase::Mempool) {
            return Err("payment cannot be submitted".into());
        }
        Ok(record)
    }

    pub(super) fn update(&mut self, record: &mut JournalRecord) -> Result<(), String> {
        let key = (record.fvk_hash, record.logical_id);
        let current = self.records.get(&key).ok_or("unknown journaled payment")?;
        if current.revision != record.revision {
            return Err("stale journal observation".into());
        }
        if current.version != record.version
            || current.genesis != record.genesis
            || current.token_hash != record.token_hash
            || current.account != record.account
            || current.origin != record.origin
            || current.intent_hash != record.intent_hash
            || current.transaction_hex != record.transaction_hex
            || current.txid != record.txid
            || current.sha256 != record.sha256
            || current.positions != record.positions
            || current.start_cursor != record.start_cursor
        {
            return Err("immutable journal binding changed".into());
        }
        record.validate(&self.genesis)?;
        record.revision = record.revision.checked_add(1).ok_or("journal revision exhausted")?;
        self.write(&record)?;
        self.records.insert(key, record.clone());
        if record.reserves() {
            self.verified_terminals.remove(&key);
        } else {
            self.verified_terminals.insert(key);
        }
        Ok(())
    }
}
