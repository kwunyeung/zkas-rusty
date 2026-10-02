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
    fn discovery_pages_only_original_token_records_and_counts_every_unlisted_reservation() {
        let dir = std::env::temp_dir().join(format!("zkas-batch-discovery-{}", rand::random::<u64>()));
        let _cleanup = TestDir(dir.clone());
        let genesis = [7; 32];
        let fvk = [1; 96];
        let account = [8; 43];
        let mut journal = BatchJournal::open(&dir, genesis).unwrap();
        let original = JournalRecord::new(
            fvk, "short", genesis, account, "https://wallet.example", [0; 32], [3; 32],
            borsh::to_vec(&payment_tx(vec![1])).unwrap(), vec![42],
        ).unwrap();
        for index in 0..33u8 {
            let mut record = original.clone();
            record.logical_id = [index; 32];
            journal.records.insert((record.fvk_hash, record.logical_id), record);
        }
        let mut legacy = original.clone();
        legacy.logical_id = [40; 32];
        legacy.origin = "legacy".into();
        journal.records.insert((legacy.fvk_hash, legacy.logical_id), legacy);
        let mut foreign = original.clone();
        foreign.logical_id = [41; 32];
        foreign.token_hash = token_hash("older");
        journal.records.insert((foreign.fvk_hash, foreign.logical_id), foreign);
        let mut unrelated = original.clone();
        unrelated.logical_id = [42; 32];
        unrelated.fvk_hash = fvk_hash(&[2; 96]);
        journal.records.insert((unrelated.fvk_hash, unrelated.logical_id), unrelated);

        let snapshot = journal.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap();
        assert_eq!(snapshot.unlisted_reservation_count, 2);
        assert_eq!(snapshot.entries.len(), 33);
        let first = snapshot.page(None, None).unwrap();
        assert_eq!(first.entries.len(), 32);
        assert_eq!(first.entries[0].logical_id, [0; 32]);
        assert_eq!(first.next_after, Some([31; 32]));
        let second = snapshot.page(first.next_after, Some(first.epoch)).unwrap();
        assert_eq!(second.entries.len(), 1);
        assert_eq!(second.entries[0].logical_id, [32; 32]);
        assert_eq!(second.next_after, None);
        assert_eq!(first.epoch, second.epoch);
        assert!(snapshot.page(Some([31; 32]), None).is_err());
        assert!(snapshot.page(Some([50; 32]), Some(first.epoch)).is_err());
        assert!(snapshot.page(first.next_after, Some([9; 32])).is_err());
        assert_eq!(journal.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap().epoch, first.epoch);
        assert_ne!(journal.discovery_snapshot(&fvk, "older", &account, &genesis).unwrap().epoch, first.epoch);
        assert!(journal.discovery_snapshot(&fvk, "short", &[9; 43], &genesis).unwrap().entries.is_empty());
        let new_token = journal.discovery_snapshot(&fvk, "new", &account, &genesis).unwrap();
        assert!(new_token.entries.is_empty());
        assert_eq!(new_token.unlisted_reservation_count, 35);
        assert!(journal.discovery_snapshot(&fvk, "short", &account, &[6; 32]).is_err());
        let unrelated_key = (fvk_hash(&[2; 96]), [42; 32]);
        journal.records.get_mut(&unrelated_key).unwrap().revision += 1;
        assert_eq!(journal.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap().epoch, first.epoch);
        let own_key = (fvk_hash(&fvk), [0; 32]);
        journal.records.get_mut(&own_key).unwrap().revision += 1;
        assert_ne!(journal.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap().epoch, first.epoch);
        let legacy_key = (fvk_hash(&fvk), [40; 32]);
        journal.records.get_mut(&legacy_key).unwrap().phase = JournalPhase::Settled;
        journal.verified_terminals.insert(legacy_key);
        let only_foreign = journal.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap();
        assert_eq!(only_foreign.unlisted_reservation_count, 1);
        assert_ne!(only_foreign.epoch, first.epoch);
        let foreign_key = (fvk_hash(&fvk), [41; 32]);
        journal.records.get_mut(&foreign_key).unwrap().phase = JournalPhase::ConflictSettled;
        journal.verified_terminals.insert(foreign_key);
        assert_eq!(journal.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap().unlisted_reservation_count, 0);
        journal.poisoned = true;
        assert!(journal.discovery_snapshot(&fvk, "short", &account, &genesis).is_err());
    }

    #[test]
    fn discovery_epoch_is_secret_per_open_and_terminal_hints_are_conservative() {
        let dir = std::env::temp_dir().join(format!("zkas-batch-discovery-reopen-{}", rand::random::<u64>()));
        let _cleanup = TestDir(dir.clone());
        let genesis = [7; 32];
        let fvk = [1; 96];
        let account = [8; 43];
        let mut journal = BatchJournal::open(&dir, genesis).unwrap();
        let record = JournalRecord::new(
            fvk, "short", genesis, account, "https://wallet.example", [2; 32], [3; 32],
            borsh::to_vec(&payment_tx(vec![1])).unwrap(), vec![42],
        ).unwrap();
        journal.insert(record).unwrap();
        let first = journal.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap();
        assert_eq!(first.entries[0].status_hint(), "finalized_unsent");
        assert_eq!(first.epoch, journal.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap().epoch);
        drop(journal);
        let mut reopened = BatchJournal::open(&dir, genesis).unwrap();
        let second = reopened.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap();
        assert_ne!(first.epoch, second.epoch);
        let key = (fvk_hash(&fvk), [2; 32]);
        let record = reopened.records.get_mut(&key).unwrap();
        record.phase = JournalPhase::Settled;
        let terminal = reopened.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap();
        assert_eq!(terminal.entries[0].status_hint(), "unknown");
        assert_ne!(terminal.epoch, second.epoch);
        reopened.verified_terminals.insert(key);
        assert_ne!(reopened.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap().epoch, terminal.epoch);
        reopened.records.get_mut(&key).unwrap().phase = JournalPhase::ConflictSettled;
        assert_eq!(reopened.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap().entries[0].status_hint(), "conflicted");
    }

    #[test]
    fn discovery_pages_cover_full_record_bound_without_duplicates() {
        let dir = std::env::temp_dir().join(format!("zkas-batch-discovery-bound-{}", rand::random::<u64>()));
        let _cleanup = TestDir(dir.clone());
        let genesis = [7; 32];
        let fvk = [1; 96];
        let account = [8; 43];
        let mut journal = BatchJournal::open(&dir, genesis).unwrap();
        let original = JournalRecord::new(
            fvk, "short", genesis, account, "https://wallet.example", [0; 32], [3; 32],
            borsh::to_vec(&payment_tx(vec![1])).unwrap(), vec![42],
        ).unwrap();
        for index in 0..MAX_RECORDS {
            let mut record = original.clone();
            record.logical_id[..4].copy_from_slice(&(index as u32).to_be_bytes());
            journal.records.insert((record.fvk_hash, record.logical_id), record);
        }
        let snapshot = journal.discovery_snapshot(&fvk, "short", &account, &genesis).unwrap();
        assert_eq!(snapshot.entries.len(), MAX_RECORDS);
        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            let page = snapshot.page(cursor, cursor.map(|_| snapshot.epoch)).unwrap();
            assert!(!page.entries.is_empty());
            assert!(page.entries.len() <= DISCOVERY_PAGE_SIZE);
            seen.extend(page.entries.iter().map(|entry| entry.logical_id));
            cursor = page.next_after;
            if cursor.is_none() { break; }
        }
        assert_eq!(seen.len(), MAX_RECORDS);
        assert_eq!(seen, snapshot.entries.iter().map(|entry| entry.logical_id).collect::<Vec<_>>());
        assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
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
use hmac::{Hmac, Mac};
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
const DISCOVERY_PAGE_SIZE: usize = 32;

#[derive(Clone)]
pub(super) struct DiscoveryEntry {
    pub logical_id: [u8; 32],
    pub revision: u64,
    pub txid: [u8; 32],
    pub sha256: [u8; 32],
    pub included_block: Option<[u8; 32]>,
    pub included_daa: Option<u64>,
    phase: JournalPhase,
}

impl DiscoveryEntry {
    pub(super) fn status_hint(&self) -> &'static str {
        match self.phase {
            JournalPhase::Finalized => "finalized_unsent",
            JournalPhase::Unknown | JournalPhase::Settled => "unknown",
            JournalPhase::Mempool => "mempool",
            JournalPhase::Included => "included",
            JournalPhase::Conflicted | JournalPhase::ConflictSettled => "conflicted",
        }
    }
}

pub(super) struct DiscoverySnapshot {
    pub epoch: [u8; 32],
    pub entries: Vec<DiscoveryEntry>,
    pub unlisted_reservation_count: usize,
}

pub(super) struct DiscoveryPage {
    pub epoch: [u8; 32],
    pub entries: Vec<DiscoveryEntry>,
    pub next_after: Option<[u8; 32]>,
    pub unlisted_reservation_count: usize,
}

impl DiscoverySnapshot {
    pub(super) fn page(&self, after: Option<[u8; 32]>, expected_epoch: Option<[u8; 32]>) -> Result<DiscoveryPage, &'static str> {
        if after.is_some() && expected_epoch.is_none() {
            return Err("discovery cursor requires epoch");
        }
        if expected_epoch.is_some_and(|epoch| epoch != self.epoch) {
            return Err("discovery inventory changed");
        }
        let start = match after {
            Some(cursor) => self.entries.iter().position(|entry| entry.logical_id == cursor)
                .map(|index| index + 1).ok_or("unknown discovery cursor")?,
            None => 0,
        };
        let end = start.saturating_add(DISCOVERY_PAGE_SIZE).min(self.entries.len());
        let entries = self.entries[start..end].to_vec();
        let next_after = if end < self.entries.len() { entries.last().map(|entry| entry.logical_id) } else { None };
        Ok(DiscoveryPage { epoch: self.epoch, entries, next_after, unlisted_reservation_count: self.unlisted_reservation_count })
    }
}

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

impl JournalPhase {
    fn epoch_code(self) -> u8 {
        match self {
            Self::Finalized => 0,
            Self::Unknown => 1,
            Self::Mempool => 2,
            Self::Included => 3,
            Self::Settled => 4,
            Self::Conflicted => 5,
            Self::ConflictSettled => 6,
        }
    }
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
    epoch_key: [u8; 32],
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
        let mut epoch_key = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut epoch_key);
        let mut journal = Self {
            dir: dir.to_owned(),
            anchor,
            _lock: lock,
            genesis,
            epoch_key,
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

    pub(super) fn discovery_snapshot(
        &self, fvk: &[u8; 96], token: &str, account: &[u8; 43], genesis: &[u8; 32],
    ) -> Result<DiscoverySnapshot, &'static str> {
        if self.poisoned || genesis != &self.genesis {
            return Err("payment journal unavailable");
        }
        let fingerprint = fvk_hash(fvk);
        let mut readable: Vec<_> = self.records.iter()
            .filter(|((owner, _), record)| owner == &fingerprint && record.origin != "legacy" && record.authenticate(token, account, genesis))
            .collect();
        readable.sort_by_key(|((_, logical_id), _)| *logical_id);
        let unlisted_reservation_count = self.records.iter().filter(|(key, record)| {
            key.0 == fingerprint
                && (record.reserves() || !self.verified_terminals.contains(key))
                && (record.origin == "legacy" || !record.authenticate(token, account, genesis))
        }).count();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.epoch_key).map_err(|_| "payment journal unavailable")?;
        mac.update(b"zkas.walletd.batch.discovery.epoch.v1");
        mac.update(genesis);
        mac.update(&fingerprint);
        mac.update(&token_hash(token));
        mac.update(account);
        mac.update(&(readable.len() as u64).to_le_bytes());
        let mut entries = Vec::with_capacity(readable.len());
        for (key, record) in readable {
            let verified_terminal = self.verified_terminals.contains(key);
            mac.update(&record.logical_id);
            mac.update(&record.revision.to_le_bytes());
            mac.update(&[record.phase.epoch_code(), u8::from(verified_terminal)]);
            entries.push(DiscoveryEntry {
                logical_id: record.logical_id,
                revision: record.revision,
                txid: record.txid,
                sha256: record.sha256,
                included_block: if matches!(record.phase, JournalPhase::Settled | JournalPhase::ConflictSettled) { None } else { record.included_block },
                included_daa: if matches!(record.phase, JournalPhase::Settled | JournalPhase::ConflictSettled) { None } else { record.included_daa },
                phase: record.phase,
            });
        }
        mac.update(&(unlisted_reservation_count as u64).to_le_bytes());
        let epoch = mac.finalize().into_bytes().into();
        Ok(DiscoverySnapshot { epoch, entries, unlisted_reservation_count })
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
