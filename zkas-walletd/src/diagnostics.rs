use std::hash::{BuildHasher, RandomState};
use std::sync::OnceLock;

static DIAGNOSTIC_HASHER: OnceLock<RandomState> = OnceLock::new();

// Correlate diagnostic lines within one process without making a wallet token
// or bundle session recoverable from logs. These labels rotate on restart and
// are never authorization credentials or persistent wallet identifiers.
pub(super) fn diagnostic_id_with(hasher: &RandomState, namespace: &str, value: &str) -> String {
    format!("{namespace}-{:016x}", hasher.hash_one((namespace, value)))
}

pub(super) fn wallet_diag_id(token: &str) -> String {
    diagnostic_id_with(DIAGNOSTIC_HASHER.get_or_init(RandomState::new), "wallet", token)
}

pub(super) fn session_diag_id(session: &str) -> String {
    diagnostic_id_with(DIAGNOSTIC_HASHER.get_or_init(RandomState::new), "session", session)
}

pub(super) fn json_error_category(error: &serde_json::Error) -> String {
    let category = match error.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "eof",
    };
    format!("{category} at line {} column {}", error.line(), error.column())
}

pub(super) fn io_error_category(error: &std::io::Error) -> std::io::ErrorKind {
    error.kind()
}

pub(super) fn join_error_category(error: &tokio::task::JoinError) -> &'static str {
    if error.is_cancelled() {
        "cancelled"
    } else if error.is_panic() {
        "panicked"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod diagnostic_redaction_tests {
    use super::*;
    use crate::{diagnose_wallets, load_wallet_meta, save_seed};

    struct CapturedErrors(std::sync::Mutex<Vec<String>>);

    impl log::Log for CapturedErrors {
        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
            metadata.level() <= log::Level::Error
        }

        fn log(&self, record: &log::Record<'_>) {
            if self.enabled(record.metadata()) {
                self.0.lock().unwrap().push(record.args().to_string());
            }
        }

        fn flush(&self) {}
    }

    static CAPTURED_ERRORS: CapturedErrors = CapturedErrors(std::sync::Mutex::new(Vec::new()));

    #[test]
    fn credential_identifiers_are_process_scoped_and_domain_separated() {
        let token = "short-secret";
        let a = wallet_diag_id(token);
        assert_eq!(a, wallet_diag_id(token));
        assert_ne!(a, session_diag_id(token));
        assert!(!a.contains(token));
        assert!(!a.contains("short"));
        let who = token;
        let donor = "other-low-entropy-token";
        assert_eq!(a, wallet_diag_id(who));
        assert_ne!(a, wallet_diag_id(donor));
        assert!(!wallet_diag_id(donor).contains(donor));
        assert_ne!(a, diagnostic_id_with(&std::hash::RandomState::new(), "wallet", token));
    }

    #[test]
    fn malformed_wallet_json_reports_only_type_and_location() {
        let sentinel = "sensitive-local-value";
        let error = serde_json::from_str::<serde_json::Value>(&format!("{{\"key\":{sentinel}}}")).unwrap_err();
        let detail = json_error_category(&error);
        assert!(detail.contains("syntax"));
        assert!(detail.contains("line"));
        assert!(!detail.contains(sentinel));
        let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, sentinel);
        assert_eq!(format!("{:?}", io_error_category(&io_error)), "PermissionDenied");
    }

    #[test]
    fn offline_report_hides_wallet_name_and_token_derived_filename() {
        let dir = std::env::temp_dir().join(format!("walletd-diagnostic-{}-{}", std::process::id(), wallet_diag_id("fixture")));
        std::fs::create_dir(&dir).unwrap();
        let token = "short-secret";
        std::fs::write(dir.join(format!("{token}.scan")), b"dummy").unwrap();
        let report = diagnose_wallets(dir.to_str().unwrap(), None);
        std::fs::remove_dir_all(dir).unwrap();
        assert!(report.contains(&wallet_diag_id(token)));
        assert!(!report.contains(token));
        assert!(!report.contains(&format!("{token}.scan")));
    }

    #[test]
    fn wallet_load_error_hides_credential_and_filename() {
        log::set_logger(&CAPTURED_ERRORS).unwrap();
        log::set_max_level(log::LevelFilter::Error);
        let token = "short-secret";
        let dir = std::env::temp_dir().join(format!("walletd-log-{}-{}", std::process::id(), wallet_diag_id(token)));
        std::fs::create_dir(&dir).unwrap();
        save_seed(dir.to_str().unwrap(), token, "testnet", &[7; 32], 0, Some("private-passphrase")).unwrap();
        assert!(load_wallet_meta(dir.to_str().unwrap(), token, None).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
        let lines = CAPTURED_ERRORS.0.lock().unwrap().join("\n");
        assert!(lines.contains(&wallet_diag_id(token)));
        assert!(!lines.contains(token));
        assert!(!lines.contains(&format!("{token}.json")));
        assert!(!lines.contains("private-passphrase"));
        assert!(!lines.contains(dir.to_str().unwrap()));
    }
}
