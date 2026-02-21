//! Vulnerability detectors: one module per detector, shared types and run_all.
//!
//! Each detector lives in its own `.rs` file. Use `run_all_detectors` to run
//! every detector (except PendingIntent, which has its own finding type and CLI flag).

mod hardcoded_secrets;
mod insecure_logging;
mod intent_spoofing;
mod ipc_intent_validation;
pub mod pending_intent;
mod rce_dynamic_loading;
mod sql_injection;
mod types;
mod webview;

pub use hardcoded_secrets::scan_hardcoded_secrets;
pub use insecure_logging::scan_insecure_logging;
pub use intent_spoofing::scan_intent_spoofing;
pub use ipc_intent_validation::scan_ipc_intent_validation;
pub use pending_intent::{scan_pending_intents, PendingIntentFinding};
pub use rce_dynamic_loading::scan_rce_dynamic_loading;
pub use sql_injection::scan_sql_injection;
pub use types::{source_sink_scan, invoke_scan, VulnFinding};
pub use webview::scan_webview_unsafe;

use crate::decompile::value_flow::ValueFlowAnalysisOwned;
use std::collections::HashSet;

/// Run all detectors (except PendingIntent) and return findings, deduplicated by category+class+method+sink_offset.
pub fn run_all_detectors(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
    logging_sources: Option<&[String]>,
) -> Vec<VulnFinding> {
    let mut all = Vec::new();
    all.extend(scan_intent_spoofing(owned, class_name, method_name));
    all.extend(scan_rce_dynamic_loading(owned, class_name, method_name));
    all.extend(scan_insecure_logging(owned, class_name, method_name, logging_sources));
    all.extend(scan_sql_injection(owned, class_name, method_name));
    all.extend(scan_webview_unsafe(owned, class_name, method_name));
    all.extend(scan_hardcoded_secrets(owned, class_name, method_name));
    all.extend(scan_ipc_intent_validation(owned, class_name, method_name));
    let mut seen: HashSet<(String, String, String, u32)> = HashSet::new();
    all.into_iter()
        .filter(|f| {
            let key = (
                f.category.clone(),
                f.class_name.clone(),
                f.method_name.clone(),
                f.sink_offset,
            );
            seen.insert(key)
        })
        .collect()
}
