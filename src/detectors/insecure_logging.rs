//! Insecure logging: sensitive source → Log.d / Log.i / println.

use crate::decompile::value_flow::ValueFlowAnalysisOwned;
use crate::detectors::types::{source_sink_scan, VulnFinding};

const LOGGING_SINKS: &[&str] = &[
    "Log.d", "Log.i", "Log.e", "Log.w", "Log.v",
    "println", "print",
];

const LOGGING_SOURCE_DEFAULTS: &[&str] = &[
    "getLastLocation",
    "getCurrentLocation",
    "getDeviceId",
    "getSubscriberId",
    "getAndroidId",
    "getPrimaryClip",
    "getText",
    "getString",
    "getToken",
];

pub fn scan_insecure_logging(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
    source_patterns: Option<&[String]>,
) -> Vec<VulnFinding> {
    let sources: Vec<&str> = source_patterns
        .map(|s| s.iter().map(String::as_str).collect::<Vec<_>>())
        .unwrap_or_else(|| LOGGING_SOURCE_DEFAULTS.to_vec());
    source_sink_scan(
        owned,
        class_name,
        method_name,
        "insecure_logging",
        &sources,
        LOGGING_SINKS,
    )
}
