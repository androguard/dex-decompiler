//! RCE via Dynamic Code Loading: scan for DexClassLoader, PathClassLoader, loadClass.

use crate::decompile::value_flow::ValueFlowAnalysisOwned;
use crate::detectors::types::{invoke_scan, VulnFinding};

const RCE_PATTERNS: &[&str] = &[
    "DexClassLoader",
    "PathClassLoader",
    "InMemoryDexClassLoader",
    "loadClass",
];

pub fn scan_rce_dynamic_loading(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
) -> Vec<VulnFinding> {
    invoke_scan(owned, class_name, method_name, "rce_dynamic_loading", RCE_PATTERNS)
}
