//! Weak crypto: SecretKeySpec / IvParameterSpec with possibly hardcoded material.

use crate::decompile::value_flow::ValueFlowAnalysisOwned;
use crate::detectors::types::{invoke_scan, VulnFinding};

const PATTERNS: &[&str] = &[
    "SecretKeySpec.<init>",
    "IvParameterSpec.<init>",
    "DESKeySpec.<init>",
    "PBEKeySpec.<init>",
];

pub fn scan_weak_crypto(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
) -> Vec<VulnFinding> {
    invoke_scan(
        owned,
        class_name,
        method_name,
        "weak_crypto",
        PATTERNS,
    )
}
