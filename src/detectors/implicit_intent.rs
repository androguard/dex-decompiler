//! Implicit Intent launches (no component/package) — hijackable by other apps.

use crate::decompile::value_flow::ValueFlowAnalysisOwned;
use crate::detectors::types::{invoke_scan, method_matches_any, VulnFinding};

const LAUNCH: &[&str] = &[
    "startActivity",
    "startActivityForResult",
    "startService",
    "bindService",
    "sendBroadcast",
    "sendOrderedBroadcast",
];

const EXPLICIT: &[&str] = &[
    "setComponent",
    "setClass",
    "setClassName",
    "setPackage",
    "Intent.setComponent",
    "Intent.setClass",
    "Intent.setClassName",
    "Intent.setPackage",
];

const IMPLICIT_HINTS: &[&str] = &[
    "setAction",
    "Intent.setAction",
    "Intent.<init>",
    "setData",
    "addCategory",
];

pub fn scan_implicit_intent(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
) -> Vec<VulnFinding> {
    let has_launch = owned
        .invoke_method_map
        .values()
        .any(|m| method_matches_any(m, LAUNCH));
    if !has_launch {
        return Vec::new();
    }
    let has_explicit = owned
        .invoke_method_map
        .values()
        .any(|m| method_matches_any(m, EXPLICIT));
    if has_explicit {
        return Vec::new();
    }
    let has_implicit_hint = owned
        .invoke_method_map
        .values()
        .any(|m| method_matches_any(m, IMPLICIT_HINTS));
    if !has_implicit_hint {
        return Vec::new();
    }
    // One finding per method (not per launch invoke) to cut OVAA-style spam.
    let mut findings = invoke_scan(
        owned,
        class_name,
        method_name,
        "implicit_intent_launch",
        LAUNCH,
    );
    findings.truncate(1);
    findings
}
