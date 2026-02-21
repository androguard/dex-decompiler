//! Hardcoded secrets: invokes that may write sensitive data (review for constants).

use crate::decompile::value_flow::ValueFlowAnalysisOwned;
use crate::detectors::types::{invoke_scan, VulnFinding};

const SECRET_SINKS: &[&str] = &[
    "putString",
    "putLong",
    "putInt",
    "putBoolean",
    "edit",
    "FileOutputStream",
    "FileWriter",
    "RequestBody.create",
    "FormBody.add",
];

pub fn scan_hardcoded_secrets(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
) -> Vec<VulnFinding> {
    invoke_scan(
        owned,
        class_name,
        method_name,
        "hardcoded_secrets_review",
        SECRET_SINKS,
    )
}
