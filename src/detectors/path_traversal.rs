//! Path traversal: getLastPathSegment / Uri path → File / openFile.

use crate::decompile::value_flow::ValueFlowAnalysisOwned;
use crate::detectors::types::{source_sink_scan, VulnFinding};

const SOURCES: &[&str] = &[
    "getLastPathSegment",
    "getPath",
    "getQueryParameter",
    "getStringExtra",
];
const SINKS: &[&str] = &[
    "File.<init>",
    "java.io.File.<init>",
    "openFile",
    "ParcelFileDescriptor.open",
    "FileInputStream.<init>",
    "FileOutputStream.<init>",
];

pub fn scan_path_traversal(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
) -> Vec<VulnFinding> {
    source_sink_scan(
        owned,
        class_name,
        method_name,
        "path_traversal",
        SOURCES,
        SINKS,
    )
}
