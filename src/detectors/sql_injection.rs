//! SQL injection: user input → rawQuery / execSQL.

use crate::decompile::value_flow::ValueFlowAnalysisOwned;
use crate::detectors::types::{source_sink_scan, VulnFinding};

const SQL_SOURCES: &[&str] = &[
    "getStringExtra",
    "getText",
    "getData",
    "getDataString",
    "getCharSequenceExtra",
];
const SQL_SINKS: &[&str] = &["rawQuery", "execSQL", "query"];

pub fn scan_sql_injection(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
) -> Vec<VulnFinding> {
    source_sink_scan(
        owned,
        class_name,
        method_name,
        "sql_injection",
        SQL_SOURCES,
        SQL_SINKS,
    )
}
