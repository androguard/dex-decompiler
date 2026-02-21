//! Shared types and helpers for source→sink and invoke-only detectors.

use crate::decompile::value_flow::ValueFlowAnalysisOwned;

/// One finding: tainted value from a source reaches a dangerous sink (or a dangerous invoke is present).
#[derive(Debug, Clone)]
pub struct VulnFinding {
    pub category: String,
    pub class_name: String,
    pub method_name: String,
    /// Optional: offset where the tainted value is produced (move-result after source API).
    pub source_offset: Option<u32>,
    pub source_desc: String,
    /// Offset of the sink invoke (or dangerous API).
    pub sink_offset: u32,
    pub sink_desc: String,
}

pub(crate) fn method_matches_any(method_ref: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| method_ref.contains(p))
}

/// Generic source→sink scan: seeds from api_return_sources matching source_patterns;
/// for each seed, value_flow_from_seed; if any read is an invoke matching a sink_pattern, report.
pub fn source_sink_scan(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
    category: &str,
    source_patterns: &[&str],
    sink_patterns: &[&str],
) -> Vec<VulnFinding> {
    let seeds: Vec<(u32, u32)> = owned
        .api_return_sources
        .iter()
        .filter(|(_, method_ref)| method_matches_any(method_ref, source_patterns))
        .map(|&((offset, reg), _)| (offset, reg))
        .collect();
    let mut findings = Vec::new();
    let analysis = owned.analysis();
    for (seed_offset, seed_reg) in seeds {
        let flow = analysis.value_flow_from_seed(seed_offset, seed_reg);
        for (read_offset, _reg) in &flow.reads {
            if let Some(sink_ref) = owned.invoke_method_map.get(read_offset) {
                if method_matches_any(sink_ref, sink_patterns) {
                    findings.push(VulnFinding {
                        category: category.to_string(),
                        class_name: class_name.to_string(),
                        method_name: method_name.to_string(),
                        source_offset: Some(seed_offset),
                        source_desc: "tainted from API".to_string(),
                        sink_offset: *read_offset,
                        sink_desc: sink_ref.clone(),
                    });
                }
            }
        }
    }
    findings
}

/// Invoke-only scan: report every invoke whose method ref matches any of the patterns.
pub fn invoke_scan(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
    category: &str,
    patterns: &[&str],
) -> Vec<VulnFinding> {
    let mut findings = Vec::new();
    for (offset, method_ref) in &owned.invoke_method_map {
        if method_matches_any(method_ref, patterns) {
            findings.push(VulnFinding {
                category: category.to_string(),
                class_name: class_name.to_string(),
                method_name: method_name.to_string(),
                source_offset: None,
                source_desc: String::new(),
                sink_offset: *offset,
                sink_desc: method_ref.clone(),
            });
        }
    }
    findings
}
