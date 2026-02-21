//! PendingIntent vulnerability detection (PITracker-like).
//!
//! Detects PendingIntent creation sites and checks:
//! - Base Intent: are modifiable fields (action, package, data, clipData) set?
//! - Destination: is the PendingIntent passed to Notification (obtainable by malware)?
//!
//! Reference: PITracker (WiSec'22) - https://diaowenrui.github.io/paper/wisec22-zhang.pdf

use crate::decompile::cfg::MethodCfg;
use crate::decompile::value_flow::{ValueFlowAnalysisOwned, ValueFlowResult};
use std::collections::{HashMap, HashSet};

const PENDING_INTENT_GET_METHODS: &[&str] = &[
    "PendingIntent.getActivity",
    "PendingIntent.getBroadcast",
    "PendingIntent.getService",
    "PendingIntent.getForegroundService",
];

const INTENT_SETTERS: &[&str] = &[
    "Intent.setAction",
    "Intent.setPackage",
    "Intent.setData",
    "Intent.setDataAndType",
    "Intent.setClipData",
];

const DANGEROUS_SINKS: &[&str] = &[
    "setContentIntent",
    "Notification.Builder.setContentIntent",
    "NotificationCompat.Builder.setContentIntent",
];

/// One PendingIntent creation site with risk info.
#[derive(Debug, Clone)]
pub struct PendingIntentFinding {
    pub class_name: String,
    pub method_name: String,
    pub invoke_offset: u32,
    pub base_intent_empty: bool,
    pub dangerous_destination: bool,
    pub destination_kind: String,
}

fn prev_offset_in_block(cfg: &MethodCfg) -> HashMap<u32, u32> {
    let mut prev = HashMap::new();
    for block in &cfg.blocks {
        let offsets = &block.instruction_offsets;
        for i in 1..offsets.len() {
            prev.insert(offsets[i], offsets[i - 1]);
        }
    }
    prev
}

fn is_pending_intent_creation(method_ref: &str) -> bool {
    PENDING_INTENT_GET_METHODS.iter().any(|m| method_ref.contains(m))
}

fn is_intent_setter(method_ref: &str) -> bool {
    INTENT_SETTERS.iter().any(|m| method_ref.contains(m))
}

fn is_dangerous_sink(method_ref: &str) -> bool {
    DANGEROUS_SINKS.iter().any(|m| method_ref.contains(m))
}

fn transitive_defs(
    owned: &ValueFlowAnalysisOwned,
    use_offset: u32,
    use_reg: u32,
) -> HashSet<(u32, u32)> {
    let analysis = owned.analysis();
    let mut defs = HashSet::new();
    let mut worklist = vec![(use_offset, use_reg)];
    let mut visited = HashSet::new();
    while let Some((off, reg)) = worklist.pop() {
        if !visited.insert((off, reg)) {
            continue;
        }
        for (d_off, d_reg) in analysis.use_def(off, reg) {
            defs.insert((d_off, d_reg));
            if let Some((reads, _)) = owned.rw_map.get(&d_off) {
                if reads.len() == 1 {
                    worklist.push((d_off, reads[0]));
                }
            }
        }
    }
    defs
}

fn base_intent_has_setters(owned: &ValueFlowAnalysisOwned, invoke_offset: u32, intent_reg: u32) -> bool {
    let prev = prev_offset_in_block(&owned.cfg);
    let defs = transitive_defs(owned, invoke_offset, intent_reg);
    for (d_off, d_reg) in &defs {
        if let Some(method_ref) = owned.invoke_method_map.get(d_off) {
            if is_intent_setter(method_ref) {
                if let Some((reads, _)) = owned.rw_map.get(d_off) {
                    if reads.first() == Some(d_reg) {
                        return true;
                    }
                }
            }
        }
        if let Some((reads, writes)) = owned.rw_map.get(d_off) {
            if reads.is_empty() && writes.len() == 1 && writes[0] == *d_reg {
                if let Some(&prev_off) = prev.get(d_off) {
                    if let Some(method_ref) = owned.invoke_method_map.get(&prev_off) {
                        if is_intent_setter(method_ref) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn classify_destination(owned: &ValueFlowAnalysisOwned, flow: &ValueFlowResult) -> (bool, String) {
    for (off, _reg) in &flow.reads {
        if let Some(method_ref) = owned.invoke_method_map.get(off) {
            if is_dangerous_sink(method_ref) {
                return (true, "Notification/setContentIntent".to_string());
            }
        }
    }
    (false, "other".to_string())
}

/// Scan one method for PendingIntent creation sites and assess risk.
pub fn scan_pending_intents(
    owned: &ValueFlowAnalysisOwned,
    class_name: &str,
    method_name: &str,
) -> Vec<PendingIntentFinding> {
    let prev = prev_offset_in_block(&owned.cfg);
    let mut findings = Vec::new();

    for ((move_result_offset, pi_reg), method_ref) in &owned.api_return_sources {
        if !is_pending_intent_creation(method_ref) {
            continue;
        }
        let Some(invoke_offset) = prev.get(move_result_offset) else {
            continue;
        };
        let empty = (vec![], vec![]);
        let (arg_reads, _) = owned.rw_map.get(invoke_offset).unwrap_or(&empty);
        if arg_reads.len() < 4 {
            continue;
        }
        let intent_reg = arg_reads[2];

        let base_intent_empty = !base_intent_has_setters(owned, *invoke_offset, intent_reg);
        let flow: ValueFlowResult = owned.analysis().value_flow_from_seed(*move_result_offset, *pi_reg);
        let (dangerous_destination, destination_kind) = classify_destination(owned, &flow);

        findings.push(PendingIntentFinding {
            class_name: class_name.to_string(),
            method_name: method_name.to_string(),
            invoke_offset: *invoke_offset,
            base_intent_empty,
            dangerous_destination,
            destination_kind,
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::cfg::{BlockEnd, CfgBlock};
    use std::collections::HashMap;

    fn make_cfg(instruction_offsets: Vec<u32>) -> MethodCfg {
        let block = CfgBlock {
            start_offset: *instruction_offsets.first().unwrap_or(&0),
            end_offset: instruction_offsets.last().copied().unwrap_or(0) + 2,
            end: BlockEnd::Exit,
            instruction_offsets: instruction_offsets.clone(),
        };
        let mut block_by_start = HashMap::new();
        block_by_start.insert(block.start_offset, 0);
        MethodCfg {
            blocks: vec![block],
            block_by_start,
            loop_headers: HashSet::new(),
            entry: 0,
        }
    }

    fn synthetic_owned(intent_has_setter: bool, sink_is_dangerous: bool) -> ValueFlowAnalysisOwned {
        let offsets = vec![0u32, 2, 4, 6, 8];
        let cfg = make_cfg(offsets.clone());
        let mut rw_map: HashMap<u32, (Vec<u32>, Vec<u32>)> = HashMap::new();
        if intent_has_setter {
            rw_map.insert(0, (vec![0, 1], vec![]));
            rw_map.insert(2, (vec![], vec![2]));
        }
        rw_map.insert(4, (vec![0, 1, 2, 3], vec![]));
        rw_map.insert(6, (vec![], vec![4]));
        rw_map.insert(8, (vec![4], vec![]));
        let api_return_sources = vec![((6, 4), "android.app.PendingIntent.getActivity".to_string())];
        let mut invoke_method_map: HashMap<u32, String> = HashMap::new();
        if intent_has_setter {
            invoke_method_map.insert(0, "android.content.Intent.setAction".to_string());
        }
        invoke_method_map.insert(4, "android.app.PendingIntent.getActivity".to_string());
        invoke_method_map.insert(8, if sink_is_dangerous {
            "android.app.Notification.Builder.setContentIntent".to_string()
        } else {
            "android.app.AlarmManager.set".to_string()
        });
        ValueFlowAnalysisOwned {
            cfg,
            rw_map,
            api_return_sources,
            invoke_method_map,
        }
    }

    #[test]
    fn scan_finds_vulnerable_site_when_intent_empty_and_dangerous_sink() {
        let owned = synthetic_owned(false, true);
        let findings = scan_pending_intents(&owned, "com.example.Foo", "bar");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.base_intent_empty);
        assert!(f.dangerous_destination);
        assert_eq!(f.invoke_offset, 4);
    }

    #[test]
    fn scan_base_intent_not_empty_when_setter_in_chain() {
        let owned = synthetic_owned(true, true);
        let findings = scan_pending_intents(&owned, "com.example.Foo", "bar");
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].base_intent_empty);
    }

    #[test]
    fn scan_destination_other_when_sink_not_dangerous() {
        let owned = synthetic_owned(false, false);
        let findings = scan_pending_intents(&owned, "com.example.Foo", "bar");
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].dangerous_destination);
        assert_eq!(findings[0].destination_kind, "other");
    }

    #[test]
    fn scan_returns_empty_when_no_pending_intent_creation() {
        let offsets = vec![0u32, 2, 4];
        let cfg = make_cfg(offsets);
        let mut rw_map: HashMap<u32, (Vec<u32>, Vec<u32>)> = HashMap::new();
        rw_map.insert(0, (vec![], vec![0]));
        rw_map.insert(4, (vec![0], vec![]));
        let owned = ValueFlowAnalysisOwned {
            cfg,
            rw_map,
            api_return_sources: vec![((4, 0), "some.Other.method".to_string())],
            invoke_method_map: HashMap::new(),
        };
        let findings = scan_pending_intents(&owned, "com.example.Foo", "bar");
        assert!(findings.is_empty());
    }
}
