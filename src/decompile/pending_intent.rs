//! PendingIntent vulnerability detection (PITracker-like).
//!
//! Detects PendingIntent creation sites and checks:
//! - Base Intent: are modifiable fields (action, package, data, clipData) set?
//! - Destination: is the PendingIntent passed to Notification (obtainable by malware)?
//!
//! Reference: PITracker (WiSec'22) - https://diaowenrui.github.io/paper/wisec22-zhang.pdf

use super::cfg::MethodCfg;
use super::value_flow::{ValueFlowAnalysisOwned, ValueFlowResult};
use std::collections::{HashMap, HashSet};

/// PendingIntent creation API names (getActivity, getBroadcast, getService, getForegroundService).
const PENDING_INTENT_GET_METHODS: &[&str] = &[
    "PendingIntent.getActivity",
    "PendingIntent.getBroadcast",
    "PendingIntent.getService",
    "PendingIntent.getForegroundService",
];

/// Intent setter methods that fill modifiable fields (paper Table 1).
const INTENT_SETTERS: &[&str] = &[
    "Intent.setAction",
    "Intent.setPackage",
    "Intent.setData",
    "Intent.setDataAndType",
    "Intent.setClipData",
];

/// Sinks where PendingIntent is obtainable by other apps (e.g. NotificationListenerService).
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
    /// Offset of the PendingIntent.get* invoke.
    pub invoke_offset: u32,
    /// Base Intent has no modifiable fields set (action, package, data, clipData).
    pub base_intent_empty: bool,
    /// PendingIntent flows to a dangerous sink (e.g. Notification).
    pub dangerous_destination: bool,
    /// Human-readable destination kind for reporting.
    pub destination_kind: String,
}

/// Build map: instruction offset -> previous instruction offset in the same block.
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

/// Check if method ref is a PendingIntent getter.
fn is_pending_intent_creation(method_ref: &str) -> bool {
    PENDING_INTENT_GET_METHODS
        .iter()
        .any(|m| method_ref.contains(m))
}

/// Check if method ref is an Intent setter for modifiable fields.
fn is_intent_setter(method_ref: &str) -> bool {
    INTENT_SETTERS.iter().any(|m| method_ref.contains(m))
}

/// Check if method ref is a dangerous sink (Notification, etc.).
fn is_dangerous_sink(method_ref: &str) -> bool {
    DANGEROUS_SINKS.iter().any(|m| method_ref.contains(m))
}

/// Collect all defs of (use_offset, use_reg) transitively (following moves).
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
            // If this def is a move, follow the source.
            if let Some((reads, _)) = owned.rw_map.get(&d_off) {
                if reads.len() == 1 {
                    worklist.push((d_off, reads[0]));
                }
            }
        }
    }
    defs
}

/// For the Intent register at the PendingIntent.get* invoke, check whether any
/// modifiable field (action, package, data, clipData) is set along its def chain.
fn base_intent_has_setters(owned: &ValueFlowAnalysisOwned, invoke_offset: u32, intent_reg: u32) -> bool {
    let prev = prev_offset_in_block(&owned.cfg);
    let defs = transitive_defs(owned, invoke_offset, intent_reg);
    for (d_off, d_reg) in &defs {
        // Case 1: def is an invoke to Intent.set* (receiver = d_reg).
        if let Some(method_ref) = owned.invoke_method_map.get(d_off) {
            if is_intent_setter(method_ref) {
                if let Some((reads, _)) = owned.rw_map.get(d_off) {
                    if reads.first() == Some(d_reg) {
                        return true;
                    }
                }
            }
        }
        // Case 2: def is move-result from Intent.set* (e.g. v2 = setAction(v0,v1); move-result v2).
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

/// Classify where the PendingIntent value flows (dangerous sink vs other).
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
        // getActivity(Context, requestCode, Intent, flags) -> intent = arg 2, flags = arg 3
        if arg_reads.len() < 4 {
            continue;
        }
        let intent_reg = arg_reads[2];
        let _flags_reg = arg_reads[3];

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
    use std::collections::HashMap;

    fn make_cfg(instruction_offsets: Vec<u32>) -> MethodCfg {
        use super::super::cfg::{BlockEnd, CfgBlock};
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

    /// Build synthetic ValueFlowAnalysisOwned: one block [0,2,4,6,8]; at 4 invoke getActivity(..., intent=v2, ...), at 6 move-result pi, at 8 invoke sink(pi).
    /// When intent_has_setter: at 0 invoke Intent.setAction(v0,v1), at 2 move-result v2 (intent flows from setAction).
    fn synthetic_owned(
        intent_has_setter: bool,
        sink_is_dangerous: bool,
    ) -> ValueFlowAnalysisOwned {
        let offsets = vec![0u32, 2, 4, 6, 8];
        let cfg = make_cfg(offsets.clone());
        let mut rw_map: HashMap<u32, (Vec<u32>, Vec<u32>)> = HashMap::new();
        if intent_has_setter {
            rw_map.insert(0, (vec![0, 1], vec![])); // invoke setAction(v0, v1)
            rw_map.insert(2, (vec![], vec![2]));    // move-result v2
        }
        rw_map.insert(4, (vec![0, 1, 2, 3], vec![])); // invoke getActivity(v0, v1, v2, v3); intent=v2
        rw_map.insert(6, (vec![], vec![4]));         // move-result v4 (PendingIntent)
        rw_map.insert(8, (vec![4], vec![]));         // invoke sink(v4)
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
        assert_eq!(findings.len(), 1, "expected one finding");
        let f = &findings[0];
        assert!(f.base_intent_empty, "base Intent should be empty");
        assert!(f.dangerous_destination, "destination should be dangerous");
        assert_eq!(f.class_name, "com.example.Foo");
        assert_eq!(f.method_name, "bar");
        assert_eq!(f.invoke_offset, 4);
    }

    #[test]
    fn scan_base_intent_not_empty_when_setter_in_chain() {
        let owned = synthetic_owned(true, true);
        let findings = scan_pending_intents(&owned, "com.example.Foo", "bar");
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].base_intent_empty, "Intent has setAction in chain");
    }

    #[test]
    fn scan_destination_other_when_sink_not_dangerous() {
        let owned = synthetic_owned(false, false);
        let findings = scan_pending_intents(&owned, "com.example.Foo", "bar");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].base_intent_empty);
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
