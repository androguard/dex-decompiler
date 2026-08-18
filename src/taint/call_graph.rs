//! Call-graph construction from invoke sites.

use std::collections::HashMap;

use crate::decompile::value_flow::ValueFlowAnalysisOwned;
use crate::error::Result;

use super::index::{MethodId, MethodIndex};

#[derive(Clone, Debug)]
pub struct CallEdge {
    pub caller: MethodId,
    pub callee: MethodId,
    /// Invoke instruction offset (method-relative).
    pub invoke_offset: u32,
    /// Argument registers at the call site (order = Dalvik invoke regs).
    pub arg_regs: Vec<u32>,
    pub method_ref: String,
}

#[derive(Debug, Default)]
pub struct CallGraph {
    /// caller → outgoing edges
    pub outs: HashMap<MethodId, Vec<CallEdge>>,
    /// callee → incoming edges
    pub ins: HashMap<MethodId, Vec<CallEdge>>,
}

impl CallGraph {
    /// Build the call graph from a precomputed value-flow cache (no re-analysis).
    pub fn build_from_vf_cache(
        index: &MethodIndex,
        vf_cache: &HashMap<MethodId, ValueFlowAnalysisOwned>,
        include: impl Fn(MethodId) -> bool,
    ) -> Result<Self> {
        let mut cg = CallGraph::default();
        for mref in &index.methods {
            if !include(mref.id) {
                continue;
            }
            let Some(owned) = vf_cache.get(&mref.id) else {
                continue;
            };
            for (&invoke_offset, method_ref) in &owned.invoke_method_map {
                let callees = index.resolve_callees(method_ref);
                if callees.is_empty() {
                    continue;
                }
                let arg_regs = owned
                    .rw_map
                    .get(&invoke_offset)
                    .map(|(reads, _)| reads.clone())
                    .unwrap_or_default();
                for callee in callees {
                    if !include(callee) {
                        continue;
                    }
                    let edge = CallEdge {
                        caller: mref.id,
                        callee,
                        invoke_offset,
                        arg_regs: arg_regs.clone(),
                        method_ref: method_ref.clone(),
                    };
                    cg.outs.entry(mref.id).or_default().push(edge.clone());
                    cg.ins.entry(callee).or_default().push(edge);
                }
            }
        }
        Ok(cg)
    }

    pub fn edge_count(&self) -> usize {
        self.outs.values().map(|v| v.len()).sum()
    }
}
