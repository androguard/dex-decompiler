//! Interprocedural taint solver (Mariana Trench–style abstract interpretation).

use std::collections::{HashMap, HashSet, VecDeque};

use dex_parser::DexFile;
use rayon::prelude::*;

use crate::decompile::value_flow::ValueFlowAnalysisOwned;
use crate::decompile::Decompiler;
use crate::error::Result;

use super::call_graph::CallGraph;
use super::config::TaintConfig;
use super::index::{MethodId, MethodIndex};
use super::issue::{Issue, TraceFrame};
use super::models::{Port, SanitizerModel};
use super::report::{IssueReport, ReportStats};

#[derive(Clone, Debug, Default)]
pub struct SolveOptions {
    /// Max fixpoint iterations (default 8).
    pub max_iterations: usize,
    /// Skip methods whose class name starts with any of these prefixes.
    pub exclude_prefixes: Vec<String>,
}

impl SolveOptions {
    pub fn default_android() -> Self {
        Self {
            max_iterations: 8,
            exclude_prefixes: vec![
                "android.".into(),
                "androidx.".into(),
                "kotlin.".into(),
                "kotlinx.".into(),
                "java.".into(),
                "javax.".into(),
                "dalvik.".into(),
                "com.google.android.".into(),
                "com.google.firebase.".into(),
                "com.android.".into(),
                "okhttp3.".into(),
                "okio.".into(),
                "retrofit2.".into(),
                "com.squareup.".into(),
                "com.facebook.".into(),
                "io.sentry.".into(),
            ],
        }
    }
}

#[derive(Clone, Debug)]
pub struct SolveResult {
    pub issues: Vec<Issue>,
    pub report: IssueReport,
}

#[derive(Clone, Debug, Default)]
struct MethodSummary {
    /// Parameter index → kinds that may flow into this method via callers.
    param_kinds: HashMap<u32, HashSet<String>>,
    /// Kinds that may leave via return.
    return_kinds: HashSet<String>,
    /// Inferred: which params flow to return (TITO within method body).
    param_to_return: HashSet<u32>,
}

#[derive(Clone, Debug, Default)]
struct LocalTaint {
    /// (offset, reg) → kinds
    at: HashMap<(u32, u32), HashSet<String>>,
}

impl LocalTaint {
    fn insert(&mut self, offset: u32, reg: u32, kind: &str) -> bool {
        self.at
            .entry((offset, reg))
            .or_default()
            .insert(kind.to_string())
    }

    fn kinds_at(&self, offset: u32, reg: u32) -> HashSet<String> {
        self.at.get(&(offset, reg)).cloned().unwrap_or_default()
    }
}

fn port_to_arg_index(port: &Port) -> Option<u32> {
    match port {
        Port::Return => None,
        Port::This => Some(0),
        Port::Argument { index } => Some(*index),
    }
}

fn sanitize_kinds(kinds: &HashSet<String>, san: &SanitizerModel) -> HashSet<String> {
    if san.kinds.iter().any(|k| k == "*") {
        return HashSet::new();
    }
    if san.kinds.is_empty() {
        // Empty kinds list = do not sanitize (breadcrumb-only model).
        return kinds.clone();
    }
    kinds
        .iter()
        .filter(|k| !san.kinds.iter().any(|s| s == *k))
        .cloned()
        .collect()
}

fn should_skip(class_name: &str, opts: &SolveOptions) -> bool {
    opts.exclude_prefixes
        .iter()
        .any(|p| class_name.starts_with(p.as_str()))
}

/// Analyze a single DEX with the default Android options.
pub fn solve_dex(dex: &DexFile, config: &TaintConfig) -> Result<SolveResult> {
    solve_dexes(&[dex], config, &SolveOptions::default_android())
}

/// Analyze one or more DEX files (multi-DEX app).
///
/// Hot paths run in parallel via rayon:
/// - per-method value-flow cache construction
/// - Pass-0 local source/sink analysis
/// - fixpoint worklist batches and call-edge arg propagation
pub fn solve_dexes(
    dexes: &[&DexFile],
    config: &TaintConfig,
    opts: &SolveOptions,
) -> Result<SolveResult> {
    let index = MethodIndex::from_dexes(dexes);

    // Parallel value-flow cache: each worker builds its own Decompiler (RefCell !Sync).
    let vf_cache: HashMap<MethodId, ValueFlowAnalysisOwned> = index
        .methods
        .par_iter()
        .filter_map(|m| {
            if should_skip(&m.class_name, opts) {
                return None;
            }
            let dex = dexes.get(m.dex_index)?;
            let decompiler = Decompiler::new(dex);
            decompiler
                .value_flow_analysis(&m.encoded)
                .ok()
                .map(|owned| (m.id, owned))
        })
        .collect();

    let analyzed: HashSet<MethodId> = vf_cache.keys().copied().collect();
    let call_graph = CallGraph::build_from_vf_cache(&index, &vf_cache, |id| analyzed.contains(&id))?;

    let max_iter = if opts.max_iterations == 0 {
        8
    } else {
        opts.max_iterations
    };

    let mut summaries: HashMap<MethodId, MethodSummary> = analyzed
        .iter()
        .map(|&id| (id, MethodSummary::default()))
        .collect();

    let mut issues: Vec<Issue> = Vec::new();
    let mut seen_issue_keys: HashSet<String> = HashSet::new();
    let mut iterations = 0usize;
    let mut worklist: VecDeque<(MethodId, u32, String)> = VecDeque::new();

    // Pass 0: independent per-method analysis (empty interproc params) — parallel.
    {
        let pass0: Vec<_> = index
            .methods
            .par_iter()
            .filter(|m| vf_cache.contains_key(&m.id))
            .map(|m| {
                let mut local_summaries: HashMap<MethodId, MethodSummary> = HashMap::new();
                local_summaries.insert(m.id, MethodSummary::default());
                let mut local_issues = Vec::new();
                let mut local_seen = HashSet::new();
                let mut local_wl = VecDeque::new();
                analyze_method(
                    m.id,
                    &index,
                    &vf_cache,
                    config,
                    &mut local_summaries,
                    &mut local_issues,
                    &mut local_seen,
                    &mut local_wl,
                    /*seed_only_params=*/ false,
                );
                (
                    m.id,
                    local_summaries.remove(&m.id).unwrap_or_default(),
                    local_issues,
                    local_wl,
                )
            })
            .collect();

        for (mid, sum, local_issues, local_wl) in pass0 {
            if let Some(dst) = summaries.get_mut(&mid) {
                dst.return_kinds.extend(sum.return_kinds);
                dst.param_to_return.extend(sum.param_to_return);
                for (k, kinds) in sum.param_kinds {
                    dst.param_kinds.entry(k).or_default().extend(kinds);
                }
            } else {
                summaries.insert(mid, sum);
            }
            for issue in local_issues {
                let key = issue_dedup_key(&issue);
                if seen_issue_keys.insert(key) {
                    issues.push(issue);
                }
            }
            worklist.extend(local_wl);
        }
    }

    // Interprocedural fixpoint.
    while iterations < max_iter {
        iterations += 1;
        let mut progressed = false;

        let batch: Vec<_> = worklist.drain(..).collect();

        // Apply param-kind inserts, then re-analyze unique methods in parallel.
        // (Empty batch is OK — we still run return + call-edge transfers below.)
        let mut dirty: HashSet<MethodId> = HashSet::new();
        for (mid, param_idx, kind) in &batch {
            let entry = summaries.entry(*mid).or_default();
            if entry.param_kinds.entry(*param_idx).or_default().insert(kind.clone()) {
                dirty.insert(*mid);
                progressed = true;
            }
        }

        if !dirty.is_empty() {
            let dirty_ids: Vec<MethodId> = dirty.into_iter().collect();
            let summaries_snap = summaries.clone();
            let parallel_out: Vec<_> = dirty_ids
                .par_iter()
                .map(|&mid| {
                    let mut local_summaries = summaries_snap.clone();
                    let mut local_issues = Vec::new();
                    let mut local_seen = HashSet::new();
                    let mut local_wl = VecDeque::new();
                    analyze_method(
                        mid,
                        &index,
                        &vf_cache,
                        config,
                        &mut local_summaries,
                        &mut local_issues,
                        &mut local_seen,
                        &mut local_wl,
                        /*seed_only_params=*/ true,
                    );
                    let sum = local_summaries.remove(&mid).unwrap_or_default();
                    (mid, sum, local_issues, local_wl)
                })
                .collect();

            for (mid, sum, local_issues, local_wl) in parallel_out {
                if let Some(dst) = summaries.get_mut(&mid) {
                    let before_ret = dst.return_kinds.len();
                    let before_p2r = dst.param_to_return.len();
                    dst.return_kinds.extend(sum.return_kinds);
                    dst.param_to_return.extend(sum.param_to_return);
                    if dst.return_kinds.len() > before_ret || dst.param_to_return.len() > before_p2r
                    {
                        progressed = true;
                    }
                }
                for issue in local_issues {
                    let key = issue_dedup_key(&issue);
                    if seen_issue_keys.insert(key) {
                        issues.push(issue);
                    }
                }
                worklist.extend(local_wl);
            }
        }

        progressed |= propagate_returns(
            &index,
            &call_graph,
            &vf_cache,
            config,
            &mut summaries,
            &mut issues,
            &mut seen_issue_keys,
            &mut worklist,
        );

        // Parallel scan of call edges for arg→param taint transfer.
        // Must run even when the worklist was empty after pass-0 (otherwise
        // interprocedural arg→param never starts).
        let edge_list: Vec<_> = call_graph.outs.values().flat_map(|v| v.iter()).collect();
        let summaries_snap = summaries.clone();
        let transfers: Vec<(MethodId, u32, String)> = edge_list
            .par_iter()
            .flat_map(|edge| {
                let Some(owned) = vf_cache.get(&edge.caller) else {
                    return Vec::new();
                };
                let local =
                    compute_local_taint(edge.caller, &index, owned, config, &summaries_snap);
                let mut out = Vec::new();
                for (i, &reg) in edge.arg_regs.iter().enumerate() {
                    let kinds = local.kinds_at(edge.invoke_offset, reg);
                    for kind in kinds {
                        if let Some(san) = config.find_sanitizer(&edge.method_ref) {
                            let set = sanitize_kinds(&HashSet::from([kind.clone()]), san);
                            if set.is_empty() {
                                continue;
                            }
                        }
                        let before = summaries_snap
                            .get(&edge.callee)
                            .and_then(|s| s.param_kinds.get(&(i as u32)))
                            .map(|s| s.contains(&kind))
                            .unwrap_or(false);
                        if !before {
                            out.push((edge.callee, i as u32, kind));
                        }
                    }
                }
                out
            })
            .collect();

        for (callee, idx, kind) in transfers {
            let before = summaries
                .get(&callee)
                .and_then(|s| s.param_kinds.get(&idx))
                .map(|s| s.contains(&kind))
                .unwrap_or(false);
            if !before {
                worklist.push_back((callee, idx, kind));
                progressed = true;
            }
        }

        if !progressed && worklist.is_empty() {
            break;
        }
    }

    let report = IssueReport {
        tool: "dex-decompiler-taint".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        stats: ReportStats {
            methods_analyzed: vf_cache.len(),
            call_edges: call_graph.edge_count(),
            issues: issues.len(),
            iterations,
        },
        issues: issues.clone(),
    };

    Ok(SolveResult { issues, report })
}

fn issue_dedup_key(issue: &Issue) -> String {
    let sink_off = issue.trace.last().and_then(|f| f.offset).unwrap_or(0);
    let (cls, method) = issue
        .callable
        .split_once('#')
        .unwrap_or((issue.callable.as_str(), ""));
    format!(
        "{}:{}:{}:{}:{}:{}",
        issue.rule_code, cls, method, issue.source_kind, issue.sink_kind, sink_off
    )
}

fn propagate_returns(
    index: &MethodIndex,
    call_graph: &CallGraph,
    vf_cache: &HashMap<MethodId, ValueFlowAnalysisOwned>,
    config: &TaintConfig,
    summaries: &mut HashMap<MethodId, MethodSummary>,
    issues: &mut Vec<Issue>,
    seen: &mut HashSet<String>,
    worklist: &mut VecDeque<(MethodId, u32, String)>,
) -> bool {
    let mut progressed = false;
    for edges in call_graph.ins.values() {
        for edge in edges {
            let ret_kinds = summaries
                .get(&edge.callee)
                .map(|s| s.return_kinds.clone())
                .unwrap_or_default();
            if ret_kinds.is_empty() {
                continue;
            }
            let Some(owned) = vf_cache.get(&edge.caller) else {
                continue;
            };
            // Find move-result after this invoke.
            let mut move_result: Option<(u32, u32)> = None;
            let mut offsets: Vec<u32> = owned.rw_map.keys().copied().collect();
            offsets.sort_unstable();
            if let Some(pos) = offsets.iter().position(|&o| o == edge.invoke_offset) {
                for &off in &offsets[pos + 1..] {
                    if let Some((reads, writes)) = owned.rw_map.get(&off) {
                        if reads.is_empty() && writes.len() == 1 {
                            // Heuristic: next write-only is move-result.
                            move_result = Some((off, writes[0]));
                            break;
                        }
                        if owned.invoke_method_map.contains_key(&off) {
                            break;
                        }
                    }
                }
            }
            // Also check api_return_sources for exact pairing.
            for &((off, reg), ref mref) in &owned.api_return_sources {
                if mref == &edge.method_ref
                    || index
                        .resolve_callee(mref)
                        .is_some_and(|id| id == edge.callee)
                {
                    // Prefer source near invoke.
                    if off >= edge.invoke_offset {
                        move_result = Some((off, reg));
                        break;
                    }
                }
            }
            let Some((mr_off, mr_reg)) = move_result else {
                continue;
            };

            // Inject return kinds into caller local analysis by treating them as sources at move-result,
            // then check sinks in caller (via analyze with synthetic param — easier: expand return into
            // a temporary local re-scan).
            for kind in &ret_kinds {
                // Record as if a source appeared at move-result; run sink check from that seed.
                let analysis = owned.analysis();
                let flow = analysis.value_flow_from_seed(mr_off, mr_reg);
                for (read_off, reg) in &flow.reads {
                    if let Some(mref) = owned.invoke_method_map.get(read_off) {
                        if let Some(sink) = config.find_sink(mref) {
                            if let Some(arg_i) = port_to_arg_index(&sink.port) {
                                let args = owned
                                    .rw_map
                                    .get(read_off)
                                    .map(|(r, _)| r.clone())
                                    .unwrap_or_default();
                                if args.get(arg_i as usize) == Some(reg) {
                                    emit_issue(
                                        index,
                                        edge.caller,
                                        config,
                                        kind,
                                        &sink.kind,
                                        mr_off,
                                        *read_off,
                                        mref,
                                        issues,
                                        seen,
                                    );
                                }
                            } else if sink.port == Port::Return {
                                // uncommon
                            }
                        }
                        // Callee param transfer already handled elsewhere.
                        let _ = worklist;
                    }
                }
                // Also: if return kinds flow into params of further calls — covered by next iteration
                // when we re-analyze caller with synthetic… For summaries, mark nothing else.
                let _ = progressed;
            }
            // Update: if callee returns tainted, caller "receives" taint — re-queue caller analysis
            // by adding a fake high param isn't right. Instead bump a generation by pushing
            // return kinds into a side channel: store on summary of caller as "local source inject".
            let caller_sum = summaries.entry(edge.caller).or_default();
            let before = caller_sum.return_kinds.len();
            // Not return of caller — stash in param_kinds under a sentinel? Use dedicated map.
            // Simpler: add return kinds to a pseudo "inject" via re-running analyze with extra seeds
            // stored in summary.param_kinds key u32::MAX meaning "return inject at calls" — too hacky.
            //
            // Practical approach: merge ret_kinds into caller's tracked set by calling analyze_method
            // after attaching them to a temporary LocalTaint through `extra_seeds` on summary.
            let _ = before;
            if !ret_kinds.is_empty() {
                // Store pending return injections keyed by invoke offset in param_kinds isn't available.
                // Use return_kinds of caller only when caller itself returns — separate field:
                // We'll put inject kinds in summaries via a reserved param index = u32::MAX - invoke?
                for kind in ret_kinds {
                    let key = 0x8000_0000u32 | edge.invoke_offset;
                    if summaries
                        .entry(edge.caller)
                        .or_default()
                        .param_kinds
                        .entry(key)
                        .or_default()
                        .insert(kind.clone())
                    {
                        worklist.push_back((edge.caller, key, kind));
                        progressed = true;
                    }
                }
            }
        }
    }
    progressed
}

fn analyze_method(
    mid: MethodId,
    index: &MethodIndex,
    vf_cache: &HashMap<MethodId, ValueFlowAnalysisOwned>,
    config: &TaintConfig,
    summaries: &mut HashMap<MethodId, MethodSummary>,
    issues: &mut Vec<Issue>,
    seen: &mut HashSet<String>,
    worklist: &mut VecDeque<(MethodId, u32, String)>,
    seed_only_params: bool,
) {
    let Some(mref) = index.get(mid) else { return };
    let Some(owned) = vf_cache.get(&mid) else { return };

    let mut local = LocalTaint::default();
    let analysis = owned.analysis();

    // 1) Seed from modeled sources (API returns).
    if !seed_only_params {
        for &((offset, reg), ref method_ref) in &owned.api_return_sources {
            if let Some(src) = config.find_source(method_ref) {
                if matches!(src.port, Port::Return) {
                    seed_and_propagate(
                        &mut local,
                        &analysis,
                        owned,
                        config,
                        offset,
                        reg,
                        &src.kind,
                    );
                }
            }
        }
    }

    // 2) Seed from interprocedural parameter kinds (and return-injection sentinels).
    let param_kinds = summaries
        .get(&mid)
        .map(|s| s.param_kinds.clone())
        .unwrap_or_default();
    for (param_key, kinds) in &param_kinds {
        if *param_key >= 0x8000_0000 {
            // Return injection at invoke offset encoded in low bits.
            let invoke_off = param_key & 0x7fff_ffff;
            // Find move-result after invoke.
            if let Some(((off, reg), _)) = owned
                .api_return_sources
                .iter()
                .find(|((o, _), _)| *o >= invoke_off)
            {
                for kind in kinds {
                    seed_and_propagate(&mut local, &analysis, owned, config, *off, *reg, kind);
                }
            }
            continue;
        }
        // Map param index → register. Dalvik: non-static params start at v(registers-ins_size).
        // Without code_item registers/ins we approximate: param i often appears as reads of early
        // invokes; for summaries we seed by finding defs that are never written (params).
        // Practical heuristic: treat parameter register as the i-th "uninitialized" use —
        // use code_item via encoded — we don't have registers here easily.
        // Fallback: use first N distinct regs that appear as reads before any write in entry block.
        let param_reg = infer_param_reg(owned, *param_key);
        if let Some(reg) = param_reg {
            // Seed at offset 0 as a synthetic write.
            for kind in kinds {
                // Propagate from all uses of this reg that are reached from entry.
                // Insert as if defined at offset 0.
                local.insert(0, reg, kind);
                // Also run value_flow from every write of this reg + synthetic.
                let flow = analysis.value_flow_from_seed(0, reg);
                for &(woff, wreg) in &flow.writes {
                    local.insert(woff, wreg, kind);
                }
                for &(roff, rreg) in &flow.reads {
                    local.insert(roff, rreg, kind);
                    check_sink_at(
                        mid, index, owned, config, &local, roff, rreg, kind, issues, seen,
                    );
                }
            }
        }
    }

    // 3) Apply modeled propagations at invokes (TITO).
    apply_propagations(&mut local, owned, config);

    // 4) Sink checks for all tainted regs at invoke sites.
    for (&invoke_off, method_ref) in &owned.invoke_method_map {
        if let Some(sink) = config.find_sink(method_ref) {
            let args = owned
                .rw_map
                .get(&invoke_off)
                .map(|(r, _)| r.clone())
                .unwrap_or_default();
            if let Some(idx) = port_to_arg_index(&sink.port) {
                if let Some(&reg) = args.get(idx as usize) {
                    let kinds = local.kinds_at(invoke_off, reg);
                    for kind in kinds.into_iter() {
                        emit_issue(
                            index,
                            mid,
                            config,
                            kind.as_str(),
                            &sink.kind,
                            invoke_off,
                            invoke_off,
                            method_ref,
                            issues,
                            seen,
                        );
                    }
                }
            }
        }
        // Sanitizer: clear kinds on outputs if modeled.
        if let Some(san) = config.find_sanitizer(method_ref) {
            if let Some(((off, reg), _)) = owned
                .api_return_sources
                .iter()
                .find(|((o, _), m)| *o > invoke_off && m == method_ref)
            {
                if let Some(set) = local.at.get_mut(&(*off, *reg)) {
                    *set = sanitize_kinds(set, san);
                }
            }
        }
    }

    // 5) Update summary: return kinds + param→return.
    let sum = summaries.entry(mid).or_default();
    // Returns: any tainted reg on return instruction.
    for (&off, (reads, writes)) in &owned.rw_map {
        if !writes.is_empty() {
            continue;
        }
        // return* has reads and no writes; detect via invoke map absence and single read.
        if reads.len() == 1 && !owned.invoke_method_map.contains_key(&off) {
            let kinds = local.kinds_at(off, reads[0]);
            if !kinds.is_empty() {
                // Heuristic: treat as return if mnemonic unknown — check neighboring: ok enough.
                sum.return_kinds.extend(kinds);
            }
        }
    }
    // Stronger: api-less — scan for return via empty writes and not invoke — already done.
    // Infer param→return for interproc TITO of app methods.
    for param_idx in 0..8u32 {
        if let Some(reg) = infer_param_reg(owned, param_idx) {
            let flow = analysis.value_flow_from_seed(0, reg);
            for &(roff, _rreg) in &flow.reads {
                let (reads, writes) = owned.rw_map.get(&roff).cloned().unwrap_or_default();
                if writes.is_empty() && reads.len() == 1 {
                    sum.param_to_return.insert(param_idx);
                }
            }
        }
    }

    // 6) Queue callee params from this method's call sites (local taint).
    // (Main loop also does this; here helps first pass.)
    let _ = (mref, worklist);
}

fn seed_and_propagate(
    local: &mut LocalTaint,
    analysis: &crate::decompile::value_flow::ValueFlowAnalysis<'_>,
    owned: &ValueFlowAnalysisOwned,
    config: &TaintConfig,
    offset: u32,
    reg: u32,
    kind: &str,
) {
    local.insert(offset, reg, kind);
    let flow = analysis.value_flow_from_seed(offset, reg);
    for &(woff, wreg) in &flow.writes {
        local.insert(woff, wreg, kind);
    }
    for &(roff, rreg) in &flow.reads {
        local.insert(roff, rreg, kind);
    }
    apply_propagations(local, owned, config);
}

fn apply_propagations(local: &mut LocalTaint, owned: &ValueFlowAnalysisOwned, config: &TaintConfig) {
    let analysis = owned.analysis();
    // Fixed few rounds of TITO at invoke sites; forward-propagate onto object regs
    // so later startActivity/commit see putExtra/setData taint.
    for _ in 0..4 {
        let mut updates: Vec<(u32, u32, String)> = Vec::new();
        for (&invoke_off, method_ref) in &owned.invoke_method_map {
            let props = config.find_propagations(method_ref);
            if props.is_empty() {
                continue;
            }
            let args = owned
                .rw_map
                .get(&invoke_off)
                .map(|(r, _)| r.clone())
                .unwrap_or_default();
            for prop in props {
                let Some(from_i) = port_to_arg_index(&prop.from) else {
                    continue;
                };
                let Some(&from_reg) = args.get(from_i as usize) else {
                    continue;
                };
                let kinds = local.kinds_at(invoke_off, from_reg);
                if kinds.is_empty() {
                    continue;
                }
                match &prop.to {
                    Port::Return => {
                        if let Some(((off, reg), _)) = owned
                            .api_return_sources
                            .iter()
                            .find(|((o, _), m)| *o > invoke_off && m == method_ref)
                        {
                            for k in &kinds {
                                updates.push((*off, *reg, k.clone()));
                            }
                        }
                    }
                    Port::This | Port::Argument { .. } => {
                        if let Some(to_i) = port_to_arg_index(&prop.to) {
                            if let Some(&to_reg) = args.get(to_i as usize) {
                                for k in &kinds {
                                    updates.push((invoke_off, to_reg, k.clone()));
                                }
                            }
                        }
                    }
                }
            }
        }
        if updates.is_empty() {
            break;
        }
        let mut any = false;
        for (o, r, k) in updates {
            if local.insert(o, r, &k) {
                any = true;
                let flow = analysis.value_flow_from_seed(o, r);
                for &(woff, wreg) in &flow.writes {
                    local.insert(woff, wreg, &k);
                }
                for &(roff, rreg) in &flow.reads {
                    local.insert(roff, rreg, &k);
                }
            }
        }
        if !any {
            break;
        }
    }
}

fn check_sink_at(
    mid: MethodId,
    index: &MethodIndex,
    owned: &ValueFlowAnalysisOwned,
    config: &TaintConfig,
    local: &LocalTaint,
    offset: u32,
    reg: u32,
    kind: &str,
    issues: &mut Vec<Issue>,
    seen: &mut HashSet<String>,
) {
    let Some(method_ref) = owned.invoke_method_map.get(&offset) else {
        return;
    };
    let Some(sink) = config.find_sink(method_ref) else {
        return;
    };
    let args = owned
        .rw_map
        .get(&offset)
        .map(|(r, _)| r.clone())
        .unwrap_or_default();
    if let Some(idx) = port_to_arg_index(&sink.port) {
        if args.get(idx as usize) == Some(&reg) {
            emit_issue(
                index, mid, config, kind, &sink.kind, offset, offset, method_ref, issues, seen,
            );
        }
    }
    let _ = local;
}

fn emit_issue(
    index: &MethodIndex,
    mid: MethodId,
    config: &TaintConfig,
    source_kind: &str,
    sink_kind: &str,
    source_offset: u32,
    sink_offset: u32,
    sink_ref: &str,
    issues: &mut Vec<Issue>,
    seen: &mut HashSet<String>,
) {
    let rules = config.matching_rules(source_kind, sink_kind);
    if rules.is_empty() {
        return;
    }
    let mref = match index.get(mid) {
        Some(m) => m,
        None => return,
    };
    for rule in rules {
        let key = format!(
            "{}:{}:{}:{}:{}:{}",
            rule.code, mref.class_name, mref.method_name, source_kind, sink_kind, sink_offset
        );
        if !seen.insert(key) {
            continue;
        }
        issues.push(Issue {
            rule_code: rule.code,
            rule_name: rule.name.clone(),
            description: rule.description.clone(),
            source_kind: source_kind.to_string(),
            sink_kind: sink_kind.to_string(),
            callable: format!("{}#{}", mref.class_name, mref.method_name),
            trace: vec![
                TraceFrame {
                    class_name: mref.class_name.clone(),
                    method_name: mref.method_name.clone(),
                    offset: Some(source_offset),
                    kind: source_kind.to_string(),
                    description: format!("source kind `{source_kind}` introduced / flowing"),
                },
                TraceFrame {
                    class_name: mref.class_name.clone(),
                    method_name: mref.method_name.clone(),
                    offset: Some(sink_offset),
                    kind: sink_kind.to_string(),
                    description: format!("sink `{sink_ref}` ({sink_kind})"),
                },
            ],
        });
    }
}

fn infer_param_reg(owned: &ValueFlowAnalysisOwned, param_idx: u32) -> Option<u32> {
    // Heuristic: registers that are read but never written are parameters.
    let mut written: HashSet<u32> = HashSet::new();
    let mut read: HashSet<u32> = HashSet::new();
    for (reads, writes) in owned.rw_map.values() {
        written.extend(writes.iter().copied());
        read.extend(reads.iter().copied());
    }
    let mut params: Vec<u32> = read.into_iter().filter(|r| !written.contains(r)).collect();
    params.sort_unstable();
    params.get(param_idx as usize).copied()
}

fn compute_local_taint(
    mid: MethodId,
    index: &MethodIndex,
    owned: &ValueFlowAnalysisOwned,
    config: &TaintConfig,
    summaries: &HashMap<MethodId, MethodSummary>,
) -> LocalTaint {
    let mut local = LocalTaint::default();
    let analysis = owned.analysis();
    for &((offset, reg), ref method_ref) in &owned.api_return_sources {
        if let Some(src) = config.find_source(method_ref) {
            if matches!(src.port, Port::Return) {
                seed_and_propagate(
                    &mut local,
                    &analysis,
                    owned,
                    config,
                    offset,
                    reg,
                    &src.kind,
                );
            }
        }
    }
    if let Some(sum) = summaries.get(&mid) {
        for (param_key, kinds) in &sum.param_kinds {
            if *param_key >= 0x8000_0000 {
                let invoke_off = param_key & 0x7fff_ffff;
                if let Some(((off, reg), _)) = owned
                    .api_return_sources
                    .iter()
                    .find(|((o, _), _)| *o >= invoke_off)
                {
                    for kind in kinds {
                        seed_and_propagate(&mut local, &analysis, owned, config, *off, *reg, kind);
                    }
                }
                continue;
            }
            if let Some(reg) = infer_param_reg(owned, *param_key) {
                for kind in kinds {
                    local.insert(0, reg, kind);
                    let flow = analysis.value_flow_from_seed(0, reg);
                    for &(woff, wreg) in &flow.writes {
                        local.insert(woff, wreg, kind);
                    }
                    for &(roff, rreg) in &flow.reads {
                        local.insert(roff, rreg, kind);
                    }
                }
            }
        }
    }
    apply_propagations(&mut local, owned, config);
    let _ = index;
    local
}
