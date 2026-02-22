//! Pass framework (jadx visitors equivalent).
//!
//! Passes transform method IR (`Vec<IrStmt>`) in sequence. Built-in passes handle
//! invoke+move-result+return folding and similar patterns.

use crate::decompile::ir::{Expr as IrExpr, Stmt as IrStmt};
use crate::decompile::ir::VarId;
use std::collections::{HashMap, HashSet};

/// A single transformation pass over method IR.
pub trait Pass {
    /// Transform the statement list; may replace, remove, or add statements.
    fn run(&self, stmts: Vec<IrStmt>) -> Vec<IrStmt>;
}

/// Runs a sequence of passes in order (jadx-style pipeline).
#[derive(Default)]
pub struct PassRunner {
    passes: Vec<Box<dyn Pass + Send>>,
}

impl PassRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pass to the pipeline (runs after previously added passes).
    pub fn add<P: Pass + Send + 'static>(&mut self, pass: P) {
        self.passes.push(Box::new(pass));
    }

    /// Run all passes in order on the given IR.
    pub fn run(&self, stmts: Vec<IrStmt>) -> Vec<IrStmt> {
        let mut current = stmts;
        for pass in &self.passes {
            current = pass.run(current);
        }
        current
    }
}

/// Merges invoke + move-result + return into single statements:
/// - `Expr(Call)` + `Assign(reg, PendingResult)` → `Assign(reg, Call)`
/// - `Assign(reg, Call)` + `Return(Var(reg))` → `Return(Call)`
/// - `Expr(Call)` + `Return(None)` → left as-is (call; return;)
#[derive(Debug, Clone, Copy, Default)]
pub struct InvokeChainPass;

impl Pass for InvokeChainPass {
    fn run(&self, stmts: Vec<IrStmt>) -> Vec<IrStmt> {
        let mut out: Vec<IrStmt> = Vec::with_capacity(stmts.len());
        let mut i = 0usize;
        while i < stmts.len() {
            // Try: Expr(Call) + Assign(reg, PendingResult) + Return(Var(reg)) → Return(Call)
            if i + 2 < stmts.len() {
                if let (
                    IrStmt::Expr { expr: IrExpr::Call { target, args }, comment: c1 },
                    IrStmt::Assign { dst, rhs: IrExpr::PendingResult, comment: c2 },
                    IrStmt::Return { value: Some(IrExpr::Var(ret_reg)), comment: c3 },
                ) = (&stmts[i], &stmts[i + 1], &stmts[i + 2])
                {
                    if dst == ret_reg {
                        let comment = merge_comment(c1.as_deref(), merge_comment(c2.as_deref(), c3.as_deref()).as_deref());
                        out.push(IrStmt::Return {
                            value: Some(IrExpr::Call { target: target.clone(), args: args.clone() }),
                            comment,
                        });
                        i += 3;
                        continue;
                    }
                }
            }

            // Try: Expr(Call) + Assign(reg, PendingResult) → Assign(reg, Call)
            if i + 1 < stmts.len() {
                if let (IrStmt::Expr { expr: IrExpr::Call { target, args }, comment: c1 }, IrStmt::Assign { dst, rhs: IrExpr::PendingResult, comment: c2 }) = (&stmts[i], &stmts[i + 1]) {
                    let comment = merge_comment(c1.as_deref(), c2.as_deref());
                    out.push(IrStmt::Assign {
                        dst: *dst,
                        rhs: IrExpr::Call { target: target.clone(), args: args.clone() },
                        comment,
                    });
                    i += 2;
                    continue;
                }
            }

            // Try: Assign(reg, Call) + Return(Var(reg)) → Return(Call)
            if i + 1 < stmts.len() {
                if let (IrStmt::Assign { dst, rhs: IrExpr::Call { target, args }, comment: c1 }, IrStmt::Return { value: Some(IrExpr::Var(ret_reg)), comment: c2 }) = (&stmts[i], &stmts[i + 1]) {
                    if dst == ret_reg {
                        let comment = merge_comment(c1.as_deref(), c2.as_deref());
                        out.push(IrStmt::Return {
                            value: Some(IrExpr::Call { target: target.clone(), args: args.clone() }),
                            comment,
                        });
                        i += 2;
                        continue;
                    }
                }
            }

            out.push(stmts[i].clone());
            i += 1;
        }
        out
    }
}

fn merge_comment(a: Option<&str>, b: Option<&str>) -> Option<String> {
    match (a, b) {
        (None, None) => None,
        (Some(x), None) | (None, Some(x)) => Some(x.to_string()),
        (Some(x), Some(y)) => Some(format!("{} | {}", x, y)),
    }
}

/// Identity pass: returns IR unchanged (useful for testing or default pipeline).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IdentityPass;

impl Pass for IdentityPass {
    fn run(&self, stmts: Vec<IrStmt>) -> Vec<IrStmt> {
        stmts
    }
}

/// Removes assigns whose destination is never used (dead store elimination).
/// When run per-block, only sees uses in that block; use `run_with_used_regs` when
/// emitting CFG so assigns used in other blocks are not removed.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeadAssignPass;

impl Pass for DeadAssignPass {
    fn run(&self, stmts: Vec<IrStmt>) -> Vec<IrStmt> {
        let used = used_var_ids(&stmts);
        stmts
            .into_iter()
            .filter(|s| {
                if let IrStmt::Assign { dst, .. } = s {
                    used.contains(dst)
                } else {
                    true
                }
            })
            .collect()
    }
}

/// Dead-assign using a precomputed set of used *register numbers* (not VarId).
/// Keeps Assign if dst.reg is in used_regs. Use when emitting CFG so assigns
/// whose destination is used in other blocks are not removed.
pub fn run_dead_assign_with_used_regs(
    stmts: Vec<IrStmt>,
    used_regs: &HashSet<u32>,
) -> Vec<IrStmt> {
    stmts
        .into_iter()
        .filter(|s| {
            if let IrStmt::Assign { dst, .. } = s {
                used_regs.contains(&dst.reg)
            } else {
                true
            }
        })
        .collect()
}

/// Collect all register numbers that are read (used) in the IR.
pub fn used_regs(stmts: &[IrStmt]) -> HashSet<u32> {
    used_var_ids(stmts).iter().map(|v| v.reg).collect()
}

/// Collect all VarIds that are read (used) in the IR (in RHS, Return, Expr).
/// Includes VarIds mentioned in Raw strings and Call args so dead-assign doesn't remove defs that are only used there.
fn used_var_ids(stmts: &[IrStmt]) -> HashSet<VarId> {
    let mut set = HashSet::new();
    for s in stmts {
        match s {
            IrStmt::Assign { rhs, .. } => collect_var_ids_expr(rhs, &mut set),
            IrStmt::Expr { expr, .. } => collect_var_ids_expr(expr, &mut set),
            IrStmt::Return { value: Some(e), .. } => collect_var_ids_expr(e, &mut set),
            IrStmt::Return { value: None, .. } | IrStmt::Raw(_) => {}
        }
    }
    set
}

fn collect_var_ids_expr(expr: &IrExpr, set: &mut HashSet<VarId>) {
    match expr {
        IrExpr::Var(v) => {
            set.insert(*v);
        }
        IrExpr::Call { args, .. } => var_ids_in_text(args, set),
        IrExpr::PendingResult => {}
        IrExpr::Raw(s) => var_ids_in_text(s, set),
    }
}

/// Collect all VarIds mentioned in text (vN or vN_k).
fn var_ids_in_text(s: &str, set: &mut HashSet<VarId>) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'v' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            i += 1;
            let mut reg: u32 = 0;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                reg = reg * 10 + (bytes[i] - b'0') as u32;
                i += 1;
            }
            let ver = if i + 1 < bytes.len() && bytes[i] == b'_' && bytes[i + 1].is_ascii_digit() {
                i += 1;
                let mut v: u32 = 0;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    v = v * 10 + (bytes[i] - b'0') as u32;
                    i += 1;
                }
                v
            } else {
                0
            };
            set.insert(VarId::new(reg, ver));
            continue;
        }
        i += 1;
    }
}

/// Linear SSA renaming (no phi insertion yet).
///
/// - Every `Stmt::Assign { dst: VarId { reg, .. }, .. }` becomes a new SSA version for that reg.
/// - All `Expr::Var` uses are rewritten to the current version at that point.
/// - `Expr::Call.args`, `Expr::Raw`, and `Stmt::Raw` get textual `vN` rewrites to `vN_k`
///   using the current version map (best-effort; does not create new defs from raw text).
#[derive(Debug, Clone, Copy, Default)]
pub struct SsaRenamePass;

impl Pass for SsaRenamePass {
    fn run(&self, stmts: Vec<IrStmt>) -> Vec<IrStmt> {
        let mut next_ver: HashMap<u32, u32> = HashMap::new();
        let mut cur_ver: HashMap<u32, u32> = HashMap::new();

        let mut out = Vec::with_capacity(stmts.len());
        for stmt in stmts {
            match stmt {
                IrStmt::Assign { mut dst, rhs, comment } => {
                    let rhs = rename_expr(rhs, &cur_ver);
                    let v = next_ver.entry(dst.reg).or_insert(0);
                    *v += 1;
                    dst.ver = *v;
                    cur_ver.insert(dst.reg, dst.ver);
                    out.push(IrStmt::Assign { dst, rhs, comment });
                }
                IrStmt::Expr { expr, comment } => {
                    out.push(IrStmt::Expr { expr: rename_expr(expr, &cur_ver), comment });
                }
                IrStmt::Return { value, comment } => {
                    let value = value.map(|e| rename_expr(e, &cur_ver));
                    out.push(IrStmt::Return { value, comment });
                }
                IrStmt::Raw(s) => out.push(IrStmt::Raw(rename_vars_in_text(&s, &cur_ver))),
            }
        }
        out
    }
}

fn rename_expr(expr: IrExpr, cur_ver: &HashMap<u32, u32>) -> IrExpr {
    match expr {
        IrExpr::Var(v) => IrExpr::Var(rename_var(v, cur_ver)),
        IrExpr::Call { target, args } => IrExpr::Call { target, args: rename_vars_in_text(&args, cur_ver) },
        IrExpr::PendingResult => IrExpr::PendingResult,
        IrExpr::Raw(s) => IrExpr::Raw(rename_vars_in_text(&s, cur_ver)),
    }
}

fn rename_var(v: VarId, cur_ver: &HashMap<u32, u32>) -> VarId {
    let ver = cur_ver.get(&v.reg).copied().unwrap_or(0);
    VarId::new(v.reg, ver)
}

/// Best-effort text rewrite: `vN` -> `vN_k` if current version for N is k>0.
/// Leaves already-versioned `vN_k` unchanged.
fn rename_vars_in_text(s: &str, cur_ver: &HashMap<u32, u32>) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'v' {
            // Ensure word boundary-ish: previous char not [A-Za-z0-9_]
            if i > 0 {
                let p = bytes[i - 1] as char;
                if p.is_ascii_alphanumeric() || p == '_' {
                    out.push('v');
                    i += 1;
                    continue;
                }
            }
            let mut j = i + 1;
            if j >= bytes.len() || !((bytes[j] as char).is_ascii_digit()) {
                out.push('v');
                i += 1;
                continue;
            }
            while j < bytes.len() && ((bytes[j] as char).is_ascii_digit()) {
                j += 1;
            }
            // If already versioned, keep as-is.
            if j < bytes.len() && bytes[j] == b'_' {
                out.push_str(&s[i..j]);
                // consume '_' and following digits
                let mut k = j + 1;
                while k < bytes.len() && ((bytes[k] as char).is_ascii_digit()) {
                    k += 1;
                }
                out.push_str(&s[j..k]);
                i = k;
                continue;
            }
            let reg: u32 = s[i + 1..j].parse().unwrap_or(0);
            let ver = cur_ver.get(&reg).copied().unwrap_or(0);
            if ver == 0 {
                out.push_str(&s[i..j]);
            } else {
                out.push_str(&format!("v{}_{}", reg, ver));
            }
            i = j;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Merge `new Foo()` + `receiver.<init>(args)` → `new Foo(args)`, and remove the bare `<init>` call.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConstructorMergePass;

impl Pass for ConstructorMergePass {
    fn run(&self, stmts: Vec<IrStmt>) -> Vec<IrStmt> {
        let mut out: Vec<IrStmt> = Vec::with_capacity(stmts.len());
        let mut i = 0;
        while i < stmts.len() {
            // Pattern: Assign(dst, Raw("new Foo()")) + Expr(Call { target: "dst.<init>", args })
            if i + 1 < stmts.len() {
                if let IrStmt::Assign { dst, rhs: IrExpr::Raw(raw), comment } = &stmts[i] {
                    if let Some(class_name) = raw.strip_prefix("new ").and_then(|s| s.strip_suffix("()")) {
                        let dst_name = if dst.ver == 0 {
                            format!("v{}", dst.reg)
                        } else {
                            format!("v{}_{}", dst.reg, dst.ver)
                        };
                        if let IrStmt::Expr { expr: IrExpr::Call { target, args }, comment: c2 } = &stmts[i + 1] {
                            if target == &format!("{}.<init>", dst_name) {
                                let merged_comment = merge_comment(comment.as_deref(), c2.as_deref());
                                out.push(IrStmt::Assign {
                                    dst: *dst,
                                    rhs: IrExpr::Raw(format!("new {}({})", class_name, args)),
                                    comment: merged_comment,
                                });
                                i += 2;
                                continue;
                            }
                        }
                    }
                }
            }
            out.push(stmts[i].clone());
            i += 1;
        }
        out
    }
}

/// Expression simplification: `v0 = v0 + 1` → `v0++`, `v0 = v0 + x` → `v0 += x`.
/// Also simplifies assignments where dst == src (self-assign after copy-prop).
#[derive(Debug, Clone, Copy, Default)]
pub struct ExprSimplifyPass;

impl Pass for ExprSimplifyPass {
    fn run(&self, stmts: Vec<IrStmt>) -> Vec<IrStmt> {
        stmts
            .into_iter()
            .map(|s| match &s {
                IrStmt::Assign {
                    dst,
                    rhs: IrExpr::Raw(raw),
                    comment,
                } => {
                    if let Some(simplified) = simplify_compound_assign(*dst, raw) {
                        IrStmt::Assign {
                            dst: *dst,
                            rhs: IrExpr::Raw(simplified),
                            comment: comment.clone(),
                        }
                    } else {
                        s
                    }
                }
                _ => s,
            })
            .collect()
    }
}

/// Try to simplify `v0 = v0 + 1` → compound assign. Returns the new RHS string.
fn simplify_compound_assign(dst: VarId, raw: &str) -> Option<String> {
    let raw = raw.trim();
    let dst_name = if dst.ver == 0 {
        format!("v{}", dst.reg)
    } else {
        format!("v{}_{}", dst.reg, dst.ver)
    };
    for op in &["+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", ">>>"] {
        // Pattern: "vN op expr" where vN is the dst
        let prefix = format!("{} {} ", dst_name, op);
        if raw.starts_with(&prefix) {
            let rhs_part = raw[prefix.len()..].trim();
            if rhs_part == "1" && (*op == "+" || *op == "-") {
                return Some(format!("__compound_{}{}_{}", dst_name, op, op));
            }
            return Some(format!("__compound_{} {}= {}", dst_name, op, rhs_part));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::ir::{Expr as IrExpr, Stmt as IrStmt, VarId};

    #[test]
    fn invoke_chain_merge_assign_then_return() {
        let stmts = vec![
            IrStmt::Expr {
                expr: IrExpr::Call { target: "Foo.bar".into(), args: "v0".into() },
                comment: Some("invoke".into()),
            },
            IrStmt::Assign {
                dst: VarId::new(1, 0),
                rhs: IrExpr::PendingResult,
                comment: Some("move-result".into()),
            },
            IrStmt::Return {
                value: Some(IrExpr::Var(VarId::new(1, 0))),
                comment: Some("return".into()),
            },
        ];
        let out = InvokeChainPass.run(stmts);
        assert_eq!(out.len(), 1);
        match &out[0] {
            IrStmt::Return { value: Some(IrExpr::Call { target, args }), .. } => {
                assert_eq!(target, "Foo.bar");
                assert_eq!(args, "v0");
            }
            _ => panic!("expected single Return(Call), got {:?}", out),
        }
    }

    #[test]
    fn invoke_chain_merge_assign_only() {
        let stmts = vec![
            IrStmt::Expr {
                expr: IrExpr::Call { target: "Baz.qux".into(), args: "v2, v3".into() },
                comment: None,
            },
            IrStmt::Assign {
                dst: VarId::new(0, 0),
                rhs: IrExpr::PendingResult,
                comment: None,
            },
        ];
        let out = InvokeChainPass.run(stmts);
        assert_eq!(out.len(), 1);
        match &out[0] {
            IrStmt::Assign { dst, rhs: IrExpr::Call { target, args }, .. } if *dst == VarId::new(0, 0) => {
                assert_eq!(target, "Baz.qux");
                assert_eq!(args, "v2, v3");
            }
            _ => panic!("expected single Assign(Call), got {:?}", out),
        }
    }

    #[test]
    fn runner_runs_passes_in_order() {
        let mut runner = PassRunner::new();
        runner.add(InvokeChainPass);
        let stmts = vec![
            IrStmt::Expr {
                expr: IrExpr::Call { target: "X.y".into(), args: "".into() },
                comment: None,
            },
            IrStmt::Assign { dst: VarId::new(0, 0), rhs: IrExpr::PendingResult, comment: None },
            IrStmt::Return { value: Some(IrExpr::Var(VarId::new(0, 0))), comment: None },
        ];
        let out = runner.run(stmts);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn ssa_renames_defs_and_uses_linearly() {
        let stmts = vec![
            IrStmt::Assign { dst: VarId::new(0, 0), rhs: IrExpr::Raw("0".into()), comment: None },
            IrStmt::Assign { dst: VarId::new(0, 0), rhs: IrExpr::Var(VarId::new(0, 0)), comment: None },
            IrStmt::Return { value: Some(IrExpr::Var(VarId::new(0, 0))), comment: None },
        ];
        let out = SsaRenamePass.run(stmts);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].to_java_line(), "v0_1 = 0;");
        assert_eq!(out[1].to_java_line(), "v0_2 = v0_1;");
        assert_eq!(out[2].to_java_line(), "return v0_2;");
    }

    #[test]
    fn dead_assign_removes_unused() {
        let stmts = vec![
            IrStmt::Assign { dst: VarId::new(0, 1), rhs: IrExpr::Raw("0".into()), comment: None },
            IrStmt::Assign { dst: VarId::new(0, 2), rhs: IrExpr::Raw("1".into()), comment: None },
            IrStmt::Return { value: Some(IrExpr::Var(VarId::new(0, 2))), comment: None },
        ];
        let out = DeadAssignPass.run(stmts);
        assert_eq!(out.len(), 2, "first assign (v0_1) is dead, should be removed");
        match &out[0] {
            IrStmt::Assign { dst, rhs: IrExpr::Raw(s), .. } => {
                assert_eq!(dst.ver, 2);
                assert_eq!(s, "1");
            }
            _ => panic!("expected assign then return"),
        }
        assert!(matches!(out[1], IrStmt::Return { .. }));
    }
}
