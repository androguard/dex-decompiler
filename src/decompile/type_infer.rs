//! Type inference for method IR: seed from params and return, propagate from Assign(Var), Assign(Call), and Raw literals.

use dex_parser::{CodeItem, DexFile, EncodedMethod};
use crate::decompile::ir::{Expr as IrExpr, Stmt as IrStmt, VarId};
use crate::java;
use std::collections::HashMap;

/// Infer Java type names for SSA variables from method signature and IR.
/// - Seeds reg 0..ins_size-1 from method params (and this for instance methods).
/// - Seeds the return variable with the method return type (if not void).
/// - Propagates: Assign(dst, Var(src)), Assign(dst, Call), Assign(dst, Raw(s)) with literal or first var's type.
pub fn infer_types(
    dex: &DexFile,
    encoded: &EncodedMethod,
    code: &CodeItem,
    stmts: &[IrStmt],
) -> HashMap<VarId, String> {
    let mut types: HashMap<VarId, String> = HashMap::new();
    let info = match dex.get_method_info(encoded.method_idx) {
        Ok(i) => i,
        Err(_) => return types,
    };
    let find_method_return_type_java = |target: &str, num_args: usize| -> Option<String> {
        let n = dex.header.method_ids_size as usize;
        for idx in 0..n {
            if let Ok(mi) = dex.get_method_info(idx as u32) {
                let key = format!("{}.{}", java::descriptor_to_java(&mi.class), mi.name);
                if key == target && mi.params.len() == num_args {
                    return Some(java::descriptor_to_java(&mi.return_type));
                }
            }
        }
        None
    };
    let ins_size = code.ins_size as u32;
    let is_static = (encoded.access_flags & 0x8) != 0;
    let class_java = java::descriptor_to_java(&info.class);
    let param_types: Vec<String> = info.params.iter().map(|p| java::descriptor_to_java(p)).collect();
    let return_type_java = java::descriptor_to_java(&info.return_type);

    // Seed param registers (version 0).
    for reg in 0..ins_size {
        let vid = VarId::new(reg, 0);
        if !is_static && reg == 0 {
            types.insert(vid, class_java.clone());
        } else {
            let param_idx = if is_static { reg as usize } else { (reg as usize).saturating_sub(1) };
            if param_idx < param_types.len() {
                types.insert(vid, param_types[param_idx].clone());
            }
        }
    }

    // Seed return variable with method return type (so e.g. "result" gets "int").
    if return_type_java != "void" {
        if let Some(return_var) = stmts.iter().find_map(|s| {
            if let IrStmt::Return { value: Some(IrExpr::Var(v)), .. } = s {
                Some(*v)
            } else {
                None
            }
        }) {
            types.insert(return_var, return_type_java.clone());
        }
    }

    // Propagate: Assign(dst, rhs) from Var, Call, or Raw (literal / first var in text). Fixpoint.
    let max_iters = stmts.len().saturating_mul(2).max(4);
    for _ in 0..max_iters {
        let mut changed = false;
        for stmt in stmts {
            if let IrStmt::Assign { dst, rhs, .. } = stmt {
                if types.contains_key(dst) {
                    continue;
                }
                let ty = match rhs {
                    IrExpr::Var(v) => types.get(v).cloned(),
                IrExpr::Call { target, args } => {
                    let n = count_args(args);
                    find_method_return_type_java(target, n)
                        .or_else(|| {
                            // receiver-style: "v0.method" -> reconstruct "Class.method" from receiver type
                            if let Some(dot) = target.rfind('.') {
                                let receiver_part = &target[..dot];
                                if let Some(vid) = parse_var_id(receiver_part) {
                                    if let Some(class) = types.get(&vid) {
                                        let method = &target[dot + 1..];
                                        let fq = format!("{}.{}", class, method);
                                        return find_method_return_type_java(&fq, n);
                                    }
                                }
                            }
                            None
                        })
                }
                    IrExpr::Raw(s) => infer_type_from_raw(s, &types),
                    IrExpr::PendingResult => None,
                };
                if let Some(t) = ty {
                    types.insert(*dst, t);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    types
}

/// Infer type from Raw RHS: string literal, new-array "new Type[size]", new-instance, literal, or first variable reference's type.
fn infer_type_from_raw(s: &str, types: &HashMap<VarId, String>) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.starts_with("new ") {
        // new-array: "new Type[size]" or "new boolean[v0]" -> array type
        if let Some(bracket) = s.find('[') {
            let element_and_brackets = s[4..bracket].trim();
            if !element_and_brackets.is_empty() {
                let ty = element_and_brackets.to_string();
                return Some(if ty.ends_with(']') { ty } else { format!("{}[]", ty) });
            }
        }
        // new-instance: "new Foo()" or "new Foo(args)" -> type is Foo
        if let Some(paren) = s.find('(') {
            let class = s[4..paren].trim();
            if !class.is_empty() {
                return Some(class.to_string());
            }
        }
    }
    // check-cast: "(Type) expr" -> type is Type
    if s.starts_with('(') {
        if let Some(close) = s.find(") ") {
            let ty = s[1..close].trim();
            if !ty.is_empty() && ty.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                return Some(ty.to_string());
            }
        }
    }
    // Java string literal (starts and ends with ")
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        return Some("java.lang.String".to_string());
    }
    // Integer literal (optional minus, digits, optional L)
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && b[i] == b'-' {
        i += 1;
    }
    if i < b.len() && b[i].is_ascii_digit() {
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i < b.len() && (b[i] == b'L' || b[i] == b'l') {
            return Some("long".to_string());
        }
        if i == b.len() || b[i] == b' ' || b[i] == b';' {
            return Some("int".to_string());
        }
        if i < b.len() && b[i] == b'.' {
            // float/double
            i += 1;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'f' || b[i] == b'F') {
                return Some("float".to_string());
            }
            return Some("double".to_string());
        }
        if i < b.len() && (b[i] == b'f' || b[i] == b'F') {
            return Some("float".to_string());
        }
    }
    // First variable reference (vN or vN_k) in the string
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'v' && i + 1 < b.len() && b[i + 1].is_ascii_digit() {
            i += 1;
            let mut reg: u32 = 0;
            while i < b.len() && b[i].is_ascii_digit() {
                reg = reg * 10 + (b[i] - b'0') as u32;
                i += 1;
            }
            let ver = if i + 1 < b.len() && b[i] == b'_' && b[i + 1].is_ascii_digit() {
                i += 1;
                let mut v: u32 = 0;
                while i < b.len() && b[i].is_ascii_digit() {
                    v = v * 10 + (b[i] - b'0') as u32;
                    i += 1;
                }
                v
            } else {
                0
            };
            let vid = VarId::new(reg, ver);
            if let Some(t) = types.get(&vid) {
                return Some(t.clone());
            }
            continue;
        }
        i += 1;
    }
    // Integer literal or binary op with literal (e.g. "v3 + 66", "v1_1 & 26") -> assume int
    if s.chars().any(|c| c.is_ascii_digit()) && s.chars().any(|c| "+-*/%&|^<>".contains(c)) {
        return Some("int".to_string());
    }
    None
}

/// Semantic role for a variable (array base, index, length) to improve naming.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticRole {
    /// Variable used as array in aget/aput (e.g. v1 in v1[v2]).
    Array,
    /// Variable used as index in aget/aput (e.g. v2 in v1[v2]). Prefer name "i" or "j".
    Index,
    /// Variable holding result of array-length. Prefer name "length" or "size".
    Length,
}

/// Detect semantic roles from Raw IR strings: "v0 = v1[v2];" -> v1=Array, v2=Index; "v0 = v1.length;" -> v1=Array, v0=Length.
fn collect_semantic_roles(stmts: &[IrStmt]) -> HashMap<VarId, SemanticRole> {
    let mut roles = HashMap::new();
    for s in stmts {
        let (assign_dst, raw) = match s {
            IrStmt::Assign { dst, rhs: IrExpr::Raw(r), .. } => (Some(*dst), r.as_str()),
            IrStmt::Raw(r) => (None, r.as_str()),
            _ => continue,
        };
        // "vN = vM[vK];" or "vM[vK] = vN;" or "vN = vM.length;"
        if let Some(bracket) = raw.find('[') {
            if let Some(close) = raw.find(']') {
                if close > bracket {
                    if let Some(array_id) = var_immediately_before(raw, bracket) {
                        roles.insert(array_id, SemanticRole::Array);
                    }
                    if let Some(index_id) = var_between(raw, bracket + 1, close) {
                        roles.insert(index_id, SemanticRole::Index);
                    }
                }
            }
        }
        if raw.contains(".length") {
            if let Some(dot) = raw.find(".length") {
                if let Some(array_id) = var_immediately_before(raw, dot) {
                    roles.insert(array_id, SemanticRole::Array);
                }
                if let Some(dst) = assign_dst {
                    roles.insert(dst, SemanticRole::Length);
                }
            }
        }
    }
    roles
}

/// VarId that ends immediately before position `pos` (e.g. the var before '[' or '.').
fn var_immediately_before(s: &str, pos: usize) -> Option<VarId> {
    let before = s.get(..pos).unwrap_or("").trim_end();
    if before.is_empty() {
        return None;
    }
    let b = before.as_bytes();
    let mut end = before.len();
    while end > 0 && (b[end - 1].is_ascii_digit() || b[end - 1] == b'_') {
        end -= 1;
    }
    if end > 0 && b[end - 1] == b'v' {
        parse_var_id(&before[end - 1..])
    } else {
        None
    }
}

/// First VarId in s[start..end].
fn var_between(s: &str, start: usize, end: usize) -> Option<VarId> {
    let sub = s.get(start..end).unwrap_or("").trim();
    let mut i = 0;
    while i < sub.len() {
        if sub.as_bytes().get(i).map(|&b| b == b'v').unwrap_or(false) {
            if let Some(v) = var_id_at_start(&sub[i..]) {
                return Some(v);
            }
        }
        i += 1;
    }
    None
}

fn var_id_at_start(s: &str) -> Option<VarId> {
    parse_var_id(s)
}

fn parse_var_id(s: &str) -> Option<VarId> {
    let s = s.trim_start();
    if !s.starts_with('v') {
        return None;
    }
    let b = s.as_bytes();
    let mut i = 1;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == 1 {
        return None;
    }
    let reg: u32 = s[1..i].parse().ok()?;
    let ver = if i < b.len() && b[i] == b'_' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        s[start..i].parse().ok().unwrap_or(0)
    } else {
        0
    };
    Some(VarId::new(reg, ver))
}

/// Build a display name for each variable: "result" for return value, "this"/"p0"/"p1" for params, semantic (array/index/length) or type-based.
#[cfg(test)]
fn build_var_names(
    stmts: &[IrStmt],
    type_map: &HashMap<VarId, String>,
    ins_size: u32,
    is_static: bool,
) -> HashMap<VarId, String> {
    build_var_names_with_regs(stmts, type_map, ins_size, ins_size, is_static)
}

pub fn build_var_names_with_regs(
    stmts: &[IrStmt],
    type_map: &HashMap<VarId, String>,
    registers_size: u32,
    ins_size: u32,
    is_static: bool,
) -> HashMap<VarId, String> {
    let return_var = stmts.iter().find_map(|s| {
        if let IrStmt::Return { value: Some(IrExpr::Var(v)), .. } = s {
            Some(*v)
        } else {
            None
        }
    });
    let roles = collect_semantic_roles(stmts);
    let mut names = HashMap::new();
    let mut counters: HashMap<&'static str, u32> = HashMap::new();
    let mut index_counter = 0u32;
    let param_base = registers_size.saturating_sub(ins_size);
    for s in stmts {
        let (def, uses) = match s {
            IrStmt::Assign { dst, rhs, .. } => {
                let uses = var_ids_in_expr(rhs);
                (Some(*dst), uses)
            }
            IrStmt::Expr { expr, .. } => (None, var_ids_in_expr(expr)),
            IrStmt::Return { value: Some(e), .. } => (None, var_ids_in_expr(e)),
            IrStmt::Return { value: None, .. } => (None, vec![]),
            IrStmt::Raw(text) => (None, var_ids_in_text(text)),
        };
        for v in &uses {
            if !names.contains_key(v) {
                names.insert(*v, name_for_var(*v, type_map, return_var, param_base, ins_size, is_static, &roles, &mut counters, &mut index_counter));
            }
        }
        if let Some(d) = def {
            if !names.contains_key(&d) {
                names.insert(d, name_for_var(d, type_map, return_var, param_base, ins_size, is_static, &roles, &mut counters, &mut index_counter));
            }
        }
    }
    names
}

fn var_ids_in_expr(expr: &IrExpr) -> Vec<VarId> {
    match expr {
        IrExpr::Var(v) => vec![*v],
        IrExpr::Call { args, .. } => var_ids_in_text(args),
        IrExpr::PendingResult => vec![],
        IrExpr::Raw(s) => var_ids_in_text(s),
    }
}

/// Collect all VarIds mentioned in text (vN or vN_k).
fn var_ids_in_text(s: &str) -> Vec<VarId> {
    let mut out = Vec::new();
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
            out.push(VarId::new(reg, ver));
            continue;
        }
        i += 1;
    }
    out
}

fn name_for_var(
    v: VarId,
    type_map: &HashMap<VarId, String>,
    return_var: Option<VarId>,
    param_base: u32,
    ins_size: u32,
    is_static: bool,
    roles: &HashMap<VarId, SemanticRole>,
    counters: &mut HashMap<&'static str, u32>,
    index_counter: &mut u32,
) -> String {
    if return_var == Some(v) {
        return "result".to_string();
    }
    // Parameter registers: version 0, reg in [param_base, param_base + ins_size).
    // In Dalvik, parameters occupy the highest registers: v(registers_size - ins_size) .. v(registers_size - 1).
    if v.ver == 0 && ins_size > 0 && v.reg >= param_base && v.reg < param_base + ins_size {
        let param_offset = v.reg - param_base;
        if !is_static && param_offset == 0 {
            return "this".to_string();
        }
        let param_idx = if is_static { param_offset } else { param_offset.saturating_sub(1) };
        return format!("p{}", param_idx);
    }
    if let Some(role) = roles.get(&v) {
        match role {
            SemanticRole::Index => {
                let names = ["i", "j", "k"];
                let idx = (*index_counter as usize).min(names.len() - 1);
                *index_counter = index_counter.saturating_add(1);
                return names[idx].to_string();
            }
            SemanticRole::Length => return "length".to_string(),
            SemanticRole::Array => {
                let c = counters.entry("arr").or_insert(0);
                let name = format!("arr{}", *c);
                *c += 1;
                return name;
            }
        }
    }
    let prefix = type_map.get(&v).map(|t| type_prefix(t)).unwrap_or("local");
    let c = counters.entry(prefix).or_insert(0);
    let name = format!("{}{}", prefix, *c);
    *c += 1;
    name
}

fn type_prefix(ty: &str) -> &'static str {
    match ty {
        "int" | "short" | "byte" => "n",
        "boolean" => "z",
        "long" => "j",
        "java.lang.String" | "String" => "str",
        "float" => "f",
        "double" => "d",
        "char" => "c",
        "java.lang.Object" | "Object" => "obj",
        "java.lang.StringBuilder" | "StringBuilder" => "sb",
        "android.content.Intent" | "Intent" => "intent",
        "android.os.Bundle" | "Bundle" => "bundle",
        "android.content.Context" | "Context" => "context",
        "android.view.View" | "View" => "view",
        _ if ty.ends_with("[]") => "arr",
        _ if ty.ends_with("Exception") => "e",
        _ if ty.ends_with("List") => "list",
        _ if ty.ends_with("Map") => "map",
        _ if ty.ends_with("Set") => "set",
        _ => "v",
    }
}

fn count_args(args: &str) -> usize {
    let s = args.trim();
    if s.is_empty() {
        return 0;
    }
    s.split(',').filter(|p| !p.trim().is_empty()).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_args_empty() {
        assert_eq!(count_args(""), 0);
        assert_eq!(count_args("   "), 0);
    }

    #[test]
    fn count_args_one_or_more() {
        assert_eq!(count_args("v0"), 1);
        assert_eq!(count_args("v0, v1"), 2);
        assert_eq!(count_args(" v0 , v1 "), 2);
    }

    #[test]
    fn build_var_names_result_and_typed() {
        use crate::decompile::ir::{Expr as IrExpr, Stmt as IrStmt, VarId};
        let stmts = vec![
            IrStmt::Assign {
                dst: VarId::new(0, 1),
                rhs: IrExpr::Raw("0".into()),
                comment: None,
            },
            IrStmt::Return {
                value: Some(IrExpr::Var(VarId::new(0, 1))),
                comment: None,
            },
        ];
        let mut type_map = std::collections::HashMap::new();
        type_map.insert(VarId::new(0, 1), "int".into());
        let names = build_var_names(&stmts, &type_map, 0, true);
        assert_eq!(names.get(&VarId::new(0, 1)), Some(&"result".to_string()));
    }

    #[test]
    fn build_var_names_semantic_array_index_length() {
        use crate::decompile::ir::{Expr as IrExpr, Stmt as IrStmt, VarId};
        // Raw as after SSA: v0_1 = v1_0[v2_0]; -> array v1_0, index v2_0
        let stmts = vec![
            IrStmt::Assign {
                dst: VarId::new(0, 1),
                rhs: IrExpr::Raw("v1_0[v2_0]  // aget".into()),
                comment: None,
            },
            IrStmt::Assign {
                dst: VarId::new(3, 0),
                rhs: IrExpr::Raw("v1_0.length  // array-length".into()),
                comment: None,
            },
        ];
        let type_map = std::collections::HashMap::new();
        let names = build_var_names(&stmts, &type_map, 0, true);
        assert_eq!(names.get(&VarId::new(1, 0)), Some(&"arr0".to_string()));
        assert_eq!(names.get(&VarId::new(2, 0)), Some(&"i".to_string()));
        assert_eq!(names.get(&VarId::new(3, 0)), Some(&"length".to_string()));
    }
}
