//! Type inference for method IR: seed from params and return, propagate from Assign(Var), Assign(Call), and Raw literals.

use dex_parser::{CodeItem, DexFile, EncodedMethod};
use crate::decompile::ir::{Expr as IrExpr, Stmt as IrStmt, VarId};
use crate::java;
use std::collections::HashMap;

/// Well-known JDK / Android API return types when the method isn't resolved from DEX ids.
fn known_api_return_type(target: &str) -> Option<&'static str> {
    let method = target.rsplit('.').next().unwrap_or(target);
    match method {
        "equals" | "equalsIgnoreCase" | "endsWith" | "startsWith" | "isEmpty" | "contains"
        | "contentEquals" | "matches" | "regionMatches" | "isBlank" => Some("boolean"),
        "length" | "indexOf" | "lastIndexOf" | "hashCode" | "compareTo" | "compareToIgnoreCase" => {
            Some("int")
        }
        "trim" | "toString" | "toLowerCase" | "toUpperCase" | "intern" | "concat" | "replace"
        | "replaceAll" | "replaceFirst" | "substring" | "getScheme" | "getHost" | "getPath"
        | "getQuery" | "getQueryParameter" | "getFragment" | "getAction" | "getDataString" => {
            Some("java.lang.String")
        }
        "getData" | "parse" => {
            // Uri.parse / Intent.getData — heuristic by name only when FQN contains Uri/Intent.
            if target.contains("Uri") {
                Some("android.net.Uri")
            } else if method == "getData" {
                Some("android.net.Uri")
            } else {
                None
            }
        }
        "charAt" => Some("char"),
        "toCharArray" => Some("char[]"),
        "getBytes" => Some("byte[]"),
        "split" => Some("java.lang.String[]"),
        "valueOf" | "copyValueOf" => Some("java.lang.String"),
        _ => None,
    }
}

/// Infer Java type names for SSA variables from method signature and IR.
/// - Seeds parameter registers at the **high** end of the frame
///   (`registers_size - ins_size .. registers_size`) from method params (and `this` for instance methods).
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
        if let Some(t) = known_api_return_type(target) {
            return Some(t.to_string());
        }
        let n = dex.header.method_ids_size as usize;
        for idx in 0..n {
            if let Ok(mi) = dex.get_method_info(idx as u32) {
                let key = format!("{}.{}", java::descriptor_to_java(&mi.class), mi.name);
                if key == target && mi.params.len() == num_args {
                    return Some(java::descriptor_to_java(&mi.return_type));
                }
            }
        }
        // Receiver-style targets (`v0.equals`, `java.lang.String.endsWith`) when the
        // declaring class isn't fully resolved from this DEX's method_ids alone.
        if let Some(dot) = target.rfind('.') {
            let method = &target[dot + 1..];
            if let Some(t) = known_api_return_type(method) {
                return Some(t.to_string());
            }
            if let Some(t) = known_api_return_type(&format!("java.lang.String.{}", method)) {
                return Some(t.to_string());
            }
        }
        None
    };
    let ins_size = code.ins_size as u32;
    let registers_size = code.registers_size as u32;
    let is_static = (encoded.access_flags & 0x8) != 0;
    let class_java = java::descriptor_to_java(&info.class);
    let param_types: Vec<String> = info.params.iter().map(|p| java::descriptor_to_java(p)).collect();
    let return_type_java = java::descriptor_to_java(&info.return_type);

    // Seed param registers (version 0) at the high end of the Dalvik frame.
    let param_base = registers_size.saturating_sub(ins_size);
    for i in 0..ins_size {
        let reg = param_base + i;
        let vid = VarId::new(reg, 0);
        if !is_static && i == 0 {
            types.insert(vid, class_java.clone());
        } else {
            let param_idx = if is_static { i as usize } else { (i as usize).saturating_sub(1) };
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

/// Fill missing SSA types from a whole-method register→type map, then re-propagate
/// Assign RHS types (so `aget` can pick up array element types across blocks).
pub fn enrich_types_with_register_map(
    type_map: &mut HashMap<VarId, String>,
    reg_types: &HashMap<u32, String>,
    stmts: &[IrStmt],
) {
    for stmt in stmts {
        for v in vars_in_stmt(stmt) {
            if !type_map.contains_key(&v) {
                if let Some(ty) = reg_types.get(&v.reg) {
                    type_map.insert(v, ty.clone());
                }
            }
        }
    }
    let max_iters = stmts.len().saturating_mul(2).max(4);
    for _ in 0..max_iters {
        let mut changed = false;
        for stmt in stmts {
            if let IrStmt::Assign { dst, rhs, .. } = stmt {
                if type_map.contains_key(dst) {
                    continue;
                }
                let ty = match rhs {
                    IrExpr::Var(v) => type_map.get(v).cloned(),
                    IrExpr::Raw(s) => infer_type_from_raw(s, type_map),
                    IrExpr::Call { .. } | IrExpr::PendingResult => None,
                };
                if let Some(t) = ty {
                    type_map.insert(*dst, t);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
}

fn vars_in_stmt(stmt: &IrStmt) -> Vec<VarId> {
    match stmt {
        IrStmt::Assign { dst, rhs, .. } => {
            let mut v = var_ids_in_expr(rhs);
            v.push(*dst);
            v
        }
        IrStmt::Expr { expr, .. } => var_ids_in_expr(expr),
        IrStmt::Return { value: Some(e), .. } => var_ids_in_expr(e),
        IrStmt::Return { value: None, .. } => vec![],
        IrStmt::Phi { dst, incomings } => {
            let mut v: Vec<VarId> = incomings.iter().map(|(_, x)| *x).collect();
            v.push(*dst);
            v
        }
        IrStmt::Raw(text) => var_ids_in_text(text),
    }
}

/// Infer type from Raw RHS: string literal, new-array "new Type[size]", new-instance, literal, or first variable reference's type.
fn infer_type_from_raw(s: &str, types: &HashMap<VarId, String>) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.starts_with("new ") {
        // filled-new-array / array literal: "new Type[]{ ... }" → Type[]
        if let Some(brace) = s.find('{') {
            let head = s[4..brace].trim();
            if head.ends_with("[]") {
                return Some(head.to_string());
            }
        }
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
    // array-length: "v0.length" / "v0_1.length" → int (must run before falling through to the array's type)
    if let Some(dot) = s.find(".length") {
        let after = s[dot + ".length".len()..].trim_start();
        // Bare `.length` or `.length // comment` — not `.length()` / other members.
        if after.is_empty() || after.starts_with('/') || after.starts_with(';') {
            return Some("int".to_string());
        }
    }
    // Array load: "v0[v1]" / "v0_1[v2_0]" → element type of the array variable
    if let Some(bracket) = s.find('[') {
        if s[bracket..].contains(']') {
            if let Some(array_id) = var_immediately_before(s, bracket) {
                if let Some(array_ty) = types.get(&array_id) {
                    if let Some(elem) = array_ty.strip_suffix("[]") {
                        return Some(elem.to_string());
                    }
                }
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
    // const-class: "android.content.Context.class" / "Foo.class"
    if let Some(ty) = s.strip_suffix(".class") {
        let ty = ty.trim();
        if !ty.is_empty()
            && ty
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '$' || c == '[' || c == ']')
        {
            return Some("java.lang.Class".to_string());
        }
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
        // "vN = new Type[vM]" → dst is Array, vM is Index (not filled-new-array `new Type[]{ ... }`)
        if let Some(dst) = assign_dst {
            if let Some(new_pos) = raw.find("new ") {
                if let Some(bracket) = raw[new_pos..].find('[') {
                    let abs_bracket = new_pos + bracket;
                    // Skip `new Type[]{ ... }` (filled-new-array); only size form has a non-empty index expr.
                    let after = raw[abs_bracket + 1..].trim_start();
                    if after.starts_with(']') {
                        // `new Type[]{ ... }` or `new Type[]`
                        roles.insert(dst, SemanticRole::Array);
                    } else if raw[abs_bracket..].contains(']') {
                        roles.insert(dst, SemanticRole::Array);
                        if let Some(index_id) = var_between(raw, abs_bracket + 1, raw.len()) {
                            roles.insert(index_id, SemanticRole::Index);
                        }
                    }
                }
            }
            // "vN = { ... }" / "vN = new int[]{ ... }" fill-array initializer → Array
            if raw.trim_start().starts_with('{') || raw.contains("[]{") {
                roles.insert(dst, SemanticRole::Array);
            }
        }
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
            IrStmt::Phi { dst, incomings } => {
                let uses: Vec<VarId> = incomings.iter().map(|(_, v)| *v).collect();
                (Some(*dst), uses)
            }
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
    unify_names_by_register(&mut names, type_map);
    names
}

/// Prefer one display name for SSA versions of the same Dalvik register **when types match**.
/// Keeps `arr0` shared across untyped/typed array uses, but does **not** collapse
/// Activity → View → TextView → String onto one debug name like `email`.
fn unify_names_by_register(names: &mut HashMap<VarId, String>, type_map: &HashMap<VarId, String>) {
    // Union-find over VarIds that share a register and compatible types.
    let vars: Vec<VarId> = names.keys().copied().collect();
    let mut parent: HashMap<VarId, VarId> = vars.iter().map(|v| (*v, *v)).collect();

    fn find(parent: &mut HashMap<VarId, VarId>, x: VarId) -> VarId {
        let mut root = x;
        while parent.get(&root).copied().unwrap_or(root) != root {
            root = parent[&root];
        }
        let mut cur = x;
        while cur != root {
            let next = parent[&cur];
            parent.insert(cur, root);
            cur = next;
        }
        root
    }
    fn union(parent: &mut HashMap<VarId, VarId>, a: VarId, b: VarId) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra != rb {
            parent.insert(ra, rb);
        }
    }

    for i in 0..vars.len() {
        for j in (i + 1)..vars.len() {
            let a = vars[i];
            let b = vars[j];
            if a.reg != b.reg {
                continue;
            }
            let ta = type_map.get(&a).map(|s| s.as_str());
            let tb = type_map.get(&b).map(|s| s.as_str());
            if types_compatible_for_naming(ta, tb) {
                union(&mut parent, a, b);
            }
        }
    }

    // Pick best name per cluster.
    let mut best: HashMap<VarId, String> = HashMap::new();
    for (vid, name) in names.iter() {
        let root = find(&mut parent, *vid);
        let score = name_quality(name, type_map.get(vid).map(|s| s.as_str()));
        match best.get(&root) {
            None => {
                best.insert(root, name.clone());
            }
            Some(cur) => {
                let cur_score = name_quality(cur, None);
                if score > cur_score {
                    best.insert(root, name.clone());
                }
            }
        }
    }
    for (vid, name) in names.iter_mut() {
        let root = find(&mut parent, *vid);
        if let Some(n) = best.get(&root) {
            *name = n.clone();
        }
    }
}

/// Normalize Java type names for comparison (`String` ≡ `java.lang.String`).
fn normalize_type_name(ty: &str) -> String {
    let t = ty.trim();
    match t {
        "String" => "java.lang.String".into(),
        "Object" => "java.lang.Object".into(),
        "CharSequence" => "java.lang.CharSequence".into(),
        "TextView" => "android.widget.TextView".into(),
        "View" => "android.view.View".into(),
        "Activity" => "android.app.Activity".into(),
        "Context" => "android.content.Context".into(),
        other => other.to_string(),
    }
}

/// True when two SSA versions of one register may share a display name.
pub(crate) fn types_compatible_for_naming(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        // Untyped defs must not inherit String/Uri/class names (avoids `host = 0`).
        // Exception: an untyped use may share an array name (`arr0`) with a typed `T[]`.
        // Typed defs may still share a name when the latest version's type is unknown.
        (None, Some(t)) => t.ends_with("[]"),
        (Some(_), None) => true,
        (None, None) => true,
        (Some(x), Some(y)) => normalize_type_name(x) == normalize_type_name(y),
    }
}

fn name_quality(name: &str, typ: Option<&str>) -> i32 {
    let mut score = 3;
    if name == "this" || name == "result" || name == "length" {
        return 20;
    }
    if name == "i" || name == "j" || name == "k" {
        return 12;
    }
    if name.starts_with("arr") {
        score = 15;
    } else if typ.is_some_and(|t| t.ends_with("[]")) {
        score = 14;
    } else if name.starts_with("local") && name.bytes().skip(5).all(|b| b.is_ascii_digit()) {
        score = 0;
    } else if name.starts_with('v') && name.bytes().skip(1).all(|b| b.is_ascii_digit()) {
        score = 1;
    } else if !name.is_empty() && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        score = 8;
    }
    score
}

fn var_ids_in_expr(expr: &IrExpr) -> Vec<VarId> {
    match expr {
        IrExpr::Var(v) => vec![*v],
        IrExpr::Call { target, args } => {
            let mut v = var_ids_in_text(target);
            v.extend(var_ids_in_text(args));
            v
        }
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
        let typ = type_map.get(&v).map(|s| s.as_str()).unwrap_or("");
        return param_display_name(param_idx as usize, typ);
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
        "int" | "short" | "byte" => "i",
        "boolean" => "z",
        "long" => "l",
        "java.lang.String" | "String" => "s",
        "float" => "f",
        "double" => "d",
        "char" => "c",
        "java.lang.Object" | "Object" => "obj",
        "java.lang.StringBuilder" | "StringBuilder" => "sb",
        "android.content.Intent" | "Intent" => "intent",
        "android.net.Uri" | "Uri" => "uri",
        "android.os.Bundle" | "Bundle" => "bundle",
        "android.content.Context" | "Context" => "ctx",
        "android.view.View" | "View" => "view",
        "java.lang.Class" | "Class" => "cls",
        _ if ty.ends_with("[]") => "arr",
        _ if ty.ends_with("Exception") => "ex",
        _ if ty.ends_with("List") => "list",
        _ if ty.ends_with("Map") => "map",
        _ if ty.ends_with("Set") => "set",
        _ => "v",
    }
}

/// Prefer type-based param names: `String p0` → keep `p0` in signature sync via
/// [`param_display_name`].
pub fn param_display_name(param_idx: usize, typ: &str) -> String {
    let base = match typ {
        "int" | "short" | "byte" => "i",
        "boolean" => "z",
        "long" => "l",
        "float" => "f",
        "double" => "d",
        "char" => "c",
        "java.lang.String" | "String" => "s",
        "android.content.Intent" | "Intent" => "intent",
        "android.net.Uri" | "Uri" => "uri",
        "android.os.Bundle" | "Bundle" => "bundle",
        "android.content.Context" | "Context" => "ctx",
        "android.view.View" | "View" => "view",
        _ if typ.ends_with("[]") => "arr",
        _ if typ.ends_with("List") => "list",
        _ if typ.ends_with("Map") => "map",
        _ => "p",
    };
    if base == "p" {
        format!("p{}", param_idx)
    } else if param_idx == 0 && matches!(base, "intent" | "bundle" | "ctx" | "view" | "uri") {
        base.to_string()
    } else {
        format!("{}{}", base, param_idx)
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
    fn build_var_names_unifies_ssa_versions_array_over_local() {
        use crate::decompile::ir::{Expr as IrExpr, Stmt as IrStmt, VarId};
        // new-array defines v0_1 as int[]; a later use of v0_0 must not stay as local0.
        let stmts = vec![
            IrStmt::Assign {
                dst: VarId::new(0, 1),
                rhs: IrExpr::Raw("new int[v1_1]".into()),
                comment: None,
            },
            IrStmt::Expr {
                expr: IrExpr::Call {
                    target: "java.util.Arrays.sort".into(),
                    args: "v0".into(), // unversioned use
                },
                comment: None,
            },
        ];
        let mut type_map = std::collections::HashMap::new();
        type_map.insert(VarId::new(0, 1), "int[]".into());
        type_map.insert(VarId::new(1, 1), "int".into());
        let names = build_var_names_with_regs(&stmts, &type_map, 4, 0, true);
        let n_typed = names.get(&VarId::new(0, 1)).cloned();
        let n_old = names.get(&VarId::new(0, 0)).cloned();
        assert!(
            n_typed.as_deref() == Some("arr0") || n_typed.as_ref().is_some_and(|s| s.starts_with("arr")),
            "typed array version should be arr*: {:?}",
            n_typed
        );
        assert_eq!(
            n_old, n_typed,
            "unversioned use must share the array name, not local0: old={:?} typed={:?}",
            n_old, n_typed
        );
    }

    #[test]
    fn build_var_names_does_not_unify_incompatible_types() {
        use crate::decompile::ir::{Expr as IrExpr, Stmt as IrStmt, VarId};
        // Same register: Activity (this) → View → String must keep distinct names.
        let stmts = vec![
            IrStmt::Assign {
                dst: VarId::new(0, 1),
                rhs: IrExpr::Call {
                    target: "v0_0.findViewById".into(),
                    args: "2131165271".into(),
                },
                comment: None,
            },
            IrStmt::Assign {
                dst: VarId::new(0, 2),
                rhs: IrExpr::Raw("(TextView) v0_1".into()),
                comment: None,
            },
            IrStmt::Assign {
                dst: VarId::new(0, 3),
                rhs: IrExpr::Call {
                    target: "v0_2.getText".into(),
                    args: "".into(),
                },
                comment: None,
            },
            IrStmt::Assign {
                dst: VarId::new(0, 4),
                rhs: IrExpr::Call {
                    target: "v0_3.toString".into(),
                    args: "".into(),
                },
                comment: None,
            },
        ];
        let mut type_map = std::collections::HashMap::new();
        type_map.insert(VarId::new(0, 0), "com.example.MainActivity".into());
        type_map.insert(VarId::new(0, 1), "android.view.View".into());
        type_map.insert(VarId::new(0, 2), "TextView".into());
        type_map.insert(VarId::new(0, 3), "java.lang.CharSequence".into());
        type_map.insert(VarId::new(0, 4), "java.lang.String".into());
        let names = build_var_names_with_regs(&stmts, &type_map, 1, 1, false);
        // Simulate debug name applied only to final String version.
        let mut names = names;
        names.insert(VarId::new(0, 4), "email".into());
        let n0 = names.get(&VarId::new(0, 0)).cloned();
        let n1 = names.get(&VarId::new(0, 1)).cloned();
        let n4 = names.get(&VarId::new(0, 4)).cloned();
        assert_eq!(n0.as_deref(), Some("this"));
        assert_ne!(n1, n4, "View and String must not share a name: {:?} vs {:?}", n1, n4);
        assert_ne!(n0, n4, "this/Activity must not become email: {:?} vs {:?}", n0, n4);
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
