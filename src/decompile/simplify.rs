//! Post-process decompiled method body to simplify invoke + move-result + return patterns.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;

/// Strip trailing "  // ..." comment from a line to get the statement part.
fn strip_trailing_comment(line: &str) -> String {
    let line = line.trim_end();
    if let Some(idx) = line.find("  // ") {
        line[..idx].trim_end().to_string()
    } else {
        line.to_string()
    }
}

/// Extract indent (leading spaces) from a line.
fn leading_indent(line: &str) -> &str {
    let trimmed = line.trim_start();
    let n = line.len() - trimmed.len();
    &line[..n]
}

/// From invoke line content like "invoke-static( v2, v3, Class.method(A, B) );",
/// extract the inner " v2, v3, Class.method(A, B) " and split into (args, method_ref)
/// where method_ref is the last comma-separated token (method ref may contain commas inside parens).
/// Also handles no-arg forms: "invoke-static( Runtime.getRuntime() );".
fn parse_invoke_args_and_method(line: &str) -> Option<(String, String)> {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    let start = stmt.find('(')?;
    let end = stmt.rfind(");")?;
    let inner = stmt[start + 1..end].trim();
    if inner.is_empty() {
        return None;
    }
    // Find the last comma at paren depth 0 (method ref can contain commas in param types).
    let mut depth = 0u32;
    let mut last_comma_at = None;
    for (i, c) in inner.chars().enumerate() {
        match c {
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => last_comma_at = Some(i),
            _ => {}
        }
    }
    let (args, method_ref) = if let Some(split_at) = last_comma_at {
        (
            inner[..split_at].trim().to_string(),
            inner[split_at + 1..].trim().to_string(),
        )
    } else {
        (String::new(), inner.to_string())
    };
    if method_ref.is_empty() {
        return None;
    }
    // Method ref from DEX is "Class.method(ParamTypes)" - use only "Class.method" for the call.
    let method_name = method_ref
        .find('(')
        .map(|i| method_ref[..i].trim_end())
        .unwrap_or(method_ref.as_str())
        .to_string();
    if method_name.is_empty() {
        return None;
    }
    Some((args, method_name))
}

/// Check if line is an invoke statement (invoke-xxx( ... );).
fn is_invoke_line(line: &str) -> bool {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    stmt.starts_with("invoke-") && stmt.contains('(') && (stmt.ends_with(" );") || stmt.ends_with(");"))
}

/// Match "Type? var = expr;" → Some((var, expr)). Type is optional (e.g. `String result = "x";`).
fn parse_simple_assign_line(line: &str) -> Option<(String, String)> {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    if !stmt.ends_with(';') {
        return None;
    }
    let eq = stmt.find(" = ")?;
    let lhs = stmt[..eq].trim();
    let rhs = stmt[eq + 3..].trim_end_matches(';').trim();
    if rhs.is_empty() || rhs == "<result>" {
        return None;
    }
    // Reject control-flow / declarations that aren't simple assigns
    if lhs.contains('(') || lhs.starts_with("return") || lhs.starts_with("if") {
        return None;
    }
    let var = lhs.split_whitespace().last()?.to_string();
    if var.is_empty() || !is_java_ident(&var) {
        return None;
    }
    Some((var, rhs.to_string()))
}

/// Match "return ident;" → Some(ident).
fn parse_return_ident_line(line: &str) -> Option<String> {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    let rest = stmt.strip_prefix("return ")?.trim_end_matches(';').trim();
    if rest.is_empty() || !is_java_ident(rest) {
        return None;
    }
    Some(rest.to_string())
}

fn is_java_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// True if `var` appears as a whole identifier in `text` (not as a substring of another ident).
fn ident_occurs(text: &str, var: &str) -> bool {
    if var.is_empty() || !text.contains(var) {
        return false;
    }
    let bytes = text.as_bytes();
    let v = var.as_bytes();
    let mut i = 0;
    while i + v.len() <= bytes.len() {
        if &bytes[i..i + v.len()] == v {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after_ok = i + v.len() == bytes.len() || !is_ident_byte(bytes[i + v.len()]);
            if before_ok && after_ok {
                return true;
            }
            i += v.len();
        } else {
            i += 1;
        }
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// Check if line is "vN = <result>;" or "ident = <result>;" and return the LHS name.
fn parse_move_result_line(line: &str) -> Option<String> {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    let eq = stmt.find(" = <result>;")?;
    let lhs = stmt[..eq].trim();
    if lhs.is_empty() {
        return None;
    }
    // vN / vN_k register forms
    if let Some(rest) = lhs.strip_prefix('v') {
        if !rest.is_empty()
            && rest
                .chars()
                .all(|c| c.is_ascii_digit() || c == '_')
        {
            return Some(lhs.to_string());
        }
    }
    if is_java_ident(lhs) {
        return Some(lhs.to_string());
    }
    None
}

/// Check if line is "return;" (return-void).
fn is_return_void_line(line: &str) -> bool {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    stmt == "return;"
}

/// Check if line is "return vN;" / "return ident;" and return the returned name.
fn parse_return_reg_line(line: &str) -> Option<String> {
    parse_return_ident_line(line).or_else(|| {
        let binding = strip_trailing_comment(line);
        let stmt = binding.trim();
        let rest = stmt.strip_prefix("return ")?.trim_end_matches(';').trim();
        if rest.starts_with('v')
            && rest.len() > 1
            && rest[1..].chars().all(|c| c.is_ascii_digit() || c == '_')
        {
            return Some(rest.to_string());
        }
        None
    })
}

/// Match "if (cond) {" line: return Some(cond), else None.
fn parse_if_condition(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = t.strip_prefix("if (")?;
    let end = rest.find(") {")?;
    Some(rest[..end].trim().to_string())
}

/// Match "return expr;" line: return Some(expr), else None.
fn parse_return_expr(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = t.strip_prefix("return ")?.trim_end_matches(';').trim();
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

/// True if the line (after stripping comment) is "return;" or "return expr;".
fn is_return_line(line: &str) -> bool {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    stmt == "return;" || (stmt.starts_with("return ") && stmt.ends_with(';'))
}

/// Match "var = new StringBuilder();" or "var = new StringBuilder(arg);", return (var, None) or (var, Some(arg)).
fn parse_new_stringbuilder(line: &str) -> Option<(String, Option<String>)> {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    let eq = stmt.find(" = ")?;
    let var = stmt[..eq].trim().to_string();
    let rhs = stmt[eq + 3..].trim_end_matches(';').trim();
    if !rhs.contains("new StringBuilder(") {
        return None;
    }
    let start = rhs.find('(')?;
    let end = rhs.rfind(')')?;
    let inner = rhs[start + 1..end].trim();
    let first_arg = if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    };
    Some((var, first_arg))
}

/// Match "var.append(arg);" or "dest = var.append(arg);", return Some((var, arg)).
fn parse_append(line: &str) -> Option<(String, String)> {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    let dot = stmt.find(".append(")?;
    let before_dot = &stmt[..dot];
    let var = if let Some(eq) = before_dot.find(" = ") {
        before_dot[eq + 3..].trim().to_string()
    } else {
        before_dot.trim().to_string()
    };
    let start = dot + ".append(".len();
    let end = stmt.rfind(");")?;
    let arg = stmt[start..end].trim().to_string();
    Some((var, arg))
}

/// Match "var.<init>();" or "var.<init>(arg);", return Some((var, optional_arg)).
fn parse_init_call(line: &str) -> Option<(String, Option<String>)> {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    let init_pos = stmt.find(".<init>(")?;
    let var = stmt[..init_pos].trim().to_string();
    let start = init_pos + ".<init>(".len();
    let end = stmt.rfind(");")?;
    let inner = stmt[start..end].trim();
    let arg = if inner.is_empty() { None } else { Some(inner.to_string()) };
    Some((var, arg))
}

/// Match "var.println(arg);" or "dest = var.println(arg);", return Some((var, arg)).
fn parse_println(line: &str) -> Option<(String, String)> {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    let dot = stmt.find(".println(")?;
    let before_dot = &stmt[..dot];
    let var = if let Some(eq) = before_dot.find(" = ") {
        before_dot[eq + 3..].trim().to_string()
    } else {
        before_dot.trim().to_string()
    };
    let start = dot + ".println(".len();
    let end = stmt.rfind(");")?;
    let arg = stmt[start..end].trim().to_string();
    Some((var, arg))
}

/// Match "dest = var.toString();" or "return var.toString();", return Some((dest_var, sb_var)) or Some(("return", sb_var)).
fn parse_to_string(line: &str) -> Option<(String, String)> {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    if let Some(rest) = stmt.strip_prefix("return ") {
        let rest = rest.trim_end_matches(';').trim();
        if let Some(var) = rest.strip_suffix(".toString()") {
            return Some(("return".to_string(), var.trim().to_string()));
        }
    }
    let eq = stmt.find(" = ")?;
    let dest = stmt[..eq].trim().to_string();
    let rhs = stmt[eq + 3..].trim_end_matches(';').trim();
    if let Some(var) = rhs.strip_suffix(".toString()") {
        return Some((dest, var.trim().to_string()));
    }
    None
}

/// Extract the register number from SSA variable names like "v2", "local2", "localN".
fn extract_reg_number(var: &str) -> Option<&str> {
    if let Some(n) = var.strip_prefix("local") {
        if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) { return Some(n); }
    }
    if let Some(n) = var.strip_prefix('v') {
        if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) { return Some(n); }
    }
    None
}

/// Inline static field references: "var = System.out;" followed by "var.println(x)" → "System.out.println(x)".
/// Handles SSA aliasing where "local2 = System.out;" and "v2.println(x)" refer to the same register.
fn inline_static_field_refs(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut aliases: Vec<(String, String, Option<String>)> = Vec::new();
    for line in &lines {
        let stmt = strip_trailing_comment(line);
        let t = stmt.trim();
        if let Some(eq) = t.find(" = ") {
            let lhs = t[..eq].trim();
            // Use the identifier only (`String s0` → `s0`), not the full typed LHS.
            let var = lhs.rsplit(' ').next().unwrap_or(lhs);
            let val = t[eq + 3..].trim_end_matches(';').trim();
            // Only static/instance field paths (e.g. System.out), never string literals
            // like "android.permission.READ_…" which also contain '.', and never
            // const-class literals (`Context.class`) which look like dotted paths.
            if is_java_ident(var) && is_simple_field_path(val) && !is_class_literal(val) {
                let reg_num = extract_reg_number(var).map(String::from);
                aliases.push((var.to_string(), val.to_string(), reg_num));
            }
        }
    }
    if aliases.is_empty() {
        return body.to_string();
    }
    let match_vars_for = |alias_var: &str, reg_num: &Option<String>| -> Vec<String> {
        let mut vars = vec![alias_var.to_string()];
        if let Some(n) = reg_num {
            let v_form = format!("v{}", n);
            let local_form = format!("local{}", n);
            if v_form != alias_var { vars.push(v_form); }
            if local_form != alias_var { vars.push(local_form); }
        }
        vars
    };
    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        let stmt = strip_trailing_comment(line);
        let t = stmt.trim();
        let mut skip = false;
        for (var, val, reg_num) in &aliases {
            let assign_stmt = format!("{} = {};", var, val);
            if t == assign_stmt {
                let candidate_vars = match_vars_for(var, reg_num);
                let non_print_use = lines.iter().enumerate().any(|(j, l)| {
                    j != idx && candidate_vars.iter().any(|cv| {
                        let prefix = format!("{}.", cv);
                        l.contains(&prefix)
                            && !l.contains(&format!("{}.println(", cv))
                            && !l.contains(&format!("{}.print(", cv))
                    })
                });
                if !non_print_use {
                    skip = true;
                    break;
                }
            }
        }
        if skip { continue; }
        let mut current_line = line.to_string();
        for (var, val, reg_num) in &aliases {
            let candidate_vars = match_vars_for(var, reg_num);
            for cv in &candidate_vars {
                for method in &["println", "print"] {
                    let from = format!("{}.{}(", cv, method);
                    let to = format!("{}.{}(", val, method);
                    current_line = current_line.replace(&from, &to);
                }
            }
        }
        out.push_str(&current_line);
        if idx < lines.len().saturating_sub(1) {
            out.push('\n');
        }
    }
    out
}

/// True if `rhs` is safe to inline into a single use.
fn is_inlineable_rhs(rhs: &str) -> bool {
    let rhs = rhs.trim();
    if rhs.is_empty() {
        return false;
    }
    // String / char literals
    if (rhs.starts_with('"') && rhs.ends_with('"')) || (rhs.starts_with('\'') && rhs.ends_with('\'') && rhs.len() >= 3) {
        return true;
    }
    // null / booleans
    if matches!(rhs, "null" | "true" | "false") {
        return true;
    }
    // Numeric (decimal / hex / float / long / float suffixes)
    if is_numeric_literal(rhs) {
        return true;
    }
    // const-class: Context.class / android.content.Context.class
    if is_class_literal(rhs) {
        return true;
    }
    // Simple identifier (copy): i0, s1, this, pickerIntent
    if is_java_ident(rhs) {
        return true;
    }
    // Simple field / static path: this.this$0, Foo.BAR, obj.field — no spaces, parens, or operators
    if is_simple_field_path(rhs) {
        return true;
    }
    // check-cast: `(TextView) expr`
    if is_cast_expr(rhs) {
        return true;
    }
    // Method / static call used once: `this.findViewById(1)`, `view.getText()`, `TextUtils.isEmpty(email)`
    if is_simple_call_expr(rhs) {
        return true;
    }
    false
}

/// `Foo.class` / `com.example.Foo.class` (DEX const-class).
fn is_class_literal(s: &str) -> bool {
    let s = s.trim();
    let Some(ty) = s.strip_suffix(".class") else {
        return false;
    };
    let ty = ty.trim();
    if ty.is_empty() || ty.contains('(') || ty.contains(' ') {
        return false;
    }
    ty.split('.').all(|p| !p.is_empty() && is_java_ident(p))
}

/// `(Type) expr` — Type starts with uppercase letter / package.
fn is_cast_expr(s: &str) -> bool {
    let s = s.trim();
    if !s.starts_with('(') {
        return false;
    }
    let Some(close) = s.find(')') else { return false };
    if close + 1 >= s.len() || s.as_bytes()[close + 1] != b' ' {
        return false;
    }
    let ty = s[1..close].trim();
    if ty.is_empty() {
        return false;
    }
    // Type name: Ident or pkg.Ident (allow [] for arrays)
    let ok_ty = ty.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '[' || c == ']')
        && ty.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false);
    if !ok_ty {
        return false;
    }
    let inner = s[close + 1..].trim();
    is_java_ident(inner)
        || is_simple_field_path(inner)
        || is_numeric_literal(inner)
        || matches!(inner, "null" | "true" | "false")
        || (inner.starts_with('"') && inner.ends_with('"'))
        || is_simple_call_expr(inner)
        || (inner.starts_with('(') && inner.contains(')') && is_cast_expr_shallow(inner))
}

fn is_cast_expr_shallow(s: &str) -> bool {
    let s = s.trim();
    if !s.starts_with('(') {
        return false;
    }
    let Some(close) = s.find(')') else { return false };
    if close + 1 >= s.len() {
        return false;
    }
    let ty = s[1..close].trim();
    !ty.is_empty()
        && ty.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false)
}

/// `recv.method(args)` including nested receivers like `((TextView) this.foo(1)).bar()`.
fn is_simple_call_expr(s: &str) -> bool {
    let s = s.trim();
    if !s.ends_with(')') || s.contains('=') {
        return false;
    }
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut open_idx = None;
    for i in (0..bytes.len()).rev() {
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open_idx = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(open) = open_idx else {
        return false;
    };
    if open == 0 {
        return false;
    }
    let recv_method = s[..open].trim();
    let Some(dot) = recv_method.rfind('.') else {
        return false;
    };
    let method = recv_method[dot + 1..].trim();
    if !is_java_ident(method) {
        return false;
    }
    let recv = recv_method[..dot].trim();
    !recv.is_empty()
}

fn is_numeric_literal(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    if bytes[0] == b'-' {
        if bytes.len() == 1 {
            return false;
        }
        i = 1;
    }
    if i + 1 < bytes.len() && bytes[i] == b'0' && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
        i += 2;
        if i >= bytes.len() {
            return false;
        }
        let mut saw_digit = false;
        while i < bytes.len() {
            let b = bytes[i];
            if b.is_ascii_hexdigit() {
                saw_digit = true;
                i += 1;
            } else if matches!(b, b'l' | b'L') && i + 1 == bytes.len() {
                return saw_digit;
            } else {
                return false;
            }
        }
        return saw_digit;
    }
    let mut saw_digit = false;
    let mut saw_dot = false;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_digit() {
            saw_digit = true;
            i += 1;
        } else if b == b'.' && !saw_dot {
            saw_dot = true;
            i += 1;
        } else if matches!(b, b'f' | b'F' | b'd' | b'D' | b'l' | b'L') && i + 1 == bytes.len() {
            return saw_digit;
        } else {
            return false;
        }
    }
    saw_digit
}

/// Literals cheap enough to duplicate at every use (`1`, `"x"`, `true`, …).
fn is_cheap_literal_rhs(rhs: &str) -> bool {
    let rhs = rhs.trim();
    if rhs.is_empty() {
        return false;
    }
    if matches!(rhs, "null" | "true" | "false") {
        return true;
    }
    if is_numeric_literal(rhs) {
        return true;
    }
    if rhs.starts_with('"') && rhs.ends_with('"') && rhs.len() >= 2 {
        return true;
    }
    if rhs.starts_with('\'') && rhs.ends_with('\'') && rhs.len() >= 3 {
        return true;
    }
    // Class literals are immutable / cheap to repeat at each use site.
    if is_class_literal(rhs) {
        return true;
    }
    false
}

/// `this.foo`, `Foo.BAR`, `a.b.c` — identifiers separated by dots only.
/// Not a class literal (`Foo.class` / `pkg.Foo.class`).
fn is_simple_field_path(s: &str) -> bool {
    let s = s.trim();
    if !s.contains('.') || s.contains('(') || s.contains(')') || s.contains(' ') || s.contains('[') {
        return false;
    }
    // `Type.class` is a const-class literal, not a field access.
    if s.ends_with(".class") {
        return false;
    }
    s.split('.').all(|p| !p.is_empty() && is_java_ident(p))
}

/// True for decompiler temps (`i0`, `s0`, `view0`, `local0`) — safe to inline away.
/// Meaningful names (`email`, `password`) are kept even when single-use.
fn is_temp_like_name(var: &str) -> bool {
    if var.is_empty() {
        return false;
    }
    // Array-index temps from SemanticRole::Index (often hold a literal 0/1).
    if matches!(var, "i" | "j" | "k") {
        return true;
    }
    if var.starts_with("local") && var.bytes().skip(5).all(|b| b.is_ascii_digit()) {
        return true;
    }
    let b = var.as_bytes();
    // i0 / s0 / v0 / o0 / …
    if b.len() >= 2
        && b[0].is_ascii_alphabetic()
        && b[1..].iter().all(|c| c.is_ascii_digit())
    {
        return true;
    }
    // view0, textView0, arr0, cls0, …
    if let Some(i) = var.bytes().rposition(|c| c.is_ascii_alphabetic()) {
        let (prefix, digits) = var.split_at(i + 1);
        if !digits.is_empty()
            && digits.bytes().all(|c| c.is_ascii_digit())
            && prefix.chars().next().map(|c| c.is_ascii_lowercase()).unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// Variable assigned on this line (`var = …` / `int var = …`), if any.
fn assign_lhs_var(line: &str) -> Option<String> {
    let binding = strip_trailing_comment(line);
    let t = binding.trim();
    let eq = t.find(" = ")?;
    let lhs = t[..eq].trim();
    let var = lhs.rsplit(' ').next().unwrap_or("");
    if !var.is_empty() && is_java_ident(var) {
        Some(var.to_string())
    } else {
        None
    }
}

/// True if `line` reassigns or mutates `var` (ends the previous value's live range).
fn line_kills_var(line: &str, var: &str) -> bool {
    if assign_lhs_var(line).as_deref() == Some(var) {
        return true;
    }
    let binding = strip_trailing_comment(line);
    let t = binding.trim();
    // Compound assigns / increments: i0 += 1; ++i0; i0++;
    let compounds = [
        format!("{} += ", var),
        format!("{} -= ", var),
        format!("{} *= ", var),
        format!("{} /= ", var),
        format!("{} %= ", var),
        format!("{} &= ", var),
        format!("{} |= ", var),
        format!("{} ^= ", var),
        format!("{} <<= ", var),
        format!("{} >>= ", var),
    ];
    if compounds.iter().any(|p| t.starts_with(p.as_str())) {
        return true;
    }
    if t == format!("++{};", var)
        || t == format!("--{};", var)
        || t == format!("{}++;", var)
        || t == format!("{}--;", var)
    {
        return true;
    }
    false
}

/// Remove bare "var; /* move-exception */" statements and inline single-use temps
/// (literals, copies, casts, single-use calls) into their only use.
///
/// Live ranges stop at the next assignment to the same name, so reused temps like
/// `s0 = "…"; …; s0 = this.foo;` are handled correctly.
fn cleanup_decompiler_artifacts(body: &str) -> String {
    let mut current = body.to_string();
    // Cast/call chains need multiple rounds: view→cast→getText→toString.
    for _ in 0..8 {
        let next = cleanup_decompiler_artifacts_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn cleanup_decompiler_artifacts_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();

    struct InlineCand {
        def_idx: usize,
        var: String,
        val: String,
        /// Exclusive end of live range (next kill or EOF).
        end_idx: usize,
        use_count: usize,
    }

    let mut cands: Vec<InlineCand> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let binding = strip_trailing_comment(line);
        let t = binding.trim();
        let Some(eq) = t.find(" = ") else { continue };
        let lhs = t[..eq].trim();
        let val = t[eq + 3..].trim_end_matches(';').trim();
        let var = lhs.rsplit(' ').next().unwrap_or(lhs);
        if var.is_empty() || !is_java_ident(var) || !is_inlineable_rhs(val) {
            continue;
        }
        // Never inline a self-referential RHS (`email = email.findViewById(...)`).
        // Allow `length = arr.length` (field access named like the dest).
        if ident_occurs(val, var) && !val.ends_with(&format!(".{}", var)) {
            continue;
        }
        let mut end_idx = lines.len();
        for (j, later) in lines.iter().enumerate().skip(idx + 1) {
            if line_kills_var(later, var) {
                end_idx = j;
                break;
            }
        }
        let use_count = {
            let mut c = lines[idx + 1..end_idx]
                .iter()
                .filter(|l| ident_occurs(l, var))
                .count();
            // Reassignment that *reads* the old value: `view0 = (TextView) view0`
            // Do NOT count a pure kill `i0 = 123` — the LHS matches but the old value is dead.
            if end_idx < lines.len() {
                let kill = lines[end_idx];
                if assign_lhs_var(kill).as_deref() == Some(var) {
                    if let Some(eq) = kill.find(" = ") {
                        if ident_occurs(&kill[eq + 3..], var) {
                            c += 1;
                        }
                    }
                } else if ident_occurs(kill, var) {
                    c += 1;
                }
            }
            c
        };
        cands.push(InlineCand {
            def_idx: idx,
            var: var.to_string(),
            val: val.to_string(),
            end_idx,
            use_count,
        });
    }

    // Inline single-use *temps*, and multi-use temps whose RHS is a cheap literal
    // (`int i0 = 1; foo(i0); bar(i0);` → `foo(1); bar(1);`).
    // Keep meaningful names (email, password, requestCode) as locals.
    // When the same temp name is reused (`i0 = layout; …; i0 = button;`), only inline the
    // *latest* live range in this pass — otherwise skipping both defs leaves a dangling use.
    let mut latest_inline_by_var: HashMap<String, usize> = HashMap::new();
    for (i, c) in cands.iter().enumerate() {
        if !is_temp_like_name(&c.var) || c.use_count == 0 {
            continue;
        }
        let want = c.use_count == 1 || is_cheap_literal_rhs(&c.val);
        if !want {
            continue;
        }
        match latest_inline_by_var.get(&c.var) {
            Some(&prev) if cands[prev].def_idx > c.def_idx => {}
            _ => {
                latest_inline_by_var.insert(c.var.clone(), i);
            }
        }
    }
    let inline_set: HashSet<usize> = latest_inline_by_var.values().copied().collect();
    let skip_indices: HashSet<usize> = cands
        .iter()
        .enumerate()
        .filter(|(i, c)| {
            let temp = is_temp_like_name(&c.var);
            (inline_set.contains(i) && temp)
                || (c.use_count == 0 && !is_simple_call_expr(&c.val) && !is_cast_expr(&c.val))
        })
        .map(|(i, _)| cands[i].def_idx)
        .collect();
    let inlines: Vec<&InlineCand> = {
        let mut v: Vec<&InlineCand> = inline_set.iter().map(|&i| &cands[i]).collect();
        // Earlier defs first so nested temps (button id → findViewById → listener) resolve.
        v.sort_by_key(|c| c.def_idx);
        v
    };

    // Substitute other single-use inlines that are live at `at_idx` into `val`.
    let materialize = |val: &str, at_idx: usize| -> String {
        let mut out = val.to_string();
        for other in &inlines {
            let live = at_idx > other.def_idx && at_idx < other.end_idx;
            let on_kill = at_idx == other.end_idx
                && at_idx > other.def_idx
                && ident_occurs(val, &other.var);
            if (live || on_kill) && ident_occurs(&out, &other.var) {
                out = replace_ident_as_expr(&out, &other.var, &other.val);
            }
        }
        out
    };

    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        let binding = strip_trailing_comment(line);
        let t = binding.trim();
        if t.ends_with("; /* move-exception */") || t.ends_with("/* move-exception */;") {
            continue;
        }
        if skip_indices.contains(&idx) {
            continue;
        }
        let mut current = line.to_string();
        for cand in &inlines {
            // Include the killing reassignment line (end_idx) when it reads the old value.
            let in_range = idx > cand.def_idx && idx < cand.end_idx;
            let on_kill_use = idx == cand.end_idx && idx > cand.def_idx && ident_occurs(line, &cand.var);
            if (in_range || on_kill_use) && ident_occurs(&current, &cand.var) {
                let replacement = materialize(&cand.val, idx);
                // On `var = … var …`, only rewrite the RHS so the LHS name stays.
                if on_kill_use && assign_lhs_var(&current).as_deref() == Some(cand.var.as_str()) {
                    if let Some(eq) = current.find(" = ") {
                        let (lhs, rhs) = current.split_at(eq + 3);
                        current = format!("{}{}", lhs, replace_ident_as_expr(rhs, &cand.var, &replacement));
                    } else {
                        current = replace_ident_as_expr(&current, &cand.var, &replacement);
                    }
                } else {
                    current = replace_ident_as_expr(&current, &cand.var, &replacement);
                }
            }
        }
        out.push_str(&current);
        if idx < lines.len().saturating_sub(1) {
            out.push('\n');
        }
    }
    out
}

/// Merge `x = new Foo();` + `x.<init>(args);` (and typed forms) into `x = new Foo(args);`.
fn merge_constructor_calls(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    if lines.len() < 2 {
        return body.to_string();
    }
    let mut skip: HashSet<usize> = HashSet::new();
    let mut replacements: HashMap<usize, String> = HashMap::new();
    let mut i = 0;
    while i + 1 < lines.len() {
        let binding = strip_trailing_comment(lines[i]);
        let t = binding.trim();
        let Some(eq) = t.find(" = ") else {
            i += 1;
            continue;
        };
        let lhs = t[..eq].trim();
        let rhs = t[eq + 3..].trim_end_matches(';').trim();
        let var = lhs.rsplit(' ').next().unwrap_or(lhs);
        let Some(class) = rhs.strip_prefix("new ").and_then(|s| s.strip_suffix("()")) else {
            i += 1;
            continue;
        };
        // Skip intervening simple assigns that don't touch `var`.
        let mut j = i + 1;
        while j < lines.len() {
            let jb = strip_trailing_comment(lines[j]);
            let jt = jb.trim();
            if let Some((init_var, args)) = parse_init_call(lines[j]) {
                if init_var == var {
                    let indent = leading_indent(lines[i]);
                    let typed = if lhs.contains(' ') {
                        format!("{}{} = new {}({});", indent, lhs, class, args.unwrap_or_default())
                    } else {
                        format!("{}{} = new {}({});", indent, var, class, args.unwrap_or_default())
                    };
                    replacements.insert(i, typed);
                    skip.insert(j);
                    i = j + 1;
                    break;
                }
            }
            if assign_lhs_var(lines[j]).as_deref() == Some(var) {
                i += 1;
                break;
            }
            // Allow simple temps between new and init.
            if parse_simple_assign_line(lines[j]).is_some() || jt.is_empty() {
                j += 1;
                continue;
            }
            i += 1;
            break;
        }
        if j >= lines.len() {
            i += 1;
        }
    }
    if replacements.is_empty() {
        return body.to_string();
    }
    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if skip.contains(&idx) {
            continue;
        }
        if let Some(rep) = replacements.get(&idx) {
            out.push_str(rep);
        } else {
            out.push_str(line);
        }
        if idx < lines.len().saturating_sub(1) {
            out.push('\n');
        }
    }
    out
}

/// Fold string-literal equals temps into `if` conditions and collapse `!(!x)`.
fn fold_equals_into_conditions(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..6 {
        let next = fold_equals_into_conditions_once(&current);
        let next = collapse_double_not_conditions(&next);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn fold_equals_into_conditions_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut skip: HashSet<usize> = HashSet::new();
    let mut replacements: HashMap<usize, String> = HashMap::new();

    for i in 0..lines.len() {
        if skip.contains(&i) {
            continue;
        }
        // Pattern: lit = "…";  bool = lit.equals(x);  if (bool|/!bool|/!(!bool))
        // or: bool = expr.equals(x); if (…)
        let Some((bvar, equals_expr)) = parse_equals_assign(lines[i]) else {
            continue;
        };
        // Optional preceding lit assign used once in equals_expr.
        let mut lit_idx: Option<usize> = None;
        let mut equals_expr = equals_expr;
        if i > 0 {
            if let Some((lvar, lval)) = parse_simple_assign_line(lines[i - 1]) {
                if is_string_literal(&lval) && ident_occurs(&equals_expr, &lvar) {
                    equals_expr = replace_ident_as_expr(&equals_expr, &lvar, &lval);
                    lit_idx = Some(i - 1);
                }
            }
        }
        // Find following if that tests bvar.
        let mut if_idx = None;
        for j in i + 1..lines.len().min(i + 4) {
            if let Some(cond) = parse_if_condition(lines[j]) {
                if condition_tests_var(&cond, &bvar) {
                    if_idx = Some(j);
                    break;
                }
            }
            // Allow only blank / comment-ish gaps
            let t = lines[j].trim();
            if !t.is_empty() && !t.starts_with("//") {
                break;
            }
        }
        let Some(if_i) = if_idx else { continue };
        let cond = parse_if_condition(lines[if_i]).unwrap();
        let new_cond = rewrite_condition_with_equals(&cond, &bvar, &equals_expr);
        let indent = leading_indent(lines[if_i]);
        replacements.insert(if_i, format!("{}if ({}) {{", indent, new_cond));
        skip.insert(i);
        if let Some(li) = lit_idx {
            // Only skip lit if unused elsewhere before if.
            let used_elsewhere = lines.iter().enumerate().any(|(k, l)| {
                k != i && k != li && k < if_i && ident_occurs(l, parse_simple_assign_line(lines[li]).unwrap().0.as_str())
            });
            if !used_elsewhere {
                skip.insert(li);
            }
        }
    }

    if replacements.is_empty() && skip.is_empty() {
        return body.to_string();
    }
    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if skip.contains(&idx) {
            continue;
        }
        if let Some(rep) = replacements.get(&idx) {
            out.push_str(rep);
        } else {
            out.push_str(line);
        }
        if idx < lines.len().saturating_sub(1) {
            out.push('\n');
        }
    }
    out
}

fn parse_equals_assign(line: &str) -> Option<(String, String)> {
    let (var, rhs) = parse_simple_assign_line(line)?;
    let rhs = rhs.trim();
    // x.equals(y) or x.endsWith(y) / startsWith / contains
    for meth in ["equals", "endsWith", "startsWith", "contains", "equalsIgnoreCase"] {
        if let Some(dot) = rhs.find(&format!(".{}(", meth)) {
            if rhs.ends_with(')') {
                return Some((var, rhs.to_string()));
            }
            let _ = dot;
        }
    }
    None
}

fn is_string_literal(s: &str) -> bool {
    let s = s.trim();
    s.len() >= 2 && s.starts_with('"') && s.ends_with('"')
}

fn condition_tests_var(cond: &str, var: &str) -> bool {
    let c = cond.trim();
    c == var
        || c == format!("!{}", var)
        || c == format!("!(!{})", var)
        || c == format!("{} == 0", var)
        || c == format!("{} != 0", var)
        || c == format!("{} == null", var)
        || c == format!("{} != null", var)
}

fn rewrite_condition_with_equals(cond: &str, var: &str, equals_expr: &str) -> String {
    let c = cond.trim();
    // Positive: var / var != 0 / var != null / !(!var)
    if c == var
        || c == format!("{} != 0", var)
        || c == format!("{} != null", var)
        || c == format!("!(!{})", var)
    {
        return equals_expr.to_string();
    }
    // Negative: !var / var == 0 / var == null
    if c == format!("!{}", var) || c == format!("{} == 0", var) || c == format!("{} == null", var)
    {
        return format!("!({})", equals_expr);
    }
    // Fallback: replace ident
    replace_ident_as_expr(c, var, equals_expr)
}

fn collapse_double_not_conditions(body: &str) -> String {
    let mut out = String::new();
    for (idx, line) in body.lines().enumerate() {
        if let Some(cond) = parse_if_condition(line) {
            let collapsed = collapse_double_not(&cond);
            if collapsed != cond {
                let indent = leading_indent(line);
                out.push_str(&format!("{}if ({}) {{", indent, collapsed));
            } else {
                out.push_str(line);
            }
        } else {
            out.push_str(line);
        }
        if idx < body.lines().count().saturating_sub(1) {
            out.push('\n');
        }
    }
    // Fix trailing newline parity
    if body.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn collapse_double_not(cond: &str) -> String {
    let mut c = cond.trim().to_string();
    for _ in 0..4 {
        if let Some(inner) = c.strip_prefix("!(").and_then(|s| s.strip_suffix(')')) {
            let inner = inner.trim();
            if let Some(inner2) = inner.strip_prefix('!') {
                let inner2 = inner2.trim().trim_start_matches('(').trim_end_matches(')').trim();
                c = inner2.to_string();
                continue;
            }
        }
        if let Some(rest) = c.strip_prefix("!!") {
            c = rest.to_string();
            continue;
        }
        break;
    }
    c
}

/// True when condition is a (possibly negated) string/predicate call like `"x".equals(y)`.
fn condition_has_string_predicate(cond: &str) -> bool {
    let c = cond.trim();
    let inner = c
        .strip_prefix("!(")
        .and_then(|s| s.strip_suffix(')'))
        .map(|s| s.trim())
        .unwrap_or(c);
    for meth in ["equals", "endsWith", "startsWith", "contains", "equalsIgnoreCase"] {
        if inner.contains(&format!(".{}(", meth)) {
            return true;
        }
    }
    false
}

fn strip_outer_not_parens(cond: &str) -> Option<String> {
    let c = cond.trim();
    let inner = c.strip_prefix("!(")?.strip_suffix(')')?;
    Some(inner.trim().to_string())
}

/// Extract string literal from `"lit".equals(…)` / `"lit".endsWith(…)` style conditions.
fn string_lit_in_predicate_cond(cond: &str) -> Option<String> {
    let c = strip_outer_not_parens(cond).unwrap_or_else(|| cond.trim().to_string());
    let c = c.trim();
    if !c.starts_with('"') {
        return None;
    }
    let end = c[1..].find('"')? + 1;
    Some(c[..=end].to_string())
}

/// Drop `name = "lit";` when the next statement is `if ("lit".equals(…))` / negated form.
fn drop_string_lits_folded_into_if(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut skip: HashSet<usize> = HashSet::new();
    for i in 0..lines.len().saturating_sub(1) {
        let Some((var, lit)) = parse_simple_assign_line(lines[i]) else {
            continue;
        };
        if !is_string_literal(&lit) {
            continue;
        }
        // Find next non-empty line
        let mut j = i + 1;
        while j < lines.len() && lines[j].trim().is_empty() {
            j += 1;
        }
        if j >= lines.len() {
            continue;
        }
        let Some(cond) = parse_if_condition(lines[j]) else {
            continue;
        };
        let Some(cond_lit) = string_lit_in_predicate_cond(&cond) else {
            continue;
        };
        if cond_lit != lit {
            continue;
        }
        // Keep if var is used in the condition (e.g. var.equals(...)) or later before reassignment.
        if ident_occurs(&cond, &var) {
            continue;
        }
        let used_later = lines.iter().enumerate().any(|(k, l)| {
            k > i && k != j && ident_occurs(l, &var) && assign_lhs_var(l).as_deref() != Some(var.as_str())
        });
        // If used later as a different value, still safe to drop THIS assign only when
        // the next if already has the literal inlined.
        if used_later {
            // Only drop if no use between assign and if.
            let used_between = (i + 1..j).any(|k| ident_occurs(lines[k], &var));
            if used_between {
                continue;
            }
        }
        skip.insert(i);
    }
    if skip.is_empty() {
        return body.to_string();
    }
    rebuild_lines(&lines, &skip, &HashMap::new(), body.ends_with('\n'))
}

fn rebuild_lines(
    lines: &[&str],
    skip: &HashSet<usize>,
    replacements: &HashMap<usize, String>,
    trailing_nl: bool,
) -> String {
    let mut out = String::new();
    let mut wrote = false;
    for (idx, line) in lines.iter().enumerate() {
        if skip.contains(&idx) {
            continue;
        }
        if wrote {
            out.push('\n');
        }
        if let Some(rep) = replacements.get(&idx) {
            out.push_str(rep);
        } else {
            out.push_str(line);
        }
        wrote = true;
        let _ = idx;
    }
    if trailing_nl && wrote {
        out.push('\n');
    } else if trailing_nl && !wrote {
        // empty
    }
    out
}

/// Find closing `}` for the block opened by the first `{` on `open_idx`.
/// Handles `} else {` by ignoring the leading `}` and matching the else-body `{`.
fn find_closing_brace_line(lines: &[&str], open_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut seen_open = false;
    for (i, line) in lines.iter().enumerate().skip(open_idx) {
        let t = line.trim();
        let mut in_str = false;
        let mut escape = false;
        for c in t.chars() {
            if in_str {
                if escape {
                    escape = false;
                } else if c == '\\' {
                    escape = true;
                } else if c == '"' {
                    in_str = false;
                }
                continue;
            }
            match c {
                '"' => in_str = true,
                '{' => {
                    depth += 1;
                    seen_open = true;
                }
                '}' => {
                    if !seen_open {
                        // Leading `}` on `} else {` — not part of the block we are matching.
                        continue;
                    }
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// End line of `if (…) { … } [else if …] [else { … }]`, past any `} else {` continuations.
fn find_if_chain_end(lines: &[&str], if_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut seen_open = false;
    for (i, line) in lines.iter().enumerate().skip(if_idx) {
        let t = line.trim();
        let mut in_str = false;
        let mut escape = false;
        let chars: Vec<char> = t.chars().collect();
        let mut ci = 0;
        while ci < chars.len() {
            let c = chars[ci];
            if in_str {
                if escape {
                    escape = false;
                } else if c == '\\' {
                    escape = true;
                } else if c == '"' {
                    in_str = false;
                }
                ci += 1;
                continue;
            }
            match c {
                '"' => in_str = true,
                '{' => {
                    depth += 1;
                    seen_open = true;
                }
                '}' => {
                    if !seen_open {
                        ci += 1;
                        continue;
                    }
                    depth -= 1;
                    if depth == 0 {
                        // `} else {` / `} else if (` continues the chain.
                        let rest: String = chars[ci + 1..].iter().collect();
                        let rest_t = rest.trim_start();
                        if rest_t.starts_with("else") {
                            // Keep scanning; following `{` re-opens.
                            ci += 1;
                            continue;
                        }
                        return Some(i);
                    }
                }
                _ => {}
            }
            ci += 1;
        }
    }
    None
}

/// End line of a full `if` / `if-else` / `if-else if` statement starting at `if_idx`.
fn find_if_statement_end(lines: &[&str], if_idx: usize) -> Option<usize> {
    let mut close = find_closing_brace_line(lines, if_idx)?;
    loop {
        let t = lines[close].trim();
        if t == "} else {" || t.starts_with("} else if (") {
            close = find_closing_brace_line(lines, close)?;
            continue;
        }
        return Some(close);
    }
}

/// Flip `if (!(pred)) { THEN } else { ELSE }` → `if (pred) { ELSE } else { THEN }`
/// when pred is a string equals/endsWith-style call. Repeat until stable.
fn flip_negated_equals_if_else(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..12 {
        let next = flip_negated_equals_if_else_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn flip_negated_equals_if_else_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    for i in 0..lines.len() {
        let Some(cond) = parse_if_condition(lines[i]) else {
            continue;
        };
        let Some(inner) = strip_outer_not_parens(&cond) else {
            continue;
        };
        if !condition_has_string_predicate(&inner) && !condition_has_string_predicate(&cond) {
            continue;
        }
        // Require predicate form inside the not
        if !condition_has_string_predicate(&format!("({})", inner))
            && !inner.contains(".equals(")
            && !inner.contains(".endsWith(")
            && !inner.contains(".startsWith(")
            && !inner.contains(".contains(")
        {
            continue;
        }
        let Some(then_close) = find_closing_brace_line(&lines, i) else {
            continue;
        };
        // Expect `} else {` on then_close
        let close_trim = lines[then_close].trim();
        if close_trim != "} else {" {
            continue;
        }
        let Some(else_close) = find_closing_brace_line(&lines, then_close) else {
            continue;
        };
        let indent = leading_indent(lines[i]);
        let then_body: Vec<&str> = lines[i + 1..then_close].to_vec();
        let else_body: Vec<&str> = lines[then_close + 1..else_close].to_vec();
        // Build flipped block
        let mut out = String::new();
        for (idx, line) in lines.iter().enumerate() {
            if idx == i {
                out.push_str(&format!("{}if ({}) {{\n", indent, inner));
                for l in &else_body {
                    out.push_str(l);
                    out.push('\n');
                }
                out.push_str(&format!("{}}} else {{\n", indent));
                for l in &then_body {
                    out.push_str(l);
                    out.push('\n');
                }
                out.push_str(&format!("{}}}", indent));
                if else_close < lines.len().saturating_sub(1) || body.ends_with('\n') {
                    out.push('\n');
                }
                continue;
            }
            if idx > i && idx <= else_close {
                continue;
            }
            out.push_str(line);
            if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
                out.push('\n');
            }
        }
        return out;
    }
    body.to_string()
}

/// Collapse `} else {\n    if (cond) {\n ... \n    }\n}` → `} else if (cond) {\n ... \n}`
fn flatten_else_if_chains(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..16 {
        let next = flatten_else_if_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn flatten_else_if_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    for i in 0..lines.len() {
        if lines[i].trim() != "} else {" {
            continue;
        }
        // Skip blanks
        let mut j = i + 1;
        while j < lines.len() && lines[j].trim().is_empty() {
            j += 1;
        }
        if j >= lines.len() {
            continue;
        }
        let Some(cond) = parse_if_condition(lines[j]) else {
            continue;
        };
        let Some(inner_end) = find_if_statement_end(&lines, j) else {
            continue;
        };
        // The `} else {` close must be followed only by this if (and its full if-else) until else-close
        let Some(else_close) = find_closing_brace_line(&lines, i) else {
            continue;
        };
        // After inner if-statement end, only whitespace until else_close
        let mut k = inner_end + 1;
        let mut only_ws = true;
        while k < else_close {
            if !lines[k].trim().is_empty() {
                only_ws = false;
                break;
            }
            k += 1;
        }
        if !only_ws || inner_end >= else_close {
            continue;
        }
        let else_indent = leading_indent(lines[i]);
        // Find the then-close of the inner if (may be `}` or `} else {` / `} else if`)
        let Some(inner_then_close) = find_closing_brace_line(&lines, j) else {
            continue;
        };
        let mut out = String::new();
        for (idx, line) in lines.iter().enumerate() {
            if idx == i {
                out.push_str(&format!("{}}} else if ({}) {{\n", else_indent, cond));
                // Emit then-body of the inner if
                for l in &lines[j + 1..inner_then_close] {
                    out.push_str(l);
                    out.push('\n');
                }
                // If inner had else/else-if, keep those clauses through the if-statement end.
                if inner_then_close < inner_end {
                    for l in &lines[inner_then_close..=inner_end] {
                        let t = l.trim();
                        if t.starts_with("} else") {
                            out.push_str(&format!("{}{}\n", else_indent, t));
                        } else {
                            out.push_str(l);
                            out.push('\n');
                        }
                    }
                } else {
                    // Plain if with no else — need its closing brace
                    out.push_str(&format!("{}}}", else_indent));
                    if else_close < lines.len().saturating_sub(1) || body.ends_with('\n') {
                        out.push('\n');
                    }
                }
                continue;
            }
            // Drop the old else wrapper (`} else {` … closing `}`).
            if idx > i && idx <= else_close {
                continue;
            }
            out.push_str(line);
            if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
                out.push('\n');
            }
        }
        return out;
    }
    body.to_string()
}

/// Merge:
/// ```text
/// path = uri.getScheme();
/// if ("a".equals(path)) {
///   path = uri.getHost();
///   if ("b".equals(path)) {
///     BODY
///   }
/// }
/// ```
/// into `if ("a".equals(uri.getScheme()) && "b".equals(uri.getHost())) { BODY }`
fn merge_nested_uri_component_checks(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..4 {
        let next = merge_nested_uri_component_checks_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn is_uri_component_getter(rhs: &str) -> bool {
    let r = rhs.trim();
    r.ends_with(".getScheme()")
        || r.ends_with(".getHost()")
        || r.ends_with(".getPath()")
        || r.ends_with(".getQuery()")
        || r.ends_with(".getFragment()")
}

fn merge_nested_uri_component_checks_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    for i in 0..lines.len().saturating_sub(1) {
        let Some((var1, getter1)) = parse_simple_assign_line(lines[i]) else {
            continue;
        };
        if !is_uri_component_getter(&getter1) {
            continue;
        }
        let mut j = i + 1;
        while j < lines.len() && lines[j].trim().is_empty() {
            j += 1;
        }
        if j >= lines.len() {
            continue;
        }
        let Some(cond1) = parse_if_condition(lines[j]) else {
            continue;
        };
        // "lit".equals(var1) or var1.equals("lit")
        if !ident_occurs(&cond1, &var1) || !condition_has_string_predicate(&cond1) {
            continue;
        }
        if strip_outer_not_parens(&cond1).is_some() {
            continue; // only merge positive checks
        }
        let Some(outer_close) = find_closing_brace_line(&lines, j) else {
            continue;
        };
        // Inside outer then: var1 = getter2; if (cond2) { body }  and nothing else
        let mut k = j + 1;
        while k < outer_close && lines[k].trim().is_empty() {
            k += 1;
        }
        if k >= outer_close {
            continue;
        }
        let Some((var2, getter2)) = parse_simple_assign_line(lines[k]) else {
            continue;
        };
        if var2 != var1 || !is_uri_component_getter(&getter2) {
            continue;
        }
        let mut m = k + 1;
        while m < outer_close && lines[m].trim().is_empty() {
            m += 1;
        }
        if m >= outer_close {
            continue;
        }
        let Some(cond2) = parse_if_condition(lines[m]) else {
            continue;
        };
        if !ident_occurs(&cond2, &var1) || !condition_has_string_predicate(&cond2) {
            continue;
        }
        if strip_outer_not_parens(&cond2).is_some() {
            continue;
        }
        let Some(inner_close) = find_closing_brace_line(&lines, m) else {
            continue;
        };
        if inner_close >= outer_close {
            continue;
        }
        // Only whitespace between inner_close and outer_close
        if (inner_close + 1..outer_close).any(|t| !lines[t].trim().is_empty()) {
            continue;
        }
        let cond1_inlined = replace_ident_as_expr(&cond1, &var1, &getter1);
        let cond2_inlined = replace_ident_as_expr(&cond2, &var1, &getter2);
        let indent = leading_indent(lines[j]);
        let mut out = String::new();
        for (idx, line) in lines.iter().enumerate() {
            if idx == i {
                // skip getter1 assign
                continue;
            }
            if idx == j {
                out.push_str(&format!(
                    "{}if ({} && {}) {{\n",
                    indent, cond1_inlined, cond2_inlined
                ));
                for l in &lines[m + 1..inner_close] {
                    out.push_str(l);
                    out.push('\n');
                }
                out.push_str(&format!("{}}}", indent));
                if outer_close < lines.len().saturating_sub(1) || body.ends_with('\n') {
                    out.push('\n');
                }
                continue;
            }
            if idx > j && idx <= outer_close {
                continue;
            }
            out.push_str(line);
            if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
                out.push('\n');
            }
        }
        return out;
    }
    body.to_string()
}

/// Inline `path = uri.getPath();` into a following equals-if when `path` is not used afterward
/// before reassignment (or only used in that if condition).
fn inline_single_use_into_equals_if(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut skip: HashSet<usize> = HashSet::new();
    let mut replacements: HashMap<usize, String> = HashMap::new();
    for i in 0..lines.len() {
        if skip.contains(&i) {
            continue;
        }
        let Some((var, getter)) = parse_simple_assign_line(lines[i]) else {
            continue;
        };
        if !is_uri_component_getter(&getter) && !getter.contains(".getQueryParameter(") {
            continue;
        }
        let mut j = i + 1;
        while j < lines.len() && lines[j].trim().is_empty() {
            j += 1;
        }
        if j >= lines.len() {
            continue;
        }
        let Some(cond) = parse_if_condition(lines[j]) else {
            continue;
        };
        if !ident_occurs(&cond, &var) || !condition_has_string_predicate(&cond) {
            continue;
        }
        // Count uses of var after the assign (excluding the if condition line's condition).
        let mut use_count = 0;
        let mut killed = false;
        for (k, l) in lines.iter().enumerate().skip(i + 1) {
            if assign_lhs_var(l).as_deref() == Some(var.as_str()) {
                killed = true;
                break;
            }
            if k == j {
                // condition use only — counted separately
                continue;
            }
            if ident_occurs(l, &var) {
                use_count += 1;
            }
        }
        // Allow inlining when the only use is the if condition (and optionally body doesn't use var).
        if use_count > 0 {
            continue;
        }
        let _ = killed;
        let new_cond = replace_ident_as_expr(&cond, &var, &getter);
        let indent = leading_indent(lines[j]);
        replacements.insert(j, format!("{}if ({}) {{", indent, new_cond));
        skip.insert(i);
    }
    if skip.is_empty() && replacements.is_empty() {
        return body.to_string();
    }
    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if skip.contains(&idx) {
            continue;
        }
        if let Some(rep) = replacements.get(&idx) {
            out.push_str(rep);
        } else {
            out.push_str(line);
        }
        if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

/// Replace `name == 0` / `!= 0` with null checks for reference-looking names in statements.
/// `setJavaScriptEnabled`, `setAllowFileAccessFromFileURLs`, `setClickable`, …
fn looks_like_boolean_api_method(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("enabled")
        || n.contains("enable")
        || n.starts_with("setallow")
        || n.starts_with("setblock")
        || n.starts_with("setdeny")
        || n.contains("visible")
        || n.contains("hidden")
        || n.contains("clickable")
        || n.contains("focusable")
        || n.contains("checked")
        || n.contains("selected")
        || n.contains("activated")
        || n.contains("javascript")
}

/// `.setFooEnabled(1)` / `.setAllowX(0)` → `true` / `false`.
fn polish_booleanish_int_args(body: &str) -> String {
    let bytes = body.as_bytes();
    let mut out = String::with_capacity(body.len());
    let mut i = 0;
    while i < bytes.len() {
        // Match `.ident(0|1)` with optional spaces inside the parens.
        if bytes[i] == b'.' {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            if j > i + 1 {
                let name = &body[i + 1..j];
                let mut k = j;
                while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                if k < bytes.len() && bytes[k] == b'(' {
                    let mut a = k + 1;
                    while a < bytes.len() && bytes[a].is_ascii_whitespace() {
                        a += 1;
                    }
                    if a < bytes.len() && (bytes[a] == b'0' || bytes[a] == b'1') {
                        let digit = bytes[a] as char;
                        let mut b = a + 1;
                        while b < bytes.len() && bytes[b].is_ascii_whitespace() {
                            b += 1;
                        }
                        if b < bytes.len() && bytes[b] == b')' && looks_like_boolean_api_method(name) {
                            out.push('.');
                            out.push_str(name);
                            out.push('(');
                            out.push_str(if digit == '1' { "true" } else { "false" });
                            out.push(')');
                            i = b + 1;
                            continue;
                        }
                    }
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn polish_null_comparisons_in_body(body: &str) -> String {
    let mut out = String::new();
    for (idx, line) in body.lines().enumerate() {
        let mut current = line.to_string();
        // if (x == 0) / if (x != 0)
        if let Some(cond) = parse_if_condition(line) {
            let new_cond = polish_null_in_condition(&cond);
            if new_cond != cond {
                current = format!("{}if ({}) {{", leading_indent(line), new_cond);
            }
        } else {
            // Also handle inline comparisons in assigns rarely needed; focus on if.
        }
        out.push_str(&current);
        if idx < body.lines().count().saturating_sub(1) {
            out.push('\n');
        }
    }
    if body.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn polish_null_in_condition(cond: &str) -> String {
    let c = cond.trim();
    for (suf, null_suf) in [(" == 0", " == null"), (" != 0", " != null")] {
        if let Some(name) = c.strip_suffix(suf) {
            let name = name.trim();
            if is_java_ident(name) && !looks_like_primitive_local(name) && !looks_like_boolean_local(name)
            {
                return format!("{}{}", name, null_suf);
            }
        }
    }
    c.to_string()
}

fn looks_like_boolean_local(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 2 && b[0] == b'z' && b[1..].iter().all(|c| c.is_ascii_digit())
}

fn looks_like_primitive_local(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 2
        && matches!(b[0], b'i' | b'j' | b'f' | b'd' | b'c' | b'b')
        && b[1..].iter().all(|c| c.is_ascii_digit())
}

/// Remove `continue;` that immediately precedes a closing `}` when it is redundant
/// (other statements already appear in the same block). Keep a lone `continue;` so
/// `while (…) { continue; }` back-edges still round-trip in tests / empty loop bodies.
fn remove_trailing_continues(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut skip = std::collections::HashSet::new();
    for i in 0..lines.len() {
        if lines[i].trim() != "continue;" {
            continue;
        }
        let next = lines[i + 1..].iter().find(|l| !l.trim().is_empty());
        if !next.is_some_and(|l| l.trim().starts_with('}')) {
            continue;
        }
        let cont_indent = leading_indent(lines[i]).len();
        let has_prior_sibling = lines[..i].iter().rev().any(|l| {
            let t = l.trim();
            if t.is_empty() {
                return false;
            }
            let ind = leading_indent(l).len();
            if ind < cont_indent {
                return false; // left the block
            }
            ind == cont_indent && t != "continue;"
        });
        if has_prior_sibling {
            skip.insert(i);
        }
    }
    if skip.is_empty() {
        return body.to_string();
    }
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        if skip.contains(&i) {
            continue;
        }
        out.push_str(line);
        if i < lines.len().saturating_sub(1) {
            out.push('\n');
        }
    }
    out
}

fn replace_ident_as_expr(text: &str, var: &str, replacement: &str) -> String {
    if var.is_empty() || !text.contains(var) {
        return text.to_string();
    }
    let needs_wrap = replacement.contains(' ')
        || (replacement.starts_with('(') && !replacement.ends_with(')'))
        || is_cast_expr(replacement);
    let bytes = text.as_bytes();
    let v = var.as_bytes();
    let mut out = String::with_capacity(text.len() + replacement.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + v.len() <= bytes.len() && &bytes[i..i + v.len()] == v {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after_ok = i + v.len() == bytes.len() || !is_ident_byte(bytes[i + v.len()]);
            if before_ok && after_ok {
                let next = bytes.get(i + v.len()).copied();
                let as_receiver = matches!(next, Some(b'.') | Some(b'['));
                if as_receiver && needs_wrap {
                    out.push('(');
                    out.push_str(replacement);
                    out.push(')');
                } else {
                    out.push_str(replacement);
                }
                i += v.len();
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Merge nested `if (A) { if (B) { BODY } }` (no else on either) into `if (A && B) { BODY }`.
fn merge_nested_if_and(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..8 {
        let next = merge_nested_if_and_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn merge_nested_if_and_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    for i in 0..lines.len() {
        let Some(cond_a) = parse_if_condition(lines[i]) else {
            continue;
        };
        let Some(outer_close) = find_closing_brace_line(&lines, i) else {
            continue;
        };
        if lines[outer_close].trim() != "}" {
            continue;
        }
        let mut j = i + 1;
        while j < outer_close && lines[j].trim().is_empty() {
            j += 1;
        }
        if j >= outer_close {
            continue;
        }
        let Some(cond_b) = parse_if_condition(lines[j]) else {
            continue;
        };
        let Some(inner_close) = find_closing_brace_line(&lines, j) else {
            continue;
        };
        if lines[inner_close].trim() != "}" {
            continue;
        }
        if (inner_close + 1..outer_close).any(|t| !lines[t].trim().is_empty()) {
            continue;
        }
        let indent = leading_indent(lines[i]);
        let mut out = String::new();
        for (idx, line) in lines.iter().enumerate() {
            if idx == i {
                out.push_str(&format!("{}if ({} && {}) {{\n", indent, cond_a, cond_b));
                for l in &lines[j + 1..inner_close] {
                    out.push_str(l);
                    out.push('\n');
                }
                out.push_str(&format!("{}}}", indent));
                if outer_close < lines.len().saturating_sub(1) || body.ends_with('\n') {
                    out.push('\n');
                }
                continue;
            }
            if idx > i && idx <= outer_close {
                continue;
            }
            out.push_str(line);
            if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
                out.push('\n');
            }
        }
        return out;
    }
    body.to_string()
}

fn parse_else_if_condition(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = t.strip_prefix("} else if (")?;
    let end = rest.find(") {")?;
    Some(rest[..end].trim().to_string())
}

fn normalized_block_stmts(lines: &[&str], start: usize, end: usize) -> Vec<String> {
    lines[start..end]
        .iter()
        .map(|l| l.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// `if (A) { BODY } else if (B) { BODY }` (no further else) → `if (A || B) { BODY }`
fn merge_short_circuit_or(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..8 {
        let next = merge_short_circuit_or_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn merge_short_circuit_or_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    for i in 0..lines.len() {
        let Some(cond_a) = parse_if_condition(lines[i]) else {
            continue;
        };
        let Some(then_close) = find_closing_brace_line(&lines, i) else {
            continue;
        };
        let else_if_line = then_close;
        let Some(cond_b) = parse_else_if_condition(lines[else_if_line]) else {
            continue;
        };
        let Some(else_close) = find_closing_brace_line(&lines, else_if_line) else {
            continue;
        };
        // find_closing_brace_line on `} else if` returns the else-if body's close; ensure
        // that line isn't `} else {` / `} else if` (would mean a further chain arm).
        let close_trim = lines[else_close].trim();
        if close_trim != "}" {
            continue;
        }
        let then_body = normalized_block_stmts(&lines, i + 1, then_close);
        let else_body = normalized_block_stmts(&lines, else_if_line + 1, else_close);
        if then_body.is_empty() || then_body != else_body {
            continue;
        }
        let indent = leading_indent(lines[i]);
        let mut out = String::new();
        for (idx, line) in lines.iter().enumerate() {
            if idx == i {
                out.push_str(&format!("{}if ({} || {}) {{\n", indent, cond_a, cond_b));
                for l in &lines[i + 1..then_close] {
                    out.push_str(l);
                    out.push('\n');
                }
                out.push_str(&format!("{}}}", indent));
                if else_close < lines.len().saturating_sub(1) || body.ends_with('\n') {
                    out.push('\n');
                }
                continue;
            }
            if idx > i && idx <= else_close {
                continue;
            }
            out.push_str(line);
            if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
                out.push('\n');
            }
        }
        return out;
    }
    body.to_string()
}

/// `if (c) { x = a; } else { x = b; }` → `x = c ? a : b;`
fn fold_assign_ternary(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..8 {
        let next = fold_assign_ternary_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn fold_assign_ternary_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    for i in 0..lines.len() {
        let Some(cond) = parse_if_condition(lines[i]) else {
            continue;
        };
        let Some(then_close) = find_closing_brace_line(&lines, i) else {
            continue;
        };
        if lines[then_close].trim() != "} else {" {
            continue;
        }
        let Some(else_close) = find_closing_brace_line(&lines, then_close) else {
            continue;
        };
        let then_stmts: Vec<&str> = lines[i + 1..then_close]
            .iter()
            .copied()
            .filter(|l| !l.trim().is_empty())
            .collect();
        let else_stmts: Vec<&str> = lines[then_close + 1..else_close]
            .iter()
            .copied()
            .filter(|l| !l.trim().is_empty())
            .collect();
        if then_stmts.len() != 1 || else_stmts.len() != 1 {
            continue;
        }
        let Some((var_a, expr_a)) = parse_simple_assign_line(then_stmts[0]) else {
            continue;
        };
        let Some((var_b, expr_b)) = parse_simple_assign_line(else_stmts[0]) else {
            continue;
        };
        if var_a != var_b {
            continue;
        }
        let lhs = {
            let ta_owned = strip_trailing_comment(then_stmts[0]);
            let tb_owned = strip_trailing_comment(else_stmts[0]);
            let ta = ta_owned.trim();
            let tb = tb_owned.trim();
            let lhs_a = ta.split(" = ").next().unwrap_or(&var_a).trim();
            let lhs_b = tb.split(" = ").next().unwrap_or(&var_b).trim();
            if lhs_a.split_whitespace().count() > 1 {
                lhs_a.to_string()
            } else if lhs_b.split_whitespace().count() > 1 {
                lhs_b.to_string()
            } else {
                var_a.clone()
            }
        };
        let indent = leading_indent(lines[i]);
        let mut out = String::new();
        for (idx, line) in lines.iter().enumerate() {
            if idx == i {
                out.push_str(&format!(
                    "{}{} = {} ? {} : {};",
                    indent, lhs, cond, expr_a, expr_b
                ));
                if else_close < lines.len().saturating_sub(1) || body.ends_with('\n') {
                    out.push('\n');
                }
                continue;
            }
            if idx > i && idx <= else_close {
                continue;
            }
            out.push_str(line);
            if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
                out.push('\n');
            }
        }
        return out;
    }
    body.to_string()
}

fn parse_iterator_assign(line: &str) -> Option<(String, String)> {
    let (var, rhs) = parse_simple_assign_line(line)?;
    let coll = rhs.strip_suffix(".iterator()")?.trim();
    if coll.is_empty() {
        return None;
    }
    Some((var, coll.to_string()))
}

fn parse_while_condition(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = t.strip_prefix("while (")?;
    let end = rest.find(") {")?;
    Some(rest[..end].trim().to_string())
}

fn parse_while_has_next(line: &str, it: &str) -> bool {
    parse_while_condition(line).is_some_and(|cond| cond == format!("{}.hasNext()", it))
}

/// `Type x = (Type) it.next();` / `x = (Type) it.next();` / `x = it.next();`
fn parse_iterator_next_line(line: &str, it: &str) -> Option<(Option<String>, String)> {
    let (var, rhs) = parse_simple_assign_line(line)?;
    let rhs = rhs.trim();
    let next_call = format!("{}.next()", it);
    let ty_opt = if let Some(rest) = rhs.strip_prefix('(') {
        let close = rest.find(')')?;
        let ty = rest[..close].trim();
        let after = rest[close + 1..].trim();
        if after != next_call {
            return None;
        }
        Some(ty.to_string())
    } else if rhs == next_call {
        None
    } else {
        return None;
    };
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    let lhs = stmt.split(" = ").next()?.trim();
    let declared_ty = if lhs.split_whitespace().count() > 1 {
        let parts: Vec<&str> = lhs.split_whitespace().collect();
        Some(parts[..parts.len() - 1].join(" "))
    } else {
        ty_opt.clone()
    };
    Some((declared_ty.or(ty_opt), var))
}

/// Restore `for (Type x : coll)` from iterator while-loops.
fn restore_foreach_iterator(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..8 {
        let next = restore_foreach_iterator_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn restore_foreach_iterator_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    for i in 0..lines.len() {
        let Some((it, coll)) = parse_iterator_assign(lines[i]) else {
            continue;
        };
        let mut j = i + 1;
        while j < lines.len() && lines[j].trim().is_empty() {
            j += 1;
        }
        if j >= lines.len() || !parse_while_has_next(lines[j], &it) {
            continue;
        }
        let Some(while_close) = find_closing_brace_line(&lines, j) else {
            continue;
        };
        let mut k = j + 1;
        while k < while_close && lines[k].trim().is_empty() {
            k += 1;
        }
        if k >= while_close {
            continue;
        }
        let Some((ty_opt, elem_var)) = parse_iterator_next_line(lines[k], &it) else {
            continue;
        };
        let indent = leading_indent(lines[j]);
        let ty = ty_opt.unwrap_or_else(|| "Object".to_string());
        let coll_expr = if coll.is_empty() {
            "/* iterator */".to_string()
        } else {
            coll
        };
        let mut out = String::new();
        for (idx, line) in lines.iter().enumerate() {
            if idx == i {
                continue;
            }
            if idx == j {
                out.push_str(&format!(
                    "{}for ({} {} : {}) {{\n",
                    indent, ty, elem_var, coll_expr
                ));
                for l in &lines[k + 1..while_close] {
                    out.push_str(l);
                    out.push('\n');
                }
                out.push_str(&format!("{}}}", indent));
                if while_close < lines.len().saturating_sub(1) || body.ends_with('\n') {
                    out.push('\n');
                }
                continue;
            }
            if idx > j && idx <= while_close {
                continue;
            }
            out.push_str(line);
            if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
                out.push('\n');
            }
        }
        return out;
    }
    body.to_string()
}

fn strip_null_check_expr(expr: &str) -> Option<String> {
    let e = expr.trim();
    const PREFIXES: &[&str] = &[
        "java.util.Objects.requireNonNull(",
        "Objects.requireNonNull(",
        "kotlin.jvm.internal.Intrinsics.checkNotNull(",
        "Intrinsics.checkNotNull(",
        "kotlin.jvm.internal.Intrinsics.checkNotNullParameter(",
        "Intrinsics.checkNotNullParameter(",
        "kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(",
        "Intrinsics.checkNotNullExpressionValue(",
    ];
    for p in PREFIXES {
        if let Some(rest) = e.strip_prefix(p) {
            if !rest.ends_with(')') {
                continue;
            }
            let inner = &rest[..rest.len() - 1];
            if let Some(arg) = split_first_arg(inner) {
                return Some(arg);
            }
        }
    }
    None
}

fn split_first_arg(args: &str) -> Option<String> {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escape = false;
    for (i, c) in args.chars().enumerate() {
        if in_str {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                let a = args[..i].trim();
                return if a.is_empty() {
                    None
                } else {
                    Some(a.to_string())
                };
            }
            _ => {}
        }
    }
    let a = args.trim();
    if a.is_empty() {
        None
    } else {
        Some(a.to_string())
    }
}

/// Strip `Objects.requireNonNull` / Kotlin `Intrinsics.checkNotNull*` wrappers.
fn strip_require_non_null(body: &str) -> String {
    let mut out = String::new();
    let line_count = body.lines().count();
    for (idx, line) in body.lines().enumerate() {
        let binding = strip_trailing_comment(line);
        let stmt = binding.trim();
        let comment = line.get(binding.len()..).unwrap_or("");
        let indent = leading_indent(line);

        // Standalone call statement → drop
        if stmt.ends_with(';') {
            let expr = stmt.trim_end_matches(';').trim();
            if strip_null_check_expr(expr).is_some() {
                continue;
            }
        }

        // Assign: x = Objects.requireNonNull(y); → x = y;
        if let Some((var, rhs)) = parse_simple_assign_line(line) {
            if let Some(inner) = strip_null_check_expr(&rhs) {
                let lhs = {
                    let s = binding.trim();
                    s.split(" = ").next().unwrap_or(&var).trim()
                };
                out.push_str(&format!("{}{} = {};{}", indent, lhs, inner, comment));
                if idx < line_count.saturating_sub(1) {
                    out.push('\n');
                }
                continue;
            }
        }

        out.push_str(line);
        if idx < line_count.saturating_sub(1) {
            out.push('\n');
        }
    }
    if body.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn parse_catch_header(line: &str) -> Option<(String, String)> {
    let t = line.trim();
    let rest = t.strip_prefix("} catch (")?;
    let end = rest.find(") {")?;
    let inside = rest[..end].trim();
    let var = inside.split_whitespace().last()?.to_string();
    if !is_java_ident(&var) {
        return None;
    }
    let types = inside[..inside.len() - var.len()].trim().to_string();
    if types.is_empty() {
        return None;
    }
    Some((types, var))
}

/// Peel identical trailing cleanup from try + catch bodies into a single `finally`.
///
/// jadx-style duplicate-path finally: when every catch (and the try) ends with the same
/// non-empty cleanup statements, emit them once in `finally` (unless a `finally` already exists).
pub fn merge_duplicate_finally(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..8 {
        let next = merge_duplicate_finally_once(&current);
        if next == current {
            return current;
        }
        current = next;
    }
    current
}

fn merge_duplicate_finally_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    if lines.len() < 6 {
        return body.to_string();
    }
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        if t == "try {" || t.ends_with(" try {") {
            if let Some(transformed) = try_merge_finally_at(&lines, i) {
                return transformed;
            }
        }
        i += 1;
    }
    body.to_string()
}

fn try_merge_finally_at(lines: &[&str], try_line: usize) -> Option<String> {
    let try_indent = leading_indent(lines[try_line]).to_string();
    let mut depth = 0i32;
    let try_body_start = try_line + 1;
    let mut try_body_end = None;
    let mut catches: Vec<(usize, usize)> = Vec::new();
    let mut j = try_line;
    let mut catch_body_start = None;
    while j < lines.len() {
        let t = lines[j].trim();
        let opens = t.chars().filter(|c| *c == '{').count() as i32;
        let closes = t.chars().filter(|c| *c == '}').count() as i32;
        if j == try_line {
            depth = 1;
            j += 1;
            continue;
        }
        if depth == 1 && t.starts_with("} catch (") {
            if let Some(cs) = catch_body_start {
                catches.push((cs, j));
            } else {
                try_body_end = Some(j);
            }
            catch_body_start = Some(j + 1);
            j += 1;
            continue;
        }
        if depth == 1 && (t == "} finally {" || t.starts_with("} finally {")) {
            return None;
        }
        if depth == 1 && t == "}" && catch_body_start.is_some() {
            if let Some(cs) = catch_body_start {
                catches.push((cs, j));
            }
            let try_end = try_body_end?;
            if catches.is_empty() {
                return None;
            }
            return peel_common_suffix(
                lines,
                try_line,
                &try_indent,
                try_body_start,
                try_end,
                &catches,
                j,
            );
        }
        depth += opens - closes;
        if depth <= 0 {
            return None;
        }
        j += 1;
    }
    None
}

fn peel_common_suffix(
    lines: &[&str],
    try_line: usize,
    try_indent: &str,
    try_body_start: usize,
    try_body_end: usize,
    catches: &[(usize, usize)],
    close_line: usize,
) -> Option<String> {
    let try_stmts = collect_top_level_stmts(lines, try_body_start, try_body_end);
    if try_stmts.is_empty() {
        return None;
    }
    let catch_stmts: Vec<Vec<String>> = catches
        .iter()
        .map(|&(s, e)| collect_top_level_stmts(lines, s, e))
        .collect();
    if catch_stmts.iter().any(|c| c.is_empty()) {
        return None;
    }
    let mut suffix_len = 0usize;
    let max_possible = try_stmts
        .len()
        .min(catch_stmts.iter().map(|c| c.len()).min().unwrap_or(0));
    while suffix_len < max_possible {
        let ti = try_stmts.len() - 1 - suffix_len;
        let want = try_stmts[ti].trim();
        if want.is_empty()
            || want == "return;"
            || want.starts_with("return ")
            || want.starts_with("throw ")
            || want.starts_with("if (")
            || want.starts_with("for ")
            || want.starts_with("while ")
            || want.starts_with("switch ")
        {
            break;
        }
        let ok = catch_stmts.iter().all(|c| {
            let ci = c.len() - 1 - suffix_len;
            c[ci].trim() == want
        });
        if !ok {
            break;
        }
        suffix_len += 1;
    }
    if suffix_len == 0 {
        return None;
    }
    let suffix = &try_stmts[try_stmts.len() - suffix_len..];
    let cleanup_ok = suffix.iter().any(|s| {
        let t = s.trim();
        t.contains(".close(")
            || t.contains(".unlock(")
            || t.contains(".recycle(")
            || t.contains(".release(")
            || t.contains(".disconnect(")
            || t.contains(".shutdown(")
    }) || suffix.iter().all(|s| {
        let t = s.trim().trim_end_matches(';');
        t.contains('.') && !t.contains('=') && !t.starts_with("throw")
    });
    if !cleanup_ok {
        return None;
    }

    let mut out: Vec<String> = lines[..try_line].iter().map(|s| (*s).to_string()).collect();
    out.push(lines[try_line].to_string());
    let try_keep = try_stmts.len() - suffix_len;
    for s in &try_stmts[..try_keep] {
        out.push(s.clone());
    }
    for &(cs, ce) in catches {
        let catch_hdr = cs - 1;
        out.push(lines[catch_hdr].to_string());
        let stmts = collect_top_level_stmts(lines, cs, ce);
        let keep = stmts.len() - suffix_len;
        for s in &stmts[..keep] {
            out.push(s.clone());
        }
    }
    let finally_indent = format!("{try_indent}    ");
    out.push(format!("{try_indent}}} finally {{"));
    for s in suffix {
        out.push(format!("{finally_indent}{}", s.trim()));
    }
    out.push(format!("{try_indent}}}"));
    for line in lines.iter().skip(close_line + 1) {
        out.push((*line).to_string());
    }
    Some(out.join("\n"))
}

fn collect_top_level_stmts(lines: &[&str], start: usize, end: usize) -> Vec<String> {
    let mut stmts = Vec::new();
    let mut i = start;
    while i < end {
        let t = lines[i].trim();
        if t.is_empty() {
            i += 1;
            continue;
        }
        if t.ends_with('{') {
            let block_start = i;
            let mut depth = 0i32;
            while i < end {
                let tt = lines[i].trim();
                depth += tt.chars().filter(|c| *c == '{').count() as i32;
                depth -= tt.chars().filter(|c| *c == '}').count() as i32;
                i += 1;
                if depth <= 0 {
                    break;
                }
            }
            // Opaque nested block — blocks suffix matching across it.
            stmts.push(lines[block_start..i].join("\n"));
            continue;
        }
        stmts.push(lines[i].to_string());
        i += 1;
    }
    stmts
}

/// Merge consecutive identical catch bodies into multi-catch `A | B`.
fn merge_multi_catch(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..8 {
        let next = merge_multi_catch_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn merge_multi_catch_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    for i in 0..lines.len() {
        let Some((types_a, var_a)) = parse_catch_header(lines[i]) else {
            continue;
        };
        let Some(close_a) = find_closing_brace_line(&lines, i) else {
            continue;
        };
        // `} catch (B …) {` often closes the previous catch on the same line.
        let (next_catch, body_a) = if parse_catch_header(lines[close_a]).is_some() {
            (close_a, lines[i + 1..close_a].to_vec())
        } else {
            let mut j = close_a + 1;
            while j < lines.len() && lines[j].trim().is_empty() {
                j += 1;
            }
            if j >= lines.len() || parse_catch_header(lines[j]).is_none() {
                continue;
            }
            (j, lines[i + 1..close_a].to_vec())
        };
        let Some((types_b, var_b)) = parse_catch_header(lines[next_catch]) else {
            continue;
        };
        if var_a != var_b {
            continue;
        }
        let Some(close_b) = find_closing_brace_line(&lines, next_catch) else {
            continue;
        };
        let (body_b, consume_end) = if parse_catch_header(lines[close_b]).is_some() {
            (lines[next_catch + 1..close_b].to_vec(), close_b - 1)
        } else {
            (lines[next_catch + 1..close_b].to_vec(), close_b)
        };
        let norm = |v: &[&str]| -> Vec<String> {
            v.iter()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        };
        if norm(&body_a) != norm(&body_b) {
            continue;
        }
        let indent = leading_indent(lines[i]);
        let mut out = String::new();
        for (idx, line) in lines.iter().enumerate() {
            if idx == i {
                out.push_str(&format!(
                    "{}}} catch ({} | {} {}) {{\n",
                    indent, types_a, types_b, var_a
                ));
                for l in &body_a {
                    out.push_str(l);
                    out.push('\n');
                }
                out.push_str(&format!("{}}}", indent));
                if consume_end < lines.len().saturating_sub(1) || body.ends_with('\n') {
                    out.push('\n');
                }
                continue;
            }
            if idx > i && idx <= consume_end {
                continue;
            }
            out.push_str(line);
            if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
                out.push('\n');
            }
        }
        return out;
    }
    body.to_string()
}

/// Text-level do-while: `while (true) { BODY; if (!cond) break; }` → `do { BODY } while (cond);`
fn restore_do_while_text(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..4 {
        let next = restore_do_while_text_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// Parse `if (cond) break;` (single-line) → Some(cond).
fn parse_if_break_oneliner(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = t.strip_prefix("if (")?;
    // Find matching `)` before ` break;`
    let mut depth = 0i32;
    let mut close = None;
    for (i, c) in rest.chars().enumerate() {
        match c {
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    close = Some(i);
                    break;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    let close = close?;
    let cond = rest[..close].trim();
    let after = rest[close + 1..].trim();
    if after == "break;" {
        Some(cond.to_string())
    } else {
        None
    }
}

fn invert_while_cond(raw_cond: &str) -> String {
    if let Some(inner) = strip_outer_not_parens(raw_cond) {
        inner
    } else if let Some(inner) = raw_cond.strip_prefix('!').map(str::trim) {
        if is_java_ident(inner) {
            inner.to_string()
        } else {
            format!("!({})", raw_cond)
        }
    } else {
        format!("!({})", raw_cond)
    }
}

fn restore_do_while_text_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    for i in 0..lines.len() {
        if lines[i].trim() != "while (true) {" {
            continue;
        }
        let Some(while_close) = find_closing_brace_line(&lines, i) else {
            continue;
        };
        if while_close <= i + 1 {
            continue;
        }
        // Find last non-empty line before while_close.
        let mut last = while_close;
        while last > i + 1 && lines[last - 1].trim().is_empty() {
            last -= 1;
        }
        let last_content = last - 1;
        if last_content <= i {
            continue;
        }

        // Pattern A: single-line `if (cond) break;` as last statement.
        if let Some(raw_cond) = parse_if_break_oneliner(lines[last_content]) {
            let while_cond = invert_while_cond(&raw_cond);
            return emit_do_while(
                &lines,
                body,
                i,
                while_close,
                last_content,
                last_content,
                &while_cond,
            );
        }

        // Pattern B/C: trailing `if (…) { … }` block ending at last_content.
        let if_close = last_content;
        if lines[if_close].trim() != "}" {
            continue;
        }
        let mut depth = 1i32;
        let mut if_idx = None;
        for t in (i + 1..if_close).rev() {
            let tr = lines[t].trim();
            depth += tr.matches('}').count() as i32;
            depth -= tr.matches('{').count() as i32;
            if depth == 0 {
                if parse_if_condition(lines[t]).is_some() {
                    if_idx = Some(t);
                }
                break;
            }
        }
        let Some(if_idx) = if_idx else {
            continue;
        };
        let Some(inner_close) = find_if_chain_end(&lines, if_idx) else {
            continue;
        };
        if inner_close != if_close {
            continue;
        }
        let Some(raw_cond) = parse_if_condition(lines[if_idx]) else {
            continue;
        };

        // Analyze then / else for break-only exit.
        let (then_start, then_end, else_start, else_end) =
            split_if_then_else(&lines, if_idx, inner_close);
        let then_body: Vec<&str> = lines[then_start..then_end]
            .iter()
            .copied()
            .filter(|l| !l.trim().is_empty())
            .collect();
        let else_body: Vec<&str> = if let (Some(es), Some(ee)) = (else_start, else_end) {
            lines[es..ee]
                .iter()
                .copied()
                .filter(|l| !l.trim().is_empty())
                .collect()
        } else {
            Vec::new()
        };

        let while_cond = if then_body.len() == 1
            && then_body[0].trim() == "break;"
            && else_body.is_empty()
        {
            // `if (cond) { break; }` → while (!cond)
            invert_while_cond(&raw_cond)
        } else if then_body.is_empty()
            && else_body.len() == 1
            && else_body[0].trim() == "break;"
        {
            // `if (cond) { } else { break; }` → while (cond)
            raw_cond
        } else {
            continue;
        };

        return emit_do_while(&lines, body, i, while_close, if_idx, if_close, &while_cond);
    }
    body.to_string()
}

/// Returns (then_start, then_end, else_start?, else_end?) exclusive ranges inside if.
fn split_if_then_else(
    lines: &[&str],
    if_idx: usize,
    if_close: usize,
) -> (usize, usize, Option<usize>, Option<usize>) {
    // Look for `} else {` between if_idx and if_close.
    let mut depth = 0i32;
    for t in if_idx + 1..if_close {
        let tr = lines[t].trim();
        if depth == 0 && (tr == "} else {" || tr.starts_with("} else {")) {
            return (if_idx + 1, t, Some(t + 1), Some(if_close));
        }
        depth += tr.matches('{').count() as i32;
        depth -= tr.matches('}').count() as i32;
    }
    (if_idx + 1, if_close, None, None)
}

fn emit_do_while(
    lines: &[&str],
    body: &str,
    while_i: usize,
    while_close: usize,
    drop_from: usize,
    drop_to: usize,
    while_cond: &str,
) -> String {
    let indent = leading_indent(lines[while_i]);
    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if idx == while_i {
            out.push_str(&format!("{}do {{\n", indent));
            for l in &lines[while_i + 1..drop_from] {
                out.push_str(l);
                out.push('\n');
            }
            out.push_str(&format!("{}}} while ({});", indent, while_cond));
            if while_close < lines.len().saturating_sub(1) || body.ends_with('\n') {
                out.push('\n');
            }
            continue;
        }
        if idx > while_i && idx <= while_close {
            continue;
        }
        let _ = (drop_from, drop_to); // drops covered by while_close skip
        out.push_str(line);
        if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

/// Restore enum switches from `$SwitchMap$…[e.ordinal()]` / `e.ordinal()` forms.
fn restore_enum_switchmap(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..8 {
        let next = restore_enum_switchmap_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current = restore_enum_switchmap_cases(&current);
    current
}

fn parse_switch_header(line: &str) -> Option<String> {
    let t = line.trim();
    let rest = t.strip_prefix("switch (")?;
    if !rest.ends_with(") {") {
        return None;
    }
    Some(rest[..rest.len() - 3].trim().to_string())
}

/// `…$SwitchMap$…[e.ordinal()]` → `e`
fn extract_switchmap_indexed_ordinal(expr: &str) -> Option<String> {
    let e = expr.trim();
    if !e.contains("$SwitchMap$") {
        return None;
    }
    let open = e.rfind('[')?;
    let close = e.rfind(']')?;
    if close != e.len() - 1 || close <= open {
        return None;
    }
    let before = e[..open].trim();
    if !before.contains("$SwitchMap$") {
        return None;
    }
    let index = e[open + 1..close].trim();
    let enum_expr = index.strip_suffix(".ordinal()")?.trim();
    if enum_expr.is_empty() {
        return None;
    }
    Some(enum_expr.to_string())
}

/// Extract `$SwitchMap$…` field key from an expression/assign RHS.
fn extract_switchmap_field_key(expr: &str) -> Option<String> {
    let e = expr.trim();
    let idx = e.find("$SwitchMap$")?;
    let rest = &e[idx..];
    let end = rest
        .find(|c: char| c == '[' || c == ';' || c == ' ' || c == ')' || c == ',')
        .unwrap_or(rest.len());
    let key = rest[..end].trim();
    if key.starts_with("$SwitchMap$") {
        Some(key.to_string())
    } else {
        None
    }
}

/// `$SwitchMap$com$example$Color` → (`com.example.Color`, `Color`)
fn enum_names_from_switchmap_key(key: &str) -> Option<(String, String)> {
    let rest = key.strip_prefix("$SwitchMap$")?;
    if rest.is_empty() {
        return None;
    }
    let fq = rest.replace('$', ".");
    let simple = fq.rsplit('.').next()?.to_string();
    Some((fq, simple))
}

/// Map `(switchmap_field_key, slot) → (enum_type_simple_or_fq, const_name)`.
fn parse_switchmap_assignments(
    body: &str,
) -> std::collections::HashMap<(String, i32), (String, String)> {
    let mut map = std::collections::HashMap::new();
    // Track local vars assigned from a SwitchMap field.
    let mut local_to_key: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in body.lines() {
        let binding = strip_trailing_comment(line);
        let stmt = binding.trim();
        if let Some((var, rhs)) = parse_simple_assign_line(line) {
            if let Some(key) = extract_switchmap_field_key(&rhs) {
                if !rhs.contains('[') {
                    local_to_key.insert(var, key);
                }
            }
        }
        // `…$SwitchMap$…[Color.RED.ordinal()] = 1;` or `map[Color.RED.ordinal()] = 1;`
        if !stmt.ends_with(';') || !stmt.contains(".ordinal()]") {
            continue;
        }
        let eq = match stmt.rfind(" = ") {
            Some(p) => p,
            None => continue,
        };
        let lhs = stmt[..eq].trim();
        let rhs = stmt[eq + 3..].trim_end_matches(';').trim();
        let Ok(slot) = rhs.parse::<i32>() else {
            continue;
        };
        let open = match lhs.rfind('[') {
            Some(p) => p,
            None => continue,
        };
        let close = match lhs.rfind(']') {
            Some(p) => p,
            None => continue,
        };
        if close != lhs.len() - 1 {
            continue;
        }
        let map_expr = lhs[..open].trim();
        let index = lhs[open + 1..close].trim();
        let enum_ord = match index.strip_suffix(".ordinal()") {
            Some(e) => e.trim(),
            None => continue,
        };
        // Color.RED or com.example.Color.GREEN
        let (enum_ty, const_name) = match enum_ord.rsplit_once('.') {
            Some((ty, name)) if is_java_ident(name) => (ty.to_string(), name.to_string()),
            _ => continue,
        };
        let key = if let Some(k) = extract_switchmap_field_key(map_expr) {
            k
        } else if is_java_ident(map_expr) {
            match local_to_key.get(map_expr) {
                Some(k) => k.clone(),
                None => continue,
            }
        } else {
            continue;
        };
        map.insert((key, slot), (enum_ty, const_name));
    }
    map
}

/// After switch selector restore, rewrite `case N:` using SwitchMap slot assignments.
fn restore_enum_switchmap_cases(body: &str) -> String {
    let assignments = parse_switchmap_assignments(body);
    if assignments.is_empty() {
        return body.to_string();
    }
    let lines: Vec<&str> = body.lines().collect();
    let mut out_lines: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let Some(expr) = parse_switch_header(lines[i]) else {
            out_lines.push(lines[i].to_string());
            i += 1;
            continue;
        };
        // Find SwitchMap key associated with this switch (from prior map assign or leftover).
        let mut switchmap_key: Option<String> = None;
        // Prefer key from assignments that mention enums matching expr type — scan nearby.
        for j in (0..i).rev() {
            let t = lines[j].trim();
            if t.is_empty() {
                continue;
            }
            if let Some((var, rhs)) = parse_simple_assign_line(lines[j]) {
                if let Some(key) = extract_switchmap_field_key(&rhs) {
                    if !rhs.contains('[') {
                        // `int[] map = …$SwitchMap$…` — only useful if switch used map (already rewritten).
                        let _ = var;
                        switchmap_key = Some(key);
                        break;
                    }
                }
            }
            if let Some(key) = extract_switchmap_field_key(t) {
                switchmap_key = Some(key);
                break;
            }
            break;
        }
        // If body still has assignment lines for a key, use the key that has slots.
        if switchmap_key.is_none() {
            // Pick any key present in assignments (typical: one SwitchMap per method).
            if let Some(((k, _), _)) = assignments.iter().next() {
                switchmap_key = Some(k.clone());
            }
        }
        let key = switchmap_key.unwrap_or_default();
        let enum_simple = enum_names_from_switchmap_key(&key).map(|(_, s)| s);
        let indent = leading_indent(lines[i]);
        out_lines.push(format!("{}switch ({}) {{", indent, expr));
        let Some(sw_close) = find_closing_brace_line(&lines, i) else {
            i += 1;
            continue;
        };
        for j in i + 1..sw_close {
            let t = lines[j].trim();
            if let Some(rest) = t.strip_prefix("case ") {
                if let Some(num_s) = rest.strip_suffix(':') {
                    if let Ok(n) = num_s.trim().parse::<i32>() {
                        if let Some((enum_ty, const_name)) = assignments.get(&(key.clone(), n)) {
                            let label = match &enum_simple {
                                Some(s) if enum_ty == s || enum_ty.ends_with(&format!(".{}", s)) => {
                                    format!("{}.{}", s, const_name)
                                }
                                Some(s) if enum_ty.rsplit('.').next() == Some(s.as_str()) => {
                                    format!("{}.{}", s, const_name)
                                }
                                _ => {
                                    // Prefer simple name when ty is already simple.
                                    if enum_ty.contains('.') {
                                        format!("{}.{}", enum_ty, const_name)
                                    } else {
                                        format!("{}.{}", enum_ty, const_name)
                                    }
                                }
                            };
                            let case_indent = leading_indent(lines[j]);
                            out_lines.push(format!("{}case {}:", case_indent, label));
                            continue;
                        }
                    }
                }
            }
            out_lines.push(lines[j].to_string());
        }
        out_lines.push(lines[sw_close].to_string());
        i = sw_close + 1;
    }
    let mut out = out_lines.join("\n");
    if body.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    // Drop SwitchMap assignment lines used only for case tables (keep if still referenced).
    out = strip_consumed_switchmap_assignments(&out);
    out
}

fn strip_consumed_switchmap_assignments(body: &str) -> String {
    // Remove lines like `…$SwitchMap$…[Color.RED.ordinal()] = 1;` after cases rewritten.
    let mut out = String::new();
    let line_count = body.lines().count();
    for (idx, line) in body.lines().enumerate() {
        let binding = strip_trailing_comment(line);
        let t = binding.trim();
        let drop = t.contains("$SwitchMap$")
            && t.contains(".ordinal()]")
            && t.contains(" = ")
            && t.ends_with(';');
        let drop_local = {
            // `map[Color.RED.ordinal()] = 1;`
            if let Some(open) = t.find('[') {
                t.contains(".ordinal()]")
                    && t.contains(" = ")
                    && t.ends_with(';')
                    && is_java_ident(t[..open].trim())
            } else {
                false
            }
        };
        if drop || drop_local {
            // skip
        } else {
            out.push_str(line);
            if idx < line_count.saturating_sub(1) {
                out.push('\n');
            }
        }
    }
    if body.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// `map[e.ordinal()]` → `(map, e)`
fn extract_map_var_ordinal(expr: &str) -> Option<(String, String)> {
    let e = expr.trim();
    let open = e.find('[')?;
    let close = e.rfind(']')?;
    if close != e.len() - 1 || close <= open {
        return None;
    }
    let map_var = e[..open].trim();
    if !is_java_ident(map_var) {
        return None;
    }
    let index = e[open + 1..close].trim();
    let enum_expr = index.strip_suffix(".ordinal()")?.trim();
    if enum_expr.is_empty() {
        return None;
    }
    Some((map_var.to_string(), enum_expr.to_string()))
}

fn extract_plain_ordinal(expr: &str) -> Option<String> {
    let e = expr.trim();
    let enum_expr = e.strip_suffix(".ordinal()")?.trim();
    if enum_expr.is_empty() || enum_expr.contains('[') {
        return None;
    }
    // Avoid `arr.length` style — require a receiver that looks like an expression/ident.
    Some(enum_expr.to_string())
}

fn line_assigns_switchmap(line: &str, map_var: &str) -> bool {
    let Some((var, rhs)) = parse_simple_assign_line(line) else {
        return false;
    };
    var == map_var && rhs.contains("$SwitchMap$")
}

fn restore_enum_switchmap_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    for i in 0..lines.len() {
        let Some(expr) = parse_switch_header(lines[i]) else {
            continue;
        };
        let indent = leading_indent(lines[i]);
        let (new_expr, drop_map_line): (String, Option<usize>) =
            if let Some(e) = extract_switchmap_indexed_ordinal(&expr) {
                (e, None)
            } else if let Some((map_var, e)) = extract_map_var_ordinal(&expr) {
                let mut map_line = None;
                let mut k = i;
                while k > 0 {
                    k -= 1;
                    if lines[k].trim().is_empty() {
                        continue;
                    }
                    if line_assigns_switchmap(lines[k], &map_var) {
                        map_line = Some(k);
                    }
                    break;
                }
                if map_line.is_some() {
                    (e, map_line)
                } else {
                    continue;
                }
            } else if let Some(e) = extract_plain_ordinal(&expr) {
                (e, None)
            } else {
                continue;
            };

        let mut out = String::new();
        for (idx, line) in lines.iter().enumerate() {
            if drop_map_line == Some(idx) {
                continue;
            }
            if idx == i {
                out.push_str(&format!("{}switch ({}) {{", indent, new_expr));
            } else {
                out.push_str(line);
            }
            if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
                out.push('\n');
            }
        }
        return out;
    }
    body.to_string()
}

/// Restore try-with-resources when finally only closes the declared resource(s).
fn restore_try_with_resources(body: &str) -> String {
    let mut current = body.to_string();
    for _ in 0..4 {
        let next = restore_try_with_resources_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn parse_resource_decl(line: &str) -> Option<(String, String, String)> {
    // `Type r = new Type(...);` or `Type r = expr;`
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    if !stmt.ends_with(';') {
        return None;
    }
    let eq = stmt.find(" = ")?;
    let lhs = stmt[..eq].trim();
    let rhs = stmt[eq + 3..].trim_end_matches(';').trim();
    if rhs.is_empty() {
        return None;
    }
    let parts: Vec<&str> = lhs.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let var = parts.last()?.to_string();
    if !is_java_ident(&var) {
        return None;
    }
    let ty = parts[..parts.len() - 1].join(" ");
    if ty.is_empty() || ty.starts_with("return") || ty.starts_with("if") {
        return None;
    }
    Some((ty, var, rhs.to_string()))
}

fn is_close_call(stmt: &str, resource: &str) -> bool {
    let t = stmt.trim().trim_end_matches(';').trim();
    t == format!("{}.close()", resource)
}

/// Collect consecutive resource decls immediately above `try_i` (blank lines allowed between).
fn collect_resource_decls_above(
    lines: &[&str],
    try_i: usize,
) -> Vec<(usize, String, String, String)> {
    let mut decls: Vec<(usize, String, String, String)> = Vec::new();
    let mut i = try_i;
    while i > 0 {
        i -= 1;
        if lines[i].trim().is_empty() {
            continue;
        }
        if let Some((ty, var, rhs)) = parse_resource_decl(lines[i]) {
            decls.push((i, ty, var, rhs));
            continue;
        }
        break;
    }
    decls.reverse();
    decls
}

/// True if finally body only closes the given resources (any order; sequential close units).
fn finally_body_only_closes_resources(
    lines: &[&str],
    body_start: usize,
    body_end: usize,
    resources: &[&str],
) -> bool {
    if resources.is_empty() {
        return false;
    }
    let mut slice: Vec<&str> = lines[body_start..body_end]
        .iter()
        .copied()
        .filter(|l| !l.trim().is_empty())
        .collect();
    if slice.is_empty() {
        return false;
    }
    let mut remaining: Vec<String> = resources.iter().map(|s| (*s).to_string()).collect();
    while !slice.is_empty() {
        let Some((res, consumed)) = take_one_resource_close_unit(&slice, &remaining) else {
            return false;
        };
        remaining.retain(|r| r != &res);
        slice = slice[consumed..].to_vec();
    }
    remaining.is_empty()
}

/// Consume one close-pattern unit for some resource in `remaining`.
/// Returns `(resource_name, lines_consumed)`.
fn take_one_resource_close_unit(slice: &[&str], remaining: &[String]) -> Option<(String, usize)> {
    if slice.is_empty() {
        return None;
    }
    // `r.close();`
    for res in remaining {
        if is_close_call(slice[0], res) {
            return Some((res.clone(), 1));
        }
    }
    // `if (r != null) { …close… }`
    if let Some(cond) = parse_if_condition(slice[0]) {
        let c = cond.replace(' ', "");
        let mut matched_res: Option<String> = None;
        for res in remaining {
            if c == format!("{}!=null", res) || c == format!("null!={}", res) {
                matched_res = Some(res.clone());
                break;
            }
        }
        let res = matched_res?;
        let if_close = find_closing_brace_line(slice, 0)?;
        if !close_block_only_closes(&slice[1..if_close], &res) {
            return None;
        }
        return Some((res, if_close + 1));
    }
    // `try { …close… } catch (…) { }` (empty catch)
    if slice[0].trim() == "try {" {
        let try_close = find_closing_brace_line(slice, 0)?;
        let try_body: Vec<&str> = slice[1..try_close]
            .iter()
            .copied()
            .filter(|l| !l.trim().is_empty())
            .collect();
        let (res, n) = take_one_resource_close_unit(&try_body, remaining)?;
        if n != try_body.len() {
            return None;
        }
        let mut i = try_close;
        let mut saw_catch = false;
        while i < slice.len() {
            let t = slice[i].trim();
            if parse_catch_header(slice[i]).is_some() || t.starts_with("} catch (") {
                let cclose = find_closing_brace_line(slice, i)?;
                let catch_body: Vec<&str> = slice[i + 1..cclose]
                    .iter()
                    .copied()
                    .filter(|l| !l.trim().is_empty())
                    .collect();
                if !catch_body.is_empty() {
                    return None;
                }
                saw_catch = true;
                i = cclose + 1;
                continue;
            }
            break;
        }
        if !saw_catch {
            return None;
        }
        return Some((res, i));
    }
    None
}

fn close_block_only_closes(lines: &[&str], resource: &str) -> bool {
    let slice: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| !l.trim().is_empty())
        .collect();
    if slice.is_empty() {
        return false;
    }
    if slice.len() == 1 && is_close_call(slice[0], resource) {
        return true;
    }
    // nested try { r.close(); } catch { }
    if slice[0].trim() == "try {" {
        let Some(try_close) = find_closing_brace_line(&slice, 0) else {
            return false;
        };
        let try_body: Vec<&str> = slice[1..try_close]
            .iter()
            .copied()
            .filter(|l| !l.trim().is_empty())
            .collect();
        if try_body.len() != 1 || !is_close_call(try_body[0], resource) {
            return false;
        }
        let mut i = try_close;
        while i < slice.len() {
            if parse_catch_header(slice[i]).is_some() || slice[i].trim().starts_with("} catch (") {
                let Some(cclose) = find_closing_brace_line(&slice, i) else {
                    return false;
                };
                let catch_body: Vec<&str> = slice[i + 1..cclose]
                    .iter()
                    .copied()
                    .filter(|l| !l.trim().is_empty())
                    .collect();
                if !catch_body.is_empty() {
                    return false;
                }
                i = cclose + 1;
                continue;
            }
            return false;
        }
        return true;
    }
    // `if (r != null) { r.close(); }`
    if let Some(cond) = parse_if_condition(slice[0]) {
        let c = cond.replace(' ', "");
        if c != format!("{}!=null", resource) && c != format!("null!={}", resource) {
            return false;
        }
        let Some(if_close) = find_closing_brace_line(&slice, 0) else {
            return false;
        };
        if if_close != slice.len() - 1 {
            return false;
        }
        let inner: Vec<&str> = slice[1..if_close]
            .iter()
            .copied()
            .filter(|l| !l.trim().is_empty())
            .collect();
        return inner.len() == 1 && is_close_call(inner[0], resource);
    }
    false
}

fn restore_try_with_resources_once(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    for try_i in 0..lines.len() {
        if lines[try_i].trim() != "try {" {
            continue;
        }
        let decls = collect_resource_decls_above(&lines, try_i);
        if decls.is_empty() {
            continue;
        }
        let resource_names: Vec<&str> = decls.iter().map(|(_, _, v, _)| v.as_str()).collect();

        let Some(try_close) = find_closing_brace_line(&lines, try_i) else {
            continue;
        };

        // Walk optional catch clauses, then require finally
        let mut cursor = try_close;
        let mut catch_ranges: Vec<(usize, usize)> = Vec::new();
        loop {
            let t = lines.get(cursor).map(|l| l.trim()).unwrap_or("");
            if parse_catch_header(lines[cursor]).is_some() || t.starts_with("} catch (") {
                let Some(cclose) = find_closing_brace_line(&lines, cursor) else {
                    break;
                };
                catch_ranges.push((cursor, cclose));
                cursor = cclose;
                continue;
            }
            break;
        }

        let ft = lines.get(cursor).map(|l| l.trim()).unwrap_or("");
        let finally_open = if ft == "} finally {" || ft.starts_with("} finally {") {
            cursor
        } else if ft == "finally {" {
            cursor
        } else {
            let mut j = cursor;
            if j < lines.len() && lines[j].trim() == "}" {
                j += 1;
                while j < lines.len() && lines[j].trim().is_empty() {
                    j += 1;
                }
            }
            if j < lines.len() && lines[j].trim() == "finally {" {
                j
            } else {
                continue;
            }
        };

        let Some(finally_close) = find_closing_brace_line(&lines, finally_open) else {
            continue;
        };
        if !finally_body_only_closes_resources(
            &lines,
            finally_open + 1,
            finally_close,
            &resource_names,
        ) {
            continue;
        }

        let decl_idxs: std::collections::HashSet<usize> =
            decls.iter().map(|(i, _, _, _)| *i).collect();
        let indent = leading_indent(lines[try_i]);
        let resources_hdr: String = decls
            .iter()
            .map(|(_, ty, var, rhs)| format!("{} {} = {}", ty, var, rhs))
            .collect::<Vec<_>>()
            .join("; ");

        let mut out = String::new();
        for (idx, line) in lines.iter().enumerate() {
            if decl_idxs.contains(&idx) {
                continue;
            }
            if idx == try_i {
                out.push_str(&format!("{}try ({}) {{\n", indent, resources_hdr));
                for l in &lines[try_i + 1..try_close] {
                    out.push_str(l);
                    out.push('\n');
                }
                if catch_ranges.is_empty() {
                    out.push_str(&format!("{}}}", indent));
                    if finally_close < lines.len().saturating_sub(1) || body.ends_with('\n') {
                        out.push('\n');
                    }
                } else {
                    for (ci, &(ch, cc)) in catch_ranges.iter().enumerate() {
                        let header = lines[ch].trim();
                        let hdr = if header.starts_with('}') {
                            header.to_string()
                        } else {
                            format!("}} {}", header)
                        };
                        out.push_str(&format!("{}{}\n", indent, hdr));
                        let body_end = if ci + 1 < catch_ranges.len()
                            || lines[cc].trim().starts_with("} finally")
                            || lines[cc].trim().starts_with("} catch")
                        {
                            cc
                        } else {
                            cc
                        };
                        for l in &lines[ch + 1..body_end] {
                            out.push_str(l);
                            out.push('\n');
                        }
                        if ci + 1 == catch_ranges.len() {
                            if lines[cc].trim().starts_with("} finally")
                                || (ci + 1 < catch_ranges.len())
                            {
                                out.push_str(&format!("{}}}", indent));
                            } else if lines[cc].trim() == "}" {
                                out.push_str(lines[cc]);
                            } else {
                                out.push_str(&format!("{}}}", indent));
                            }
                            if finally_close < lines.len().saturating_sub(1) || body.ends_with('\n')
                            {
                                out.push('\n');
                            }
                        }
                    }
                }
                continue;
            }
            if idx > try_i && idx <= finally_close {
                continue;
            }
            out.push_str(line);
            if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
                out.push('\n');
            }
        }
        return out;
    }
    body.to_string()
}

/// Strip obvious redundant casts: `(T) new T(...)`, `(T)(T)x`, typed assign forms.
fn strip_redundant_casts(body: &str) -> String {
    let mut out = String::new();
    let line_count = body.lines().count();
    for (idx, line) in body.lines().enumerate() {
        let binding = strip_trailing_comment(line);
        let stmt = binding.trim();
        let comment = line.get(binding.len()..).unwrap_or("");
        let indent = leading_indent(line);

        if let Some(new_stmt) = rewrite_redundant_casts_stmt(stmt) {
            out.push_str(indent);
            out.push_str(&new_stmt);
            out.push_str(comment);
        } else {
            out.push_str(line);
        }
        if idx < line_count.saturating_sub(1) {
            out.push('\n');
        }
    }
    if body.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn rewrite_redundant_casts_stmt(stmt: &str) -> Option<String> {
    if stmt.is_empty() {
        return None;
    }
    let ends_semi = stmt.ends_with(';');
    let core = stmt.trim_end_matches(';').trim();
    let rewritten = if let Some(eq) = core.find(" = ") {
        let lhs = core[..eq].trim();
        let rhs = core[eq + 3..].trim();
        let mut new_rhs = strip_redundant_casts_expr(rhs);
        new_rhs = strip_casts_anywhere(&new_rhs);
        // `Type x = (Type) …` when cast type matches declared type
        let new_rhs = if let Some(decl_ty) = lhs.rsplit_once(' ').map(|(t, _)| t.trim()) {
            strip_matching_decl_cast(decl_ty, &new_rhs)
        } else {
            new_rhs
        };
        if new_rhs == rhs {
            return None;
        }
        format!("{} = {}", lhs, new_rhs)
    } else {
        let mut new_core = strip_redundant_casts_expr(core);
        new_core = strip_casts_anywhere(&new_core);
        if new_core == core {
            return None;
        }
        new_core
    };
    Some(if ends_semi {
        format!("{};", rewritten)
    } else {
        rewritten
    })
}

/// Scan an expression/statement for `(T) new T(...)` / `(T)(T)x` / `(T) null` substrings.
fn strip_casts_anywhere(expr: &str) -> String {
    let mut e = expr.to_string();
    for _ in 0..16 {
        let next = strip_casts_anywhere_once(&e);
        if next == e {
            break;
        }
        e = next;
    }
    e
}

fn strip_casts_anywhere_once(expr: &str) -> String {
    // Find `(Type)` prefixes and try local strip rules at each site.
    let bytes = expr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'(' {
            if let Some((ty, rest_start)) = split_leading_cast_at(expr, i) {
                let after_cast = &expr[rest_start..];
                let trimmed = after_cast.trim_start();
                let rest_off = rest_start + (after_cast.len() - trimmed.len());
                // `(T)(T)…`
                if let Some((ty2, rest2_start_rel)) = split_leading_cast_at(expr, rest_off) {
                    if types_equal_for_cast(&ty, &ty2) {
                        let mut out = String::new();
                        out.push_str(&expr[..i]);
                        out.push('(');
                        out.push_str(&ty);
                        out.push(')');
                        out.push(' ');
                        out.push_str(expr[rest2_start_rel..].trim_start());
                        return out;
                    }
                }
                // `(T) new T(...)`
                if looks_like_new_of_type(&expr[rest_off..], &ty) {
                    let mut out = String::new();
                    out.push_str(&expr[..i]);
                    out.push_str(&expr[rest_off..]);
                    return out;
                }
                // `(T) null`
                if trimmed == "null"
                    || trimmed.starts_with("null;")
                    || trimmed.starts_with("null)")
                    || trimmed.starts_with("null,")
                    || trimmed.starts_with("null ")
                {
                    let mut out = String::new();
                    out.push_str(&expr[..i]);
                    out.push_str("null");
                    out.push_str(&trimmed["null".len()..]);
                    return out;
                }
                i = rest_start;
                continue;
            }
        }
        i += 1;
    }
    expr.to_string()
}

fn split_leading_cast_at(expr: &str, start: usize) -> Option<(String, usize)> {
    let e = &expr[start..];
    if !e.starts_with('(') {
        return None;
    }
    let mut depth = 0i32;
    let mut end_byte = None;
    for (i, c) in e.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end_byte = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let end_byte = end_byte?;
    let ty = e[1..end_byte].trim();
    if ty.is_empty() || !looks_like_type_name(ty) {
        return None;
    }
    let rest_rel = end_byte + 1;
    if rest_rel >= e.len() {
        return None;
    }
    let rest = e[rest_rel..].trim_start();
    if rest.is_empty() {
        return None;
    }
    // Avoid `(a + b)` grouping
    let first = rest.chars().next()?;
    if first == '.' || first == '[' || first == ')' {
        return None;
    }
    // Cast must be followed by something that isn't an infix operator starting immediately
    // without a cast-like operand (new, ident, '(', null)
    if !(first.is_ascii_alphabetic()
        || first == '_'
        || first == '('
        || first == '"'
        || first == '\'')
    {
        return None;
    }
    Some((ty.to_string(), start + rest_rel))
}

fn strip_matching_decl_cast(decl_ty: &str, rhs: &str) -> String {
    if let Some((cast_ty, inner)) = split_leading_cast(rhs) {
        if types_equal_for_cast(decl_ty, &cast_ty) {
            // `Type x = (Type) new Type(...)` or `(Type) (Type) y` already partially stripped
            if inner.trim().starts_with("new ") || split_leading_cast(inner.trim()).is_none() {
                // Prefer dropping when new Type or simple expr; keep one cast if inner still cast of different type
                    if let Some((inner_ty, _)) = split_leading_cast(inner.trim()) {
                    if types_equal_for_cast(decl_ty, &inner_ty) {
                        return strip_redundant_casts_expr(&inner);
                    }
                } else if looks_like_new_of_type(inner.trim(), decl_ty) || inner.trim() == "null" {
                    return strip_redundant_casts_expr(&inner);
                }
            }
        }
    }
    rhs.to_string()
}

fn types_equal_for_cast(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        s.trim()
            .replace(" ", "")
            .trim_start_matches("java.lang.")
            .to_string()
    };
    norm(a) == norm(b)
}

fn looks_like_new_of_type(expr: &str, ty: &str) -> bool {
    let e = expr.trim();
    let Some(rest) = e.strip_prefix("new ") else {
        return false;
    };
    let rest = rest.trim_start();
    let ty_simple = ty.rsplit('.').next().unwrap_or(ty).trim();
    rest.starts_with(ty) || rest.starts_with(ty_simple)
}

fn split_leading_cast(expr: &str) -> Option<(String, String)> {
    let e = expr.trim();
    if !e.starts_with('(') {
        return None;
    }
    let mut depth = 0i32;
    let mut end = None;
    for (i, c) in e.chars().enumerate() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end?;
    let ty = e[1..end].trim();
    if ty.is_empty() || !looks_like_type_name(ty) {
        return None;
    }
    let rest = e[end + 1..].trim();
    if rest.is_empty() {
        return None;
    }
    // Avoid treating `(a + b)` as a cast
    if rest.starts_with('.') || rest.starts_with('[') || rest.starts_with(')') {
        return None;
    }
    Some((ty.to_string(), rest.to_string()))
}

fn looks_like_type_name(ty: &str) -> bool {
    let t = ty.trim();
    if t.is_empty() {
        return false;
    }
    // Reject operators / keywords used as casts accidentally
    if t.contains("==") || t.contains("&&") || t.contains("||") || t.contains('+') || t.contains(' ')
    {
        // Allow generic `List<String>` and arrays `int[]`
        if !(t.contains('<') || t.contains('[') || t.contains('.')) {
            return false;
        }
        // `Final String` is not a type cast
        if t.split_whitespace().count() > 1 && !t.contains('<') && !t.contains('[') {
            return false;
        }
    }
    let first = t.chars().next().unwrap();
    first.is_ascii_alphabetic() || first == '_'
}

fn strip_redundant_casts_expr(expr: &str) -> String {
    let mut e = expr.trim().to_string();
    for _ in 0..8 {
        let next = strip_redundant_casts_expr_once(&e);
        if next == e {
            break;
        }
        e = next;
    }
    e
}

fn strip_redundant_casts_expr_once(expr: &str) -> String {
    let e = expr.trim();
    // `(T)(T)x` / `(T) (T) x`
    if let Some((ty1, rest)) = split_leading_cast(e) {
        if let Some((ty2, inner)) = split_leading_cast(rest.trim()) {
            if types_equal_for_cast(&ty1, &ty2) {
                return format!("({}) {}", ty1, inner);
            }
        }
        // `(T) new T(...)`
        if looks_like_new_of_type(rest.trim(), &ty1) {
            return rest.trim().to_string();
        }
        // `(T) null` → `null`
        if rest.trim() == "null" {
            return "null".to_string();
        }
    }
    e.to_string()
}

/// Turn StringConcatFactory / invoke-custom makeConcat leftovers into `a + b + c`.
fn restore_string_concat_indy(body: &str) -> String {
    let mut out = String::new();
    let line_count = body.lines().count();
    for (idx, line) in body.lines().enumerate() {
        let binding = strip_trailing_comment(line);
        let stmt = binding.trim();
        let comment = line.get(binding.len()..).unwrap_or("");
        let indent = leading_indent(line);
        if let Some(new_stmt) = rewrite_string_concat_indy_stmt(stmt) {
            out.push_str(indent);
            out.push_str(&new_stmt);
            out.push_str(comment);
        } else {
            out.push_str(line);
        }
        if idx < line_count.saturating_sub(1) {
            out.push('\n');
        }
    }
    if body.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn rewrite_string_concat_indy_stmt(stmt: &str) -> Option<String> {
    if stmt.is_empty() {
        return None;
    }
    let ends_semi = stmt.ends_with(';');
    let core = stmt.trim_end_matches(';').trim();
    let rewritten = if let Some(eq) = core.find(" = ") {
        let lhs = core[..eq].trim();
        let rhs = core[eq + 3..].trim();
        let new_rhs = rewrite_string_concat_indy_expr(rhs)?;
        format!("{} = {}", lhs, new_rhs)
    } else if let Some(ret) = core.strip_prefix("return ") {
        let new_e = rewrite_string_concat_indy_expr(ret.trim())?;
        format!("return {}", new_e)
    } else {
        rewrite_string_concat_indy_expr(core)?
    };
    Some(if ends_semi {
        format!("{};", rewritten)
    } else {
        rewritten
    })
}

fn rewrite_string_concat_indy_expr(expr: &str) -> Option<String> {
    let e = expr.trim();
    // `/* invoke-custom makeConcat… */ (a, b, c)`
    if let Some(idx) = e.find("/*") {
        if let Some(end) = e[idx..].find("*/") {
            let comment = &e[idx..idx + end + 2];
            let lower = comment.to_ascii_lowercase();
            if lower.contains("makeconcat") || lower.contains("stringconcatfactory") {
                let rest = e[idx + end + 2..].trim();
                if let Some(args) = extract_paren_arg_list(rest) {
                    if !args.is_empty() {
                        return Some(args.join(" + "));
                    }
                }
            }
        }
    }
    // `StringConcatFactory.makeConcat(…)` / `makeConcatWithConstants(…)`
    for prefix in [
        "java.lang.invoke.StringConcatFactory.makeConcatWithConstants(",
        "java.lang.invoke.StringConcatFactory.makeConcat(",
        "StringConcatFactory.makeConcatWithConstants(",
        "StringConcatFactory.makeConcat(",
    ] {
        if let Some(rest) = e.strip_prefix(prefix) {
            if !rest.ends_with(')') {
                continue;
            }
            let inner = &rest[..rest.len() - 1];
            let args = split_top_level_args(inner);
            if !args.is_empty() {
                // makeConcatWithConstants often has recipe string first — drop string literal recipe if present
                let parts: Vec<String> = if prefix.contains("WithConstants")
                    && args[0].starts_with('"')
                {
                    args[1..].to_vec()
                } else {
                    args
                };
                if !parts.is_empty() {
                    return Some(parts.join(" + "));
                }
            }
        }
    }
    None
}

fn extract_paren_arg_list(expr: &str) -> Option<Vec<String>> {
    let e = expr.trim();
    let rest = e.strip_prefix('(')?;
    if !rest.ends_with(')') {
        return None;
    }
    let inner = &rest[..rest.len() - 1];
    Some(split_top_level_args(inner))
}

fn split_top_level_args(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escape = false;
    let mut start = 0usize;
    let chars: Vec<char> = args.chars().collect();
    for i in 0..chars.len() {
        let c = chars[i];
        if in_str {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                let piece = chars[start..i].iter().collect::<String>().trim().to_string();
                if !piece.is_empty() {
                    out.push(piece);
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    let piece = chars[start..].iter().collect::<String>().trim().to_string();
    if !piece.is_empty() {
        out.push(piece);
    }
    out
}

/// Rewrite legacy `vN = { 1, 2 };` to `vN = new int[]{ 1, 2 };`.
fn polish_fill_array_initializers(body: &str) -> String {
    let mut out = String::new();
    let line_count = body.lines().count();
    for (idx, line) in body.lines().enumerate() {
        let binding = strip_trailing_comment(line);
        let stmt = binding.trim();
        let comment = line.get(binding.len()..).unwrap_or("");
        if let Some(new_stmt) = rewrite_bare_array_init(stmt) {
            out.push_str(leading_indent(line));
            out.push_str(&new_stmt);
            out.push_str(comment);
        } else {
            out.push_str(line);
        }
        if idx < line_count.saturating_sub(1) {
            out.push('\n');
        }
    }
    if body.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn rewrite_bare_array_init(stmt: &str) -> Option<String> {
    if !stmt.ends_with(';') {
        return None;
    }
    let eq = stmt.find(" = ")?;
    let lhs = stmt[..eq].trim();
    let rhs = stmt[eq + 3..].trim_end_matches(';').trim();
    if !rhs.starts_with('{') || !rhs.ends_with('}') || rhs.contains("new ") {
        return None;
    }
    let inner = rhs[1..rhs.len() - 1].trim();
    let ty = if inner.split(',').any(|e| {
        let e = e.trim();
        e.ends_with('L') || e.ends_with('l')
    }) {
        "long"
    } else if inner.split(',').any(|e| {
        let e = e.trim();
        e.contains('.')
            || e.ends_with('f')
            || e.ends_with('F')
            || e.ends_with('d')
            || e.ends_with('D')
    }) {
        "double"
    } else {
        "int"
    };
    Some(format!("{} = new {}[]{{ {} }};", lhs, ty, inner))
}

/// Replace whole-identifier occurrences of `var` with `replacement`.
/// When the use is a receiver (`var.` / `var[`), wrap casts/complex exprs in parentheses.
/// and "invoke(...); vN = <result>;" into "vN = method(args);".
/// Also collapses "if (cond) { return a; } else { return b; }" into "return cond ? a : b;" (JADX-style).
/// When `is_constructor` is true, "receiver.<init>();" (no args) is simplified to "super();".
pub fn simplify_method_body(body: &str, is_constructor: bool) -> String {
    let lines: Vec<String> = body.lines().map(String::from).collect();
    if lines.len() < 2 {
        return body.to_string();
    }
    let mut i = 0usize;
    let mut out = String::new();
    let mut skip_unreachable_indent: Option<usize> = None;
    while i < lines.len() {
        let line = &lines[i];

        // Skip unreachable code after "return ...;": skip only lines with indent > return's indent until we see "}" at same or less indent.
        if let Some(return_indent) = skip_unreachable_indent {
            let line_indent = leading_indent(line).len();
            if line_indent > return_indent {
                i += 1;
                continue;
            }
            // Same or less indent: output this line (e.g. "}" or "} else {") and stop skipping.
            out.push_str(line);
            if i < lines.len().saturating_sub(1) {
                out.push('\n');
            }
            skip_unreachable_indent = None;
            i += 1;
            continue;
        }

        // Try: var = expr; return var;  (or "Type var = expr;") → return expr;
        if i + 1 < lines.len() {
            if let (Some((var, expr)), Some(ret_var)) = (
                parse_simple_assign_line(line),
                parse_return_ident_line(&lines[i + 1]),
            ) {
                if var == ret_var {
                    let indent = leading_indent(line);
                    writeln!(out, "{}return {};", indent, expr).ok();
                    skip_unreachable_indent = Some(indent.len());
                    i += 2;
                    continue;
                }
            }
        }

        // Try: if (cond) { return a; } else { return b; } → return cond ? a : b;
        if i + 4 < lines.len() {
            if let Some(cond) = parse_if_condition(line) {
                let then_line = lines[i + 1].trim();
                let else_line = lines[i + 2].trim();
                let return_b_line = lines[i + 3].trim();
                let close_line = lines[i + 4].trim();
                if parse_return_expr(then_line).is_some()
                    && else_line.contains("} else {")
                    && parse_return_expr(return_b_line).is_some()
                    && close_line.trim() == "}"
                {
                    let then_expr = parse_return_expr(then_line).unwrap();
                    let else_expr = parse_return_expr(return_b_line).unwrap();
                    let indent = leading_indent(line);
                    writeln!(out, "{}return {} ? {} : {};", indent, cond, then_expr, else_expr).ok();
                    skip_unreachable_indent = Some(indent.len());
                    i += 5;
                    continue;
                }
            }
        }

        // Try: invoke + move-result + return (same reg)
        if is_invoke_line(line)
            && i + 2 < lines.len()
            && parse_move_result_line(&lines[i + 1]).is_some()
            && parse_return_reg_line(&lines[i + 2]).is_some()
        {
            let move_reg = parse_move_result_line(&lines[i + 1]).unwrap();
            let return_reg = parse_return_reg_line(&lines[i + 2]).unwrap();
            if move_reg == return_reg {
                if let Some((args, method_ref)) = parse_invoke_args_and_method(line) {
                    let indent = leading_indent(line);
                    let call = format!("{}({});", method_ref, args);
                    writeln!(out, "{}return {}", indent, call).ok();
                    skip_unreachable_indent = Some(indent.len());
                    i += 3;
                    continue;
                }
            }
        }

        // Try: invoke + move-result (no return)
        if is_invoke_line(line)
            && i + 1 < lines.len()
            && parse_move_result_line(&lines[i + 1]).is_some()
        {
            let move_reg = parse_move_result_line(&lines[i + 1]).unwrap();
            if let Some((args, method_ref)) = parse_invoke_args_and_method(line) {
                let indent = leading_indent(line);
                let call = format!("{}({});", method_ref, args);
                writeln!(out, "{}{} = {}", indent, move_reg, call).ok();
                i += 2;
                continue;
            }
        }

        // Try: invoke + return; (void call) → emit as normal Java call "method(args);" then "return;"
        if is_invoke_line(line)
            && i + 1 < lines.len()
            && is_return_void_line(&lines[i + 1])
        {
            if let Some((args, method_ref)) = parse_invoke_args_and_method(line) {
                let indent = leading_indent(line);
                let call = format!("{}({});", method_ref, args);
                writeln!(out, "{}{}", indent, call).ok();
                writeln!(out, "{}", lines[i + 1]).ok();
                i += 2;
                continue;
            }
        }

        // Try: StringBuilder chain → a + b + c
        // Handles SSA-aliased variables: new StringBuilder() on sb0 may be used as v3 in
        // <init>, append, toString. Also folds into println if the toString result is used there.
        if let Some((_sb_var, first_opt)) = parse_new_stringbuilder(line) {
            let mut parts: Vec<String> = if let Some(a) = first_opt {
                vec![a]
            } else {
                vec![]
            };
            let mut j = i + 1;
            let chain_start = i;
            let mut const_assigns: Vec<(String, String)> = Vec::new();

            while j < lines.len() {
                let jline = lines[j].trim();
                if let Some((_init_var, init_arg)) = parse_init_call(&lines[j]) {
                    if let Some(arg) = init_arg {
                        parts.push(arg);
                    }
                    j += 1;
                    continue;
                }
                if jline.contains(" = ") && !jline.contains(".append(") && !jline.contains(".toString(") && !jline.contains("new ") && !jline.contains(".println(") {
                    if let Some(eq) = jline.find(" = ") {
                        let var = jline[..eq].trim();
                        let val = jline[eq + 3..].trim_end_matches(';').trim();
                        if !var.is_empty() && !val.is_empty() && !val.contains('(') {
                            const_assigns.push((var.to_string(), val.to_string()));
                            j += 1;
                            continue;
                        }
                    }
                }
                break;
            }

            while j < lines.len() {
                if let Some((_v, arg)) = parse_append(&lines[j]) {
                    parts.push(arg);
                    j += 1;
                    continue;
                }
                break;
            }

            if j < lines.len() && !parts.is_empty() {
                if let Some((dest, _to_str_var)) = parse_to_string(&lines[j]) {
                    let indent = leading_indent(line);
                    let inline_const = |s: &str| -> String {
                        for (cvar, cval) in &const_assigns {
                            if s == cvar { return cval.clone(); }
                        }
                        s.to_string()
                    };
                    let parts_inlined: Vec<String> = parts.iter().map(|p| inline_const(p)).collect();
                    let concat = parts_inlined.join(" + ");

                    if dest == "return" {
                        writeln!(out, "{}return {};", indent, concat).ok();
                        skip_unreachable_indent = Some(indent.len());
                        i = j + 1;
                        continue;
                    }
                    if j + 1 < lines.len() {
                        if let Some((print_obj, print_arg)) = parse_println(&lines[j + 1]) {
                            if print_arg == dest {
                                let receiver = const_assigns.iter()
                                    .rfind(|(_, v)| v == "System.out")
                                    .map(|(k, _)| k.as_str());
                                let obj = if receiver.is_some_and(|r| r == print_obj || print_obj.starts_with("local") || print_obj.starts_with("v")) {
                                    "System.out"
                                } else {
                                    &print_obj
                                };
                                writeln!(out, "{}{}.println({});", indent, obj, concat).ok();
                                i = j + 2;
                                continue;
                            }
                        }
                    }
                    writeln!(out, "{}{} = {};", indent, dest, concat).ok();
                    i = j + 1;
                    continue;
                }
            }
            if j > chain_start + 1 {
                // partial chain matched but no toString found; emit original lines
            }
        }

        out.push_str(line);
        if i < lines.len().saturating_sub(1) {
            out.push('\n');
        }
        if is_return_line(line) {
            skip_unreachable_indent = Some(leading_indent(line).len());
        }
        i += 1;
    }
    // Simplify "x + -N" to "x - N" (e.g. "local0 + -3" → "local0 - 3").
    out = out.replace(" + -", " - ");
    // Fold assign ternary before dead-assign cleanup removes unused x=a / x=b arms.
    out = fold_assign_ternary(&out);
    // Inline "var = System.out;" → replace var.println(x) with System.out.println(x) and remove the assignment.
    out = inline_static_field_refs(&out);
    // Remove bare "var; /* move-exception */" lines and inline single-use temps (consts / simple copies).
    out = cleanup_decompiler_artifacts(&out);
    // Merge `x = new T(); x.<init>(args);` → `x = new T(args);`
    out = merge_constructor_calls(&out);
    // Fold `lit; x = lit.equals(y); if (x)` and collapse `!(!z)` conditions.
    out = fold_equals_into_conditions(&out);
    // Drop leftover `url = "/login";` before `if ("/login".equals(…))`.
    out = drop_string_lits_folded_into_if(&out);
    // `if (!(lit.equals(x))) { A } else { B }` → `if (lit.equals(x)) { B } else { A }`
    out = flip_negated_equals_if_else(&out);
    // `} else { if (c) {` → `} else if (c) {`
    out = flatten_else_if_chains(&out);
    // Nested scheme/host Uri checks → `a && b`
    out = merge_nested_uri_component_checks(&out);
    // General nested `if (A) { if (B) { BODY } }` → `if (A && B) { BODY }`
    out = merge_nested_if_and(&out);
    // `if (A) { BODY } else if (B) { BODY }` → `if (A || B) { BODY }`
    out = merge_short_circuit_or(&out);
    // Iterator while → for-each
    out = restore_foreach_iterator(&out);
    // Objects.requireNonNull / Intrinsics.checkNotNull* strip
    out = strip_require_non_null(&out);
    // Identical consecutive catches → multi-catch
    out = merge_multi_catch(&out);
    // Duplicate cleanup at end of try + each catch → finally
    out = merge_duplicate_finally(&out);
    // `while (true) { …; if (!c) break; }` → do-while
    out = restore_do_while_text(&out);
    // `$SwitchMap$[e.ordinal()]` / `e.ordinal()` → `switch (e)`
    out = restore_enum_switchmap(&out);
    // try + finally-close → try-with-resources
    out = restore_try_with_resources(&out);
    // `(T) new T(...)` / `(T)(T)x` strip
    out = strip_redundant_casts(&out);
    // StringConcatFactory / makeConcat indy → `a + b`
    out = restore_string_concat_indy(&out);
    // Legacy `vN = { … }` → `new int[]{ … }`
    out = polish_fill_array_initializers(&out);
    // `path = uri.getScheme(); if ("x".equals(path))` → inline getter into if when single-use.
    out = inline_single_use_into_equals_if(&out);
    // `.setJavaScriptEnabled(1)` → `.setJavaScriptEnabled(true)` for boolean-looking APIs.
    out = polish_booleanish_int_args(&out);
    // `obj == 0` / `!= 0` → null when the name looks like a reference.
    out = polish_null_comparisons_in_body(&out);
    // `continue;` right before the loop's closing `}` is a no-op.
    out = remove_trailing_continues(&out);
    // Only in constructors: simplify "receiver.<init>();" (no args) to "super();".
    if is_constructor {
        let mut simplified = String::new();
        for line in out.lines() {
            let binding = strip_trailing_comment(line);
            let stmt = binding.trim();
            let ind = leading_indent(line);
            let comment_part = line.get(binding.len()..).unwrap_or("");
            if stmt.ends_with(".<init>();") {
                let prefix = stmt.trim_end_matches(".<init>();");
                if prefix.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !prefix.is_empty() {
                    writeln!(simplified, "{}super();{}", ind, comment_part).ok();
                    continue;
                }
            }
            simplified.push_str(line);
            if !line.is_empty() {
                simplified.push('\n');
            }
        }
        if simplified.ends_with('\n') && !out.ends_with('\n') {
            simplified.pop();
        }
        out = simplified;
    }
    // Rebase indentation to consistent 4-space levels (fixes over-indented bodies).
    out = normalize_java_indent(&out);
    out
}

/// Re-indent Java-like source to 4 spaces per brace level.
/// Preserves the indent of the first non-empty line as the base level.
pub fn normalize_java_indent(body: &str) -> String {
    if body.is_empty() {
        return body.to_string();
    }
    const IND: &str = "    ";
    let lines: Vec<&str> = body.lines().collect();
    let mut base_levels = 0usize;
    for line in &lines {
        if !line.trim().is_empty() {
            let spaces = line.len() - line.trim_start().len();
            base_levels = spaces / 4;
            // If someone used 8-space steps, first content line may be at 16 spaces
            // while the method signature (not in body) is at 4. Bodies usually start
            // at indent 2 (8 spaces) after the fix; clamp wild bases.
            if base_levels > 2 && spaces % 8 == 0 && spaces >= 16 {
                base_levels = 2;
            }
            break;
        }
    }
    let mut depth = base_levels;
    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
                out.push('\n');
            }
            continue;
        }
        let starts_with_close = trimmed.starts_with('}');
        if starts_with_close {
            depth = depth.saturating_sub(1);
        }
        out.push_str(&IND.repeat(depth));
        out.push_str(trimmed);
        if idx < lines.len().saturating_sub(1) || body.ends_with('\n') {
            out.push('\n');
        }
        // Adjust depth from braces outside strings/comments (best-effort).
        let mut in_str: Option<char> = None;
        let mut in_line_comment = false;
        let mut in_block_comment = false;
        let bytes: Vec<char> = trimmed.chars().collect();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            let next = bytes.get(i + 1).copied();
            if in_line_comment {
                break;
            }
            if in_block_comment {
                if c == '*' && next == Some('/') {
                    in_block_comment = false;
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            if let Some(q) = in_str {
                if c == '\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    in_str = None;
                }
                i += 1;
                continue;
            }
            if c == '/' && next == Some('/') {
                in_line_comment = true;
                i += 2;
                continue;
            }
            if c == '/' && next == Some('*') {
                in_block_comment = true;
                i += 2;
                continue;
            }
            if c == '"' || c == '\'' {
                in_str = Some(c);
                i += 1;
                continue;
            }
            if c == '{' {
                depth += 1;
            } else if c == '}' {
                // Already decreased once for a leading `}` before emit.
                if !(starts_with_close && i == 0) {
                    depth = depth.saturating_sub(1);
                }
            }
            i += 1;
        }
    }
    // Avoid adding a trailing newline if the input had none.
    if !body.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Replace try { /* monitor-enter(lock) */ body /* monitor-exit */ } catch (Throwable ...) with synchronized (lock) { body }.
/// Must be run after wrap_body_with_try_catch so the body actually contains the "try {" wrapper.
pub fn simplify_synchronized_blocks(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    if lines.len() < 4 {
        return body.to_string();
    }
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let stmt = line.trim();
        let indent = leading_indent(line);
        if stmt == "try {" {
            let mut j = i + 1;
            let mut lock: Option<String> = None;
            let mut monitor_enter_line = None;
            while j < lines.len() {
                let l = lines[j];
                let t = l.trim();
                if let Some(open) = t.find("/* monitor-enter(") {
                    let start = open + "/* monitor-enter(".len();
                    let end = t[start..].find(')').map(|p| start + p).unwrap_or(t.len());
                    lock = Some(t[start..end].trim().to_string());
                    monitor_enter_line = Some(j);
                    break;
                }
                if t.starts_with("} catch (Throwable") {
                    break;
                }
                j += 1;
            }
            if let (Some(lock_var), Some(mon_ln)) = (lock, monitor_enter_line) {
                let mut body_lines: Vec<&str> = Vec::new();
                let mut k = mon_ln + 1;
                while k < lines.len() {
                    let l = lines[k];
                    let t = l.trim();
                    if t.starts_with("} catch (Throwable") {
                        break;
                    }
                    if t.contains("/* monitor-exit(") {
                        k += 1;
                        continue;
                    }
                    body_lines.push(l);
                    k += 1;
                }
                let catch_start = k;
                if catch_start < lines.len() && lines[catch_start].trim().starts_with("} catch (Throwable") {
                    let mut brace_count = 0;
                    let mut catch_end = catch_start;
                    for (idx, l) in lines[catch_start..].iter().enumerate() {
                        for c in l.chars() {
                            if c == '{' {
                                brace_count -= 1;
                            } else if c == '}' {
                                brace_count += 1;
                            }
                        }
                        catch_end = catch_start + idx;
                        if brace_count > 0 {
                            break;
                        }
                    }
                    writeln!(out, "{}synchronized ({}) {{", indent, lock_var).ok();
                    for bl in &body_lines {
                        out.push_str(bl);
                        out.push('\n');
                    }
                    writeln!(out, "{}}}", indent).ok();
                    i = catch_end + 1;
                    continue;
                }
            }
        }
        out.push_str(line);
        if i < lines.len().saturating_sub(1) {
            out.push('\n');
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_comment() {
        let line = "        return v0;  // // 1234: return-object v0";
        assert_eq!(strip_trailing_comment(line).trim(), "return v0;");
    }

    #[test]
    fn parse_invoke() {
        let line = "        invoke-static( v2, v3, Class.method(A, B) );  // comment";
        let (args, method_name) = parse_invoke_args_and_method(line).unwrap();
        assert_eq!(args, "v2, v3");
        assert_eq!(method_name, "Class.method");
    }

    #[test]
    fn parse_invoke_no_args() {
        let line = "        invoke-static( Runtime.getRuntime() );  // x";
        let (args, method_name) = parse_invoke_args_and_method(line).unwrap();
        assert_eq!(args, "");
        assert_eq!(method_name, "Runtime.getRuntime");
    }

    #[test]
    fn parse_move_result() {
        assert_eq!(
            parse_move_result_line("        v0 = <result>;  // x"),
            Some("v0".to_string())
        );
        assert_eq!(
            parse_move_result_line("        v5 = <result>;"),
            Some("v5".to_string())
        );
        assert_eq!(
            parse_move_result_line("        e = <result>;"),
            Some("e".to_string())
        );
        assert_eq!(parse_move_result_line("        v0 = v1;"), None);
    }

    #[test]
    fn parse_return_reg() {
        assert_eq!(
            parse_return_reg_line("        return v0;  // x"),
            Some("v0".to_string())
        );
        assert_eq!(
            parse_return_reg_line("        return v3;"),
            Some("v3".to_string())
        );
        assert_eq!(
            parse_return_reg_line("        return e;"),
            Some("e".to_string())
        );
        assert_eq!(parse_return_reg_line("        return;"), None);
    }

    #[test]
    fn simplify_invoke_move_result_return() {
        let body = "        invoke-static( v2, v3, Foo.bar(A, B) );  // comment\n        v0 = <result>;  // move-result\n        return v0;  // return";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("return Foo.bar(v2, v3);"),
            "expected 'return Foo.bar(v2, v3);' in {:?}",
            simplified
        );
        assert!(!simplified.contains("<result>"));
    }

    #[test]
    fn simplify_invoke_move_result_only() {
        // Resolved invoke has "Receiver, MethodRef" - method ref is last (e.g. Class.method(Params)).
        let body = "        invoke-virtual( v0, Foo.bar(A, B) );  // x\n        v2 = <result>;  // y";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("v2 = Foo.bar(v0);"),
            "expected 'v2 = Foo.bar(v0);' in {:?}",
            simplified
        );
        assert!(!simplified.contains("<result>"));
    }

    #[test]
    fn simplify_invoke_no_arg_static_named_result() {
        let body = "        invoke-static(Runtime.getRuntime());\n        e = <result>;\n        e = e.exec(\"logcat -d\");";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("e = Runtime.getRuntime();"),
            "expected folded getRuntime in {:?}",
            simplified
        );
        assert!(!simplified.contains("invoke-static"));
        assert!(!simplified.contains("<result>"));
        assert!(simplified.contains("e = e.exec(\"logcat -d\");"));
    }

    #[test]
    fn simplify_invoke_return_void() {
        // invoke-static + return; → normal Java call then return;
        let body = "        invoke-static( v1, ViewCompatJB.postInvalidateOnAnimation(android.view.View) );  // x\n        return;  // y";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("ViewCompatJB.postInvalidateOnAnimation(v1);"),
            "expected Java-style call in {:?}",
            simplified
        );
        assert!(simplified.contains("return;"));
        assert!(!simplified.contains("invoke-static"));
    }

    #[test]
    fn simplify_if_return_else_return_to_ternary() {
        let body = "        if (n0 > 0) {\n            return n0;\n        } else {\n            return 0;\n        }";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("return n0 > 0 ? n0 : 0;"),
            "expected ternary in {:?}",
            simplified
        );
        assert!(!simplified.contains("} else {"));
    }

    #[test]
    fn simplify_stringbuilder_append_to_concat() {
        let body = "        sb = new StringBuilder();\n        sb.append(a);\n        sb.append(b);\n        s = sb.toString();";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("s = a + b;"),
            "expected 's = a + b;' in {:?}",
            simplified
        );
        assert!(!simplified.contains("StringBuilder"));
    }

    #[test]
    fn simplify_stringbuilder_return_to_string() {
        let body = "        sb = new StringBuilder(x);\n        sb.append(y);\n        return sb.toString();";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("return x + y;"),
            "expected 'return x + y;' in {:?}",
            simplified
        );
    }

    #[test]
    fn simplify_stringbuilder_ssa_aliased_with_init_and_println() {
        let body = "\
                        local2 = System.out;\n\
                        StringBuilder sb0 = new StringBuilder();\n\
                        str0 = \"test2 \";\n\
                        v3.<init>(str0);\n\
                        local3 = v3.append(n0);\n\
                        local4 = v3.toString();\n\
                        v2.println(local4);";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("System.out.println(\"test2 \" + n0);"),
            "expected 'System.out.println(\"test2 \" + n0);' in {:?}",
            simplified
        );
        assert!(!simplified.contains("StringBuilder"), "StringBuilder should be gone: {:?}", simplified);
    }

    #[test]
    fn simplify_stringbuilder_dest_assign_append() {
        let body = "\
                sb = new StringBuilder();\n\
                local0 = sb.append(a);\n\
                local1 = sb.append(b);\n\
                s = sb.toString();";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("s = a + b;"),
            "expected 's = a + b;' in {:?}",
            simplified
        );
        assert!(!simplified.contains("StringBuilder"));
    }

    #[test]
    fn simplify_remove_move_exception() {
        let body = "\
                local0; /* move-exception */\n\
                n0 = 12;\n\
                System.out.println(n0);";
        let simplified = simplify_method_body(body, false);
        assert!(!simplified.contains("move-exception"), "move-exception should be removed: {:?}", simplified);
        assert!(
            simplified.contains("System.out.println(12);"),
            "single-use numeric should be inlined: {:?}",
            simplified
        );
        assert!(!simplified.contains("n0 = 12"), "n0 assignment should be removed: {:?}", simplified);
    }

    #[test]
    fn simplify_inline_class_literal_and_index_zero() {
        // Mirrors reflection Class[] / Object[] setup from OVAA invokePlugins.
        let body = "\
                Class[] arr0 = new Class[1];\n\
                local1 = android.content.Context.class;\n\
                j = 0;\n\
                arr0[j] = local1;\n\
                Object[] arr1 = new Object[1];\n\
                arr1[j] = this;\n\
                m.invoke(null, arr1);";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("arr0[0] = android.content.Context.class")
                || simplified.contains("arr0[0]=android.content.Context.class"),
            "expected Context.class inlined at arr0[0]: {:?}",
            simplified
        );
        assert!(
            !simplified.contains("local1"),
            "local1 should be gone: {:?}",
            simplified
        );
        assert!(
            !simplified.contains("[j]"),
            "index j should fold to 0: {:?}",
            simplified
        );
    }

    #[test]
    fn simplify_inline_single_use_string_constant() {
        let body = "\
                str0 = \"test\";\n\
                System.out.println(str0);";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("System.out.println(\"test\");"),
            "expected inlined string constant: {:?}",
            simplified
        );
        assert!(!simplified.contains("str0"), "str0 assignment should be removed: {:?}", simplified);
    }

    /// OVAA LoginActivity.onCreate pattern: reuse `i0` for layout then button id across an if.
    #[test]
    fn simplify_ovaa_login_i0_reuse_across_if() {
        let body = "\
        super.onCreate(bundle);\n\
        int i0 = 2131361820;\n\
        this.setContentView(i0);\n\
        oversecured.ovaa.utils.LoginUtils v0 = oversecured.ovaa.utils.LoginUtils.getInstance(this);\n\
        this.loginUtils = v0;\n\
        boolean z0 = v0.isLoggedIn();\n\
        if (!z0) {\n\
            i0 = 2131165294;\n\
            View view0 = this.findViewById(i0);\n\
            oversecured.ovaa.activities.LoginActivity$1 v1 = new oversecured.ovaa.activities.LoginActivity$1(this);\n\
            view0.setOnClickListener(v1);\n\
            return;\n\
        } else {\n\
            this.onLoginFinished();\n\
            return;\n\
        }";
        let once = cleanup_decompiler_artifacts_once(body);
        assert!(
            once.contains("2131165294"),
            "first cleanup pass must keep button id:\n{}",
            once
        );
        let cleaned = cleanup_decompiler_artifacts(body);
        assert!(
            cleaned.contains("2131165294"),
            "cleanup loop must keep button id:\n{}",
            cleaned
        );
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("2131165294"),
            "button resource id must survive simplify:\ncleaned={:?}\nsimplified={:?}",
            cleaned,
            simplified
        );
        assert!(
            !simplified.contains("findViewById(i0)"),
            "dangling i0 after removing button assign: {:?}",
            simplified
        );
        assert!(
            !simplified.contains("findViewById(2131361820)"),
            "layout id must not replace button id: {:?}",
            simplified
        );
    }

    #[test]
    fn simplify_inline_findview_cast_gettext_tostring_chain() {
        let body = "\
                view0 = this.findViewById(2131165271);\n\
                view0 = (TextView) view0;\n\
                view0 = view0.getText();\n\
                email = view0.toString();\n\
                i1 = android.text.TextUtils.isEmpty(email);";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("this.findViewById(2131165271)")
                && simplified.contains("(TextView)")
                && simplified.contains("getText()")
                && simplified.contains("toString()")
                && simplified.contains("email ="),
            "expected chained findViewById into email, got:\n{}",
            simplified
        );
        assert!(
            simplified.contains("isEmpty(email)"),
            "email should remain for isEmpty, got:\n{}",
            simplified
        );
        assert!(
            !simplified.contains("view0 ="),
            "intermediate view0 assigns should be gone: {}",
            simplified
        );
    }

    #[test]
    fn simplify_inline_single_use_numeric_in_call() {
        let body = "\
                Intent pickerIntent = new Intent();\n\
                s0 = \"image/*\";\n\
                pickerIntent.setType(s0);\n\
                s0 = this.this$0;\n\
                int i0 = 1001;\n\
                s0.startActivityForResult(pickerIntent, i0);";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("pickerIntent.setType(\"image/*\");"),
            "expected inlined MIME type: {:?}",
            simplified
        );
        assert!(
            simplified.contains("this.this$0.startActivityForResult(pickerIntent, 1001);"),
            "expected inlined receiver + request code: {:?}",
            simplified
        );
        assert!(!simplified.contains("int i0"), "i0 should be removed: {:?}", simplified);
        assert!(!simplified.contains("s0 ="), "s0 temps should be removed: {:?}", simplified);
    }

    #[test]
    fn simplify_inline_multi_use_cheap_literal() {
        let body = "\
                int i0 = 1001;\n\
                foo(i0);\n\
                bar(i0);";
        let simplified = simplify_method_body(body, false);
        assert!(
            !simplified.contains("int i0") && !simplified.contains("i0 ="),
            "cheap multi-use temp should be inlined: {:?}",
            simplified
        );
        assert!(
            simplified.contains("foo(1001);") && simplified.contains("bar(1001);"),
            "{:?}",
            simplified
        );
    }

    #[test]
    fn simplify_inline_webview_boolean_settings() {
        let body = "\
    private void setupWebView(android.webkit.WebView p0) {\n\
        webView.setWebChromeClient(new android.webkit.WebChromeClient());\n\
        webView.setWebViewClient(new android.webkit.WebViewClient());\n\
        int i0 = 1;\n\
        webView.getSettings().setJavaScriptEnabled(i0);\n\
        webView.getSettings().setAllowFileAccessFromFileURLs(i0);\n\
        return;\n\
    }";
        let simplified = simplify_method_body(body, false);
        assert!(
            !simplified.contains("int i0") && !simplified.contains("i0 ="),
            "i0 should be removed: {:?}",
            simplified
        );
        assert!(
            simplified.contains("setJavaScriptEnabled(true)"),
            "expected boolean true: {:?}",
            simplified
        );
        assert!(
            simplified.contains("setAllowFileAccessFromFileURLs(true)"),
            "expected boolean true: {:?}",
            simplified
        );
    }

    #[test]
    fn simplify_keep_multi_use_non_temp_numeric() {
        // Meaningful names stay as locals even when the RHS is a cheap literal.
        let body = "\
                int requestCode = 1001;\n\
                foo(requestCode);\n\
                bar(requestCode);";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("requestCode = 1001") || simplified.contains("int requestCode = 1001"),
            "named local should keep assignment: {:?}",
            simplified
        );
        assert!(
            simplified.contains("foo(requestCode);") && simplified.contains("bar(requestCode);"),
            "{:?}",
            simplified
        );
    }

    #[test]
    fn simplify_dead_sysout_assignment_removed() {
        let body = "\
                local0 = System.out;\n\
                str0 = \"hello\";\n\
                v0.println(str0);";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("System.out.println(\"hello\");"),
            "expected System.out.println(\"hello\") in {:?}",
            simplified
        );
        assert!(!simplified.contains("local0 = System.out"), "dead assignment should be removed: {:?}", simplified);
    }

    #[test]
    fn simplify_inline_return_string_constant() {
        let body = "                        String result = \"bad_name\";\n                        return result;";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("return \"bad_name\";"),
            "expected return \"bad_name\"; in {:?}",
            simplified
        );
        assert!(!simplified.contains("String result"), "assignment should be removed: {:?}", simplified);
        assert!(!simplified.contains("return result"), "return result should be folded: {:?}", simplified);
    }

    #[test]
    fn simplify_assign_return_call() {
        let body = "                result = Foo.bar(x);\n                return result;";
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains("return Foo.bar(x);"),
            "expected return Foo.bar(x); in {:?}",
            simplified
        );
    }

    #[test]
    fn normalize_over_indented_constructor_body() {
        let body = "                super();\n                return;\n";
        let out = normalize_java_indent(body);
        assert!(
            out.contains("        super();"),
            "expected 8-space indent, got {:?}",
            out
        );
        assert!(
            !out.contains("                super"),
            "16-space indent should be gone: {:?}",
            out
        );
    }

    #[test]
    fn simplify_normalizes_indent() {
        let body = "                super();\n                return;\n";
        let simplified = simplify_method_body(body, true);
        let super_line = simplified.lines().find(|l| l.contains("super();")).unwrap();
        let spaces = super_line.len() - super_line.trim_start().len();
        assert_eq!(spaces, 8, "body statements should be 8 spaces, got {:?}: {:?}", spaces, simplified);
    }
}

/// Best-effort restore of `switch (str.hashCode())` + equals cases into `switch (str)` with string labels.
///
/// Looks for the common javac pattern:
/// ```text
/// switch (s.hashCode()) {
/// case 97:
///     if (!s.equals("a")) break;
///     ...
/// ```
/// and rewrites case labels to the string when equals is found in the case body.
/// Also folds `int h = s.hashCode(); switch (h)` and accepts `"lit".equals(s)`.
pub fn restore_string_switch(body: &str) -> String {
    if !body.contains("hashCode()") || !body.contains("switch (") {
        return body.to_string();
    }
    let mut lines: Vec<String> = body.lines().map(|l| l.to_string()).collect();
    fold_hashcode_temp_into_switch(&mut lines);
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim().to_string();
        if let Some(inner) = trimmed
            .strip_prefix("switch (")
            .and_then(|s| s.strip_suffix(") {"))
        {
            let inner = inner.trim().to_string();
            if inner.ends_with(".hashCode()") {
                let expr = inner
                    .trim_end_matches(".hashCode()")
                    .trim()
                    .to_string();
                let indent = leading_indent(&lines[i]).to_string();
                lines[i] = format!("{}switch ({}) {{", indent, expr);
                let mut j = i + 1;
                while j < lines.len() {
                    let t = lines[j].trim().to_string();
                    if t == "}" {
                        break;
                    }
                    if let Some(rest) = t.strip_prefix("case ") {
                        let case_num = rest.trim().trim_end_matches(':').trim().to_string();
                        let case_hash = parse_java_int_literal(&case_num);
                        let mut k = j + 1;
                        let mut found: Vec<String> = Vec::new();
                        while k < lines.len() {
                            let tk = lines[k].trim().to_string();
                            if tk.starts_with("case ") || tk.starts_with("default:") || tk == "}" {
                                break;
                            }
                            if let Some(eq) = extract_string_equals(&tk, &expr) {
                                if !found.iter().any(|s| s == &eq) {
                                    found.push(eq);
                                }
                            }
                            k += 1;
                        }
                        // Prefer equals whose Java hashCode matches the case int when available.
                        let chosen = if found.len() == 1 {
                            Some(found[0].clone())
                        } else if found.len() > 1 {
                            if let Some(h) = case_hash {
                                found
                                    .iter()
                                    .find(|s| java_string_hash_code(s) == h)
                                    .cloned()
                                    .or_else(|| Some(found[0].clone()))
                            } else {
                                Some(found[0].clone())
                            }
                        } else {
                            None
                        };
                        if let Some(s) = chosen {
                            // Reject when hash is present and clearly wrong (keep numeric case).
                            let hash_ok = case_hash
                                .map(|h| java_string_hash_code(&s) == h)
                                .unwrap_or(true);
                            if hash_ok {
                                let cindent = leading_indent(&lines[j]).to_string();
                                lines[j] = format!(
                                    "{}case \"{}\": // was {}",
                                    cindent,
                                    escape_switch_str(&s),
                                    case_num
                                );
                                clear_string_equals_guards(&mut lines, j + 1, &expr);
                            }
                        }
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }
    // Drop blank lines left by guard removal (preserve indent structure lightly).
    let mut cleaned = Vec::with_capacity(lines.len());
    for (idx, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            let prev_empty = cleaned.last().map(|l: &String| l.trim().is_empty()).unwrap_or(true);
            let next_case = lines
                .get(idx + 1)
                .map(|l| {
                    let t = l.trim();
                    t.starts_with("case ") || t.starts_with("default:") || t == "}"
                })
                .unwrap_or(false);
            if prev_empty || next_case {
                continue;
            }
        }
        cleaned.push(line.clone());
    }
    cleaned.join("\n")
}

/// Fold `int h = expr.hashCode();` / `h = expr.hashCode();` immediately before `switch (h)`.
fn fold_hashcode_temp_into_switch(lines: &mut [String]) {
    let mut i = 1;
    while i < lines.len() {
        let sw = lines[i].trim().to_string();
        if let Some(inner) = sw
            .strip_prefix("switch (")
            .and_then(|s| s.strip_suffix(") {"))
        {
            let disc = inner.trim();
            if is_java_ident(disc) {
                // Look back over blank lines for `… disc = expr.hashCode();`
                let mut p = i;
                while p > 0 {
                    p -= 1;
                    if lines[p].trim().is_empty() {
                        continue;
                    }
                    if let Some(expr) = parse_hashcode_assign(lines[p].trim(), disc) {
                        let indent = leading_indent(&lines[i]).to_string();
                        lines[i] = format!("{}switch ({}.hashCode()) {{", indent, expr);
                        lines[p] = String::new();
                    }
                    break;
                }
            }
        }
        i += 1;
    }
}

fn parse_hashcode_assign(line: &str, disc: &str) -> Option<String> {
    // `int h = s.hashCode();` or `h = s.hashCode();`
    let line = line.trim().trim_end_matches(';').trim();
    let assign = if let Some(rest) = line.strip_prefix("int ") {
        rest.trim()
    } else {
        line
    };
    let (lhs, rhs) = assign.split_once('=')?;
    if lhs.trim() != disc {
        return None;
    }
    let rhs = rhs.trim();
    rhs.strip_suffix(".hashCode()")
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
}

fn clear_string_equals_guards(lines: &mut [String], start: usize, expr: &str) {
    let mut k = start;
    while k < lines.len() {
        let tk = lines[k].trim().to_string();
        if tk.starts_with("case ") || tk.starts_with("default:") || tk == "}" {
            break;
        }
        let is_guard = extract_string_equals(&tk, expr).is_some()
            || (tk.contains(".equals(") && (tk.contains(expr) || tk.contains(&format!("\"{expr}"))));
        if is_guard && tk.starts_with("if (") {
            lines[k] = String::new();
            if k + 1 < lines.len() && lines[k + 1].trim() == "break;" {
                lines[k + 1] = String::new();
            }
        } else if tk == "break;"
            && lines.get(k.wrapping_sub(1)).map(|l| l.trim().is_empty() || l.trim().contains(".equals(")).unwrap_or(false)
        {
            // orphaned break after cleared multi-line if — leave alone unless previous was equals
            if lines.get(k.wrapping_sub(1)).map(|l| l.trim().contains(".equals(")).unwrap_or(false) {
                lines[k] = String::new();
            }
        }
        k += 1;
    }
}

fn parse_java_int_literal(s: &str) -> Option<i32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return i32::from_str_radix(hex, 16).ok();
    }
    s.parse::<i32>().ok()
}

/// Java `String.hashCode()` (31-bit polynomial over UTF-16 code units; BMP chars = Rust chars).
pub fn java_string_hash_code(s: &str) -> i32 {
    let mut h: i32 = 0;
    for c in s.encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(c as i32);
    }
    h
}

/// Extract string literal from `recv.equals("…")` or `"…".equals(recv)` (optional `!` / `if`).
fn extract_string_equals(line: &str, recv: &str) -> Option<String> {
    if let Some(s) = extract_equals_string(line, recv) {
        return Some(s);
    }
    // "lit".equals(recv) / !"lit".equals(recv)
    let needle = format!(".equals({recv})");
    let idx = line.find(&needle)?;
    let before = &line[..idx];
    let q = before.rfind('"')?;
    // walk back to opening quote
    let mut i = q;
    let bytes = before.as_bytes();
    while i > 0 {
        i -= 1;
        if bytes[i] == b'"' {
            // check not escaped
            let mut bs = 0;
            let mut j = i;
            while j > 0 && bytes[j - 1] == b'\\' {
                bs += 1;
                j -= 1;
            }
            if bs % 2 == 0 {
                let lit = &before[i + 1..q];
                return Some(unescape_java_str(lit));
            }
        }
    }
    None
}

fn extract_equals_string(line: &str, recv: &str) -> Option<String> {
    // Patterns: s.equals("foo") / !s.equals("foo")
    let needle = format!("{}.equals(", recv);
    let idx = line.find(&needle)?;
    let after = &line[idx + needle.len()..];
    let after = after.trim_start();
    parse_java_string_literal(after)
}

fn parse_java_string_literal(after: &str) -> Option<String> {
    if !after.starts_with('"') {
        return None;
    }
    let mut out = String::new();
    let mut chars = after[1..].chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    out.push(match n {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        other => other,
                    });
                }
            }
            '"' => return Some(out),
            other => out.push(other),
        }
    }
    None
}

fn unescape_java_str(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(match n {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    other => other,
                });
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn escape_switch_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod string_switch_tests {
    use super::*;

    #[test]
    fn restores_string_case_label() {
        let body = r#"        switch (s.hashCode()) {
        case 97:
            if (!s.equals("a")) break;
            return 1;
        }
"#;
        let out = restore_string_switch(body);
        assert!(out.contains("switch (s)"));
        assert!(out.contains("case \"a\":"));
    }

    /// jadx `switches/TestSwitchOverStrings` — multi-case + no leftover hash discriminant.
    #[test]
    fn jadx_restores_multiple_string_cases() {
        let body = r#"        switch (str.hashCode()) {
        case -603257287:
            if (!str.equals("frewhyh")) break;
            return 1;
        case 3556498:
            if (!str.equals("test")) break;
            return 3;
        default:
            return 0;
        }
"#;
        let out = restore_string_switch(body);
        assert!(out.contains("switch (str)"));
        assert!(out.contains("case \"frewhyh\":"));
        assert!(out.contains("case \"test\":"));
        assert!(!out.contains("case -603257287:") || out.contains("// was"));
    }

    #[test]
    fn restores_literal_first_equals() {
        let body = r#"        switch (s.hashCode()) {
        case 97:
            if (!"a".equals(s)) break;
            return 1;
        }
"#;
        let out = restore_string_switch(body);
        assert!(out.contains("switch (s)"), "{out}");
        assert!(out.contains("case \"a\":"), "{out}");
    }

    #[test]
    fn folds_hashcode_temp_disc() {
        let body = r#"        int h = s.hashCode();
        switch (h) {
        case 97:
            if (!s.equals("a")) break;
            return 1;
        }
"#;
        let out = restore_string_switch(body);
        assert!(out.contains("switch (s)"), "{out}");
        assert!(out.contains("case \"a\":"), "{out}");
        assert!(!out.contains("switch (h)"), "{out}");
    }

    #[test]
    fn rejects_wrong_hash_keeps_numeric() {
        let body = r#"        switch (s.hashCode()) {
        case 99:
            if (!s.equals("a")) break;
            return 1;
        }
"#;
        let out = restore_string_switch(body);
        // "a".hashCode() == 97, not 99 — keep numeric case
        assert!(out.contains("case 99:"), "{out}");
        assert!(!out.contains("case \"a\":"), "{out}");
    }

    #[test]
    fn java_string_hash_matches_known() {
        assert_eq!(java_string_hash_code("a"), 97);
        assert_eq!(java_string_hash_code("test"), 3556498);
    }

    #[test]
    fn merge_duplicate_finally_peels_close() {
        let body = r#"        try {
            work();
            r.close();
        } catch (IOException e) {
            log(e);
            r.close();
        }
"#;
        let out = merge_duplicate_finally(body);
        assert!(out.contains("} finally {"), "{out}");
        assert!(out.contains("r.close();"), "{out}");
        assert_eq!(out.matches("r.close();").count(), 1, "{out}");
        assert!(out.contains("log(e);"), "{out}");
        assert!(out.contains("work();"), "{out}");
    }

    #[test]
    fn inline_array_string_temps() {
        let body = r#"        String s0 = "android.permission.READ_EXTERNAL_STORAGE";
        String s1 = "android.permission.WRITE_EXTERNAL_STORAGE";
        String[] permissions = new String[]{ s0, s1 };
        int length = permissions.length;
        int i0 = 0;
        while (i0 < length) {
            String permission = permissions[i0];
            i0 = i0 + 1;
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("READ_EXTERNAL_STORAGE") && out.contains("WRITE_EXTERNAL_STORAGE"),
            "should inline strings: {}",
            out
        );
        assert!(
            !out.contains("s0") && !out.contains("s1 ="),
            "string temps should be gone: {}",
            out
        );
    }

    /// OVAA MainActivity.processDeeplink-style nested inverted equals → else-if chain.
    #[test]
    fn simplify_ovaa_process_deeplink_else_if_chain() {
        let body = r#"        String path = uri.getScheme();
        if ("oversecured".equals(path)) {
            path = uri.getHost();
            url = "ovaa";
            if ("ovaa".equals(path)) {
                path = uri.getPath();
                url = "/logout";
                if (!("/logout".equals(path))) {
                    url = "/login";
                    if (!("/login".equals(path))) {
                        url = "/grant_uri_permissions";
                        if (!("/grant_uri_permissions".equals(path))) {
                            url = "/webview";
                            if ("/webview".equals(path)) {
                                this.startActivity(i);
                            }
                        } else {
                            this.startActivityForResult(url, i1);
                        }
                    } else {
                        this.loginUtils.setLoginUrl(url);
                        this.startActivity(intent0);
                    }
                } else {
                    this.loginUtils.logout();
                    this.startActivity(url);
                }
            }
        }
        return;
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("\"oversecured\".equals(uri.getScheme())")
                && out.contains("\"ovaa\".equals(uri.getHost())"),
            "scheme/host should merge into && :\n{}",
            out
        );
        assert!(
            out.contains("else if") || out.matches("else if").count() >= 1,
            "expected else-if chain:\n{}",
            out
        );
        assert!(
            out.contains("\"/logout\".equals(path)")
                && !out.contains("!(\"/logout\".equals(path))"),
            "logout check should be positive:\n{}",
            out
        );
        assert!(
            !out.contains("url = \"/logout\"")
                && !out.contains("url = \"ovaa\"")
                && !out.contains("url = \"/login\""),
            "folded string lits should be dropped:\n{}",
            out
        );
        assert!(
            out.contains("loginUtils.logout()")
                && out.contains("setLoginUrl")
                && out.contains("startActivityForResult"),
            "branch bodies must survive:\n{}",
            out
        );
    }

    #[test]
    fn flip_and_flatten_simple_negated_equals() {
        let body = r#"        if (!("a".equals(path))) {
            if (!("b".equals(path))) {
                foo();
            } else {
                bar();
            }
        } else {
            baz();
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("if (\"a\".equals(path))") && out.contains("else if (\"b\".equals(path))"),
            "expected positive else-if:\n{}",
            out
        );
        assert!(out.contains("baz();") && out.contains("bar();") && out.contains("foo();"), "{}", out);
    }

    #[test]
    fn jadx_conditions_short_circuit_and() {
        let body = r#"        if (a) {
            if (b) {
                foo();
            }
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("if (a && b)"),
            "expected short-circuit && merge:\n{}",
            out
        );
        assert!(out.contains("foo();"), "{}", out);
        assert!(
            !out.contains("if (a) {") || out.contains("if (a && b)"),
            "outer-only if should be gone:\n{}",
            out
        );
    }

    #[test]
    fn jadx_conditions_short_circuit_or() {
        let body = r#"        if (a) {
            foo();
        } else {
            if (b) {
                foo();
            }
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("if (a || b)"),
            "expected short-circuit || merge:\n{}",
            out
        );
        assert!(out.contains("foo();"), "{}", out);
        assert!(
            !out.contains("else if"),
            "else-if should collapse into ||:\n{}",
            out
        );
    }

    #[test]
    fn jadx_conditions_else_if_emit() {
        // Text-level flatten (emit-time else-if is covered by region emit; this asserts simplify path).
        let body = r#"        if (a) {
            foo();
        } else {
            if (b) {
                bar();
            } else {
                baz();
            }
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("else if (b)"),
            "expected else if:\n{}",
            out
        );
        assert!(
            !out.contains("} else {\n            if (b)"),
            "should not nest else/if:\n{}",
            out
        );
        assert!(out.contains("foo();") && out.contains("bar();") && out.contains("baz();"), "{}", out);
    }

    #[test]
    fn jadx_ternary_assign() {
        let body = r#"        if (c) {
            x = a;
        } else {
            x = b;
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("x = c ? a : b;"),
            "expected assign ternary:\n{}",
            out
        );
        assert!(!out.contains("} else {"), "else should be gone:\n{}", out);
    }

    #[test]
    fn jadx_loops_foreach_iterator() {
        let body = r#"        it = list.iterator();
        while (it.hasNext()) {
            String s = (String) it.next();
            System.out.println(s);
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("for (String s : list)"),
            "expected for-each:\n{}",
            out
        );
        assert!(out.contains("System.out.println(s);"), "{}", out);
        assert!(
            !out.contains("hasNext()") && !out.contains("iterator()"),
            "iterator while should be gone:\n{}",
            out
        );
    }

    #[test]
    #[allow(non_snake_case)] // jadx-style name
    fn jadx_strip_requireNonNull() {
        let body = r#"        x = Objects.requireNonNull(y);
        Objects.requireNonNull(z);
        Intrinsics.checkNotNullParameter(arg, "arg");
        kotlin.jvm.internal.Intrinsics.checkNotNull(obj);
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("x = y;"),
            "requireNonNull assign should unwrap:\n{}",
            out
        );
        assert!(
            !out.contains("requireNonNull") && !out.contains("checkNotNull"),
            "null-check calls should be stripped:\n{}",
            out
        );
    }

    #[test]
    fn jadx_trycatch_multi_catch() {
        let body = r#"        try {
            foo();
        } catch (IOException e) {
            log(e);
        } catch (RuntimeException e) {
            log(e);
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("} catch (IOException | RuntimeException e)"),
            "expected multi-catch:\n{}",
            out
        );
        assert_eq!(
            out.matches("log(e);").count(),
            1,
            "body should appear once:\n{}",
            out
        );
    }

    #[test]
    fn simplify_fill_array_new_type() {
        let body = r#"        v0 = { 1, 2, 3 };
        v1 = { 1L, 2L };
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("v0 = new int[]{ 1, 2, 3 };"),
            "expected typed int array:\n{}",
            out
        );
        assert!(
            out.contains("v1 = new long[]{ 1L, 2L };"),
            "expected typed long array:\n{}",
            out
        );
    }

    #[test]
    fn jadx_loops_do_while_text() {
        let body = r#"        while (true) {
            work();
            if (!done) {
                break;
            }
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("do {") && out.contains("} while (done);"),
            "expected do-while:\n{}",
            out
        );
        assert!(out.contains("work();"), "{}", out);
        assert!(!out.contains("while (true)"), "while(true) should be gone:\n{}", out);
    }

    #[test]
    fn jadx_loops_do_while_break_positive() {
        let body = r#"        while (true) {
            work();
            if (done) {
                break;
            }
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("do {") && out.contains("} while (!(done));"),
            "expected do-while with negated cond:\n{}",
            out
        );
        assert!(!out.contains("while (true)"), "{}", out);
    }

    #[test]
    fn jadx_loops_do_while_break_oneliner() {
        let body = r#"        while (true) {
            work();
            if (done) break;
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("do {") && out.contains("} while (!(done));"),
            "expected oneliner do-while:\n{}",
            out
        );
    }

    #[test]
    fn jadx_loops_do_while_break_in_else() {
        let body = r#"        while (true) {
            work();
            if (ok) {
            } else {
                break;
            }
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("do {") && out.contains("} while (ok);"),
            "expected else-break do-while:\n{}",
            out
        );
    }

    #[test]
    fn jadx_switches_enum_switchmap() {
        let body = r#"        Outer.$SwitchMap$com$example$Color[Color.RED.ordinal()] = 1;
        Outer.$SwitchMap$com$example$Color[Color.BLUE.ordinal()] = 2;
        switch (Outer.$SwitchMap$com$example$Color[color.ordinal()]) {
            case 1:
                return "red";
            case 2:
                return "blue";
            default:
                return "?";
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("switch (color)"),
            "expected switch on enum expr:\n{}",
            out
        );
        assert!(
            out.contains("case Color.RED:") || out.contains("case com.example.Color.RED:"),
            "expected enum case label:\n{}",
            out
        );
        assert!(
            out.contains("case Color.BLUE:") || out.contains("case com.example.Color.BLUE:"),
            "expected blue case:\n{}",
            out
        );
        assert!(
            !out.contains("$SwitchMap$") && !out.contains(".ordinal()"),
            "SwitchMap/ordinal should be gone:\n{}",
            out
        );

        let body2 = r#"        int[] map = Outer.$SwitchMap$com$example$Color;
        switch (map[color.ordinal()]) {
            case 1:
                use(1);
        }
"#;
        let out2 = simplify_method_body(body2, false);
        assert!(out2.contains("switch (color)"), "map form:\n{}", out2);
        assert!(!out2.contains("$SwitchMap$"), "map assign dropped:\n{}", out2);

        let body3 = r#"        switch (color.ordinal()) {
            case 0:
                break;
        }
"#;
        let out3 = simplify_method_body(body3, false);
        assert!(out3.contains("switch (color)"), "plain ordinal:\n{}", out3);
    }

    #[test]
    fn jadx_try_with_resources() {
        let body = r#"        FileInputStream r = new FileInputStream(path);
        try {
            use(r);
        } catch (IOException e) {
            log(e);
        } finally {
            if (r != null) {
                r.close();
            }
        }
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("try (FileInputStream r = new FileInputStream(path))"),
            "expected try-with-resources:\n{}",
            out
        );
        assert!(out.contains("use(r);"), "{}", out);
        assert!(
            out.contains("} catch (IOException e)"),
            "catch should remain:\n{}",
            out
        );
        assert!(
            !out.contains("finally") && !out.contains(".close()"),
            "finally/close should be gone:\n{}",
            out
        );
    }

    #[test]
    fn jadx_try_with_resources_multi() {
        let body = r#"        FileInputStream in = new FileInputStream(path);
        FileOutputStream out = new FileOutputStream(dest);
        try {
            copy(in, out);
        } finally {
            if (in != null) {
                in.close();
            }
            if (out != null) {
                out.close();
            }
        }
"#;
        let simplified = simplify_method_body(body, false);
        assert!(
            simplified.contains(
                "try (FileInputStream in = new FileInputStream(path); FileOutputStream out = new FileOutputStream(dest))"
            ),
            "expected multi try-with-resources:\n{}",
            simplified
        );
        assert!(simplified.contains("copy(in, out);"), "{}", simplified);
        assert!(
            !simplified.contains("finally") && !simplified.contains(".close()"),
            "finally/close should be gone:\n{}",
            simplified
        );
    }

    #[test]
    fn jadx_strip_redundant_cast() {
        let body = r#"        String s = (String) new String("x");
        Object o = (String) (String) y;
        Object n = (String) null;
        use((String) new String("z"));
"#;
        let out = simplify_method_body(body, false);
        assert!(
            out.contains("String s = new String(\"x\")"),
            "cast of new should drop:\n{}",
            out
        );
        assert!(
            out.contains("Object o = (String) y") || out.contains("o = (String)y"),
            "double cast should collapse:\n{}",
            out
        );
        assert!(
            !out.contains("(String) (String)") && !out.contains("(String)(String)"),
            "double same cast gone:\n{}",
            out
        );
        assert!(
            out.contains("Object n = null") || out.contains("n = null"),
            "cast of null:\n{}",
            out
        );
        assert!(
            out.contains("use(new String(\"z\"))"),
            "cast of new in call:\n{}",
            out
        );
    }

    #[test]
    fn jadx_string_concat_indy() {
        let body = r#"        String s = /* invoke-custom makeConcat */ (a, b, c);
        String t = StringConcatFactory.makeConcat(x, y);
        return /* invoke-custom makeConcatWithConstants */ (p, q);
"#;
        let out = simplify_method_body(body, false);
        assert!(out.contains("a + b + c"), "makeConcat comment:\n{}", out);
        assert!(out.contains("x + y"), "StringConcatFactory:\n{}", out);
        assert!(out.contains("return p + q"), "return concat:\n{}", out);
        assert!(!out.contains("makeConcat"), "indy leftover gone:\n{}", out);
    }
}
