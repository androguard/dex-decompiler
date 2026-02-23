//! Post-process decompiled method body to simplify invoke + move-result + return patterns.

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
    let split_at = last_comma_at?;
    let args = inner[..split_at].trim().to_string();
    let method_ref = inner[split_at + 1..].trim().to_string();
    // Method ref from DEX is "Class.method(ParamTypes)" - use only "Class.method" for the call.
    let method_name = method_ref
        .find('(')
        .map(|i| method_ref[..i].trim_end())
        .unwrap_or(method_ref.as_str())
        .to_string();
    Some((args, method_name))
}

/// Check if line is an invoke statement (invoke-xxx( ... );).
fn is_invoke_line(line: &str) -> bool {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    stmt.starts_with("invoke-") && stmt.contains('(') && (stmt.ends_with(" );") || stmt.ends_with(");"))
}

/// Check if line is "vN = <result>;" and return Some(N).
fn parse_move_result_line(line: &str) -> Option<u32> {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    if !stmt.starts_with('v') || !stmt.contains("= <result>;") {
        return None;
    }
    let after_v = stmt.strip_prefix('v')?;
    let eq_pos = after_v.find(" = ")?;
    let num_part = after_v[..eq_pos].trim();
    if num_part.is_empty() || !num_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    num_part.parse().ok()
}

/// Check if line is "return;" (return-void).
fn is_return_void_line(line: &str) -> bool {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    stmt == "return;"
}

/// Check if line is "return vN;" and return Some(N).
fn parse_return_reg_line(line: &str) -> Option<u32> {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    let rest = stmt.strip_prefix("return v")?;
    let rest = rest.strip_suffix(';')?;
    if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    rest.parse().ok()
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
            let var = t[..eq].trim();
            let val = t[eq + 3..].trim_end_matches(';').trim();
            if val.contains('.') && !val.contains('(') && !val.contains(' ') {
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

/// Remove bare "var; /* move-exception */" statements and inline single-use string/numeric constants.
fn cleanup_decompiler_artifacts(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();

    // Collect string constants (safe to inline) and numeric constants (only remove if dead).
    let mut string_consts: Vec<(usize, String, String)> = Vec::new();
    let mut numeric_consts: Vec<(usize, String)> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let binding = strip_trailing_comment(line);
        let t = binding.trim();
        if let Some(eq) = t.find(" = ") {
            let lhs = t[..eq].trim();
            let val = t[eq + 3..].trim_end_matches(';').trim();
            let var = lhs.rsplit(' ').next().unwrap_or(lhs);
            if !var.is_empty() && !var.contains(' ') {
                if val.starts_with('"') && val.ends_with('"') {
                    string_consts.push((idx, var.to_string(), val.to_string()));
                } else if !val.is_empty() && val.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
                    numeric_consts.push((idx, var.to_string()));
                }
            }
        }
    }

    // String constants: inline if used exactly once
    let single_use_strings: Vec<(usize, String, String)> = string_consts
        .into_iter()
        .filter(|(def_idx, var, _)| {
            let use_count = lines.iter().enumerate()
                .filter(|(j, l)| *j != *def_idx && l.contains(var.as_str()))
                .count();
            use_count == 1
        })
        .collect();

    // Numeric constants: remove definition only if the variable is completely unused
    let dead_numeric_indices: std::collections::HashSet<usize> = numeric_consts
        .into_iter()
        .filter(|(def_idx, var)| {
            lines.iter().enumerate()
                .filter(|(j, l)| *j != *def_idx && l.contains(var.as_str()))
                .count() == 0
        })
        .map(|(idx, _)| idx)
        .collect();

    let mut skip_indices: std::collections::HashSet<usize> = single_use_strings.iter().map(|(i, _, _)| *i).collect();
    skip_indices.extend(&dead_numeric_indices);

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
        for (_, var, val) in &single_use_strings {
            if current.contains(var.as_str()) {
                current = current.replace(var.as_str(), val.as_str());
            }
        }
        out.push_str(&current);
        if idx < lines.len().saturating_sub(1) {
            out.push('\n');
        }
    }
    out
}

/// Simplify method body: collapse "invoke(...); vN = <result>; return vN;" into "return method(args);"
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
                writeln!(out, "{}v{} = {}", indent, move_reg, call).ok();
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
    // Inline "var = System.out;" → replace var.println(x) with System.out.println(x) and remove the assignment.
    out = inline_static_field_refs(&out);
    // Remove bare "var; /* move-exception */" lines and inline single-use string constants.
    out = cleanup_decompiler_artifacts(&out);
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
    fn parse_move_result() {
        assert_eq!(parse_move_result_line("        v0 = <result>;  // x"), Some(0));
        assert_eq!(parse_move_result_line("        v5 = <result>;"), Some(5));
        assert_eq!(parse_move_result_line("        v0 = v1;"), None);
    }

    #[test]
    fn parse_return_reg() {
        assert_eq!(parse_return_reg_line("        return v0;  // x"), Some(0));
        assert_eq!(parse_return_reg_line("        return v3;"), Some(3));
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
        assert!(simplified.contains("n0 = 12;"), "n0 = 12 should remain (used later): {:?}", simplified);
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
}
