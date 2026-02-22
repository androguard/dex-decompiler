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

/// Match "var.append(arg);", return Some((var, arg)).
fn parse_append(line: &str) -> Option<(String, String)> {
    let binding = strip_trailing_comment(line);
    let stmt = binding.trim();
    let dot = stmt.find(".append(")?;
    let var = stmt[..dot].trim().to_string();
    let start = dot + ".append(".len();
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
        if let Some((sb_var, first_opt)) = parse_new_stringbuilder(line) {
            let mut parts: Vec<String> = if let Some(a) = first_opt {
                vec![a]
            } else {
                vec![]
            };
            let mut j = i + 1;
            while j < lines.len() {
                if let Some((v, arg)) = parse_append(&lines[j]) {
                    if v == sb_var {
                        parts.push(arg);
                        j += 1;
                        continue;
                    }
                }
                break;
            }
            if j >= i + 1 && j < lines.len() && !parts.is_empty() {
                if let Some((dest, to_str_var)) = parse_to_string(&lines[j]) {
                    if to_str_var == sb_var {
                        let indent = leading_indent(line);
                        let concat = parts.join(" + ");
                        if dest == "return" {
                            writeln!(out, "{}return {};", indent, concat).ok();
                            skip_unreachable_indent = Some(indent.len());
                        } else {
                            writeln!(out, "{}{} = {};", indent, dest, concat).ok();
                        }
                        i = j + 1;
                        continue;
                    }
                }
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
}
