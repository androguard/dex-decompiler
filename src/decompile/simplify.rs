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

/// Simplify method body: collapse "invoke(...); vN = <result>; return vN;" into "return method(args);"
/// and "invoke(...); vN = <result>;" into "vN = method(args);".
pub fn simplify_method_body(body: &str) -> String {
    let lines: Vec<String> = body.lines().map(String::from).collect();
    if lines.len() < 2 {
        return body.to_string();
    }
    let mut i = 0usize;
    let mut out = String::new();
    while i < lines.len() {
        let line = &lines[i];

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
        let simplified = simplify_method_body(body);
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
        let simplified = simplify_method_body(body);
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
        let simplified = simplify_method_body(body);
        assert!(
            simplified.contains("ViewCompatJB.postInvalidateOnAnimation(v1);"),
            "expected Java-style call in {:?}",
            simplified
        );
        assert!(simplified.contains("return;"));
        assert!(!simplified.contains("invoke-static"));
    }
}
