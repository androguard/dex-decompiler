//! Per-instruction read/write sets (which registers are read/written).
//! Used for reaching definitions and value-flow / tainting.

use super::{
    parse_instance_field_operands, parse_one_reg, parse_static_field_operands, parse_three_regs,
    parse_two_regs, parse_two_regs_and_literal,
};

/// Parse a comma-separated list of registers (e.g. "v0, v1" -> [0, 1]).
fn parse_reg_list(s: &str) -> Vec<u32> {
    s.split(',')
        .map(str::trim)
        .filter_map(|p| p.strip_prefix('v').and_then(|n| n.parse().ok()))
        .collect()
}

/// Return (regs_read, regs_written) for an instruction given mnemonic and resolved operands.
/// Used for value-flow and tainting. Unknown opcodes return (empty, empty).
pub fn instruction_reads_writes(mnemonic: &str, ops_resolved: &str) -> (Vec<u32>, Vec<u32>) {
    let m = mnemonic;
    let ops = ops_resolved.trim();

    // move / move-object: dst = src
    if matches!(m, "move" | "move/from16" | "move/16" | "move-object") {
        if let Some((dst, src)) = parse_two_regs(ops) {
            return (vec![src], vec![dst]);
        }
    }

    // move-result*: dst = result
    if m.starts_with("move-result") {
        if let Some(dst) = parse_one_reg(ops) {
            return (vec![], vec![dst]);
        }
    }

    // const*: dst = literal
    if matches!(m, "const/4" | "const/16" | "const" | "const-string" | "const-string/jumbo" | "const-class") {
        let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
        if let Some(first) = parts.first().and_then(|p| p.strip_prefix('v')) {
            if first.parse::<u32>().is_ok() {
                let reg: u32 = first.parse().unwrap();
                return (vec![], vec![reg]);
            }
        }
    }

    // return*: read reg
    if matches!(m, "return" | "return-wide" | "return-object") {
        if let Some(reg) = parse_one_reg(ops) {
            return (vec![reg], vec![]);
        }
    }
    if m == "return-void" {
        return (vec![], vec![]);
    }

    // invoke*: read all arg regs (everything before the method ref)
    if m.starts_with("invoke-") {
        let regs = parse_invoke_arg_regs(ops);
        return (regs, vec![]);
    }

    // if-*: read one or two regs (filter branch offset)
    if m.starts_with("if-") {
        let regs: Vec<u32> = ops
            .split(',')
            .map(str::trim)
            .filter(|p| !(p.starts_with('+') || p.starts_with('-') || p.starts_with("0x")))
            .filter_map(|p| p.strip_prefix('v').and_then(|n| n.parse().ok()))
            .collect();
        if !regs.is_empty() {
            return (regs, vec![]);
        }
    }

    // packed-switch / sparse-switch: read one reg
    if matches!(m, "packed-switch" | "sparse-switch") {
        if let Some(reg) = parse_one_reg(ops) {
            return (vec![reg], vec![]);
        }
    }

    // Binary ops: dst, src1, src2 or dst, src, lit
    if let Some((a, b, c)) = parse_three_regs(ops) {
        if matches!(m, "add-int" | "sub-int" | "mul-int" | "div-int" | "rem-int"
            | "and-int" | "or-int" | "xor-int" | "shl-int" | "shr-int" | "ushr-int"
            | "add-long" | "sub-long" | "mul-long" | "div-long" | "rem-long"
            | "and-long" | "or-long" | "xor-long" | "shl-long" | "shr-long" | "ushr-long"
            | "add-float" | "sub-float" | "mul-float" | "div-float" | "rem-float"
            | "add-double" | "sub-double" | "mul-double" | "div-double" | "rem-double"
            | "add-int/2addr" | "sub-int/2addr" | "rsub-int" | "add-int/lit8" | "rsub-int/lit8"
            | "new-array" | "aget" | "aput" | "iget" | "iput" | "sget" | "sput"
            | "invoke-virtual" | "invoke-direct" | "invoke-static" | "invoke-interface" | "invoke-super") {
            // Most 3-reg: dest = src1 op src2 -> read b,c write a. new-array: dest, size -> read b write a. iget: dest, object, field -> read b write a. iput: value, object, field -> read a,b.
            if m.starts_with("iput") {
                return (vec![a, b], vec![]);
            }
            if m.starts_with("aput") {
                return (vec![a, b, c], vec![]);
            }
            return (vec![b, c], vec![a]);
        }
    }
    if let Some((dst, src, _lit)) = parse_two_regs_and_literal(ops) {
        if matches!(m, "add-int/lit8" | "rsub-int/lit8" | "mul-int/lit8" | "div-int/lit8" | "rem-int/lit8"
            | "and-int/lit8" | "or-int/lit8" | "xor-int/lit8" | "shl-int/lit8" | "shr-int/lit8" | "ushr-int/lit8") {
            return (vec![src], vec![dst]);
        }
    }

    // Two-reg: e.g. move-exception, check-cast, instance-of
    if let Some((dst, src)) = parse_two_regs(ops) {
        if matches!(m, "move-exception" | "check-cast" | "instance-of") {
            return (vec![src], vec![dst]);
        }
    }

    // iget: dest, object, field -> read object, write dest
    if m.starts_with("iget") {
        if let Some((dest, object_reg, _)) = parse_instance_field_operands(ops) {
            return (vec![object_reg], vec![dest]);
        }
    }
    // iput: value, object, field -> read value, object
    if m.starts_with("iput") {
        if let Some((value_reg, object_reg, _)) = parse_instance_field_operands(ops) {
            return (vec![value_reg, object_reg], vec![]);
        }
    }
    // sget: reg, field -> write reg
    if m.starts_with("sget") {
        if let Some((reg, _)) = parse_static_field_operands(ops) {
            return (vec![], vec![reg]);
        }
    }
    // sput: reg, field -> read reg
    if m.starts_with("sput") {
        if let Some((reg, _)) = parse_static_field_operands(ops) {
            return (vec![reg], vec![]);
        }
    }

    // throw: read reg
    if m == "throw" {
        if let Some(reg) = parse_one_reg(ops) {
            return (vec![reg], vec![]);
        }
    }

    // new-instance: write one reg
    if m == "new-instance" {
        if let Some(reg) = parse_one_reg(ops) {
            return (vec![], vec![reg]);
        }
    }

    // new-array: dest, size -> read size, write dest
    if m == "new-array" {
        let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
        if parts.len() >= 2 {
            if let (Some(dst), Some(sz)) = (
                parts[0].strip_prefix('v').and_then(|n| n.parse().ok()),
                parts[1].strip_prefix('v').and_then(|n| n.parse().ok()),
            ) {
                return (vec![sz], vec![dst]);
            }
        }
    }

    // goto: no regs
    if m.starts_with("goto") || m == "nop" {
        return (vec![], vec![]);
    }

    (vec![], vec![])
}

/// From invoke operands "v0, v1, Lclass;->m(I)V" return [0, 1].
fn parse_invoke_arg_regs(ops: &str) -> Vec<u32> {
    let mut depth = 0u32;
    let mut last_comma = None;
    for (i, c) in ops.chars().enumerate() {
        match c {
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => last_comma = Some(i),
            _ => {}
        }
    }
    let args_str = match last_comma {
        Some(i) => ops[..i].trim(),
        None => ops.trim(),
    };
    parse_reg_list(args_str)
}

#[cfg(test)]
mod tests {
    use super::instruction_reads_writes;

    #[test]
    fn move_read_write() {
        let (r, w) = instruction_reads_writes("move", "v1, v0");
        assert_eq!(r, vec![0]);
        assert_eq!(w, vec![1]);
    }

    #[test]
    fn return_read() {
        let (r, w) = instruction_reads_writes("return", "v0");
        assert_eq!(r, vec![0]);
        assert!(w.is_empty());
    }

    #[test]
    fn const_write() {
        let (r, w) = instruction_reads_writes("const/4", "v0, 0");
        assert!(r.is_empty());
        assert_eq!(w, vec![0]);
    }
}
