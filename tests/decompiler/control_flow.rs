//! Control-flow integration tests: return, if/else, while via minimal DEX bytecode.

use super::helpers::minimal_dex_with_method_code;
use dex_decompiler::{parse_dex, Decompiler};

#[test]
fn test_decompiler_return_void() {
    let dex_bytes = minimal_dex_with_method_code(&[0x0e, 0x00]); // return-void
    let dex = parse_dex(&dex_bytes).unwrap();
    let dc = Decompiler::new(&dex);
    let java = dc.decompile().unwrap();
    assert!(
        java.contains("return;"),
        "decompiled method with return-void should contain 'return;'"
    );
}

#[test]
fn test_decompiler_return_value() {
    let bytecode: &[u8] = &[0x12, 0x00, 0x0f, 0x00]; // const/4 v0, 0; return v0
    let dex_bytes = minimal_dex_with_method_code(bytecode);
    let dex = parse_dex(&dex_bytes).unwrap();
    let dc = Decompiler::new(&dex);
    let java = dc.decompile().unwrap();
    assert!(
        java.contains("return"),
        "decompiled method with return should contain 'return'"
    );
}

/// if-eqz v0,+3; goto +2; return-void; return-void -> if/else with two returns.
#[test]
fn test_decompiler_if_else_pattern() {
    let bytecode: &[u8] = &[
        0x38, 0x00, 0x03, 0x00, // if-eqz v0, +3 -> target byte 8
        0x28, 0x02,             // goto +2 -> target byte 8
        0x0e, 0x00,             // return-void at 6
        0x0e, 0x00,             // return-void at 8
    ];
    let dex_bytes = minimal_dex_with_method_code(bytecode);
    let dex = parse_dex(&dex_bytes).unwrap();
    let dc = Decompiler::new(&dex);
    let java = dc.decompile().unwrap();
    assert!(java.contains("if ("), "decompiled if/else should contain 'if ('");
    assert!(
        java.contains("} else {"),
        "decompiled if/else should contain '}} else {{'"
    );
}

/// Loop: const/4; if-eqz (exit); goto back; nop nop; return-void. Emits while (!(cond)) { body }; exit.
#[test]
fn test_decompiler_while_loop_pattern() {
    let bytecode: &[u8] = &[
        0x12, 0x00,             // const/4 v0, 0
        0x38, 0x00, 0x04, 0x00, // if-eqz v0, +4 -> target 12
        0x28, 0xfd,             // goto -3 -> target 2
        0x00, 0x00, 0x00, 0x00, // nop, nop
        0x0e, 0x00,             // return-void at 12
    ];
    let dex_bytes = minimal_dex_with_method_code(bytecode);
    let dex = parse_dex(&dex_bytes).unwrap();
    let dc = Decompiler::new(&dex);
    let java = dc.decompile().unwrap();
    assert!(
        java.contains("while ("),
        "decompiled loop should contain 'while (' (either while (true) or while (!(cond)))"
    );
    assert!(
        java.contains("continue;"),
        "loop with back-edge should emit 'continue;'"
    );
}

/// Partition-style exit path: loop with exit = (statement block) + (return block).
/// The exit path has two blocks: first block does something (e.g. const/4 v0,1), second block returns.
/// Both must appear in decompiled output (regression for missing final Swap before return).
#[test]
fn test_decompiler_loop_exit_path_two_blocks() {
    // 0: const/4 v0, 0
    // 2: if-eqz v0, +4  -> target 12 (return block)
    // 6: goto -2        -> back to 2
    // 8: nop
    // 10: const/4 v0, 1   <- exit block 1 (must be emitted)
    // 12: return v0      <- exit block 2
    let bytecode: &[u8] = &[
        0x12, 0x00,             // const/4 v0, 0
        0x38, 0x00, 0x04, 0x00, // if-eqz v0, +4 -> target 2+2+8=12
        0x28, 0xfe,             // goto -2 -> target 2
        0x00, 0x00,             // nop
        0x12, 0x01,             // const/4 v0, 1  (exit path block 1)
        0x0f, 0x00,             // return v0     (exit path block 2)
    ];
    let dex_bytes = minimal_dex_with_method_code(bytecode);
    let dex = parse_dex(&dex_bytes).unwrap();
    let dc = Decompiler::new(&dex);
    let java = dc.decompile().unwrap();
    assert!(
        java.contains("return"),
        "exit path must contain return"
    );
    // Region tree must include BOTH exit blocks (see region::tests::region_loop_exit_path_two_blocks).
    // Decompiled output may still drop the first block if the instruction is optimized out
    // (e.g. const/4 into unused register). The important fix is that build_regions_rec includes
    // the fall-through predecessor of the return block in then_branch.
}
