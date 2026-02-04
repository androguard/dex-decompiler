//! Control-flow graph for method body: basic blocks, loop detection, if/else structure.
//! Used to emit structured Java (if/else, while/for).

use dex_bytecode::{basic_blocks, Instruction};
use std::collections::{HashMap, HashSet};

/// Parse packed/sparse-switch payload at expected offset; return (case_value, target_byte_offset) for each case.
/// Target offset is in the same space as block start_offset (byte offset in code buffer).
fn parse_switch_payload(data: &[u8], switch_ins_off: usize) -> Option<Vec<(i32, u32)>> {
    if switch_ins_off + 6 > data.len() {
        return None;
    }
    let rel_units = i32::from_le_bytes(
        data[switch_ins_off + 2..switch_ins_off + 6]
            .try_into()
            .unwrap_or([0, 0, 0, 0]),
    );
    let try_payload = |off: usize| -> Option<(u16, u16)> {
        if off + 4 > data.len() {
            return None;
        }
        let id = u16::from_le_bytes(data[off..off + 2].try_into().unwrap_or([0, 0]));
        let sz = u16::from_le_bytes(data[off + 2..off + 4].try_into().unwrap_or([0, 0]));
        if id == 0x0100 || id == 0x0200 {
            Some((id, sz))
        } else {
            None
        }
    };
    let cand_a = (switch_ins_off as i32 + rel_units * 2) as usize;
    let cand_b = (switch_ins_off as i32 + 2 + rel_units * 2) as usize;
    let mut payload_off = None;
    for &off in &[cand_a, cand_b] {
        if off + 4 <= data.len() && try_payload(off).is_some() {
            payload_off = Some(off);
            break;
        }
    }
    let payload_off = payload_off.or_else(|| {
        let start = cand_a.saturating_sub(8);
        let end = (cand_a + 8).min(data.len().saturating_sub(4));
        (start..=end).find(|&off| off + 4 <= data.len() && try_payload(off).is_some())
    })?;
    let (ident, size) = try_payload(payload_off)?;
    let size = size as usize;
    let mut out = Vec::with_capacity(size);
    match ident {
        0x0100 => {
            if payload_off + 8 + size * 4 > data.len() {
                return None;
            }
            let first_key = i32::from_le_bytes(
                data[payload_off + 4..payload_off + 8]
                    .try_into()
                    .unwrap_or([0, 0, 0, 0]),
            );
            let targets_base = payload_off + 8;
            for i in 0..size {
                let rel = i32::from_le_bytes(
                    data[targets_base + i * 4..targets_base + i * 4 + 4]
                        .try_into()
                        .unwrap_or([0, 0, 0, 0]),
                );
                // Target in 16-bit units from switch instruction; same as dex-bytecode: base + rel*2.
                let target_byte = ((switch_ins_off as i32) + rel * 2) as u32;
                out.push((first_key + i as i32, target_byte));
            }
        }
        0x0200 => {
            if payload_off + 4 + size * 8 > data.len() {
                return None;
            }
            let keys_base = payload_off + 4;
            let targets_base = payload_off + 4 + size * 4;
            for i in 0..size {
                let key = i32::from_le_bytes(
                    data[keys_base + i * 4..keys_base + i * 4 + 4]
                        .try_into()
                        .unwrap_or([0, 0, 0, 0]),
                );
                let rel = i32::from_le_bytes(
                    data[targets_base + i * 4..targets_base + i * 4 + 4]
                        .try_into()
                        .unwrap_or([0, 0, 0, 0]),
                );
                let target_byte = ((switch_ins_off as i32) + rel * 2) as u32;
                out.push((key, target_byte));
            }
        }
        _ => return None,
    }
    // basic_blocks uses byte offsets in the buffer; ensure we don't exceed slice length
    for (_, t) in out.iter_mut() {
        if *t as usize > data.len() {
            return None;
        }
    }
    Some(out)
}

/// Block index in the CFG (entry = 0 when blocks are sorted by start_offset).
pub type BlockId = usize;

/// Kind of control flow at the end of a block.
#[derive(Debug, Clone)]
pub enum BlockEnd {
    /// Fall-through to next block (no branch, or return/throw).
    FallThrough,
    /// Unconditional branch (goto) to target block.
    Goto(BlockId),
    /// Conditional branch: if condition then branch_target else fall_through.
    Conditional {
        condition: String,
        branch_target: BlockId,
        fall_through: BlockId,
    },
    /// Packed/sparse switch: (case value -> block), default block.
    Switch {
        /// Variable/expression used in switch (e.g. "local0").
        condition: String,
        /// (case value, target block) in payload order.
        cases: Vec<(i32, BlockId)>,
        /// Block for default (fall-through from switch instruction).
        default_block: BlockId,
    },
    /// Return or throw; no successor.
    Exit,
}

/// Extended block with resolved successors and end kind.
#[derive(Debug, Clone)]
pub struct CfgBlock {
    #[allow(dead_code)]
    pub start_offset: u32,
    pub end_offset: u32,
    pub end: BlockEnd,
    /// Instruction byte offsets (in code buffer) that belong to this block.
    pub instruction_offsets: Vec<u32>,
}

/// Method-level CFG: blocks, entry, loop headers.
#[derive(Debug)]
pub struct MethodCfg {
    pub blocks: Vec<CfgBlock>,
    /// Map: byte offset (block start) -> BlockId.
    pub block_by_start: HashMap<u32, BlockId>,
    /// Block ids that are targets of back edges (loop headers).
    pub loop_headers: HashSet<BlockId>,
    /// Entry block id (block containing first instruction).
    pub entry: BlockId,
}

impl MethodCfg {
    /// Build CFG from decoded instructions and bytecode. base_offset is 0 when using insns_slice.
    pub fn build(
        instructions: &[Instruction],
        data: &[u8],
        base_offset: usize,
        condition_for_offset: &impl Fn(&Instruction) -> String,
    ) -> Self {
        let raw_blocks = basic_blocks(instructions, data, base_offset);
        if raw_blocks.is_empty() {
            return Self {
                blocks: vec![],
                block_by_start: HashMap::new(),
                loop_headers: HashSet::new(),
                entry: 0,
            };
        }

        let mut block_by_start: HashMap<u32, BlockId> = HashMap::new();
        for (i, b) in raw_blocks.iter().enumerate() {
            block_by_start.insert(b.start_offset, i);
        }

        let entry = *block_by_start.get(&(base_offset as u32)).unwrap_or(&0);

        let mut blocks: Vec<CfgBlock> = Vec::with_capacity(raw_blocks.len());
        for (_i, rb) in raw_blocks.iter().enumerate() {
            let start = rb.start_offset;
            let end = rb.end_offset;

            let instruction_offsets: Vec<u32> = instructions
                .iter()
                .filter(|ins| {
                    let off = (ins.offset as usize) + base_offset;
                    off >= start as usize && off < end as usize
                })
                .map(|ins| (ins.offset as usize + base_offset) as u32)
                .collect();

            let last_ins = instruction_offsets.last().and_then(|&off| {
                instructions.iter().find(|ins| (ins.offset as usize) + base_offset == off as usize)
            });

            let fall_through_id = block_by_start.get(&end).copied();
            let branch_target_ids: Vec<BlockId> = rb
                .successors
                .iter()
                .filter_map(|&off| block_by_start.get(&off).copied())
                .collect();

            let end_final = if let Some(ins) = last_ins {
                let m = ins.mnemonic();
                // Look for packed/sparse-switch anywhere in the block (e.g. block may be const, packed-switch, goto).
                let switch_ins = instruction_offsets.iter().find_map(|&off| {
                    let ins_here = instructions.iter().find(|i| (i.offset as usize) + base_offset == off as usize)?;
                    if ins_here.mnemonic() == "packed-switch" || ins_here.mnemonic() == "sparse-switch" {
                        Some((ins_here, (off as usize).saturating_sub(base_offset)))
                    } else {
                        None
                    }
                });
                if let Some((switch_ins, ins_off_in_slice)) = switch_ins {
                    if let Some(case_targets) = parse_switch_payload(data, ins_off_in_slice) {
                        // Default block: if the next instruction after the switch is a goto, default is goto target; else fall-through.
                        let next_off_abs = (base_offset + ins_off_in_slice + 6) as u32;
                        let default_id = if instruction_offsets.contains(&next_off_abs) {
                            instructions
                                .iter()
                                .find(|i| (i.offset as usize) + base_offset == next_off_abs as usize)
                                .and_then(|i| {
                                    if i.mnemonic().starts_with("goto") {
                                        branch_target_ids.first().copied()
                                    } else {
                                        None
                                    }
                                })
                        } else {
                            None
                        }
                        .or_else(|| {
                            let key = (ins_off_in_slice + 6) as u32;
                            block_by_start.get(&key).copied()
                        })
                        .or_else(|| fall_through_id)
                        .unwrap_or(entry);
                        let cases: Vec<(i32, BlockId)> = case_targets
                            .into_iter()
                            .filter_map(|(val, off)| {
                                let bid = block_by_start.get(&off).copied().or_else(|| {
                                    raw_blocks
                                        .iter()
                                        .position(|b| {
                                            let end = if b.end_offset == u32::MAX {
                                                usize::MAX
                                            } else {
                                                b.end_offset as usize
                                            };
                                            (b.start_offset as usize..end).contains(&(off as usize))
                                        })
                                        .map(|i| i as BlockId)
                                })?;
                                Some((val, bid))
                            })
                            .collect();
                        if !cases.is_empty() {
                            blocks.push(CfgBlock {
                                start_offset: start,
                                end_offset: end,
                                end: BlockEnd::Switch {
                                    condition: condition_for_offset(switch_ins),
                                    cases,
                                    default_block: default_id,
                                },
                                instruction_offsets: instruction_offsets.clone(),
                            });
                            continue;
                        }
                    }
                }
                match m {
                    "return-void" | "return" | "return-wide" | "return-object" | "throw" => BlockEnd::Exit,
                    "goto" | "goto/16" | "goto/32" => {
                        if let Some(&tid) = branch_target_ids.first() {
                            BlockEnd::Goto(tid)
                        } else {
                            fall_through_id.map(|_| BlockEnd::FallThrough).unwrap_or(BlockEnd::Exit)
                        }
                    }
                    "if-eq" | "if-ne" | "if-lt" | "if-ge" | "if-gt" | "if-le"
                    | "if-eqz" | "if-nez" | "if-ltz" | "if-gez" | "if-gtz" | "if-lez" => {
                        let cond = condition_for_offset(ins);
                        let then_id = branch_target_ids.first().copied().unwrap_or(entry);
                        let else_id = fall_through_id.unwrap_or(entry);
                        BlockEnd::Conditional {
                            condition: cond,
                            branch_target: then_id,
                            fall_through: else_id,
                        }
                    }
                    "packed-switch" | "sparse-switch" => {
                        let ins_off_in_slice = instruction_offsets
                            .last()
                            .copied()
                            .map(|o| (o as usize).saturating_sub(base_offset))
                            .unwrap_or(0);
                        if let Some(case_targets) = parse_switch_payload(data, ins_off_in_slice) {
                            let default_off = (ins_off_in_slice + 6) as u32;
                            let default_id = block_by_start
                                .get(&default_off)
                                .copied()
                                .or_else(|| fall_through_id)
                                .unwrap_or(entry);
                            let cases: Vec<(i32, BlockId)> = case_targets
                                .into_iter()
                                .filter_map(|(val, off)| {
                                    let bid = block_by_start.get(&off).copied().or_else(|| {
                                        raw_blocks
                                            .iter()
                                            .position(|b| {
                                                let end = if b.end_offset == u32::MAX {
                                                    usize::MAX
                                                } else {
                                                    b.end_offset as usize
                                                };
                                                (b.start_offset as usize..end).contains(&(off as usize))
                                            })
                                            .map(|i| i as BlockId)
                                    })?;
                                    Some((val, bid))
                                })
                                .collect();
                            if !cases.is_empty() {
                                BlockEnd::Switch {
                                    condition: condition_for_offset(ins),
                                    cases,
                                    default_block: default_id,
                                }
                            } else {
                                fall_through_id
                                    .map(|_| BlockEnd::FallThrough)
                                    .unwrap_or(BlockEnd::Exit)
                            }
                        } else {
                            fall_through_id
                                .map(|_| BlockEnd::FallThrough)
                                .unwrap_or(BlockEnd::Exit)
                        }
                    }
                    _ => fall_through_id
                        .map(|_| BlockEnd::FallThrough)
                        .unwrap_or(BlockEnd::Exit),
                }
            } else {
                fall_through_id
                    .map(|_| BlockEnd::FallThrough)
                    .unwrap_or(BlockEnd::Exit)
            };

            blocks.push(CfgBlock {
                start_offset: start,
                end_offset: end,
                end: end_final,
                instruction_offsets,
            });
        }

        // Detect loop headers: blocks that are targets of back edges (edge from B to A where A.start < B.start).
        let mut loop_headers = HashSet::new();
        for (_i, rb) in raw_blocks.iter().enumerate() {
            for &succ_off in &rb.successors {
                if let Some(&succ_id) = block_by_start.get(&succ_off) {
                    let succ_start = raw_blocks[succ_id].start_offset;
                    let my_start = rb.start_offset;
                    if succ_start < my_start {
                        loop_headers.insert(succ_id);
                    }
                }
            }
        }

        Self {
            blocks,
            block_by_start,
            loop_headers,
            entry,
        }
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// All (from_block_id, to_block_id) edges for graph visualization.
    pub fn successor_edges(&self) -> Vec<(BlockId, BlockId)> {
        let mut edges = Vec::new();
        for (from_id, block) in self.blocks.iter().enumerate() {
            match &block.end {
                BlockEnd::FallThrough => {
                    if let Some(ft) = self.fall_through_block(from_id) {
                        edges.push((from_id, ft));
                    }
                }
                BlockEnd::Goto(t) => edges.push((from_id, *t)),
                BlockEnd::Conditional { branch_target, fall_through, .. } => {
                    edges.push((from_id, *branch_target));
                    edges.push((from_id, *fall_through));
                }
                BlockEnd::Switch { cases, default_block, .. } => {
                    for (_, bid) in cases {
                        edges.push((from_id, *bid));
                    }
                    edges.push((from_id, *default_block));
                }
                BlockEnd::Exit => {}
            }
        }
        edges
    }

    pub fn fall_through_block(&self, block_id: BlockId) -> Option<BlockId> {
        let end = self.blocks[block_id].end_offset;
        self.block_by_start.get(&end).copied()
    }

    /// Blocks that fall through to the given block (predecessors by fall-through only).
    /// Used to include the full exit path when branch_target is e.g. a return-only block
    /// and the real exit (e.g. Swap + return) is the block that falls through to it.
    pub fn blocks_that_fall_through_to(&self, target: BlockId) -> Vec<BlockId> {
        let mut preds = Vec::new();
        for bid in 0..self.blocks.len() {
            if self.fall_through_block(bid) == Some(target) {
                preds.push(bid);
            }
        }
        preds
    }

    /// True if `target` is reachable from `start` without entering `exclude` (e.g. loop header).
    pub fn reachable_from(&self, start: BlockId, target: BlockId, exclude: Option<BlockId>) -> bool {
        use std::collections::HashSet;
        let mut visited = HashSet::new();
        let mut stack = vec![start];
        while let Some(bid) = stack.pop() {
            if bid == target {
                return true;
            }
            if visited.contains(&bid) || exclude == Some(bid) {
                continue;
            }
            visited.insert(bid);
            let block = &self.blocks[bid];
            match &block.end {
                BlockEnd::FallThrough => {
                    if let Some(ft) = self.fall_through_block(bid) {
                        stack.push(ft);
                    }
                }
                BlockEnd::Goto(t) => stack.push(*t),
                BlockEnd::Conditional { branch_target, fall_through, .. } => {
                    stack.push(*branch_target);
                    stack.push(*fall_through);
                }
                BlockEnd::Switch { cases, default_block, .. } => {
                    for (_, bid) in cases {
                        stack.push(*bid);
                    }
                    stack.push(*default_block);
                }
                BlockEnd::Exit => {}
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockEnd, MethodCfg};
    use dex_bytecode::decode_all;

    fn condition_for(_ins: &dex_bytecode::Instruction) -> String {
        "v0 == 0".to_string()
    }

    /// Single return-void: entry block ends in Exit (basic_blocks may split after branch/return).
    #[test]
    fn cfg_single_return_void() {
        let bytecode: &[u8] = &[0x0e, 0x00]; // return-void
        let instructions = decode_all(bytecode, 0).unwrap();
        let cfg = MethodCfg::build(&instructions, bytecode, 0, &condition_for);
        assert!(cfg.block_count() >= 1);
        assert!(matches!(cfg.blocks[cfg.entry].end, BlockEnd::Exit));
        assert!(cfg.loop_headers.is_empty());
    }

    /// if-eqz v0, +3; goto +2; return-void; return-void
    /// Blocks: [0-4) if-eqz, [4-6) goto, [6-8) return-void, [8-10) return-void.
    /// Then-branch target = 6 (offset 6), else fall-through = 4.
    #[test]
    fn cfg_if_else_two_branches() {
        // if-eqz v0, +3 (21t: target = 0+2+3*2 = 8); goto +2 (target 4+2+2*2 = 8); return-void at 6; return-void at 8
        let bytecode: &[u8] = &[
            0x38, 0x00, 0x03, 0x00, // if-eqz v0, +3 -> target byte 8
            0x28, 0x02,             // goto +2 -> target byte 4+4=8
            0x0e, 0x00,             // return-void at 6
            0x0e, 0x00,             // return-void at 8
        ];
        let instructions = decode_all(bytecode, 0).unwrap();
        let cfg = MethodCfg::build(&instructions, bytecode, 0, &condition_for);
        assert!(cfg.block_count() >= 2);
        let has_conditional = cfg.blocks.iter().any(|b| matches!(&b.end, BlockEnd::Conditional { .. }));
        assert!(has_conditional, "expected at least one conditional block (if-eqz)");
    }

    /// Loop: const/4; if-eqz (exit); goto back to if-eqz block. Back edge target is loop header.
    #[test]
    fn cfg_loop_back_edge() {
        // const/4 v0,0 (0..2); if-eqz v0,+4 (2..6) target 12; goto -3 (6..8) target 2; nop nop (8..12); return-void (12..14)
        let bytecode: &[u8] = &[
            0x12, 0x00,             // const/4 v0, 0
            0x38, 0x00, 0x04, 0x00, // if-eqz v0, +4 -> target byte 12
            0x28, 0xfd,             // goto -3 -> target byte 2
            0x00, 0x00, 0x00, 0x00, // nop, nop
            0x0e, 0x00,             // return-void at 12
        ];
        let instructions = decode_all(bytecode, 0).unwrap();
        let cfg = MethodCfg::build(&instructions, bytecode, 0, &condition_for);
        assert!(!cfg.loop_headers.is_empty(), "goto back to earlier block should create loop header");
    }

    /// Linear sequence: const/4, return (value-return). At least one block ends in Exit.
    #[test]
    fn cfg_linear_then_return() {
        let bytecode: &[u8] = &[
            0x12, 0x00, // const/4 v0, 0
            0x0f, 0x00, // return v0
        ];
        let instructions = decode_all(bytecode, 0).unwrap();
        let cfg = MethodCfg::build(&instructions, bytecode, 0, &condition_for);
        assert!(cfg.block_count() >= 1);
        let has_exit = cfg.blocks.iter().any(|b| matches!(b.end, BlockEnd::Exit));
        assert!(has_exit, "linear method with return should have an Exit block");
    }
}
