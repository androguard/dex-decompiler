//! Region maker: structured control flow (SESE-style regions) from CFG.
//!
//! Builds a region tree (Block, Seq, If, Loop) from MethodCfg, then emission
//! walks the tree to produce Java if/else and while.

use crate::decompile::cfg::{BlockEnd, BlockId, MethodCfg};
use std::collections::HashSet;

/// Single-entry single-exit style region for structured emission.
#[derive(Debug, Clone)]
pub enum Region {
    /// A single basic block (by id).
    Block(BlockId),
    /// Sequential list of regions (no branching between them).
    Seq(Vec<Region>),
    /// Conditional: if (condition) then_branch else else_branch.
    If {
        condition: String,
        then_branch: Box<Region>,
        else_branch: Box<Region>,
    },
    /// Loop: while (true) { body }. Header block is the loop header; body includes it.
    Loop {
        header: BlockId,
        body: Box<Region>,
    },
    /// Switch: switch (condition) { case v: case_body ... default: default_body }.
    Switch {
        condition: String,
        cases: Vec<(i32, Box<Region>)>,
        default: Box<Region>,
    },
}

/// Returns true if the region has no substantive content (empty seq or seq of empty regions).
/// Used to omit useless `} else { }` in emission.
pub fn region_is_empty(region: &Region) -> bool {
    match region {
        Region::Seq(children) => children.is_empty() || children.iter().all(region_is_empty),
        Region::Block(_) | Region::If { .. } | Region::Loop { .. } | Region::Switch { .. } => false,
    }
}

/// Like region_is_empty but uses the CFG to treat a Block as empty when that block has no instructions.
/// This allows flipping "if (cond) { } else { body }" to "if (!cond) { body }" when the then-branch is an empty block.
pub fn region_is_empty_with_cfg(region: &Region, cfg: &MethodCfg) -> bool {
    match region {
        Region::Block(bid) => cfg
            .blocks
            .get(*bid)
            .map(|b| b.instruction_offsets.is_empty())
            .unwrap_or(false),
        Region::Seq(children) => {
            children.is_empty() || children.iter().all(|c| region_is_empty_with_cfg(c, cfg))
        }
        Region::If { .. } | Region::Loop { .. } | Region::Switch { .. } => false,
    }
}

/// Returns true if the region contains a Loop (at any depth).
/// Used to prefer "if (cond) { short/return } else { loop }" by swapping when then has loop and else doesn't.
pub fn region_contains_loop(region: &Region) -> bool {
    match region {
        Region::Block(_) => false,
        Region::Seq(children) => children.iter().any(region_contains_loop),
        Region::If { then_branch, else_branch, .. } => {
            region_contains_loop(then_branch) || region_contains_loop(else_branch)
        }
        Region::Loop { .. } => true,
        Region::Switch { cases, default, .. } => {
            cases.iter().any(|(_, r)| region_contains_loop(r)) || region_contains_loop(default)
        }
    }
}

/// If loop body is Seq([Block(header), If { condition, then_branch, else_branch }]), returns
/// (condition, else_branch, then_branch) so emitter can emit "while (!(condition)) { else_branch }; then_branch".
/// When then_branch is non-empty (e.g. exit block with Swap + return), it is emitted after the while.
pub fn loop_body_break_pattern(body: &Region, header: BlockId) -> Option<(&str, &Region, &Region)> {
    match body {
        Region::Seq(children) if children.len() >= 2 => {
            let (first, second) = (&children[0], &children[1]);
            match (first, second) {
                (Region::Block(bid), Region::If { condition, then_branch, else_branch })
                    if *bid == header =>
                {
                    Some((condition.as_str(), else_branch, then_branch))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// First Block(block_id) in depth-first order; used to get loop exit block for break emission.
pub fn first_block(region: &Region) -> Option<BlockId> {
    match region {
        Region::Block(bid) => Some(*bid),
        Region::Seq(children) => children.iter().find_map(first_block),
        Region::If { then_branch, else_branch, .. } => {
            first_block(then_branch).or_else(|| first_block(else_branch))
        }
        Region::Loop { body, .. } => first_block(body),
        Region::Switch { cases, default, .. } => {
            cases.first().and_then(|(_, r)| first_block(r)).or_else(|| first_block(default))
        }
    }
}

/// Last Block(block_id) in a Seq (depth-first, last child); used to detect for-loop update tail.
pub fn last_block(region: &Region) -> Option<BlockId> {
    match region {
        Region::Block(bid) => Some(*bid),
        Region::Seq(children) => children.last().and_then(last_block),
        Region::If { .. } | Region::Loop { .. } | Region::Switch { .. } => None,
    }
}

/// If region is a Seq ending with a single Block, returns (prefix region without that block, that block id).
pub fn split_tail_block(region: &Region) -> Option<(Region, BlockId)> {
    match region {
        Region::Seq(children) if !children.is_empty() => {
            let last = children.last()?;
            if let Region::Block(bid) = last {
                let prefix: Vec<Region> = children[..children.len() - 1].to_vec();
                Some((Region::Seq(prefix), *bid))
            } else {
                None
            }
        }
        Region::Block(bid) => Some((Region::Seq(vec![]), *bid)),
        _ => None,
    }
}

/// If region is a Seq ending with two Blocks, returns (prefix, second-to-last block id, last block id).
pub fn split_tail_two_blocks(region: &Region) -> Option<(Region, BlockId, BlockId)> {
    match region {
        Region::Seq(children) if children.len() >= 2 => {
            let last = children.last()?;
            let second = children.get(children.len() - 2)?;
            match (second, last) {
                (Region::Block(bid1), Region::Block(bid2)) => {
                    let prefix: Vec<Region> = children[..children.len() - 2].to_vec();
                    Some((Region::Seq(prefix), *bid1, *bid2))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// For-loop pattern: when we have Seq([Block(init), Loop { header, body }]) and body is
/// Seq([Block(header), If { condition, then_branch, else_branch }]), and else_branch ends with
/// either (1) a single Block (update+goto) or (2) two Blocks (update block, goto-only block),
/// returns (init_block_id, header, condition, body_without_update, then_branch, update_block_id).
pub fn for_loop_pattern(seq: &[Region]) -> Option<(BlockId, BlockId, &str, Region, &Region, BlockId)> {
    if seq.len() != 2 {
        return None;
    }
    let (init_region, loop_region) = (&seq[0], &seq[1]);
    let init_block = match init_region {
        Region::Block(bid) => *bid,
        _ => return None,
    };
    let (header, body) = match loop_region {
        Region::Loop { header, body } => (*header, body.as_ref()),
        _ => return None,
    };
    let (condition, else_branch, then_branch) = loop_body_break_pattern(body, header)?;
    let (body_without_update, update_block) = if let Some((prefix, update_bid, _back_bid)) = split_tail_two_blocks(else_branch) {
        (prefix, update_bid)
    } else if let Some((prefix, single_bid)) = split_tail_block(else_branch) {
        (prefix, single_bid)
    } else {
        return None;
    };
    Some((init_block, header, condition, body_without_update, then_branch, update_block))
}

/// Build a region tree from the CFG starting at entry.
/// Uses the same structure as the current emit (loop headers -> Loop, conditionals -> If, rest -> Seq).
pub fn build_regions(cfg: &MethodCfg, entry: BlockId) -> Option<Region> {
    let mut emitted = HashSet::new();
    build_regions_rec(cfg, entry, None, &mut emitted, None)
}

/// Like build_regions but only includes blocks in `allowed`. Used for try body (only try-range blocks)
/// or catch body (only handler-range blocks). Successors outside `allowed` are treated as exit.
pub fn build_regions_filtered(
    cfg: &MethodCfg,
    entry: BlockId,
    allowed: &HashSet<BlockId>,
) -> Option<Region> {
    if !allowed.contains(&entry) {
        return None;
    }
    let mut emitted = HashSet::new();
    build_regions_rec(cfg, entry, None, &mut emitted, Some(allowed))
}

fn build_regions_rec(
    cfg: &MethodCfg,
    block_id: BlockId,
    loop_header: Option<BlockId>,
    emitted: &mut HashSet<BlockId>,
    allowed: Option<&HashSet<BlockId>>,
) -> Option<Region> {
    if emitted.contains(&block_id) {
        return None;
    }
    if let Some(allowed_set) = allowed {
        if !allowed_set.contains(&block_id) {
            return None;
        }
    }
    let block = &cfg.blocks[block_id];
    let is_loop_header = cfg.loop_headers.contains(&block_id);

    if is_loop_header && loop_header != Some(block_id) {
        emitted.insert(block_id);
        let body = build_loop_body(cfg, block_id, emitted, allowed);
        return Some(Region::Loop {
            header: block_id,
            body: Box::new(body),
        });
    }

    emitted.insert(block_id);
    let is_back_edge = matches!(&block.end, BlockEnd::Goto(t) if loop_header == Some(*t));
    let block_region = Region::Block(block_id);
    if is_back_edge {
        return Some(block_region);
    }

    match &block.end {
        BlockEnd::Exit => Some(block_region),
        BlockEnd::FallThrough => {
            let ft = cfg.fall_through_block(block_id)?;
            if allowed.map(|a| !a.contains(&ft)).unwrap_or(false) {
                return Some(block_region);
            }
            let next = build_regions_rec(cfg, ft, loop_header, emitted, allowed)?;
            Some(Region::Seq(vec![block_region, next]))
        }
        BlockEnd::Goto(t) => {
            if allowed.map(|a| !a.contains(t)).unwrap_or(false) {
                return Some(block_region);
            }
            let next = build_regions_rec(cfg, *t, loop_header, emitted, allowed)?;
            Some(Region::Seq(vec![block_region, next]))
        }
        BlockEnd::Conditional {
            condition,
            branch_target,
            fall_through,
        } => {
            // If branch_target is the loop header (back-edge), don't pull in fall-through predecessors
            // or we'd steal the loop body (e.g. in-loop Swap) into the then branch and leave else empty.
            // Otherwise, if some block falls through to branch_target (e.g. Swap → return), start
            // then_branch from that block so we emit the full exit path.
            let then_start = if loop_header == Some(*branch_target) {
                *branch_target
            } else {
                cfg.blocks_that_fall_through_to(*branch_target)
                    .into_iter()
                    .find(|&bid| {
                        !emitted.contains(&bid)
                            && !cfg.reachable_from(*fall_through, bid, loop_header)
                    })
                    .unwrap_or(*branch_target)
            };
            // Inside a loop, build else (loop body) before then so the body blocks (e.g. in-loop Swap)
            // are claimed by else_branch, not stolen by then_start when a body block falls through to then target.
            let (then_r, else_r) = if loop_header.is_some() {
                let else_r = build_regions_rec(cfg, *fall_through, loop_header, emitted, allowed)
                    .unwrap_or_else(|| Region::Seq(vec![]));
                let then_r = build_regions_rec(cfg, then_start, loop_header, emitted, allowed)
                    .unwrap_or_else(|| Region::Seq(vec![]));
                (then_r, else_r)
            } else {
                let then_r = build_regions_rec(cfg, then_start, loop_header, emitted, allowed)
                    .unwrap_or_else(|| Region::Seq(vec![]));
                let else_r = build_regions_rec(cfg, *fall_through, loop_header, emitted, allowed)
                    .unwrap_or_else(|| Region::Seq(vec![]));
                (then_r, else_r)
            };
            Some(Region::Seq(vec![
                block_region,
                Region::If {
                    condition: condition.clone(),
                    then_branch: Box::new(then_r),
                    else_branch: Box::new(else_r),
                },
            ]))
        }
        BlockEnd::Switch {
            condition,
            cases,
            default_block,
        } => {
            let stop_at: HashSet<BlockId> = std::iter::once(*default_block).collect();
            let case_regions: Vec<(i32, Box<Region>)> = cases
                .iter()
                .filter_map(|(val, bid)| {
                    let r = build_regions_rec_until(cfg, *bid, &stop_at, loop_header, emitted, allowed)
                        .unwrap_or_else(|| Region::Seq(vec![]));
                    Some((*val, Box::new(r)))
                })
                .collect();
            let default_r = build_regions_rec(cfg, *default_block, loop_header, emitted, allowed)
                .unwrap_or_else(|| Region::Seq(vec![]));
            Some(Region::Seq(vec![
                block_region,
                Region::Switch {
                    condition: condition.clone(),
                    cases: case_regions,
                    default: Box::new(default_r),
                },
            ]))
        }
    }
}

/// Build region from block_id until we hit a block in stop_at (exclusive). Used for switch case bodies.
fn build_regions_rec_until(
    cfg: &MethodCfg,
    block_id: BlockId,
    stop_at: &HashSet<BlockId>,
    loop_header: Option<BlockId>,
    emitted: &mut HashSet<BlockId>,
    allowed: Option<&HashSet<BlockId>>,
) -> Option<Region> {
    if stop_at.contains(&block_id) {
        return None;
    }
    if emitted.contains(&block_id) {
        return None;
    }
    if let Some(allowed_set) = allowed {
        if !allowed_set.contains(&block_id) {
            return None;
        }
    }
    let block = &cfg.blocks[block_id];
    emitted.insert(block_id);
    let block_region = Region::Block(block_id);
    let is_back_edge = matches!(&block.end, BlockEnd::Goto(t) if loop_header == Some(*t));
    if is_back_edge {
        return Some(block_region);
    }
    match &block.end {
        BlockEnd::Exit => Some(block_region),
        BlockEnd::FallThrough => {
            let ft = match cfg.fall_through_block(block_id) {
                Some(id) if !stop_at.contains(&id) => id,
                _ => return Some(block_region),
            };
            if allowed.map(|a| !a.contains(&ft)).unwrap_or(false) {
                return Some(block_region);
            }
            let next = build_regions_rec_until(cfg, ft, stop_at, loop_header, emitted, allowed)?;
            Some(Region::Seq(vec![block_region, next]))
        }
        BlockEnd::Goto(t) => {
            if stop_at.contains(t) {
                return Some(block_region);
            }
            if allowed.map(|a| !a.contains(t)).unwrap_or(false) {
                return Some(block_region);
            }
            let next = build_regions_rec_until(cfg, *t, stop_at, loop_header, emitted, allowed)?;
            Some(Region::Seq(vec![block_region, next]))
        }
        BlockEnd::Conditional {
            condition,
            branch_target,
            fall_through,
        } => {
            let then_start = *branch_target;
            let then_r = if stop_at.contains(&then_start) {
                Region::Seq(vec![])
            } else {
                build_regions_rec_until(cfg, then_start, stop_at, loop_header, emitted, allowed)
                    .unwrap_or_else(|| Region::Seq(vec![]))
            };
            let else_r = if stop_at.contains(fall_through) {
                Region::Seq(vec![])
            } else {
                build_regions_rec_until(cfg, *fall_through, stop_at, loop_header, emitted, allowed)
                    .unwrap_or_else(|| Region::Seq(vec![]))
            };
            Some(Region::Seq(vec![
                block_region,
                Region::If {
                    condition: condition.clone(),
                    then_branch: Box::new(then_r),
                    else_branch: Box::new(else_r),
                },
            ]))
        }
        BlockEnd::Switch { .. } => Some(block_region),
    }
}

fn build_loop_body(
    cfg: &MethodCfg,
    header_id: BlockId,
    emitted: &mut HashSet<BlockId>,
    allowed: Option<&HashSet<BlockId>>,
) -> Region {
    let block = &cfg.blocks[header_id];
    let block_reg = Region::Block(header_id);
    match &block.end {
        BlockEnd::Exit => block_reg,
        BlockEnd::FallThrough => {
            if let Some(ft) = cfg.fall_through_block(header_id) {
                let next = build_regions_rec(cfg, ft, Some(header_id), emitted, allowed)
                    .unwrap_or_else(|| Region::Seq(vec![]));
                return Region::Seq(vec![block_reg, next]);
            }
            block_reg
        }
        BlockEnd::Goto(t) if *t == header_id => block_reg,
        BlockEnd::Goto(t) => {
            let next = build_regions_rec(cfg, *t, Some(header_id), emitted, allowed)
                .unwrap_or_else(|| Region::Seq(vec![]));
            Region::Seq(vec![block_reg, next])
        }
        BlockEnd::Conditional {
            condition,
            branch_target,
            fall_through,
        } => {
            // If some block falls through to branch_target (e.g. Swap block → return block),
            // start then_branch from that block so we emit the full exit path. Exclude blocks
            // that are reachable from the loop body (fall_through), or we'd pick the wrong block
            // (e.g. the in-loop block that ends at the same address as the exit block start).
            let then_start = cfg
                .blocks_that_fall_through_to(*branch_target)
                .into_iter()
                .find(|&bid| {
                    !emitted.contains(&bid)
                        && !cfg.reachable_from(*fall_through, bid, Some(header_id))
                })
                .unwrap_or(*branch_target);
            let then_r = build_regions_rec(cfg, then_start, Some(header_id), emitted, allowed)
                .unwrap_or_else(|| Region::Seq(vec![]));
            let else_r = build_regions_rec(cfg, *fall_through, Some(header_id), emitted, allowed)
                .unwrap_or_else(|| Region::Seq(vec![]));
            Region::Seq(vec![
                block_reg,
                Region::If {
                    condition: condition.clone(),
                    then_branch: Box::new(then_r),
                    else_branch: Box::new(else_r),
                },
            ])
        }
        BlockEnd::Switch { .. } => block_reg,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dex_bytecode::decode_all;

    fn condition_for(_ins: &dex_bytecode::Instruction) -> String {
        "v0 == 0".to_string()
    }

    #[test]
    fn region_linear_single_block() {
        let bytecode: &[u8] = &[0x0e, 0x00]; // return-void
        let instructions = decode_all(bytecode, 0).unwrap();
        let cfg = MethodCfg::build(&instructions, bytecode, 0, &condition_for);
        let r = build_regions(&cfg, cfg.entry);
        assert!(r.is_some());
        let r = r.unwrap();
        assert!(matches!(r, Region::Block(_) | Region::Seq(_)));
    }

    #[test]
    fn region_if_else() {
        let bytecode: &[u8] = &[
            0x38, 0x00, 0x03, 0x00,
            0x28, 0x02,
            0x0e, 0x00,
            0x0e, 0x00,
        ];
        let instructions = decode_all(bytecode, 0).unwrap();
        let cfg = MethodCfg::build(&instructions, bytecode, 0, &condition_for);
        let r = build_regions(&cfg, cfg.entry);
        assert!(r.is_some());
        let r = r.unwrap();
        let has_if = match &r {
            Region::Seq(s) => s.iter().any(|x| matches!(x, Region::If { .. })),
            _ => false,
        };
        assert!(has_if, "expected If region in {:?}", r);
    }

    #[test]
    fn region_loop() {
        let bytecode: &[u8] = &[
            0x12, 0x00,
            0x38, 0x00, 0x04, 0x00,
            0x28, 0xfd,
            0x00, 0x00, 0x00, 0x00,
            0x0e, 0x00,
        ];
        let instructions = decode_all(bytecode, 0).unwrap();
        let cfg = MethodCfg::build(&instructions, bytecode, 0, &condition_for);
        let r = build_regions(&cfg, cfg.entry);
        assert!(r.is_some());
        let r = r.unwrap();
        let has_loop = contains_loop(&r);
        assert!(has_loop, "expected region tree to contain Loop, got {:?}", r);
    }

    fn contains_loop(r: &Region) -> bool {
        match r {
            Region::Loop { .. } => true,
            Region::Seq(s) => s.iter().any(contains_loop),
            Region::If { then_branch, else_branch, .. } => contains_loop(then_branch) || contains_loop(else_branch),
            Region::Block(_) | Region::Switch { .. } => false,
        }
    }

    /// Partition-style: exit path = (block A) + (block B return).
    /// The first If's then_branch (exit path) must include BOTH blocks (A and B).
    #[test]
    fn region_loop_exit_path_two_blocks() {
        // Same layout as test_decompiler_loop_exit_path_two_blocks: const/4; if-eqz +4 (target 12); goto -2; nop; const/4 v0,1; return v0
        let bytecode: &[u8] = &[
            0x12, 0x00,             // const/4 v0, 0
            0x38, 0x00, 0x04, 0x00, // if-eqz v0, +4 -> target 12
            0x28, 0xfe,             // goto -2 -> target 2
            0x00, 0x00,             // nop
            0x12, 0x01,             // const/4 v0, 1  (exit block 1)
            0x0f, 0x00,             // return v0     (exit block 2)
        ];
        let instructions = decode_all(bytecode, 0).unwrap();
        let cfg = MethodCfg::build(&instructions, bytecode, 0, &condition_for);
        let r = build_regions(&cfg, cfg.entry).expect("build_regions");
        fn block_count(r: &Region) -> usize {
            match r {
                Region::Block(_) => 1,
                Region::Seq(s) => s.iter().map(block_count).sum(),
                Region::If { then_branch, else_branch, .. } => block_count(then_branch) + block_count(else_branch),
                Region::Loop { body, .. } => block_count(body),
                Region::Switch { cases, default, .. } => {
                    cases.iter().map(|(_, r)| block_count(r)).sum::<usize>() + block_count(default)
                }
            }
        }
        fn first_if_then_branch(r: &Region) -> Option<&Region> {
            match r {
                Region::If { then_branch, .. } => Some(then_branch),
                Region::Seq(s) => s.iter().find_map(first_if_then_branch),
                Region::Loop { body, .. } => first_if_then_branch(body.as_ref()),
                Region::Block(_) | Region::Switch { .. } => None,
            }
        }
        let then_branch = first_if_then_branch(&r).expect("region tree should contain an If");
        let then_blocks = block_count(then_branch);
        assert!(
            then_blocks >= 2,
            "exit path (then_branch) must contain at least 2 blocks (e.g. const/4 + return), got {}; then_branch = {:?}; full region = {:?}",
            then_blocks,
            then_branch,
            r
        );
    }
}
