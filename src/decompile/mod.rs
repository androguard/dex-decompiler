//! DEX to Java decompilation: decode bytecode with dex-bytecode, map to Java source.
//! Supports structured control flow: if/else, while loops (via CFG).
//! Simplification pass: collapse invoke + move-result + return into single return.

mod cfg;
pub mod graph;
mod ir;
pub mod pass;
pub mod pending_intent;
mod read_write;
pub mod region;
mod simplify;
mod type_infer;
pub mod value_flow;

use cfg::{BlockEnd, BlockId, MethodCfg};
use region::{build_regions, Region};
use dex_bytecode::{decode_all, Instruction};
use dex_parser::{ClassDef, CodeItem, DexFile, EncodedMethod, NO_INDEX};
use crate::error::{DexDecompilerError, Result};
use crate::java;
use std::fmt::Write;
use ir::{Expr as IrExpr, Stmt as IrStmt, VarId};
use pass::{run_dead_assign_with_used_regs, DeadAssignPass, InvokeChainPass, PassRunner, SsaRenamePass, used_regs};
use std::collections::{HashMap, HashSet};
use type_infer::{build_var_names, infer_types};
use value_flow::{
    build_api_return_sources, build_invoke_method_map, build_instruction_rw_map,
    ValueFlowAnalysisOwned,
};

/// Options for filtering which classes are decompiled (e.g. `--only-package`, `--exclude`).
#[derive(Clone, Default)]
pub struct DecompilerOptions {
    /// If set, only classes in this package (or the exact class) are decompiled. E.g. `com.example`.
    pub only_package: Option<String>,
    /// Exclude classes whose name equals or starts with any of these (after trimming trailing `.` or `.*`). E.g. `android.`
    pub exclude: Vec<String>,
}

/// One instruction row for bytecode display (e.g. in web UI).
#[derive(Debug, Clone)]
pub struct MethodBytecodeRow {
    pub offset: u32,
    pub mnemonic: String,
    pub operands: String,
}

/// One CFG block node for graph visualization.
#[derive(Debug, Clone)]
pub struct CfgNodeInfo {
    pub id: usize,
    pub start_offset: u32,
    pub end_offset: u32,
    pub label: String,
}

/// One CFG edge for graph visualization.
#[derive(Debug, Clone)]
pub struct CfgEdgeInfo {
    pub from_id: usize,
    pub to_id: usize,
}

/// Returns true if `class_name` should be included given only_package and exclude.
fn class_matches_filter(class_name: &str, only_package: Option<&str>, exclude: &[String]) -> bool {
    if let Some(prefix) = only_package {
        let prefix = prefix.trim_end_matches('.');
        if !(class_name == prefix || class_name.starts_with(&format!("{}.", prefix))) {
            return false;
        }
    }
    for exc in exclude {
        let exc = exc.trim_end_matches('.').trim_end_matches('*').trim();
        if class_name == exc || class_name.starts_with(&format!("{}.", exc)) {
            return false;
        }
    }
    true
}

/// Decompiler: takes a parsed DexFile and emits Java source.
pub struct Decompiler<'a> {
    pub dex: &'a DexFile,
    only_package: Option<String>,
    exclude: Vec<String>,
}

impl<'a> Decompiler<'a> {
    pub fn new(dex: &'a DexFile) -> Self {
        Self {
            dex,
            only_package: None,
            exclude: vec![],
        }
    }

    /// Create a decompiler with package/class filters.
    pub fn with_options(dex: &'a DexFile, options: DecompilerOptions) -> Self {
        Self {
            dex,
            only_package: options.only_package,
            exclude: options.exclude,
        }
    }

    /// Decompile entire DEX to Java source (one or more class declarations).
    /// Respects only_package and exclude when set.
    pub fn decompile(&self) -> Result<String> {
        let mut out = String::new();
        let mut first = true;
        for class_def_result in self.dex.class_defs() {
            let class_def = class_def_result.map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
            let class_type = self.dex.get_type(class_def.class_idx).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
            let class_name = java::descriptor_to_java(&class_type);
            if !class_matches_filter(&class_name, self.only_package.as_deref(), &self.exclude) {
                continue;
            }
            if !first {
                writeln!(&mut out).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            }
            first = false;
            let class_java = self.decompile_class(&class_def)?;
            write!(&mut out, "{}", class_java).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        Ok(out)
    }

    /// Decompile entire DEX into a directory with package structure (e.g. `out/com/example/MyClass.java`).
    pub fn decompile_to_dir(&self, base_path: &std::path::Path) -> Result<()> {
        self.decompile_to_dir_with_progress(base_path, None)
    }

    /// Like `decompile_to_dir`, but calls `progress(current, total, class_name)` after each class (1-based current).
    /// Respects only_package and exclude; progress total is the number of included classes.
    pub fn decompile_to_dir_with_progress(
        &self,
        base_path: &std::path::Path,
        mut progress: Option<&mut dyn FnMut(usize, usize, &str)>,
    ) -> Result<()> {
        let class_defs: Vec<_> = self.dex.class_defs().collect();
        let included: Vec<_> = class_defs
            .into_iter()
            .filter_map(|class_def_result| {
                let class_def = class_def_result.map_err(|e| DexDecompilerError::Parse(e.to_string())).ok()?;
                let class_type = self.dex.get_type(class_def.class_idx).map_err(|e| DexDecompilerError::Parse(e.to_string())).ok()?;
                let class_name = java::descriptor_to_java(&class_type);
                if class_matches_filter(&class_name, self.only_package.as_deref(), &self.exclude) {
                    Some((class_def, class_name))
                } else {
                    None
                }
            })
            .collect();
        let total = included.len();
        for (i, (class_def, class_name)) in included.into_iter().enumerate() {
            if let Some(p) = &mut progress {
                p(i + 1, total, &class_name);
            }
            let (rel_dir, file_name) = class_name_to_path(&class_name);
            let class_java = self.decompile_class(&class_def)?;
            let full_dir = base_path.join(rel_dir);
            std::fs::create_dir_all(&full_dir).map_err(|e| DexDecompilerError::Decompilation(format!("create dir {}: {}", full_dir.display(), e)))?;
            let file_path = full_dir.join(file_name);
            std::fs::write(&file_path, class_java).map_err(|e| DexDecompilerError::Decompilation(format!("write {}: {}", file_path.display(), e)))?;
        }
        Ok(())
    }

    /// Decompile one class to Java source.
    pub fn decompile_class(&self, class_def: &ClassDef) -> Result<String> {
        let class_type = self.dex.get_type(class_def.class_idx).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
        let class_name = java::descriptor_to_java(&class_type);
        let super_type = if class_def.superclass_idx != NO_INDEX {
            let s = self.dex.get_type(class_def.superclass_idx).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
            java::descriptor_to_java(&s)
        } else {
            "Object".to_string()
        };
        let flags = java::access_flags_to_java(class_def.access_flags, true);
        let mut out = String::new();
        for f in &flags {
            write!(&mut out, "{} ", f).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        write!(&mut out, "class {} extends {}", class_name, super_type)
            .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        writeln!(&mut out, " {{").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;

        let class_data = self.dex.get_class_data(class_def).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
        if let Some(ref cd) = class_data {
            for f in &cd.static_fields {
                if let Ok(fi) = self.dex.get_field_info(f.field_idx) {
                    let typ = java::descriptor_to_java(&fi.typ);
                    let name = fi.name;
                    let fflags = java::access_flags_to_java(f.access_flags, false);
                    for fl in &fflags {
                        write!(&mut out, "    {} ", fl).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                    }
                    writeln!(&mut out, "{} {};", typ, name).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                }
            }
            for f in &cd.instance_fields {
                if let Ok(fi) = self.dex.get_field_info(f.field_idx) {
                    let typ = java::descriptor_to_java(&fi.typ);
                    let name = fi.name;
                    let fflags = java::access_flags_to_java(f.access_flags, false);
                    for fl in &fflags {
                        write!(&mut out, "    {} ", fl).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                    }
                    writeln!(&mut out, "{} {};", typ, name).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                }
            }
            for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
                let method_java = self.decompile_method(m)?;
                write!(&mut out, "{}", method_java).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            }
        }

        writeln!(&mut out, "}}").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        Ok(out)
    }

    /// Decompile one method: signature + body (disassembly-based Java-like body).
    pub fn decompile_method(&self, encoded: &EncodedMethod) -> Result<String> {
        let info = self.dex.get_method_info(encoded.method_idx).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
        let return_type = java::descriptor_to_java(&info.return_type);
        let params: Vec<String> = info.params.iter().map(|p| java::descriptor_to_java(p)).collect();
        let flags = java::access_flags_to_java(encoded.access_flags, false);
        let mut out = String::new();
        for f in &flags {
            write!(&mut out, "    {} ", f).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        let name = &info.name;
        let params_str = params.iter().enumerate().map(|(i, t)| format!("{} p{}", t, i)).collect::<Vec<_>>().join(", ");
        write!(&mut out, "{} {}({}) ", return_type, name, params_str)
            .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        if flags.contains(&"abstract") || flags.contains(&"native") {
            writeln!(&mut out, ";").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            return Ok(out);
        }
        if encoded.code_off == 0 {
            writeln!(&mut out, "{{ }}").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            return Ok(out);
        }
        let code = self.dex.get_code_item(encoded.code_off).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
        // Raw DEX instructions line by line before the method body.
        let raw_listing = self.raw_dex_instructions_listing(&code)?;
        if !raw_listing.is_empty() {
            writeln!(&mut out).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            write!(&mut out, "{}", raw_listing).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        let body = self.decompile_method_body(&code, encoded)?;
        writeln!(&mut out, "{{").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        write!(&mut out, "{}", body).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        if !body.ends_with('\n') {
            writeln!(&mut out).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        writeln!(&mut out, "    }}").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        Ok(out)
    }

    /// Bytecode rows and CFG graph for a method (for web UI / visualization).
    pub fn get_method_bytecode_and_cfg(
        &self,
        encoded: &EncodedMethod,
    ) -> Result<(Vec<MethodBytecodeRow>, Vec<CfgNodeInfo>, Vec<CfgEdgeInfo>)> {
        if encoded.code_off == 0 {
            return Ok((vec![], vec![], vec![]));
        }
        let code = self.dex.get_code_item(encoded.code_off).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
        let insns_bytes = code.insns_slice(&*self.dex.data);
        let base_offset = 0usize;
        let instructions = decode_all(insns_bytes, base_offset)
            .map_err(|e| DexDecompilerError::Disassembly(e.to_string()))?;
        let base_off = code.insns_off;
        let rows: Vec<MethodBytecodeRow> = instructions
            .iter()
            .map(|ins| {
                let offset = (ins.offset as usize + base_off) as u32;
                let operands = self.resolve_operands(ins.operands());
                MethodBytecodeRow {
                    offset,
                    mnemonic: ins.mnemonic().to_string(),
                    operands,
                }
            })
            .collect();
        let condition_for = |ins: &Instruction| {
            let ops = ins.operands();
            let resolved = self.resolve_operands(ops);
            format_condition(ins.mnemonic(), &resolved)
        };
        let cfg = MethodCfg::build(&instructions, insns_bytes, base_offset, &condition_for);
        let base_off_u32 = base_off as u32;
        let nodes: Vec<CfgNodeInfo> = cfg
            .blocks
            .iter()
            .enumerate()
            .map(|(id, block)| {
                let label = block
                    .instruction_offsets
                    .first()
                    .and_then(|&off| {
                        instructions.iter().find(|i| (i.offset as usize) + base_offset == off as usize)
                    })
                    .map(|ins| {
                        let ops = self.resolve_operands(ins.operands());
                        let abs_off = block.start_offset + base_off_u32;
                        format!("0x{:04x}: {} {}", abs_off, ins.mnemonic(), ops)
                    })
                    .unwrap_or_else(|| {
                        let start_abs = block.start_offset + base_off_u32;
                        let end_abs = block.end_offset.wrapping_add(base_off_u32);
                        format!("B{} (0x{:04x}-0x{:04x})", id, start_abs, end_abs)
                    });
                let start_offset = block.start_offset + base_off_u32;
                let end_offset = if block.end_offset == u32::MAX {
                    u32::MAX
                } else {
                    block.end_offset + base_off_u32
                };
                CfgNodeInfo {
                    id,
                    start_offset,
                    end_offset,
                    label,
                }
            })
            .collect();
        let edges: Vec<CfgEdgeInfo> = cfg
            .successor_edges()
            .into_iter()
            .map(|(from_id, to_id)| CfgEdgeInfo { from_id, to_id })
            .collect();
        Ok((rows, nodes, edges))
    }

    /// Value-flow / tainting: build CFG and per-instruction read/write map for a method.
    /// Use `.analysis().value_flow_from_seed(offset, reg)` to get all reads/writes of a value.
    pub fn value_flow_analysis(&self, encoded: &EncodedMethod) -> Result<ValueFlowAnalysisOwned> {
        if encoded.code_off == 0 {
            return Err(DexDecompilerError::Decompilation(
                "value_flow_analysis: method has no code".into(),
            ));
        }
        let code = self.dex.get_code_item(encoded.code_off).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
        let insns_bytes = code.insns_slice(&*self.dex.data);
        let base_offset = 0usize;
        let instructions = decode_all(insns_bytes, base_offset)
            .map_err(|e| DexDecompilerError::Disassembly(e.to_string()))?;
        let condition_for = |ins: &Instruction| {
            let resolved = self.resolve_operands(ins.operands());
            format_condition(ins.mnemonic(), &resolved)
        };
        // CFG and rw_map use the same offset space (relative to method code start: 0, 2, 4, ...).
        let cfg = MethodCfg::build(&instructions, insns_bytes, base_offset, &condition_for);
        let rw_map = build_instruction_rw_map(&instructions, base_offset as u32, |ops| self.resolve_operands(ops));
        let api_return_sources = build_api_return_sources(&instructions, base_offset as u32, |ops| self.resolve_operands(ops));
        let invoke_method_map = build_invoke_method_map(&instructions, base_offset as u32, |ops| self.resolve_operands(ops));
        Ok(ValueFlowAnalysisOwned {
            cfg,
            rw_map,
            api_return_sources,
            invoke_method_map,
        })
    }

    /// Raw DEX instructions line by line as comments (before the method body).
    fn raw_dex_instructions_listing(&self, code: &CodeItem) -> Result<String> {
        let insns_bytes = code.insns_slice(&*self.dex.data);
        let instructions = decode_all(insns_bytes, 0)
            .map_err(|e| DexDecompilerError::Disassembly(e.to_string()))?;
        let base_off = code.insns_off;
        let mut out = String::new();
        for ins in &instructions {
            let offset = ins.offset as usize + base_off;
            let m = ins.mnemonic();
            let ops = self.resolve_operands(ins.operands());
            writeln!(out, "    // {:04x}: {} {}", offset, m, ops).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        if !instructions.is_empty() {
            writeln!(out).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        Ok(out)
    }

    /// Decompile method body: build CFG, emit structured Java (if/else, while).
    fn decompile_method_body(&self, code: &CodeItem, encoded: &EncodedMethod) -> Result<String> {
        let insns_bytes = code.insns_slice(&*self.dex.data);
        let base_offset = 0usize;
        let instructions = decode_all(insns_bytes, base_offset)
            .map_err(|e| DexDecompilerError::Disassembly(e.to_string()))?;
        if instructions.is_empty() {
            return Ok("        // (no instructions)\n".to_string());
        }

        let condition_for = |ins: &Instruction| {
            let ops = ins.operands();
            let resolved = self.resolve_operands(ops);
            format_condition(ins.mnemonic(), &resolved)
        };
        let cfg = MethodCfg::build(&instructions, insns_bytes, base_offset, &condition_for);
        if cfg.block_count() == 0 {
            return self.decompile_method_body_linear(&instructions, code.insns_off, encoded, code, insns_bytes);
        }

        let global_used_regs = self.method_used_regs(&cfg, &instructions, code.insns_off, insns_bytes);
        let mut out = String::new();
        let mut declared = HashSet::new();
        if let Some(root) = build_regions(&cfg, cfg.entry) {
            self.emit_region(&root, &cfg, &instructions, code.insns_off, encoded, code, &mut out, 2, None, None, &mut declared, Some(&global_used_regs))?;
        }
        if out.is_empty() {
            out = "        // (no instructions)\n".to_string();
        } else {
            out = simplify::simplify_method_body(&out);
        }
        if code.tries_size > 0 {
            out = format!("        // try/catch ({} tries) - handlers not yet emitted\n{}", code.tries_size, out);
        }
        Ok(out)
    }

    /// Fallback: linear instruction list (no CFG structure).
    fn decompile_method_body_linear(
        &self,
        instructions: &[Instruction],
        base_off: usize,
        encoded: &EncodedMethod,
        code: &CodeItem,
        code_insns: &[u8],
    ) -> Result<String> {
        let mut out = String::new();
        let stmts = self.instructions_to_ir(instructions, base_off, code_insns)?;
        let stmts = self.default_pass_runner().run(stmts);
        let type_map = infer_types(self.dex, encoded, code, &stmts);
        let ins_size = code.ins_size as u32;
        let is_static = (encoded.access_flags & 0x8) != 0;
        let name_map = build_var_names(&stmts, &type_map, ins_size, is_static);
        let mut declared = HashSet::new();
        for line in self.codegen_ir_lines(&stmts, Some(&type_map), Some(&name_map), &mut declared) {
            if !line.is_empty() {
                writeln!(&mut out, "        {}", line).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            }
        }
        if out.is_empty() {
            out = "        // (no instructions)\n".to_string();
        } else {
            out = simplify::simplify_method_body(&out);
        }
        if code.tries_size > 0 {
            out = format!("        // try/catch ({} tries) - handlers not yet emitted\n{}", code.tries_size, out);
        }
        Ok(out)
    }

    /// Emit Java from a region tree (structured control flow).
    /// Returns true if we emitted break (caller should stop emitting siblings).
    fn emit_region(
        &self,
        region: &Region,
        cfg: &MethodCfg,
        instructions: &[Instruction],
        base_off: usize,
        encoded: &EncodedMethod,
        code: &CodeItem,
        out: &mut String,
        indent: usize,
        skip_goto_to: Option<BlockId>,
        break_target: Option<BlockId>,
        declared: &mut HashSet<String>,
        global_used_regs: Option<&HashSet<u32>>,
    ) -> Result<bool> {
        let ind = "        ".repeat(indent);
        match region {
            Region::Block(block_id) => {
                self.emit_block_instructions(cfg, instructions, base_off, *block_id, skip_goto_to, break_target, encoded, code, out, indent, declared, global_used_regs, false)
            }
            Region::Seq(children) => {
                for (i, r) in children.iter().enumerate() {
                    let skip_block_last = match (r, children.get(i + 1)) {
                        (Region::Block(bid), Some(Region::Switch { .. })) => {
                            matches!(&cfg.blocks[*bid].end, BlockEnd::Switch { .. })
                        }
                        _ => false,
                    };
                    let emitted_break = if skip_block_last {
                        if let Region::Block(block_id) = r {
                            self.emit_block_instructions(
                                cfg, instructions, base_off, *block_id, skip_goto_to, break_target,
                                encoded, code, out, indent, declared, global_used_regs, true,
                            )?
                        } else {
                            self.emit_region(r, cfg, instructions, base_off, encoded, code, out, indent, skip_goto_to, break_target, declared, global_used_regs)?
                        }
                    } else {
                        self.emit_region(r, cfg, instructions, base_off, encoded, code, out, indent, skip_goto_to, break_target, declared, global_used_regs)?
                    };
                    if emitted_break {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Region::If {
                condition,
                then_branch,
                else_branch,
            } => {
                let then_empty = region::region_is_empty(then_branch);
                let else_empty = region::region_is_empty(else_branch);
                if then_empty && !else_empty {
                    writeln!(out, "{}if (!({})) {{", ind, condition).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                    let _ = self.emit_region(else_branch, cfg, instructions, base_off, encoded, code, out, indent + 1, skip_goto_to, break_target, declared, global_used_regs)?;
                } else {
                    writeln!(out, "{}if ({}) {{", ind, condition).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                    let _ = self.emit_region(then_branch, cfg, instructions, base_off, encoded, code, out, indent + 1, skip_goto_to, break_target, declared, global_used_regs)?;
                    if !else_empty {
                        writeln!(out, "{}}} else {{", ind).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                        let _ = self.emit_region(else_branch, cfg, instructions, base_off, encoded, code, out, indent + 1, skip_goto_to, break_target, declared, global_used_regs)?;
                    }
                }
                writeln!(out, "{}}}", ind).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                Ok(false)
            }
            Region::Loop { header, body } => {
                if let Some((condition, else_branch, then_branch)) = region::loop_body_break_pattern(body, *header) {
                    let exit_block = region::first_block(then_branch);
                    writeln!(out, "{}while (!({})) {{", ind, condition).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                    let _ = self.emit_block_instructions(cfg, instructions, base_off, *header, Some(*header), None, encoded, code, out, indent + 1, declared, global_used_regs, true)?;
                    let _ = self.emit_region(else_branch, cfg, instructions, base_off, encoded, code, out, indent + 1, Some(*header), exit_block, declared, global_used_regs)?;
                    writeln!(out, "{}}}", ind).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                    if !region::region_is_empty(then_branch) {
                        let _ = self.emit_region(then_branch, cfg, instructions, base_off, encoded, code, out, indent, skip_goto_to, break_target, declared, global_used_regs)?;
                    }
                } else {
                    writeln!(out, "{}while (true) {{", ind).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                    let _ = self.emit_region(body, cfg, instructions, base_off, encoded, code, out, indent + 1, Some(*header), None, declared, global_used_regs)?;
                    writeln!(out, "{}}}", ind).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                }
                Ok(false)
            }
            Region::Switch {
                condition,
                cases,
                default,
            } => {
                writeln!(out, "{}switch ({}) {{", ind, condition).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                for (value, body) in cases {
                    writeln!(out, "{}case {}:", ind, value).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                    let _ = self.emit_region(body, cfg, instructions, base_off, encoded, code, out, indent + 1, skip_goto_to, break_target, declared, global_used_regs)?;
                }
                writeln!(out, "{}default:", ind).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                let _ = self.emit_region(default, cfg, instructions, base_off, encoded, code, out, indent + 1, skip_goto_to, break_target, declared, global_used_regs)?;
                writeln!(out, "{}}}", ind).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                Ok(false)
            }
        }
    }

    /// Collect register numbers that are read (used) in any block, so dead-assign doesn't remove assigns used in other blocks.
    fn method_used_regs(&self, cfg: &MethodCfg, instructions: &[Instruction], base_off: usize, code_insns: &[u8]) -> HashSet<u32> {
        let mut runner = PassRunner::new();
        runner.add(InvokeChainPass);
        runner.add(SsaRenamePass);
        let mut used = HashSet::new();
        for block_id in 0..cfg.blocks.len() {
            let seq = self.block_instruction_seq(cfg, instructions, block_id, None, false);
            let stmts = self.instructions_to_ir(&seq, base_off, code_insns).unwrap_or_default();
            let stmts = runner.run(stmts);
            used.extend(used_regs(&stmts));
        }
        used
    }

    /// Instruction list for a block (for method_used_regs or emit_block_instructions).
    /// When skip_last_instruction is true (e.g. loop header with condition), omit the last instruction.
    fn block_instruction_seq(
        &self,
        cfg: &MethodCfg,
        instructions: &[Instruction],
        block_id: BlockId,
        skip_goto_to: Option<BlockId>,
        skip_last_instruction: bool,
    ) -> Vec<Instruction> {
        let block = &cfg.blocks[block_id];
        let skip_last = match &block.end {
            BlockEnd::Goto(t) if skip_goto_to == Some(*t) => true,
            _ => false,
        };
        let offs = &block.instruction_offsets;
        let mut seq: Vec<Instruction> = Vec::new();
        let drop_last = skip_last_instruction
            && matches!(&block.end, BlockEnd::Conditional { .. } | BlockEnd::Switch { .. });
        let skip_switch_ins = skip_last_instruction && matches!(&block.end, BlockEnd::Switch { .. });
        let limit = if drop_last && !offs.is_empty() {
            offs.len() - 1
        } else {
            offs.len()
        };
        for (i, &off) in offs.iter().enumerate() {
            if i >= limit {
                break;
            }
            let is_last = i == offs.len() - 1;
            if skip_last && is_last {
                break;
            }
            if let Some(ins) = instructions.iter().find(|ins| ins.offset == off) {
                if skip_switch_ins && (ins.mnemonic() == "packed-switch" || ins.mnemonic() == "sparse-switch") {
                    continue;
                }
                seq.push(ins.clone());
            }
        }
        seq
    }

    fn emit_block_instructions(
        &self,
        cfg: &MethodCfg,
        instructions: &[Instruction],
        base_off: usize,
        block_id: BlockId,
        skip_goto_to: Option<BlockId>,
        break_target: Option<BlockId>,
        encoded: &EncodedMethod,
        code: &CodeItem,
        out: &mut String,
        indent: usize,
        declared: &mut HashSet<String>,
        global_used_regs: Option<&HashSet<u32>>,
        skip_last_instruction: bool,
    ) -> Result<bool> {
        let ind = "        ".repeat(indent);
        let block = &cfg.blocks[block_id];
        let seq = self.block_instruction_seq(cfg, instructions, block_id, skip_goto_to, skip_last_instruction);
        let code_insns = code.insns_slice(&*self.dex.data);
        let stmts = self.instructions_to_ir(&seq, base_off, code_insns)?;
        let stmts = if let Some(used_regs) = global_used_regs {
            let mut runner = PassRunner::new();
            runner.add(InvokeChainPass);
            runner.add(SsaRenamePass);
            run_dead_assign_with_used_regs(runner.run(stmts), used_regs)
        } else {
            self.default_pass_runner().run(stmts)
        };
        let type_map = infer_types(self.dex, encoded, code, &stmts);
        let ins_size = code.ins_size as u32;
        let is_static = (encoded.access_flags & 0x8) != 0;
        let name_map = build_var_names(&stmts, &type_map, ins_size, is_static);
        for line in self.codegen_ir_lines(&stmts, Some(&type_map), Some(&name_map), declared) {
            if !line.is_empty() {
                writeln!(out, "{}{}", ind, line).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            }
        }
        match &block.end {
            BlockEnd::Goto(t) if break_target == Some(*t) => {
                writeln!(out, "{}break;", ind).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                Ok(true)
            }
            BlockEnd::Goto(t) if skip_goto_to == Some(*t) => {
                writeln!(out, "{}continue;", ind).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn codegen_ir_lines(
        &self,
        stmts: &[IrStmt],
        type_map: Option<&HashMap<VarId, String>>,
        name_map: Option<&HashMap<VarId, String>>,
        declared: &mut HashSet<String>,
    ) -> Vec<String> {
        stmts
            .iter()
            .map(|s| self.codegen_stmt_line(s, type_map, name_map, declared))
            .collect()
    }

    fn codegen_stmt_line(
        &self,
        stmt: &IrStmt,
        type_map: Option<&HashMap<VarId, String>>,
        name_map: Option<&HashMap<VarId, String>>,
        declared: &mut HashSet<String>,
    ) -> String {
        match (stmt, type_map) {
            (IrStmt::Assign { dst, rhs, comment }, Some(types)) if types.get(dst).is_some() => {
                let ty = types.get(dst).unwrap();
                let var = name_map.and_then(|n| n.get(dst).cloned()).unwrap_or_else(|| IrExpr::Var(*dst).to_java());
                let rhs_str = rhs.to_java_with_names(name_map);
                let base = if declared.insert(var.clone()) {
                    format!("{} {} = {};", ty, var, rhs_str)
                } else {
                    format!("{} = {};", var, rhs_str)
                };
                append_comment_typed(base, comment.as_deref())
            }
            _ => stmt.to_java_line_with_names(name_map),
        }
    }

    /// Convert a sequence of Dalvik instructions into method IR (raw form).
    /// InvokeChainPass is run by the pipeline to merge invoke+move-result+return.
    fn instructions_to_ir(&self, instructions: &[Instruction], base_off: usize, code_insns: &[u8]) -> Result<Vec<IrStmt>> {
        #[derive(Clone, Debug)]
        struct PendingInvoke {
            call_expr: IrExpr,
            comment: String,
        }

        let mut out: Vec<IrStmt> = Vec::new();
        let mut pending_invoke: Option<PendingInvoke> = None;

        let flush_pending_invoke = |out: &mut Vec<IrStmt>, pending_invoke: &mut Option<PendingInvoke>| {
            if let Some(pi) = pending_invoke.take() {
                out.push(IrStmt::Expr { expr: pi.call_expr, comment: Some(pi.comment) });
            }
        };

        for ins in instructions {
            let m = ins.mnemonic();
            let ops = ins.operands();
            let ops_resolved = self.resolve_operands(ops);
            let offset = ins.offset as usize + base_off;
            let comment = format!("{:04x}: {} {}", offset, m, ops);

            if pending_invoke.is_some() && !m.starts_with("move-result") {
                flush_pending_invoke(&mut out, &mut pending_invoke);
            }

            if m.starts_with("invoke-") {
                if let Some((target, args)) = parse_invoke_call_parts(&ops_resolved) {
                    pending_invoke = Some(PendingInvoke {
                        call_expr: IrExpr::Call { target, args },
                        comment,
                    });
                } else {
                    out.push(IrStmt::Raw(format!("{}( {} );  // // {}", m, ops_resolved, comment)));
                }
                continue;
            }

            if m == "move-result" || m == "move-result-wide" || m == "move-result-object" {
                if let Some(pi) = pending_invoke.take() {
                    if let Some(reg) = parse_one_reg(&ops_resolved) {
                        out.push(IrStmt::Expr { expr: pi.call_expr, comment: Some(pi.comment) });
                        out.push(IrStmt::Assign {
                            dst: ir::VarId::new(reg, 0),
                            rhs: IrExpr::PendingResult,
                            comment: Some(comment),
                        });
                        continue;
                    }
                }
                let line = self.instruction_to_java(ins, base_off, code_insns)?;
                out.push(IrStmt::Raw(format!("{}  // // {}", line, comment)));
                continue;
            }

            if m == "return-void" {
                flush_pending_invoke(&mut out, &mut pending_invoke);
                out.push(IrStmt::Return { value: None, comment: Some(comment) });
                continue;
            }

            if m == "return" || m == "return-wide" || m == "return-object" {
                flush_pending_invoke(&mut out, &mut pending_invoke);
                if let Some(reg) = parse_one_reg(&ops_resolved) {
                    out.push(IrStmt::Return {
                        value: Some(IrExpr::Var(ir::VarId::new(reg, 0))),
                        comment: Some(comment),
                    });
                } else {
                    let line = self.instruction_to_java(ins, base_off, code_insns)?;
                    out.push(IrStmt::Raw(format!("{}  // // {}", line, comment)));
                }
                continue;
            }

            // Emit Assign IR for const and binary ops so type inference and naming apply.
            if let Some((dst_reg, rhs_str)) = parse_assign_rhs(m, &ops_resolved) {
                flush_pending_invoke(&mut out, &mut pending_invoke);
                out.push(IrStmt::Assign {
                    dst: ir::VarId::new(dst_reg, 0),
                    rhs: IrExpr::Raw(rhs_str),
                    comment: Some(comment),
                });
                continue;
            }

            flush_pending_invoke(&mut out, &mut pending_invoke);
            let line = self.instruction_to_java(ins, base_off, code_insns)?;
            out.push(IrStmt::Raw(line));
        }

        flush_pending_invoke(&mut out, &mut pending_invoke);
        Ok(out)
    }

    /// Default pass pipeline (jadx-style). Runs after instructions_to_ir, before codegen.
    fn default_pass_runner(&self) -> PassRunner {
        let mut runner = PassRunner::new();
        runner.add(InvokeChainPass);
        runner.add(SsaRenamePass);
        runner.add(DeadAssignPass);
        runner
    }

    /// Map one Dalvik instruction to a Java-like statement (or comment).
    fn instruction_to_java(&self, ins: &Instruction, base_off: usize, code_insns: &[u8]) -> Result<String> {
        let m = ins.mnemonic();
        let ops = ins.operands();
        let ops_resolved = self.resolve_operands(ops);
        let offset = ins.offset as usize + base_off;
        // Emit as comment + Java-like line for key opcodes; others as disassembly comment.
        let comment = format!("// {:04x}: {} {}", offset, m, ops);
        let stmt = match m {
            "nop" => String::new(),
            "return-void" => "return;".into(),
            "return" => parse_one_reg(&ops_resolved).map(|r| format!("return v{};", r)).unwrap_or_default(),
            "return-wide" => parse_one_reg(&ops_resolved).map(|r| format!("return v{};", r)).unwrap_or_default(),
            "return-object" => parse_one_reg(&ops_resolved).map(|r| format!("return v{};", r)).unwrap_or_default(),
            "move" | "move/from16" | "move/16" => parse_two_regs(&ops_resolved).map(|(d, s)| format!("v{} = v{};", d, s)).unwrap_or_default(),
            "move-object" => parse_two_regs(&ops_resolved).map(|(d, s)| format!("v{} = v{};", d, s)).unwrap_or_default(),
            "move-result" | "move-result-wide" | "move-result-object" => parse_one_reg(&ops_resolved).map(|r| format!("v{} = <result>;", r)).unwrap_or_default(),
            "const/4" | "const/16" | "const" => parse_const_into_reg(&ops_resolved).unwrap_or_default(),
            "const-string" | "const-string/jumbo" => parse_string_ref(&ops_resolved).unwrap_or_default(),
            "invoke-virtual" | "invoke-super" | "invoke-direct" | "invoke-static" | "invoke-interface" => {
                format!("{}( {} );", m, ops_resolved)
            }
            "invoke-virtual/range" | "invoke-super/range" | "invoke-direct/range" | "invoke-static/range" | "invoke-interface/range" => {
                format!("{}( {} );", m, ops_resolved)
            }
            "if-eq" | "if-ne" | "if-lt" | "if-ge" | "if-gt" | "if-le"
            | "if-eqz" | "if-nez" | "if-ltz" | "if-gez" | "if-gtz" | "if-lez" => {
                // No real label is emitted; show only bytecode comment to avoid "goto label" with no label.
                String::new()
            }
            "goto" | "goto/16" | "goto/32" => String::new(),
            "packed-switch" | "sparse-switch" => format_switch(ins, code_insns, &ops_resolved),
            "new-instance" => parse_new_instance(&ops_resolved).unwrap_or_default(),
            "new-array" => format_new_array(&ops_resolved).unwrap_or_default(),
            "iget" | "iget-wide" | "iget-object" | "iget-boolean" => format_iget(&ops_resolved),
            "iput" | "iput-wide" | "iput-object" | "iput-boolean" => format_iput(&ops_resolved),
            "sget" | "sget-wide" | "sget-object" => format_sget(&ops_resolved),
            "sput" | "sput-wide" | "sput-object" => format_sput(&ops_resolved),
            "throw" => parse_one_reg(&ops_resolved).map(|r| format!("throw v{};", r)).unwrap_or_default(),
            // Binary int ops (2addr): vA, vB → vA = vA op vB
            "add-int/2addr" | "add-long/2addr" => format_binop_2addr(&ops_resolved, "+"),
            "sub-int/2addr" | "sub-long/2addr" => format_binop_2addr(&ops_resolved, "-"),
            "mul-int/2addr" | "mul-long/2addr" => format_binop_2addr(&ops_resolved, "*"),
            "div-int/2addr" | "div-long/2addr" => format_binop_2addr(&ops_resolved, "/"),
            "rem-int/2addr" | "rem-long/2addr" => format_binop_2addr(&ops_resolved, "%"),
            "and-int/2addr" | "and-long/2addr" => format_binop_2addr(&ops_resolved, "&"),
            "or-int/2addr" | "or-long/2addr" => format_binop_2addr(&ops_resolved, "|"),
            "xor-int/2addr" | "xor-long/2addr" => format_binop_2addr(&ops_resolved, "^"),
            "shl-int/2addr" | "shl-long/2addr" => format_binop_2addr(&ops_resolved, "<<"),
            "shr-int/2addr" | "shr-long/2addr" => format_binop_2addr(&ops_resolved, ">>"),
            "ushr-int/2addr" | "ushr-long/2addr" => format_binop_2addr(&ops_resolved, ">>>"),
            // lit8: vA, vB, #CC → vA = vB op lit (or rsub: vA = lit - vB)
            "add-int/lit8" => format_lit8(&ops_resolved, "+"),
            "rsub-int/lit8" => format_lit8_rsub(&ops_resolved),
            "mul-int/lit8" => format_lit8(&ops_resolved, "*"),
            "div-int/lit8" => format_lit8(&ops_resolved, "/"),
            "rem-int/lit8" => format_lit8(&ops_resolved, "%"),
            "and-int/lit8" => format_lit8(&ops_resolved, "&"),
            "or-int/lit8" => format_lit8(&ops_resolved, "|"),
            "xor-int/lit8" => format_lit8(&ops_resolved, "^"),
            "shl-int/lit8" => format_lit8(&ops_resolved, "<<"),
            "shr-int/lit8" => format_lit8(&ops_resolved, ">>"),
            "ushr-int/lit8" => format_lit8(&ops_resolved, ">>>"),
            // lit16: same as lit8 (vA, vB, literal)
            "add-int/lit16" => format_lit8(&ops_resolved, "+"),
            "rsub-int" => format_lit8_rsub(&ops_resolved),
            "mul-int/lit16" => format_lit8(&ops_resolved, "*"),
            "div-int/lit16" => format_lit8(&ops_resolved, "/"),
            "rem-int/lit16" => format_lit8(&ops_resolved, "%"),
            "and-int/lit16" => format_lit8(&ops_resolved, "&"),
            "or-int/lit16" => format_lit8(&ops_resolved, "|"),
            "xor-int/lit16" => format_lit8(&ops_resolved, "^"),
            // Three-register binary (F23x): vA, vB, vC → vA = vB op vC
            "add-int" | "add-long" => format_binop_23x(&ops_resolved, "+"),
            "sub-int" | "sub-long" => format_binop_23x(&ops_resolved, "-"),
            "mul-int" | "mul-long" => format_binop_23x(&ops_resolved, "*"),
            "div-int" | "div-long" => format_binop_23x(&ops_resolved, "/"),
            "rem-int" | "rem-long" => format_binop_23x(&ops_resolved, "%"),
            "and-int" | "and-long" => format_binop_23x(&ops_resolved, "&"),
            "or-int" | "or-long" => format_binop_23x(&ops_resolved, "|"),
            "xor-int" | "xor-long" => format_binop_23x(&ops_resolved, "^"),
            "shl-int" | "shl-long" => format_binop_23x(&ops_resolved, "<<"),
            "shr-int" | "shr-long" => format_binop_23x(&ops_resolved, ">>"),
            "ushr-int" | "ushr-long" => format_binop_23x(&ops_resolved, ">>>"),
            "add-float" | "add-double" => format_binop_23x(&ops_resolved, "+"),
            "sub-float" | "sub-double" => format_binop_23x(&ops_resolved, "-"),
            "mul-float" | "mul-double" => format_binop_23x(&ops_resolved, "*"),
            "div-float" | "div-double" => format_binop_23x(&ops_resolved, "/"),
            "rem-float" | "rem-double" => format_binop_23x(&ops_resolved, "%"),
            // Float/double 2addr: same as int 2addr
            "add-float/2addr" | "add-double/2addr" => format_binop_2addr(&ops_resolved, "+"),
            "sub-float/2addr" | "sub-double/2addr" => format_binop_2addr(&ops_resolved, "-"),
            "mul-float/2addr" | "mul-double/2addr" => format_binop_2addr(&ops_resolved, "*"),
            "div-float/2addr" | "div-double/2addr" => format_binop_2addr(&ops_resolved, "/"),
            "rem-float/2addr" | "rem-double/2addr" => format_binop_2addr(&ops_resolved, "%"),
            // Unary (F12x): vA, vB → vA = op vB
            "neg-int" | "neg-long" | "neg-float" | "neg-double" => format_unary(&ops_resolved, "-"),
            "not-int" | "not-long" => format_unary(&ops_resolved, "~"),
            // Casts (F12x): vA, vB → vA = (type) vB
            "int-to-long" => format_cast(&ops_resolved, "long"),
            "int-to-float" => format_cast(&ops_resolved, "float"),
            "int-to-double" => format_cast(&ops_resolved, "double"),
            "long-to-int" => format_cast(&ops_resolved, "int"),
            "long-to-float" => format_cast(&ops_resolved, "float"),
            "long-to-double" => format_cast(&ops_resolved, "double"),
            "float-to-int" => format_cast(&ops_resolved, "int"),
            "float-to-long" => format_cast(&ops_resolved, "long"),
            "float-to-double" => format_cast(&ops_resolved, "double"),
            "double-to-int" => format_cast(&ops_resolved, "int"),
            "double-to-long" => format_cast(&ops_resolved, "long"),
            "double-to-float" => format_cast(&ops_resolved, "float"),
            "int-to-byte" => format_cast(&ops_resolved, "byte"),
            "int-to-char" => format_cast(&ops_resolved, "char"),
            "int-to-short" => format_cast(&ops_resolved, "short"),
            // Array
            "array-length" => format_array_length(&ops_resolved),
            "aget" | "aget-wide" | "aget-object" | "aget-boolean" | "aget-byte" | "aget-char" | "aget-short" => {
                format_aget(&ops_resolved)
            }
            "aput" | "aput-wide" | "aput-object" | "aput-boolean" | "aput-byte" | "aput-char" | "aput-short" => {
                format_aput(&ops_resolved)
            }
            // Comparison (F23x): vA, vB, vC → vA = (vB op vC) ? 1 : 0; we emit Java-like comparison
            "cmpl-float" | "cmpg-float" | "cmpl-double" | "cmpg-double" | "cmp-long" => {
                format_cmp(&ops_resolved, m)
            }
            _ => format!("{}; // {}", ops_resolved, m),
        };
        if stmt.is_empty() {
            Ok(comment)
        } else {
            Ok(format!("{}  // {}", stmt, comment))
        }
    }

    /// Resolve string@N, type@N, field@N, method@N in operands using DEX indices.
    fn resolve_operands(&self, operands: &str) -> String {
        let parts: Vec<&str> = operands.split(',').map(str::trim).collect();
        parts
            .iter()
            .map(|part| resolve_one(self.dex, part))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Parse resolved invoke operands string into Java call parts.
/// Input format: \"v0, v1, pkg.Clz.m(java.lang.String, int)\" (method ref last, may contain commas).
/// Output: (\"pkg.Clz.m\", \"v0, v1\")
fn parse_invoke_call_parts(ops_resolved: &str) -> Option<(String, String)> {
    let inner = ops_resolved.trim();
    if inner.is_empty() {
        return None;
    }
    // Find last comma at depth 0 to split args from method ref.
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
    let args = inner[..split_at].trim();
    let method_ref = inner[split_at + 1..].trim();
    let method_name = method_ref.split('(').next().unwrap_or(method_ref).trim();
    Some((method_name.to_string(), args.to_string()))
}

fn append_comment_typed(base: String, comment: Option<&str>) -> String {
    match comment {
        None => base,
        Some(c) if c.is_empty() => base,
        Some(c) => format!("{}  // // {}", base, c),
    }
}

/// True if the token looks like a branch offset (e.g. "+008h", "-4") rather than a register/value.
fn is_branch_offset(token: &str) -> bool {
    let t = token.trim();
    if t.is_empty() {
        return true;
    }
    let b = t.as_bytes();
    (b[0] == b'+' || b[0] == b'-') && t[1..].trim().chars().all(|c| c.is_ascii_hexdigit() || c == 'h')
        || (t.starts_with("0x") && t[2..].chars().all(|c| c.is_ascii_hexdigit()))
}

/// Format Dalvik conditional branch as a Java boolean expression for if/while.
/// Operands may include branch offset (e.g. "v0, +008h"); we use only register/value parts.
fn format_condition(mnemonic: &str, resolved_operands: &str) -> String {
    let parts: Vec<&str> = resolved_operands
        .split(',')
        .map(str::trim)
        .filter(|p| !is_branch_offset(p))
        .collect();
    match mnemonic {
        "if-eq" => {
            if parts.len() >= 2 {
                format!("{} == {}", parts[0], parts[1])
            } else {
                resolved_operands.to_string()
            }
        }
        "if-ne" => {
            if parts.len() >= 2 {
                format!("{} != {}", parts[0], parts[1])
            } else {
                resolved_operands.to_string()
            }
        }
        "if-lt" => {
            if parts.len() >= 2 {
                format!("{} < {}", parts[0], parts[1])
            } else {
                resolved_operands.to_string()
            }
        }
        "if-ge" => {
            if parts.len() >= 2 {
                format!("{} >= {}", parts[0], parts[1])
            } else {
                resolved_operands.to_string()
            }
        }
        "if-gt" => {
            if parts.len() >= 2 {
                format!("{} > {}", parts[0], parts[1])
            } else {
                resolved_operands.to_string()
            }
        }
        "if-le" => {
            if parts.len() >= 2 {
                format!("{} <= {}", parts[0], parts[1])
            } else {
                resolved_operands.to_string()
            }
        }
        "if-eqz" => {
            if !parts.is_empty() {
                format!("{} == 0", parts[0])
            } else {
                resolved_operands.to_string()
            }
        }
        "if-nez" => {
            if !parts.is_empty() {
                format!("{} != 0", parts[0])
            } else {
                resolved_operands.to_string()
            }
        }
        "if-ltz" => {
            if !parts.is_empty() {
                format!("{} < 0", parts[0])
            } else {
                resolved_operands.to_string()
            }
        }
        "if-gez" => {
            if !parts.is_empty() {
                format!("{} >= 0", parts[0])
            } else {
                resolved_operands.to_string()
            }
        }
        "if-gtz" => {
            if !parts.is_empty() {
                format!("{} > 0", parts[0])
            } else {
                resolved_operands.to_string()
            }
        }
        "if-lez" => {
            if !parts.is_empty() {
                format!("{} <= 0", parts[0])
            } else {
                resolved_operands.to_string()
            }
        }
        _ => resolved_operands.to_string(),
    }
}

/// Map Java class name to (relative_dir, file_name) for dumping.
/// e.g. "com.example.MyClass" -> ("com/example", "MyClass.java"), "Outer$Inner" -> ("", "Outer$Inner.java").
fn class_name_to_path(class_name: &str) -> (std::path::PathBuf, String) {
    let parts: Vec<&str> = class_name.split('.').collect();
    if parts.len() <= 1 {
        return (std::path::PathBuf::new(), format!("{}.java", class_name));
    }
    let simple_name = parts[parts.len() - 1];
    let package_dir = parts[..parts.len() - 1].join("/");
    let path = if package_dir.is_empty() {
        std::path::PathBuf::new()
    } else {
        std::path::PathBuf::from(package_dir)
    };
    (path, format!("{}.java", simple_name))
}

/// Resolve one operand token (e.g. string@5 -> "hello", type@2 -> java.lang.String).
fn resolve_one(dex: &DexFile, part: &str) -> String {
    if let Some(idx_str) = part.strip_prefix("string@") {
        if let Ok(idx) = idx_str.parse::<u32>() {
            if let Ok(s) = dex.get_string(idx) {
                return format!("\"{}\"", escape_java_string(&s));
            }
        }
    }
    if let Some(idx_str) = part.strip_prefix("type@") {
        if let Ok(idx) = idx_str.parse::<u32>() {
            if let Ok(desc) = dex.get_type(idx) {
                return java::descriptor_to_java(&desc);
            }
        }
    }
    if let Some(idx_str) = part.strip_prefix("field@") {
        if let Ok(idx) = idx_str.parse::<u32>() {
            if let Ok(fi) = dex.get_field_info(idx) {
                return format!("{}.{}", java::descriptor_to_java(&fi.class), fi.name);
            }
        }
    }
    if let Some(idx_str) = part.strip_prefix("method@") {
        if let Ok(idx) = idx_str.parse::<u32>() {
            if let Ok(mi) = dex.get_method_info(idx) {
                let params = mi.params.iter().map(|p| java::descriptor_to_java(p)).collect::<Vec<_>>().join(", ");
                return format!("{}.{}({})", java::descriptor_to_java(&mi.class), mi.name, params);
            }
        }
    }
    part.to_string()
}

/// Escape string for use inside a Java string literal (for tests and reuse).
pub(crate) fn escape_java_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

pub(crate) fn parse_one_reg(ops: &str) -> Option<u32> {
    let s = ops.trim().strip_prefix('v')?;
    s.split(',').next()?.trim().parse().ok()
}

pub(crate) fn parse_two_regs(ops: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        return None;
    }
    let a = parts[0].strip_prefix('v')?.parse().ok()?;
    let b = parts[1].strip_prefix('v')?.parse().ok()?;
    Some((a, b))
}

/// Parse "vA, vB, literal" (e.g. add-int/lit8). Returns (dest_reg, src_reg, literal_str).
pub(crate) fn parse_two_regs_and_literal(ops: &str) -> Option<(u32, u32, String)> {
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    if parts.len() < 3 {
        return None;
    }
    let a = parts[0].strip_prefix('v')?.parse().ok()?;
    let b = parts[1].strip_prefix('v')?.parse().ok()?;
    let lit = parts[2].to_string();
    Some((a, b, lit))
}

/// Parse "vA, vB, vC" (e.g. add-int). Returns (dest_reg, src1_reg, src2_reg).
pub(crate) fn parse_three_regs(ops: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    if parts.len() < 3 {
        return None;
    }
    let a = parts[0].strip_prefix('v')?.parse().ok()?;
    let b = parts[1].strip_prefix('v')?.parse().ok()?;
    let c = parts[2].strip_prefix('v')?.parse().ok()?;
    Some((a, b, c))
}

/// Parse iget/iput operands: "vA, vB, ClassName.fieldName" -> (dest_reg, object_reg, field_name).
/// field_name is the segment after the last dot (Java instance field access).
pub(crate) fn parse_instance_field_operands(ops: &str) -> Option<(u32, u32, String)> {
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    if parts.len() < 3 {
        return None;
    }
    let dest = parts[0].strip_prefix('v')?.parse().ok()?;
    let object_reg = parts[1].strip_prefix('v')?.parse().ok()?;
    let field_ref = parts[2].trim();
    let field_name = field_ref.rsplit('.').next().unwrap_or(field_ref).to_string();
    Some((dest, object_reg, field_name))
}

/// Parse sget/sput operands: "vA, ClassName.fieldName" -> (reg, field_ref).
pub(crate) fn parse_static_field_operands(ops: &str) -> Option<(u32, String)> {
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        return None;
    }
    let reg = parts[0].strip_prefix('v')?.parse().ok()?;
    let field_ref = parts[1].trim().to_string();
    Some((reg, field_ref))
}

pub(crate) fn parse_const_into_reg(ops: &str) -> Option<String> {
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        return None;
    }
    let reg = parts[0].strip_prefix('v')?;
    let val = parts[1];
    Some(format!("v{} = {};", reg, val))
}

/// Parse assignment-like instruction into (dst_reg, rhs_expr_string) for IR Assign.
/// Returns None for non-assignment or unparseable ops.
fn parse_assign_rhs(m: &str, ops: &str) -> Option<(u32, String)> {
    match m {
        "const/4" | "const/16" | "const" => {
            let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
            if parts.len() < 2 {
                return None;
            }
            let reg: u32 = parts[0].strip_prefix('v')?.parse().ok()?;
            let val = parts[1].to_string();
            Some((reg, val))
        }
        "const-string" | "const-string/jumbo" => {
            let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
            if parts.len() < 2 {
                return None;
            }
            let reg: u32 = parts[0].strip_prefix('v')?.parse().ok()?;
            // Second part is already resolved (e.g. "4" or "\"hello\"") by resolve_operands
            let val = parts[1].to_string();
            Some((reg, val))
        }
        "sub-int/2addr" | "add-int/2addr" | "mul-int/2addr" | "div-int/2addr" | "rem-int/2addr"
        | "and-int/2addr" | "or-int/2addr" | "xor-int/2addr" | "shl-int/2addr" | "shr-int/2addr" | "ushr-int/2addr"
        | "add-long/2addr" | "sub-long/2addr" | "mul-long/2addr" | "div-long/2addr" | "rem-long/2addr"
        | "and-long/2addr" | "or-long/2addr" | "xor-long/2addr" | "shl-long/2addr" | "shr-long/2addr" | "ushr-long/2addr"
        | "add-float/2addr" | "sub-float/2addr" | "mul-float/2addr" | "div-float/2addr" | "rem-float/2addr"
        | "add-double/2addr" | "sub-double/2addr" | "mul-double/2addr" | "div-double/2addr" | "rem-double/2addr" => {
            let op = match m {
                "sub-int/2addr" | "sub-long/2addr" | "sub-float/2addr" | "sub-double/2addr" => "-",
                "add-int/2addr" | "add-long/2addr" | "add-float/2addr" | "add-double/2addr" => "+",
                "mul-int/2addr" | "mul-long/2addr" | "mul-float/2addr" | "mul-double/2addr" => "*",
                "div-int/2addr" | "div-long/2addr" | "div-float/2addr" | "div-double/2addr" => "/",
                "rem-int/2addr" | "rem-long/2addr" | "rem-float/2addr" | "rem-double/2addr" => "%",
                "and-int/2addr" | "and-long/2addr" => "&",
                "or-int/2addr" | "or-long/2addr" => "|",
                "xor-int/2addr" | "xor-long/2addr" => "^",
                "shl-int/2addr" | "shl-long/2addr" => "<<",
                "shr-int/2addr" | "shr-long/2addr" => ">>",
                "ushr-int/2addr" | "ushr-long/2addr" => ">>>",
                _ => return None,
            };
            parse_two_regs(ops).map(|(a, b)| (a, format!("v{} {} v{}", a, op, b)))
        }
        "add-int/lit8" | "mul-int/lit8" | "div-int/lit8" | "rem-int/lit8" | "and-int/lit8" | "or-int/lit8" | "xor-int/lit8"
        | "shl-int/lit8" | "shr-int/lit8" | "ushr-int/lit8"
        | "add-int/lit16" | "mul-int/lit16" | "div-int/lit16" | "rem-int/lit16" | "and-int/lit16" | "or-int/lit16" | "xor-int/lit16" => {
            let op = if m.contains("add") { "+" } else if m.contains("mul") { "*" } else if m.contains("div") { "/" }
                else if m.contains("rem") { "%" } else if m.contains("and") { "&" } else if m.contains("or") { "|" }
                else if m.contains("xor") { "^" } else if m.contains("shl") { "<<" } else if m.contains("shr") && !m.contains("ushr") { ">>" }
                else { ">>>" };
            parse_two_regs_and_literal(ops).map(|(dest, src, lit)| (dest, format!("v{} {} {}", src, op, lit)))
        }
        "rsub-int/lit8" | "rsub-int" => {
            parse_two_regs_and_literal(ops).map(|(dest, src, lit)| (dest, format!("{} - v{}", lit, src)))
        }
        "add-int" | "add-long" | "sub-int" | "sub-long" | "mul-int" | "mul-long" | "div-int" | "div-long" | "rem-int" | "rem-long"
        | "and-int" | "and-long" | "or-int" | "or-long" | "xor-int" | "xor-long" | "shl-int" | "shl-long" | "shr-int" | "shr-long" | "ushr-int" | "ushr-long" => {
            let op = if m.contains("add") { "+" } else if m.contains("sub") { "-" } else if m.contains("mul") { "*" }
                else if m.contains("div") { "/" } else if m.contains("rem") { "%" } else if m.contains("and") { "&" }
                else if m.contains("or") { "|" } else if m.contains("xor") { "^" } else if m.contains("shl") { "<<" }
                else if m.contains("ushr") { ">>>" } else { ">>" };
            parse_three_regs(ops).map(|(a, b, c)| (a, format!("v{} {} v{}", b, op, c)))
        }
        "neg-int" | "neg-long" | "neg-float" | "neg-double" | "not-int" | "not-long" => {
            let op = if m.starts_with("neg") { "-" } else { "~" };
            parse_two_regs(ops).map(|(a, b)| (a, format!("{}{}", op, format!("v{}", b))))
        }
        "move" | "move/from16" | "move/16" | "move-object" => {
            parse_two_regs(ops).map(|(d, s)| (d, format!("v{}", s)))
        }
        "new-array" => {
            let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
            if parts.len() < 3 {
                return None;
            }
            let dst_reg: u32 = parts[0].strip_prefix('v')?.parse().ok()?;
            let size_reg: u32 = parts[1].strip_prefix('v')?.parse().ok()?;
            let type_str = parts[2]; // e.g. "boolean[]"
            let element_type = type_str.strip_suffix("[]").unwrap_or(type_str);
            Some((dst_reg, format!("new {}[v{}]", element_type, size_reg)))
        }
        _ => None,
    }
}

pub(crate) fn parse_string_ref(ops: &str) -> Option<String> {
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        return None;
    }
    let reg = parts[0].strip_prefix('v')?;
    let idx = parts[1]; // string@N or similar
    Some(format!("v{} = {};", reg, idx))
}

pub(crate) fn parse_new_instance(ops: &str) -> Option<String> {
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    if parts.len() < 2 {
        return None;
    }
    let reg = parts[0].strip_prefix('v')?;
    let typ = parts[1];
    Some(format!("v{} = new {}();", reg, typ))
}

/// new-array vA, vB, type → "vA = new ElementType[vB];" (operands may be vN or names).
fn format_new_array(ops: &str) -> Option<String> {
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    if parts.len() < 3 {
        return None;
    }
    let dst = parts[0];
    let size = parts[1];
    let type_str = parts[2]; // e.g. "boolean[]" or "int[]"
    let element_type = type_str.strip_suffix("[]").unwrap_or(type_str);
    Some(format!("{} = new {}[{}];", dst, element_type, size))
}

/// Format *-int/2addr or *-long/2addr: vA, vB → "vA = vA op vB;"
fn format_binop_2addr(ops: &str, op: &str) -> String {
    parse_two_regs(ops)
        .map(|(a, b)| format!("v{} = v{} {} v{};", a, a, op, b))
        .unwrap_or_default()
}

/// Format *-int/lit8: vA, vB, lit → "vA = vB op lit;"
fn format_lit8(ops: &str, op: &str) -> String {
    parse_two_regs_and_literal(ops)
        .map(|(dest, src, lit)| format!("v{} = v{} {} {};", dest, src, op, lit))
        .unwrap_or_default()
}

/// Format rsub-int/lit8 or rsub-int (lit16): vA, vB, lit → "vA = lit - vB;"
fn format_lit8_rsub(ops: &str) -> String {
    parse_two_regs_and_literal(ops)
        .map(|(dest, src, lit)| format!("v{} = {} - v{};", dest, lit, src))
        .unwrap_or_default()
}

/// Format three-register binary (F23x): vA, vB, vC → "vA = vB op vC;"
fn format_binop_23x(ops: &str, op: &str) -> String {
    parse_three_regs(ops)
        .map(|(a, b, c)| format!("v{} = v{} {} v{};", a, b, op, c))
        .unwrap_or_default()
}

/// Format unary (F12x): vA, vB → "vA = op vB;"
fn format_unary(ops: &str, op: &str) -> String {
    parse_two_regs(ops)
        .map(|(a, b)| format!("v{} = {}v{};", a, op, b))
        .unwrap_or_default()
}

/// Format cast (F12x): vA, vB → "vA = (type) vB;"
fn format_cast(ops: &str, target_type: &str) -> String {
    parse_two_regs(ops)
        .map(|(a, b)| format!("v{} = ({}) v{};", a, target_type, b))
        .unwrap_or_default()
}

/// Format iget*: vA, vB, field → "vA = vB.fieldName;"
fn format_iget(ops: &str) -> String {
    parse_instance_field_operands(ops)
        .map(|(dest, obj, field_name)| format!("v{} = v{}.{};", dest, obj, field_name))
        .unwrap_or_default()
}

/// Format iput*: vA (value), vB (object), field → "vB.fieldName = vA;"
fn format_iput(ops: &str) -> String {
    parse_instance_field_operands(ops)
        .map(|(value_reg, object_reg, field_name)| format!("v{}.{} = v{};", object_reg, field_name, value_reg))
        .unwrap_or_default()
}

/// Format sget*: vA, ClassName.fieldName → "vA = ClassName.fieldName;"
fn format_sget(ops: &str) -> String {
    parse_static_field_operands(ops)
        .map(|(reg, field_ref)| format!("v{} = {};", reg, field_ref))
        .unwrap_or_default()
}

/// Format sput*: vA, ClassName.fieldName → "ClassName.fieldName = vA;"
fn format_sput(ops: &str) -> String {
    parse_static_field_operands(ops)
        .map(|(reg, field_ref)| format!("{} = v{};", field_ref, reg))
        .unwrap_or_default()
}

/// Format array-length: vA, vB → "vA = vB.length;"
fn format_array_length(ops: &str) -> String {
    parse_two_regs(ops)
        .map(|(a, b)| format!("v{} = v{}.length;", a, b))
        .unwrap_or_default()
}

/// Format aget: vA, vB, vC → "vA = vB[vC];"
fn format_aget(ops: &str) -> String {
    parse_three_regs(ops)
        .map(|(a, b, c)| format!("v{} = v{}[v{}];", a, b, c))
        .unwrap_or_default()
}

/// Format aput: vA, vB, vC → "vB[vC] = vA;"
fn format_aput(ops: &str) -> String {
    parse_three_regs(ops)
        .map(|(a, b, c)| format!("v{}[v{}] = v{};", b, c, a))
        .unwrap_or_default()
}

/// Format packed-switch / sparse-switch: parse payload and emit "switch (var) { case 0: case 1: ... default: break; }".
/// Branch offset in F31t is in 16-bit code units from the start of the switch instruction to the payload.
const PACKED_SWITCH_ID: u16 = 0x0100;
const SPARSE_SWITCH_ID: u16 = 0x0200;

fn format_switch(ins: &Instruction, code_insns: &[u8], ops_resolved: &str) -> String {
    let var = ops_resolved.split(',').next().map(str::trim).unwrap_or("v0");
    let ins_off = ins.offset as usize;
    if ins_off + 6 > code_insns.len() {
        return format!("switch ({});  // (payload missing)", var);
    }
    let rel_units = i32::from_le_bytes(
        code_insns[ins_off + 2..ins_off + 6]
            .try_into()
            .unwrap_or([0, 0, 0, 0]),
    );
    // Payload byte offset: F31t branch is in 16-bit units. ART/dex-bytecode use (instruction+2)+rel*2;
    // some DEX use instruction+rel*2. Try both and only consider in-range offsets.
    let try_at = |off: usize| -> Option<(u16, u16)> {
        if off + 4 > code_insns.len() {
            return None;
        }
        let id = u16::from_le_bytes(code_insns[off..off + 2].try_into().unwrap_or([0, 0]));
        let sz = u16::from_le_bytes(code_insns[off + 2..off + 4].try_into().unwrap_or([0, 0]));
        if id == PACKED_SWITCH_ID || id == SPARSE_SWITCH_ID {
            Some((id, sz))
        } else {
            None
        }
    };
    let to_valid = |c: usize| -> Option<usize> {
        if c <= code_insns.len().saturating_sub(4) {
            Some(c)
        } else {
            None
        }
    };
    let cand_a = (ins_off as i32 + rel_units * 2) as usize; // branch from instruction start
    let cand_b = (ins_off as i32 + 2 + rel_units * 2) as usize; // branch from instruction+2
    let mut candidates: Vec<usize> = [cand_a, cand_b, (ins_off as i32 + rel_units) as usize, (ins_off as i32 + 2 + rel_units) as usize]
        .iter()
        .filter_map(|&c| to_valid(c))
        .collect();
    // If no candidate matched, scan a small window (alignment / offset convention)
    if candidates.iter().all(|&c| try_at(c).is_none()) {
        let center = cand_a;
        let start = center.saturating_sub(8);
        let end = (center + 8).min(code_insns.len().saturating_sub(4));
        for off in start..=end {
            if try_at(off).is_some() {
                candidates.push(off);
                break;
            }
        }
    }
    let (payload_off, ident, size) = match candidates
        .iter()
        .find_map(|&off| try_at(off).map(|(id, sz)| (off, id, sz as usize)))
    {
        Some(t) => t,
        None => return format!("switch ({});  // (payload not found)", var),
    };
    let mut cases = Vec::new();
    match ident {
        PACKED_SWITCH_ID => {
            if payload_off + 8 + size * 4 > code_insns.len() {
                return format!("switch ({});  // (packed payload truncated)", var);
            }
            let first_key = i32::from_le_bytes(
                code_insns[payload_off + 4..payload_off + 8]
                    .try_into()
                    .unwrap_or([0, 0, 0, 0]),
            );
            for i in 0..size {
                cases.push((first_key + i as i32).to_string());
            }
        }
        SPARSE_SWITCH_ID => {
            if payload_off + 4 + size * 8 > code_insns.len() {
                return format!("switch ({});  // (sparse payload truncated)", var);
            }
            for i in 0..size {
                let key_off = payload_off + 4 + i * 4;
                let key = i32::from_le_bytes(
                    code_insns[key_off..key_off + 4]
                        .try_into()
                        .unwrap_or([0, 0, 0, 0]),
                );
                cases.push(key.to_string());
            }
        }
        _ => return format!("switch ({});  // (unknown payload)", var),
    }
    let case_str: Vec<String> = cases.iter().map(|k| format!("case {}:", k)).collect();
    format!("switch ({}) {{ {} default: break; }}", var, case_str.join(" "))
}

/// Format cmp (F23x): vA, vB, vC → vA = -1/0/1 comparison result.
fn format_cmp(ops: &str, mnemonic: &str) -> String {
    parse_three_regs(ops).map(|(a, b, c)| {
        // cmpl: less -> -1, greater -> 1, equal -> 0; cmpg: same (NaN handling differs in Dalvik).
        // cmp-long: (vB > vC) ? 1 : ((vB < vC) ? -1 : 0)
        match mnemonic {
            "cmpl-float" | "cmpl-double" | "cmpg-float" | "cmpg-double" => {
                format!("v{} = (v{} < v{}) ? -1 : ((v{} > v{}) ? 1 : 0);", a, b, c, b, c)
            }
            "cmp-long" => {
                format!("v{} = (v{} > v{}) ? 1 : ((v{} < v{}) ? -1 : 0);", a, b, c, b, c)
            }
            _ => format!("v{} = (v{} < v{}) ? -1 : ((v{} > v{}) ? 1 : 0);", a, b, c, b, c),
        }
    }).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_one_reg_valid() {
        assert_eq!(parse_one_reg("v0"), Some(0));
        assert_eq!(parse_one_reg("v1"), Some(1));
        assert_eq!(parse_one_reg("v255"), Some(255));
        assert_eq!(parse_one_reg("  v3  "), Some(3));
        assert_eq!(parse_one_reg("v0, v1"), Some(0)); // first only
    }

    #[test]
    fn parse_one_reg_invalid() {
        assert_eq!(parse_one_reg(""), None);
        assert_eq!(parse_one_reg("0"), None);
        assert_eq!(parse_one_reg("r0"), None);
    }

    #[test]
    fn parse_two_regs_valid() {
        assert_eq!(parse_two_regs("v0, v1"), Some((0, 1)));
        assert_eq!(parse_two_regs("v2, v3"), Some((2, 3)));
        assert_eq!(parse_two_regs("v0, v1, v2"), Some((0, 1)));
    }

    #[test]
    fn parse_two_regs_invalid() {
        assert_eq!(parse_two_regs("v0"), None);
        assert_eq!(parse_two_regs("v0, string@5"), None); // second not v-prefixed
    }

    #[test]
    fn parse_two_regs_and_literal_valid() {
        assert_eq!(
            parse_two_regs_and_literal("v1, v3, 66"),
            Some((1, 3, "66".into()))
        );
        assert_eq!(
            parse_two_regs_and_literal("v0, v1, 26"),
            Some((0, 1, "26".into()))
        );
    }

    #[test]
    fn parse_two_regs_and_literal_invalid() {
        assert_eq!(parse_two_regs_and_literal("v0, v1"), None);
    }

    #[test]
    fn format_binop_2addr_sub_or() {
        assert_eq!(format_binop_2addr("v0, v3", "-"), "v0 = v0 - v3;");
        assert_eq!(format_binop_2addr("v0, v1", "|"), "v0 = v0 | v1;");
    }

    #[test]
    fn format_lit8_add_and() {
        assert_eq!(format_lit8("v1, v3, 66", "+"), "v1 = v3 + 66;");
        assert_eq!(format_lit8("v1, v1, 26", "&"), "v1 = v1 & 26;");
    }

    #[test]
    fn test_format_lit8_rsub() {
        assert_eq!(super::format_lit8_rsub("v0, v1, 23"), "v0 = 23 - v1;");
    }

    #[test]
    fn parse_three_regs_valid() {
        assert_eq!(parse_three_regs("v0, v1, v2"), Some((0, 1, 2)));
        assert_eq!(parse_three_regs("v1, v3, v0"), Some((1, 3, 0)));
    }

    #[test]
    fn format_binop_23x_add() {
        assert_eq!(super::format_binop_23x("v0, v1, v2", "+"), "v0 = v1 + v2;");
    }

    #[test]
    fn format_unary_neg() {
        assert_eq!(super::format_unary("v0, v1", "-"), "v0 = -v1;");
    }

    #[test]
    fn format_array_length_aget_aput() {
        assert_eq!(super::format_array_length("v0, v1"), "v0 = v1.length;");
        assert_eq!(super::format_aget("v0, v1, v2"), "v0 = v1[v2];");
        assert_eq!(super::format_aput("v0, v1, v2"), "v1[v2] = v0;");
    }

    #[test]
    fn format_iget_iput_sget_sput() {
        assert_eq!(
            super::format_iget("v2, v5, android.support.v4.widget.SimpleCursorAdapter.mCursor"),
            "v2 = v5.mCursor;"
        );
        assert_eq!(
            super::format_iput("v3, v1, pkg.Clz.fieldName"),
            "v1.fieldName = v3;"
        );
        assert_eq!(super::format_sget("v0, Foo.staticField"), "v0 = Foo.staticField;");
        assert_eq!(super::format_sput("v1, Bar.other"), "Bar.other = v1;");
    }

    #[test]
    fn parse_const_into_reg_valid() {
        assert_eq!(
            parse_const_into_reg("v0, 42"),
            Some("v0 = 42;".into())
        );
        assert_eq!(
            parse_const_into_reg("v1, -1"),
            Some("v1 = -1;".into())
        );
    }

    #[test]
    fn parse_const_into_reg_invalid() {
        assert_eq!(parse_const_into_reg("v0"), None);
    }

    #[test]
    fn parse_string_ref_valid() {
        assert_eq!(
            parse_string_ref("v0, string@5"),
            Some("v0 = string@5;".into())
        );
        assert_eq!(
            parse_string_ref("v1, \"hello\""),
            Some("v1 = \"hello\";".into())
        );
    }

    #[test]
    fn parse_new_instance_valid() {
        assert_eq!(
            parse_new_instance("v0, java.lang.Object"),
            Some("v0 = new java.lang.Object();".into())
        );
        assert_eq!(
            parse_new_instance("v1, type@2"),
            Some("v1 = new type@2();".into())
        );
    }

    #[test]
    fn format_new_array_valid() {
        assert_eq!(
            format_new_array("v0, v0, boolean[]"),
            Some("v0 = new boolean[v0];".into())
        );
        assert_eq!(
            format_new_array("v1, v2, int[]"),
            Some("v1 = new int[v2];".into())
        );
    }

    #[test]
    fn escape_java_string_plain() {
        assert_eq!(escape_java_string("hello"), "hello");
    }

    #[test]
    fn escape_java_string_quotes_and_backslash() {
        assert_eq!(escape_java_string("a\"b"), "a\\\"b");
        assert_eq!(escape_java_string("a\\b"), "a\\\\b");
    }

    #[test]
    fn escape_java_string_control_chars() {
        assert_eq!(escape_java_string("a\nb"), "a\\nb");
        assert_eq!(escape_java_string("a\rb"), "a\\rb");
        assert_eq!(escape_java_string("a\tb"), "a\\tb");
    }

    #[test]
    fn format_condition_binary() {
        assert_eq!(format_condition("if-eq", "v0, v1"), "v0 == v1");
        assert_eq!(format_condition("if-ne", "v0, v1"), "v0 != v1");
        assert_eq!(format_condition("if-lt", "v0, v1"), "v0 < v1");
        assert_eq!(format_condition("if-ge", "v0, v1"), "v0 >= v1");
        assert_eq!(format_condition("if-gt", "v0, v1"), "v0 > v1");
        assert_eq!(format_condition("if-le", "v0, v1"), "v0 <= v1");
    }

    #[test]
    fn format_condition_unary() {
        assert_eq!(format_condition("if-eqz", "v0"), "v0 == 0");
        assert_eq!(format_condition("if-nez", "v0"), "v0 != 0");
        assert_eq!(format_condition("if-ltz", "v0"), "v0 < 0");
        assert_eq!(format_condition("if-gez", "v0"), "v0 >= 0");
        assert_eq!(format_condition("if-gtz", "v0"), "v0 > 0");
        assert_eq!(format_condition("if-lez", "v0"), "v0 <= 0");
    }

    #[test]
    fn format_condition_ignores_branch_offset() {
        assert_eq!(format_condition("if-eqz", "v0, +008h"), "v0 == 0");
        assert_eq!(format_condition("if-eq", "v0, v1, +00ch"), "v0 == v1");
    }

    #[test]
    fn class_name_to_path_default_package() {
        let (dir, file) = super::class_name_to_path("Test");
        assert_eq!(dir, std::path::PathBuf::new());
        assert_eq!(file, "Test.java");
    }

    #[test]
    fn class_name_to_path_with_package() {
        let (dir, file) = super::class_name_to_path("com.example.MyClass");
        assert_eq!(dir, std::path::PathBuf::from("com/example"));
        assert_eq!(file, "MyClass.java");
    }

    #[test]
    fn class_name_to_path_inner_class() {
        let (dir, file) = super::class_name_to_path("com.example.Outer$Inner");
        assert_eq!(dir, std::path::PathBuf::from("com/example"));
        assert_eq!(file, "Outer$Inner.java");
    }
}
