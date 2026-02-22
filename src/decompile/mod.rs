//! DEX to Java decompilation: decode bytecode with dex-bytecode, map to Java source.
//! Supports structured control flow: if/else, while loops (via CFG).
//! Simplification pass: collapse invoke + move-result + return into single return.

pub mod annotations;
pub mod cfg;
mod ir;
pub mod pass;
mod read_write;
pub mod region;
mod simplify;
mod try_catch;
mod type_infer;
pub mod value_flow;

use cfg::{BlockEnd, BlockId, MethodCfg};
use region::{build_regions, for_loop_pattern, region_contains_loop, region_is_empty, region_is_empty_with_cfg, Region};
use dex_bytecode::{decode_all, Instruction};
use dex_parser::{ClassDef, CodeItem, DexFile, EncodedMethod, NO_INDEX};
use crate::error::{DexDecompilerError, Result};
use crate::java;
use std::fmt::Write;
use ir::{Expr as IrExpr, Stmt as IrStmt, VarId};
use pass::{run_dead_assign_with_used_regs, ConstructorMergePass, DeadAssignPass, ExprSimplifyPass, InvokeChainPass, PassRunner, SsaRenamePass, used_regs};
use std::cell::RefCell;
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
    /// If true, emit raw DEX instructions as comments before each method body.
    pub show_bytecode: bool,
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
    show_bytecode: bool,
    /// Lazy index: class_name -> ClassDef. Avoids repeated full DEX scan in find_class_def / find_method.
    class_def_index: RefCell<Option<HashMap<String, ClassDef>>>,
    /// Lazy index: enclosing_class -> (inner_class_name, constructor_param_count) for inner classes extending Thread.
    inner_thread_index: RefCell<Option<HashMap<String, Vec<(String, usize)>>>>,
    /// Cache: inner_class_name -> decompiled run() body (before capture replacement). Avoids re-decompiling same run().
    inner_run_body_cache: RefCell<HashMap<String, String>>,
}

impl<'a> Decompiler<'a> {
    pub fn new(dex: &'a DexFile) -> Self {
        Self {
            dex,
            only_package: None,
            exclude: vec![],
            show_bytecode: false,
            class_def_index: RefCell::new(None),
            inner_thread_index: RefCell::new(None),
            inner_run_body_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Create a decompiler with package/class filters.
    pub fn with_options(dex: &'a DexFile, options: DecompilerOptions) -> Self {
        Self {
            dex,
            only_package: options.only_package,
            exclude: options.exclude,
            show_bytecode: options.show_bytecode,
            class_def_index: RefCell::new(None),
            inner_thread_index: RefCell::new(None),
            inner_run_body_cache: RefCell::new(HashMap::new()),
        }
    }

    /// Build class_name -> ClassDef index on first use (one pass over DEX).
    fn ensure_class_def_index(&self) -> Result<()> {
        if self.class_def_index.borrow().is_some() {
            return Ok(());
        }
        let mut map = HashMap::new();
        for class_def_result in self.dex.class_defs() {
            let class_def = class_def_result.map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
            let class_type = self.dex.get_type(class_def.class_idx).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
            let name = java::descriptor_to_java(&class_type);
            map.insert(name, class_def.clone());
        }
        *self.class_def_index.borrow_mut() = Some(map);
        Ok(())
    }

    /// Build enclosing_class -> [(inner_name, param_count)] for inner classes extending Thread.
    fn ensure_inner_thread_index(&self) -> Result<()> {
        if self.inner_thread_index.borrow().is_some() {
            return Ok(());
        }
        let thread_java = java::descriptor_to_java("Ljava/lang/Thread;");
        let mut map: HashMap<String, Vec<(String, usize)>> = HashMap::new();
        for class_def_result in self.dex.class_defs() {
            let class_def = class_def_result.map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
            let class_type = self.dex.get_type(class_def.class_idx).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
            let name = java::descriptor_to_java(&class_type);
            let Some((enclosing, suffix)) = name.rsplit_once('$') else {
                continue;
            };
            if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if class_def.superclass_idx == NO_INDEX {
                continue;
            }
            let super_type = self.dex.get_type(class_def.superclass_idx).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
            if java::descriptor_to_java(&super_type) != thread_java {
                continue;
            }
            let class_data_opt = self.dex.get_class_data(&class_def).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
            let Some(ref class_data) = class_data_opt.as_ref() else {
                continue;
            };
            for enc in &class_data.direct_methods {
                let info = self.dex.get_method_info(enc.method_idx).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
                if info.name == "<init>" {
                    map.entry(enclosing.to_string()).or_default().push((name.clone(), info.params.len()));
                    break;
                }
            }
        }
        *self.inner_thread_index.borrow_mut() = Some(map);
        Ok(())
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

    /// Collect (ClassDef, class_name) for all classes that pass only_package and exclude filters.
    /// Used for parallel decompilation (e.g. by the CLI).
    pub fn collect_included_classes(&self) -> Result<Vec<(ClassDef, String)>> {
        let mut out = Vec::new();
        for class_def_result in self.dex.class_defs() {
            let class_def = class_def_result.map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
            let class_type = self.dex.get_type(class_def.class_idx).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
            let class_name = java::descriptor_to_java(&class_type);
            if class_matches_filter(&class_name, self.only_package.as_deref(), &self.exclude) {
                out.push((class_def, class_name));
            }
        }
        Ok(out)
    }

    /// Like `decompile_to_dir`, but calls `progress(current, total, class_name)` after each class (1-based current).
    /// Respects only_package and exclude; progress total is the number of included classes.
    pub fn decompile_to_dir_with_progress(
        &self,
        base_path: &std::path::Path,
        mut progress: Option<&mut dyn FnMut(usize, usize, &str)>,
    ) -> Result<()> {
        let included = self.collect_included_classes()?;
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
        let (package, simple_class_name) = split_package_and_class(&class_name);
        let class_data = self.dex.get_class_data(class_def).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
        let super_type = if class_def.superclass_idx != NO_INDEX {
            let s = self.dex.get_type(class_def.superclass_idx).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
            shorten_java_names(&java::descriptor_to_java(&s))
        } else {
            "Object".to_string()
        };
        let flags = java::access_flags_to_java(class_def.access_flags, true);
        let mut out = String::new();
        if !package.is_empty() {
            writeln!(&mut out, "// package {}", package).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        let imports = collect_class_imports(
            self.dex,
            class_def,
            class_data.as_ref(),
            &class_name,
            &package,
        )?;
        for fqn in &imports {
            writeln!(&mut out, "import {};", fqn).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        if !imports.is_empty() {
            writeln!(&mut out).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        let class_annotation_type_ids = annotations::class_annotation_type_ids(self.dex.data.as_ref(), class_def).unwrap_or_default();
        for type_idx in &class_annotation_type_ids {
            if let Ok(desc) = self.dex.get_type(*type_idx) {
                let java_type = java::descriptor_to_java(&desc);
                let name = annotation_short_name(&java_type);
                writeln!(&mut out, "@{}", name).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            }
        }
        let enum_constants = detect_enum_constants(self.dex, class_def, class_data.as_ref(), &class_name, &super_type);
        let is_enum = !enum_constants.is_empty();

        for f in &flags {
            write!(&mut out, "{} ", f).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        if is_enum {
            write!(&mut out, "enum {}", simple_class_name)
                .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        } else {
            write!(&mut out, "class {} extends {}", simple_class_name, super_type)
                .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        writeln!(&mut out, " {{").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;

        if let Some(ref cd) = class_data {
            if is_enum {
                writeln!(&mut out, "    {}", enum_constants.join(", "))
                    .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                writeln!(&mut out, "    ;").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            }
            for f in &cd.static_fields {
                if let Ok(fi) = self.dex.get_field_info(f.field_idx) {
                    if is_enum && enum_constants.contains(&fi.name.to_string()) {
                        continue;
                    }
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
                let method_java = self.decompile_method(m, Some(&simple_class_name), Some(&class_name))?;
                write!(&mut out, "{}", method_java).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            }
        }

        writeln!(&mut out, "}}").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        Ok(out)
    }

    /// Decompile one method: signature + body (disassembly-based Java-like body).
    /// When called from decompile_class, pass class_simple_name so constructors emit as "ClassName()" not "void <init>()".
    /// Pass class_name (full) when decompiling a class method so anonymous Thread inlining can resolve inner classes.
    pub fn decompile_method(
        &self,
        encoded: &EncodedMethod,
        class_simple_name: Option<&str>,
        class_name: Option<&str>,
    ) -> Result<String> {
        let info = self.dex.get_method_info(encoded.method_idx).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
        let return_type = java::descriptor_to_java(&info.return_type);
        let params: Vec<String> = info.params.iter().map(|p| java::descriptor_to_java(p)).collect();
        let flags = java::access_flags_to_java(encoded.access_flags, false);
        let mut out = String::new();
        for f in &flags {
            write!(&mut out, "    {} ", f).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        let is_constructor = info.name == "<init>";
        let name = if is_constructor && class_simple_name.is_some() {
            class_simple_name.unwrap()
        } else {
            &info.name
        };
        let params_str = params.iter().enumerate().map(|(i, t)| format!("{} p{}", t, i)).collect::<Vec<_>>().join(", ");
        if is_constructor && class_simple_name.is_some() {
            write!(&mut out, "{}({}) ", name, params_str)
                .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        } else {
            write!(&mut out, "{} {}({}) ", return_type, name, params_str)
                .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        if flags.contains(&"abstract") || flags.contains(&"native") {
            writeln!(&mut out, ";").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            return Ok(out);
        }
        if encoded.code_off == 0 {
            writeln!(&mut out, "{{ }}").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            return Ok(out);
        }
        let code = self.dex.get_code_item(encoded.code_off).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
        // Raw DEX instructions as comments before the method body (only when requested).
        if self.show_bytecode {
            let raw_listing = self.raw_dex_instructions_listing(&code)?;
            if !raw_listing.is_empty() {
                writeln!(&mut out).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                write!(&mut out, "{}", raw_listing).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            }
        }
        let body = self.decompile_method_body(&code, encoded, class_name)?;
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

    /// Find the first ClassDef in the DEX for the given class name (Java FQN, e.g. "androguard.test.TestSynthetic$1").
    fn find_class_def(&self, class_name: &str) -> Option<ClassDef> {
        let _ = self.ensure_class_def_index();
        self.class_def_index.borrow().as_ref()?.get(class_name).cloned()
    }

    /// Find the first EncodedMethod in the DEX for the given class and method name.
    pub fn find_method(&self, class_name: &str, method_name: &str) -> Option<EncodedMethod> {
        let _ = self.ensure_class_def_index();
        let class_def = self.class_def_index.borrow().as_ref()?.get(class_name)?.clone();
        let class_data_opt = self.dex.get_class_data(&class_def).ok()?;
        let class_data = class_data_opt.as_ref()?;
        for encoded in class_data.direct_methods.iter().chain(class_data.virtual_methods.iter()) {
            let info = self.dex.get_method_info(encoded.method_idx).ok()?;
            if info.name == method_name {
                return Some(encoded.clone());
            }
        }
        None
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
    fn decompile_method_body(
        &self,
        code: &CodeItem,
        encoded: &EncodedMethod,
        class_name: Option<&str>,
    ) -> Result<String> {
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
            return self.decompile_method_body_linear(&instructions, code.insns_off, encoded, code, insns_bytes, class_name);
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
            let is_constructor = self
                .dex
                .get_method_info(encoded.method_idx)
                .map(|info| info.name == "<init>")
                .unwrap_or(false);
            out = simplify::simplify_method_body(&out, is_constructor);
            if let Some(enclosing) = class_name {
                out = self.inline_anonymous_threads(&out, enclosing)?;
            }
        }
        if code.tries_size > 0 {
            out = self.wrap_body_with_try_catch(&out, encoded.code_off, code)?;
            out = simplify::simplify_synchronized_blocks(&out);
        }
        Ok(out)
    }

    /// Inline anonymous Thread: replace "X.<init>(args);" + "X.start();" with
    /// "new Thread() { public void run() { <inner run body> } }.start();"
    fn inline_anonymous_threads(&self, body: &str, enclosing_class: &str) -> Result<String> {
        let lines: Vec<&str> = body.lines().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            let stmt = line.trim().trim_end_matches(|c| c == ' ' || c == '\t');
            let stmt_clean = if let Some(comment) = stmt.find("  // ") {
                stmt[..comment].trim_end()
            } else {
                stmt
            };
            if let Some(open) = stmt_clean.find(".<init>(") {
                let receiver = stmt_clean[..open].trim();
                let close = stmt_clean.find(");").unwrap_or(stmt_clean.len());
                let args_str = stmt_clean[open + ".<init>(".len()..close].trim();
                let args: Vec<String> = if args_str.is_empty() {
                    vec![]
                } else {
                    args_str.split(',').map(|s| s.trim().to_string()).collect()
                };
                let next_line = lines.get(i + 1).map(|l| {
                    let t = l.trim();
                    if let Some(c) = t.find("  // ") { t[..c].trim_end() } else { t }
                }).unwrap_or("");
                if !receiver.is_empty()
                    && receiver.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && next_line == format!("{}.start();", receiver)
                {
                    if let Some((replacement, skip)) = self.build_anonymous_thread_inline(
                        enclosing_class,
                        &args,
                        line,
                    )? {
                        out.push_str(&replacement);
                        if !replacement.ends_with('\n') {
                            out.push('\n');
                        }
                        i += skip;
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
        Ok(out)
    }

    /// Build replacement for anonymous Thread and number of lines to skip (2 or 3 if assignment line included).
    fn build_anonymous_thread_inline(
        &self,
        enclosing_class: &str,
        args: &[String],
        first_line: &str,
    ) -> Result<Option<(String, usize)>> {
        let indent = first_line.len() - first_line.trim_start().len();
        let indent_str: String = first_line.chars().take(indent).collect();
        let Some(inner_class_name) = self.find_inner_thread_class(enclosing_class, args.len())? else {
            return Ok(None);
        };
        let run_encoded = match self.find_method(&inner_class_name, "run") {
            Some(enc) => enc,
            None => return Ok(None),
        };
        if run_encoded.code_off == 0 {
            return Ok(None);
        }
        let mut run_java = {
            let mut cache = self.inner_run_body_cache.borrow_mut();
            if let Some(cached) = cache.get(&inner_class_name) {
                cached.clone()
            } else {
                let code = self.dex.get_code_item(run_encoded.code_off).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
                let body = self.decompile_method_body(&code, &run_encoded, None)?;
                cache.insert(inner_class_name.clone(), body.clone());
                body
            }
        };
        let val_replacements = self.inner_class_capture_map(&inner_class_name, args)?;
        for (field_name, arg) in &val_replacements {
            run_java = replace_capture_in_body(&run_java, field_name, arg);
        }
        run_java = replace_capture_assignees_in_body(&run_java, &val_replacements);
        if let Some(first_arg) = args.first() {
            run_java = replace_synchronized_lock_with_arg(&run_java, first_arg);
        }
        if args.len() == 2 {
            if let Some(second_arg) = args.get(1) {
                run_java = replace_whole_word(&run_java, "v1", second_arg);
            }
        }
        run_java = strip_unreachable_exception_junk_after_return(&run_java);
        let run_indent = format!("{}    ", indent_str);
        let run_lines: String = run_java
            .lines()
            .map(|l| {
                let trimmed = l.trim_start();
                if trimmed.is_empty() {
                    run_indent.clone()
                } else {
                    format!("{}{}", run_indent, l.trim())
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let block = format!(
            "{}new Thread() {{\n{}    public void run() {{\n{}\n{}    }}\n{}}}.start();",
            indent_str,
            indent_str,
            run_lines,
            indent_str,
            indent_str,
        );
        Ok(Some((block, 2)))
    }

    /// Find inner class (enclosing_class$N) that extends Thread and has constructor with given arity.
    fn find_inner_thread_class(&self, enclosing_class: &str, num_args: usize) -> Result<Option<String>> {
        self.ensure_inner_thread_index()?;
        let inner = self
            .inner_thread_index
            .borrow()
            .as_ref()
            .and_then(|m| m.get(enclosing_class))
            .and_then(|v| v.iter().find(|(_, n)| *n == num_args))
            .map(|(name, _)| name.clone());
        Ok(inner)
    }

    /// Map val$* field names to outer arg names for inlining.
    fn inner_class_capture_map(&self, inner_class_name: &str, args: &[String]) -> Result<Vec<(String, String)>> {
        let class_def = match self.find_class_def(inner_class_name) {
            Some(cd) => cd,
            None => return Ok(vec![]),
        };
        let class_data_opt = self.dex.get_class_data(&class_def).map_err(|e| DexDecompilerError::Parse(e.to_string()))?;
        let class_data = class_data_opt.as_ref();
        let Some(cd) = class_data else {
            return Ok(vec![]);
        };
        let fields: Vec<String> = cd
            .instance_fields
            .iter()
            .filter_map(|f| self.dex.get_field_info(f.field_idx).ok())
            .filter(|fi| fi.name.starts_with("val$"))
            .map(|fi| fi.name.clone())
            .collect();
        let mut out = Vec::with_capacity(fields.len());
        for (i, name) in fields.into_iter().enumerate() {
            if let Some(arg) = args.get(i) {
                out.push((name, arg.clone()));
            }
        }
        Ok(out)
    }

    /// Wrap method body in try { body } catch (Type e) { ... } when code has try items.
    fn wrap_body_with_try_catch(
        &self,
        body: &str,
        code_off: u32,
        code: &CodeItem,
    ) -> Result<String> {
        let data = self.dex.data.as_ref();
        let Some(pairs) = try_catch::try_handler_pairs(data, code_off, code) else {
            return Ok(format!("        // try/catch ({} tries) - failed to parse handlers\n{}", code.tries_size, body));
        };
        if pairs.is_empty() {
            return Ok(format!("        // try/catch ({} tries)\n{}", code.tries_size, body));
        }
        let mut out = String::new();
        writeln!(out, "        try {{").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        out.push_str(body);
        if !body.ends_with('\n') {
            out.push('\n');
        }
        let (_, first_handler) = &pairs[0];
        for type_addr in &first_handler.handlers {
            let type_name = self.dex
                .get_type(type_addr.type_idx)
                .map_err(|e| DexDecompilerError::Parse(e.to_string()))
                .map(|d| shorten_java_names(&java::descriptor_to_java(&d)))?;
            writeln!(out, "        }} catch ({} e) {{", type_name)
                .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            writeln!(out, "            // handler at code unit {}", type_addr.addr)
                .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            writeln!(out, "        }}").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
        }
        if let Some(addr) = first_handler.catch_all_addr {
            writeln!(out, "        }} catch (Throwable e) {{")
                .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            writeln!(out, "            // catch-all handler at code unit {}", addr)
                .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
            writeln!(out, "        }}").map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
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
        class_name: Option<&str>,
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
            let is_constructor = self
                .dex
                .get_method_info(encoded.method_idx)
                .map(|info| info.name == "<init>")
                .unwrap_or(false);
            out = simplify::simplify_method_body(&out, is_constructor);
            if let Some(enclosing) = class_name {
                out = self.inline_anonymous_threads(&out, enclosing)?;
            }
        }
        if code.tries_size > 0 {
            out = self.wrap_body_with_try_catch(&out, encoded.code_off, code)?;
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
                if let Some((init_block, header, condition, body_without_update, then_branch, update_block)) =
                    for_loop_pattern(children)
                {
                    if self.block_is_single_const_init(cfg, instructions, init_block)
                        && self.block_is_single_update_and_back_edge(cfg, instructions, update_block, header)
                    {
                        let mut init_buf = String::new();
                        self.emit_block_instructions(
                            cfg, instructions, base_off, init_block, skip_goto_to, break_target,
                            encoded, code, &mut init_buf, indent, declared, global_used_regs, false,
                        )?;
                        let init_str = init_buf
                            .trim()
                            .lines()
                            .next()
                            .unwrap_or("")
                            .trim()
                            .trim_end_matches(';')
                            .trim();
                        let mut update_buf = String::new();
                        self.emit_block_instructions(
                            cfg, instructions, base_off, update_block, Some(header), break_target,
                            encoded, code, &mut update_buf, indent, declared, global_used_regs, false,
                        )?;
                        let update_str = update_buf
                            .trim()
                            .lines()
                            .find(|l| !l.trim().is_empty() && l.trim() != "continue;")
                            .unwrap_or(&"")
                            .trim()
                            .trim_end_matches(';')
                            .trim();
                        if !init_str.is_empty() && !update_str.is_empty() {
                            writeln!(
                                out,
                                "{}for ({}; {}; {}) {{",
                                ind,
                                shorten_java_names(init_str),
                                shorten_java_names(condition),
                                shorten_java_names(update_str),
                            )
                            .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                            let _ = self.emit_block_instructions(
                                cfg, instructions, base_off, header, Some(header), None,
                                encoded, code, out, indent + 1, declared, global_used_regs, true,
                            )?;
                            let _ = self.emit_region(
                                &body_without_update,
                                cfg,
                                instructions,
                                base_off,
                                encoded,
                                code,
                                out,
                                indent + 1,
                                Some(header),
                                region::first_block(then_branch),
                                declared,
                                global_used_regs,
                            )?;
                            writeln!(out, "{}}}", ind)
                                .map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                            if !region_is_empty(then_branch) {
                                let _ = self.emit_region(
                                    then_branch,
                                    cfg,
                                    instructions,
                                    base_off,
                                    encoded,
                                    code,
                                    out,
                                    indent,
                                    skip_goto_to,
                                    break_target,
                                    declared,
                                    global_used_regs,
                                )?;
                            }
                            return Ok(false);
                        }
                    }
                }
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
                let then_empty = region_is_empty_with_cfg(then_branch, cfg);
                let else_empty = region_is_empty_with_cfg(else_branch, cfg);
                if then_empty && else_empty {
                    // Skip emitting empty if (cond) { } — no effect.
                    return Ok(false);
                }
                // At top level only: prefer "if (cond) { short/return } else { loop }" by swapping when then has loop and else doesn't.
                let at_top_level = skip_goto_to.is_none() && break_target.is_none();
                let then_has_loop = region_contains_loop(then_branch);
                let else_has_loop = region_contains_loop(else_branch);
                let (condition, then_branch, else_branch) = if at_top_level && then_has_loop && !else_has_loop {
                    (negate_condition(condition), else_branch, then_branch)
                } else {
                    (condition.clone(), then_branch, else_branch)
                };
                let then_empty_after = region_is_empty_with_cfg(then_branch, cfg);
                let else_empty_after = region_is_empty_with_cfg(else_branch, cfg);
                if then_empty_after && !else_empty_after {
                    let neg = negate_condition(&condition);
                    writeln!(out, "{}if ({}) {{", ind, shorten_java_names(&neg)).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                    let _ = self.emit_region(else_branch, cfg, instructions, base_off, encoded, code, out, indent + 1, skip_goto_to, break_target, declared, global_used_regs)?;
                } else {
                    writeln!(out, "{}if ({}) {{", ind, shorten_java_names(&condition)).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                    let _ = self.emit_region(then_branch, cfg, instructions, base_off, encoded, code, out, indent + 1, skip_goto_to, break_target, declared, global_used_regs)?;
                    if !else_empty_after {
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
                    let while_cond = negate_condition(&condition);
                    writeln!(out, "{}while ({}) {{", ind, shorten_java_names(&while_cond)).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                    let _ = self.emit_block_instructions(cfg, instructions, base_off, *header, Some(*header), None, encoded, code, out, indent + 1, declared, global_used_regs, true)?;
                    let _ = self.emit_region(else_branch, cfg, instructions, base_off, encoded, code, out, indent + 1, Some(*header), exit_block, declared, global_used_regs)?;
                    writeln!(out, "{}}}", ind).map_err(|_| DexDecompilerError::Decompilation("write".into()))?;
                    if !region_is_empty_with_cfg(then_branch, cfg) {
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
    /// Runs the pipeline once over the full method instead of per-block for speed.
    fn method_used_regs(&self, _cfg: &MethodCfg, instructions: &[Instruction], base_off: usize, code_insns: &[u8]) -> HashSet<u32> {
        let mut runner = PassRunner::new();
        runner.add(InvokeChainPass);
        runner.add(SsaRenamePass);
        let stmts = self.instructions_to_ir(instructions, base_off, code_insns).unwrap_or_default();
        let stmts = runner.run(stmts);
        used_regs(&stmts)
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

    /// True if block has exactly one instruction that is const/4, const/16, or const.
    fn block_is_single_const_init(
        &self,
        cfg: &MethodCfg,
        instructions: &[Instruction],
        block_id: BlockId,
    ) -> bool {
        let seq = self.block_instruction_seq(cfg, instructions, block_id, None, false);
        if seq.len() != 1 {
            return false;
        }
        let m = seq[0].mnemonic();
        m == "const/4" || m == "const/16" || m == "const"
    }

    /// True if block has exactly one instruction that is an add-int (update). The block may
    /// fall through to a goto-back block (two-block tail) or contain goto itself (single-block tail).
    fn block_is_single_update_and_back_edge(
        &self,
        cfg: &MethodCfg,
        instructions: &[Instruction],
        block_id: BlockId,
        header: BlockId,
    ) -> bool {
        let block = &cfg.blocks[block_id];
        let seq = self.block_instruction_seq(cfg, instructions, block_id, None, false);
        if seq.len() == 1 {
            let m = seq[0].mnemonic();
            let add_like = m.starts_with("add-int") || m.starts_with("add-long");
            if add_like {
                return true;
            }
        }
        if seq.len() == 2 {
            let m = seq[0].mnemonic();
            let add_like = m.starts_with("add-int") || m.starts_with("add-long");
            let goto_header = matches!(&block.end, BlockEnd::Goto(t) if *t == header);
            return add_like && goto_header;
        }
        false
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
            runner.add(ConstructorMergePass);
            runner.add(ExprSimplifyPass);
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
        let line = match (stmt, type_map) {
            (IrStmt::Assign { dst, rhs, comment }, Some(types)) if types.get(dst).is_some() => {
                let ty = types.get(dst).unwrap();
                let var = name_map.and_then(|n| n.get(dst).cloned()).unwrap_or_else(|| IrExpr::Var(*dst).to_java());
                let rhs_str = rhs.to_java_with_names(name_map);
                // Handle compound assign markers from ExprSimplifyPass
                if let Some(compound) = rhs_str.strip_prefix("__compound_") {
                    format_compound_line(compound, &var, name_map)
                } else if declared.insert(var.clone()) {
                    format!("{} {} = {};", shorten_type(ty), var, rhs_str)
                } else {
                    format!("{} = {};", var, rhs_str)
                }
            }
            _ => {
                let raw = stmt.to_java_line_with_names(name_map);
                // Handle compound assign in untyped path
                if raw.contains("__compound_") {
                    resolve_compound_in_line(&raw, name_map)
                } else {
                    raw
                }
            }
        };
        shorten_java_names(&line)
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
            if m.ends_with("-payload") {
                continue;
            }
            let ops = ins.operands();
            let ops_resolved = self.resolve_operands(ops);
            let offset = ins.offset as usize + base_off;
            let comment = format!("{:04x}: {} {}", offset, m, ops);

            if pending_invoke.is_some() && !m.starts_with("move-result") {
                flush_pending_invoke(&mut out, &mut pending_invoke);
            }

            if m.starts_with("invoke-") {
                let is_instance = m.starts_with("invoke-virtual") || m.starts_with("invoke-interface")
                    || m.starts_with("invoke-direct") || m.starts_with("invoke-super");
                if let Some((target, args)) = parse_invoke_call_parts(&ops_resolved) {
                    let (target, args) = if is_instance {
                        to_receiver_style(&target, &args)
                    } else {
                        (target, args)
                    };
                    pending_invoke = Some(PendingInvoke {
                        call_expr: IrExpr::Call { target, args },
                        comment,
                    });
                } else {
                    out.push(IrStmt::Raw(format!("{}({});", m, ops_resolved)));
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
                    out.push(IrStmt::Raw(line));
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
        runner.add(ConstructorMergePass);
        runner.add(ExprSimplifyPass);
        runner.add(DeadAssignPass);
        runner
    }

    /// Map one Dalvik instruction to a Java-like statement (or comment).
    fn instruction_to_java(&self, ins: &Instruction, base_off: usize, code_insns: &[u8]) -> Result<String> {
        let m = ins.mnemonic();
        if m.ends_with("-payload") {
            return Ok(String::new());
        }
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
            // check-cast vA, type → "vA = (Type) vA;"
            "check-cast" => format_check_cast(&ops_resolved),
            // instance-of vA, vB, type → "vA = vB instanceof Type;"
            "instance-of" => format_instance_of(&ops_resolved),
            // const-class vA, type → "vA = Type.class;"
            "const-class" => format_const_class(&ops_resolved),
            // monitor-enter/exit
            "monitor-enter" => parse_one_reg(&ops_resolved).map(|r| format!("/* monitor-enter(v{}) */", r)).unwrap_or_default(),
            "monitor-exit" => parse_one_reg(&ops_resolved).map(|r| format!("/* monitor-exit(v{}) */", r)).unwrap_or_default(),
            // fill-array-data: parse payload and emit /* arr = { ... } */
            "fill-array-data" => format_fill_array_data(ins, code_insns, &ops_resolved),
            _ => format!("{}; /* {} */", ops_resolved, m),
        };
        if stmt.is_empty() {
            if self.show_bytecode {
                Ok(comment)
            } else {
                Ok(String::new())
            }
        } else if self.show_bytecode {
            Ok(format!("{}  // {}", stmt, comment))
        } else {
            Ok(stmt)
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

/// Replace synthetic capture references in inlined run() body: "receiver.val$name" and "val$name" → arg.
fn replace_capture_in_body(body: &str, field_name: &str, arg: &str) -> String {
    let dot_field = format!(".{}", field_name);
    let mut result = body.to_string();
    while let Some(pos) = result.find(&dot_field) {
        let start = result[..pos]
            .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .map(|i| i + 1)
            .unwrap_or(0);
        result = format!("{}{}{}", &result[..start], arg, &result[pos + dot_field.len()..]);
    }
    result = result.replace(field_name, arg);
    result
}

/// After capture replacement: find "var = arg;" lines and replace whole-word "var" with "arg" in body, then remove those assignment lines.
fn replace_capture_assignees_in_body(
    body: &str,
    val_replacements: &[(String, String)],
) -> String {
    let args: std::collections::HashSet<&str> = val_replacements.iter().map(|(_, a)| a.as_str()).collect();
    let mut assignees: Vec<(String, String)> = Vec::new();
    for line in body.lines() {
        let stmt = line.trim();
        let stmt_clean = if let Some(idx) = stmt.find("  // ") {
            stmt[..idx].trim_end()
        } else {
            stmt
        };
        if let Some(eq) = stmt_clean.find(" = ") {
            let var = stmt_clean[..eq].trim();
            let rhs = stmt_clean[eq + 3..].trim_end_matches(';').trim();
            if args.contains(rhs) && !var.is_empty() && var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                assignees.push((var.to_string(), rhs.to_string()));
            }
        }
    }
    let mut result = body.to_string();
    for (var, arg) in &assignees {
        result = replace_whole_word(&result, var, arg);
    }
    result
        .lines()
        .filter(|line| {
            let stmt = line.trim();
            let stmt_clean = if let Some(idx) = stmt.find("  // ") {
                stmt[..idx].trim_end()
            } else {
                stmt
            };
            if let Some(eq) = stmt_clean.find(" = ") {
                let var = stmt_clean[..eq].trim();
                let rhs = stmt_clean[eq + 3..].trim_end_matches(';').trim();
                if args.contains(rhs) && assignees.iter().any(|(v, a)| v == var && a == rhs) {
                    return false;
                }
            }
            true
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Replace "synchronized (VAR)" with "synchronized (arg)" so the lock uses the outer capture (first arg = Object).
fn replace_synchronized_lock_with_arg(body: &str, arg: &str) -> String {
    let prefix = "synchronized (";
    let mut result = body.to_string();
    let mut search_from = 0;
    while let Some(rel_start) = result[search_from..].find(prefix) {
        let start = search_from + rel_start;
        let paren_start = start + prefix.len();
        if let Some(paren_end) = result[paren_start..].find(')') {
            let end = paren_start + paren_end;
            result = format!("{}{}{}", &result[..paren_start], arg, &result[end..]);
            search_from = paren_start + arg.len() + 1;
        } else {
            break;
        }
    }
    result
}

/// Remove unreachable exception-handler lines after "return;" (e.g. "var; /* move-exception */", "throw var;", "/* monitor-exit */").
fn strip_unreachable_exception_junk_after_return(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        out.push_str(line);
        if i < lines.len().saturating_sub(1) {
            out.push('\n');
        }
        let stmt = line.trim();
        let stmt_clean = if let Some(idx) = stmt.find("  // ") {
            stmt[..idx].trim_end()
        } else {
            stmt
        };
        if stmt_clean == "return;" {
            let return_indent = line.len() - line.trim_start().len();
            i += 1;
            while i < lines.len() {
                let next = lines[i];
                let next_indent = next.len() - next.trim_start().len();
                if next.trim().is_empty() {
                    i += 1;
                    continue;
                }
                if next_indent <= return_indent && (next.trim().starts_with('}') || next.trim().starts_with("} catch")) {
                    break;
                }
                let t = next.trim();
                let drop = t.contains("/* move-exception */")
                    || t.contains("/* monitor-exit(")
                    || (t.starts_with("throw ") && t.ends_with(';'));
                if drop {
                    i += 1;
                    continue;
                }
                break;
            }
        }
        i += 1;
    }
    out
}

/// Replace whole-word occurrences of `from` with `to` (so "v1" does not match inside "v10").
fn replace_whole_word(body: &str, from: &str, to: &str) -> String {
    if from.is_empty() {
        return body.to_string();
    }
    let mut result = String::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        if body[i..].starts_with(from) {
            let start = i;
            let end = i + from.len();
            let prev_ok = start == 0
                || !body[..start].chars().rev().next().map_or(false, |c| c.is_ascii_alphanumeric() || c == '_');
            let next_ok = end >= body.len()
                || !body[end..].chars().next().map_or(false, |c| c.is_ascii_alphanumeric() || c == '_');
            if prev_ok && next_ok {
                result.push_str(to);
                i = end;
                continue;
            }
        }
        let ch_len = body[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
        result.push_str(&body[i..i + ch_len]);
        i += ch_len;
    }
    result
}

/// For instance calls (virtual/interface/direct/super), transform `Class.method` + `receiver, args`
/// into `receiver.method` + `args`. The class name is dropped in favor of the receiver variable.
fn to_receiver_style(target: &str, args: &str) -> (String, String) {
    let method_name = target.rsplit('.').next().unwrap_or(target);
    let args = args.trim();
    if args.is_empty() {
        return (target.to_string(), args.to_string());
    }
    // Split off the first argument (receiver) — watch for nested parens
    if let Some(comma_pos) = find_first_comma(args) {
        let receiver = args[..comma_pos].trim();
        let rest = args[comma_pos + 1..].trim();
        (format!("{}.{}", receiver, method_name), rest.to_string())
    } else {
        // Single arg = receiver, no remaining args
        (format!("{}.{}", args, method_name), String::new())
    }
}

fn find_first_comma(s: &str) -> Option<usize> {
    let mut depth = 0u32;
    for (i, c) in s.chars().enumerate() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
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

/// Format compound assign marker into proper Java (e.g. `i++` or `n0 += 3`).
fn format_compound_line(compound: &str, var: &str, name_map: Option<&HashMap<VarId, String>>) -> String {
    let compound = if let Some(nm) = name_map {
        ir::substitute_names_in_text_pub(compound, nm)
    } else {
        compound.to_string()
    };
    // __compound_vN++ or __compound_vN--
    if compound.ends_with("++") || compound.ends_with("--") {
        let op = &compound[compound.len() - 2..];
        return format!("{}{};", var, op);
    }
    // __compound_vN += expr
    if let Some(rest) = compound.strip_prefix(&format!("{} ", var)) {
        return format!("{} {};", var, rest.trim());
    }
    // fallback: try to match by stripping vN part
    if let Some(idx) = compound.find(" ") {
        let rest = &compound[idx..];
        return format!("{}{};", var, rest.trim_end().trim_end_matches(';'));
    }
    format!("{};", compound)
}

/// Handle compound assign markers in raw/untyped lines.
fn resolve_compound_in_line(line: &str, name_map: Option<&HashMap<VarId, String>>) -> String {
    if let Some(eq_pos) = line.find(" = __compound_") {
        let var = line[..eq_pos].trim();
        let after = line[eq_pos + " = __compound_".len()..].trim_end_matches(';').trim();
        let after = if let Some(nm) = name_map {
            ir::substitute_names_in_text_pub(after, nm)
        } else {
            after.to_string()
        };
        if after.ends_with("++") || after.ends_with("--") {
            let op = &after[after.len() - 2..];
            return format!("{}{};", var, op);
        }
        if let Some(rest) = after.strip_prefix(&format!("{} ", var)) {
            return format!("{} {};", var, rest);
        }
        if let Some(idx) = after.find(' ') {
            return format!("{}{};", var, &after[idx..]);
        }
    }
    line.to_string()
}

/// Shorten common Java types: `java.lang.String` → `String`, `java.lang.Object` → `Object`, etc.
fn shorten_type(ty: &str) -> String {
    shorten_java_names(ty)
}

/// Split a fully qualified class name into (package, simple_class_name).
/// e.g. "androguard.test.TestIfs" → ("androguard.test", "TestIfs"); "TestIfs" → ("", "TestIfs").
fn split_package_and_class(fully_qualified: &str) -> (String, String) {
    match fully_qualified.rfind('.') {
        Some(dot) => (
            fully_qualified[..dot].to_string(),
            fully_qualified[dot + 1..].to_string(),
        ),
        None => (String::new(), fully_qualified.to_string()),
    }
}

/// Annotation type to short name for @Override, @Nullable, etc. e.g. "android.annotation.Override" → "Override".
fn annotation_short_name(java_type: &str) -> &str {
    java_type.rsplit('.').next().unwrap_or(java_type)
}

/// Primitives and void: no import needed.
const PRIMITIVE_OR_VOID: &[&str] = &[
    "void", "boolean", "byte", "short", "char", "int", "long", "float", "double",
];

const ACC_STATIC: u32 = 0x8;
const ACC_FINAL: u32 = 0x10;

/// Pure logic: given super type and static field (type, name, flags), return enum constant names if this is an enum.
/// Used by detect_enum_constants and by tests.
fn enum_constants_from_static_fields(
    class_name: &str,
    super_type: &str,
    static_fields: &[(String, String, u32)],
) -> Vec<String> {
    if super_type.trim() != "Enum" {
        return vec![];
    }
    let mut constants = Vec::new();
    for (field_typ, field_name, access_flags) in static_fields {
        if (access_flags & (ACC_STATIC | ACC_FINAL)) != (ACC_STATIC | ACC_FINAL) {
            continue;
        }
        if field_typ == class_name {
            constants.push(field_name.clone());
        }
    }
    constants
}

/// Detect enum pattern: class extends Enum and has static final fields of its own type (enum constants).
/// Returns the list of constant names in declaration order; empty if not an enum.
fn detect_enum_constants(
    dex: &DexFile,
    _class_def: &ClassDef,
    class_data: Option<&dex_parser::ClassData>,
    class_name: &str,
    super_type: &str,
) -> Vec<String> {
    let Some(ref cd) = class_data else {
        return vec![];
    };
    let mut static_fields: Vec<(String, String, u32)> = Vec::new();
    for f in &cd.static_fields {
        let Ok(fi) = dex.get_field_info(f.field_idx) else {
            continue;
        };
        let field_typ = java::descriptor_to_java(&fi.typ);
        static_fields.push((field_typ, fi.name.to_string(), f.access_flags));
    }
    enum_constants_from_static_fields(class_name, super_type, &static_fields)
}

/// Collect fully-qualified types used in this class (super, fields, method signatures) for import statements.
/// Excludes java.lang.*, same-package types, primitives, and the current class.
fn collect_class_imports(
    dex: &DexFile,
    class_def: &ClassDef,
    class_data: Option<&dex_parser::ClassData>,
    class_name: &str,
    package: &str,
) -> Result<Vec<String>> {
    let mut fqns: std::collections::HashSet<String> = std::collections::HashSet::new();

    let add_type = |fqns: &mut std::collections::HashSet<String>, ty: &str| {
        let base = ty.trim_end_matches(']').trim_end_matches('[').trim();
        if base.is_empty() || PRIMITIVE_OR_VOID.contains(&base) {
            return;
        }
        if base.starts_with("java.lang.") {
            return;
        }
        if base == class_name {
            return;
        }
        if !package.is_empty() && (base == package || base.starts_with(&format!("{}.", package))) {
            return;
        }
        fqns.insert(base.to_string());
    };

    if class_def.superclass_idx != NO_INDEX {
        if let Ok(s) = dex.get_type(class_def.superclass_idx) {
            let ty = java::descriptor_to_java(&s);
            add_type(&mut fqns, &ty);
        }
    }

    if let Some(cd) = class_data {
        for f in cd.static_fields.iter().chain(cd.instance_fields.iter()) {
            if let Ok(fi) = dex.get_field_info(f.field_idx) {
                let ty = java::descriptor_to_java(&fi.typ);
                add_type(&mut fqns, &ty);
            }
        }
        for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
            if let Ok(info) = dex.get_method_info(m.method_idx) {
                let ret = java::descriptor_to_java(&info.return_type);
                add_type(&mut fqns, &ret);
                for p in &info.params {
                    let ty = java::descriptor_to_java(p);
                    add_type(&mut fqns, &ty);
                }
            }
        }
    }

    let mut list: Vec<String> = fqns.into_iter().collect();
    list.sort();
    Ok(list)
}

/// Shorten fully-qualified Java names in a line.
fn shorten_java_names(line: &str) -> String {
    let mut s = line.to_string();
    for prefix in &[
        "java.lang.", "java.util.", "java.io.", "android.content.",
        "android.os.", "android.app.", "android.view.", "android.widget.",
    ] {
        while let Some(pos) = s.find(prefix) {
            // Only shorten if the previous char is a word boundary
            let before = if pos > 0 { s.as_bytes()[pos - 1] } else { b' ' };
            if before.is_ascii_alphanumeric() || before == b'_' {
                break;
            }
            s = format!("{}{}", &s[..pos], &s[pos + prefix.len()..]);
        }
    }
    s
}

/// Negate a condition properly: `a != b` → `a == b`, `a >= 0` → `a < 0`, etc.
/// Falls back to `!(cond)` for complex expressions.
fn negate_condition(cond: &str) -> String {
    let cond = cond.trim();
    let ops: &[(&str, &str)] = &[
        (" != ", " == "), (" == ", " != "),
        (" >= ", " < "),  (" < ",  " >= "),
        (" > ",  " <= "), (" <= ", " > "),
    ];
    for (op, neg) in ops {
        if let Some(pos) = cond.find(op) {
            return format!("{}{}{}", &cond[..pos], neg, &cond[pos + op.len()..]);
        }
    }
    format!("!({})", cond)
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
        "packed-switch" | "sparse-switch" => {
            if !parts.is_empty() {
                parts[0].to_string()
            } else {
                resolved_operands.to_string()
            }
        }
        _ => resolved_operands.to_string(),
    }
}

/// Map Java class name to (relative_dir, file_name) for dumping.
/// e.g. "com.example.MyClass" -> ("com/example", "MyClass.java"), "Outer$Inner" -> ("", "Outer$Inner.java").
pub fn class_name_to_path(class_name: &str) -> (std::path::PathBuf, String) {
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
            parse_two_regs_and_literal(ops).map(|(dest, src, lit)| {
                let lit_trim = lit.trim();
                let rhs = if op == "+" && lit_trim.starts_with('-') && lit_trim.len() > 1 {
                    let magnitude = lit_trim[1..].trim();
                    format!("v{} - {}", src, magnitude)
                } else {
                    format!("v{} {} {}", src, op, lit)
                };
                (dest, rhs)
            })
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
        "move" | "move/from16" | "move/16" | "move-object" | "move-wide" | "move-wide/from16" | "move-object/from16" => {
            parse_two_regs(ops).map(|(d, s)| (d, format!("v{}", s)))
        }
        // Int-to-* casts
        "int-to-long" => parse_two_regs(ops).map(|(a, b)| (a, format!("(long) v{}", b))),
        "int-to-float" => parse_two_regs(ops).map(|(a, b)| (a, format!("(float) v{}", b))),
        "int-to-double" => parse_two_regs(ops).map(|(a, b)| (a, format!("(double) v{}", b))),
        "long-to-int" => parse_two_regs(ops).map(|(a, b)| (a, format!("(int) v{}", b))),
        "long-to-float" => parse_two_regs(ops).map(|(a, b)| (a, format!("(float) v{}", b))),
        "long-to-double" => parse_two_regs(ops).map(|(a, b)| (a, format!("(double) v{}", b))),
        "float-to-int" => parse_two_regs(ops).map(|(a, b)| (a, format!("(int) v{}", b))),
        "float-to-long" => parse_two_regs(ops).map(|(a, b)| (a, format!("(long) v{}", b))),
        "float-to-double" => parse_two_regs(ops).map(|(a, b)| (a, format!("(double) v{}", b))),
        "double-to-int" => parse_two_regs(ops).map(|(a, b)| (a, format!("(int) v{}", b))),
        "double-to-long" => parse_two_regs(ops).map(|(a, b)| (a, format!("(long) v{}", b))),
        "double-to-float" => parse_two_regs(ops).map(|(a, b)| (a, format!("(float) v{}", b))),
        "int-to-byte" => parse_two_regs(ops).map(|(a, b)| (a, format!("(byte) v{}", b))),
        "int-to-char" => parse_two_regs(ops).map(|(a, b)| (a, format!("(char) v{}", b))),
        "int-to-short" => parse_two_regs(ops).map(|(a, b)| (a, format!("(short) v{}", b))),
        "new-array" => {
            let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
            if parts.len() < 3 {
                return None;
            }
            let dst_reg: u32 = parts[0].strip_prefix('v')?.parse().ok()?;
            let size_reg: u32 = parts[1].strip_prefix('v')?.parse().ok()?;
            let type_str = parts[2];
            let element_type = type_str.strip_suffix("[]").unwrap_or(type_str);
            Some((dst_reg, format!("new {}[v{}]", element_type, size_reg)))
        }
        "iget" | "iget-wide" | "iget-object" | "iget-boolean" | "iget-byte" | "iget-char" | "iget-short" => {
            if let Some((dest, obj, field)) = parse_instance_field_operands(ops) {
                Some((dest, format!("v{}.{}", obj, field)))
            } else {
                None
            }
        }
        "sget" | "sget-wide" | "sget-object" | "sget-boolean" | "sget-byte" | "sget-char" | "sget-short" => {
            if let Some((reg, field_ref)) = parse_static_field_operands(ops) {
                Some((reg, field_ref))
            } else {
                None
            }
        }
        "aget" | "aget-wide" | "aget-object" | "aget-boolean" | "aget-byte" | "aget-char" | "aget-short" => {
            parse_three_regs(ops).map(|(a, b, c)| (a, format!("v{}[v{}]", b, c)))
        }
        "array-length" => {
            parse_two_regs(ops).map(|(a, b)| (a, format!("v{}.length", b)))
        }
        "new-instance" => {
            let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
            if parts.len() < 2 { return None; }
            let reg: u32 = parts[0].strip_prefix('v')?.parse().ok()?;
            Some((reg, format!("new {}()", parts[1])))
        }
        "check-cast" => {
            let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
            if parts.len() < 2 { return None; }
            let reg: u32 = parts[0].strip_prefix('v')?.parse().ok()?;
            Some((reg, format!("({}) v{}", parts[1], reg)))
        }
        "instance-of" => {
            let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
            if parts.len() < 3 { return None; }
            let dst: u32 = parts[0].strip_prefix('v')?.parse().ok()?;
            Some((dst, format!("v{} instanceof {}", parts[1].strip_prefix('v').unwrap_or(parts[1]), parts[2])))
        }
        "const-class" => {
            let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
            if parts.len() < 2 { return None; }
            let reg: u32 = parts[0].strip_prefix('v')?.parse().ok()?;
            Some((reg, format!("{}.class", parts[1])))
        }
        "const-wide/16" | "const-wide/32" | "const-wide" | "const-wide/high16" | "const/high16" => {
            let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
            if parts.len() < 2 { return None; }
            let reg: u32 = parts[0].strip_prefix('v')?.parse().ok()?;
            Some((reg, parts[1..].join(", ")))
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

/// Format *-int/lit8: vA, vB, lit → "vA = vB op lit;" or "vA = vB - N;" when lit is negative and op is "+".
fn format_lit8(ops: &str, op: &str) -> String {
    parse_two_regs_and_literal(ops)
        .map(|(dest, src, lit)| {
            let lit_trim = lit.trim();
            if op == "+" && lit_trim.starts_with('-') && lit_trim.len() > 1 {
                let magnitude = lit_trim[1..].trim();
                format!("v{} = v{} - {};", dest, src, magnitude)
            } else {
                format!("v{} = v{} {} {};", dest, src, op, lit)
            }
        })
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
const FILL_ARRAY_DATA_ID: u16 = 0x0300;

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

/// Parse fill-array-data payload and return a comment like "/* arr = { 1, 2, 3 } */".
/// Payload: ident 0x0300 (u16), element_width (u16), size (u32), then size*element_width bytes (LE).
fn format_fill_array_data(ins: &Instruction, code_insns: &[u8], ops_resolved: &str) -> String {
    let arr_reg = ops_resolved.split(',').next().map(str::trim).unwrap_or("v0");
    let ins_off = ins.offset as usize;
    if ins_off + 6 > code_insns.len() {
        return format!("/* fill-array-data {} */", ops_resolved);
    }
    let rel_units = i32::from_le_bytes(
        code_insns[ins_off + 2..ins_off + 6]
            .try_into()
            .unwrap_or([0, 0, 0, 0]),
    );
    let try_payload = |off: usize| -> Option<(u16, u32)> {
        if off + 8 > code_insns.len() {
            return None;
        }
        let id = u16::from_le_bytes(code_insns[off..off + 2].try_into().unwrap_or([0, 0]));
        if id != FILL_ARRAY_DATA_ID {
            return None;
        }
        let elem_w = u16::from_le_bytes(code_insns[off + 2..off + 4].try_into().unwrap_or([0, 0]));
        let size = u32::from_le_bytes(code_insns[off + 4..off + 8].try_into().unwrap_or([0, 0, 0, 0]));
        if elem_w != 1 && elem_w != 2 && elem_w != 4 && elem_w != 8 {
            return None;
        }
        Some((elem_w, size))
    };
    let cand_a = (ins_off as i32 + rel_units * 2) as usize;
    let cand_b = (ins_off as i32 + 2 + rel_units * 2) as usize;
    let (payload_off, elem_width, size) = match [cand_a, cand_b]
        .iter()
        .find_map(|&off| try_payload(off).map(|(w, s)| (off, w, s)))
    {
        Some(t) => t,
        None => return format!("/* fill-array-data {} */", ops_resolved),
    };

    let data_start = payload_off + 8;
    let data_len = (size as usize).saturating_mul(elem_width as usize);
    if data_start + data_len > code_insns.len() {
        return format!("/* fill-array-data {} */", ops_resolved);
    }

    let mut values: Vec<String> = Vec::new();
    for i in 0..(size as usize) {
        let el_off = data_start + i * (elem_width as usize);
        let val = match elem_width {
            1 => {
                let b = code_insns.get(el_off).copied().unwrap_or(0);
                (b as i8 as i32).to_string()
            }
            2 => {
                if el_off + 2 > code_insns.len() {
                    break;
                }
                let s = i16::from_le_bytes(code_insns[el_off..el_off + 2].try_into().unwrap_or([0, 0]));
                s.to_string()
            }
            4 => {
                if el_off + 4 > code_insns.len() {
                    break;
                }
                let n = i32::from_le_bytes(code_insns[el_off..el_off + 4].try_into().unwrap_or([0, 0, 0, 0]));
                n.to_string()
            }
            8 => {
                if el_off + 8 > code_insns.len() {
                    break;
                }
                let n = i64::from_le_bytes(code_insns[el_off..el_off + 8].try_into().unwrap_or([0; 8]));
                n.to_string()
            }
            _ => break,
        };
        values.push(val);
    }
    let init = values.join(", ");
    format!("/* {} = {{ {} }} */", arr_reg, init)
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

/// check-cast: "vN, Type" → "vN = (Type) vN;"
fn format_check_cast(ops: &str) -> String {
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    if parts.len() >= 2 {
        let reg = parts[0];
        let ty = parts[1];
        format!("{} = ({}) {};", reg, ty, reg)
    } else {
        String::new()
    }
}

/// instance-of: "vA, vB, Type" → "vA = vB instanceof Type;"
fn format_instance_of(ops: &str) -> String {
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    if parts.len() >= 3 {
        format!("{} = {} instanceof {};", parts[0], parts[1], parts[2])
    } else {
        String::new()
    }
}

/// const-class: "vA, Type" → "vA = Type.class;"
fn format_const_class(ops: &str) -> String {
    let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
    if parts.len() >= 2 {
        format!("{} = {}.class;", parts[0], parts[1])
    } else {
        String::new()
    }
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
    fn format_lit8_add_negative_simplifies_to_sub() {
        assert_eq!(format_lit8("v0, v1, -3", "+"), "v0 = v1 - 3;");
        assert_eq!(format_lit8("v2, v2, -1", "+"), "v2 = v2 - 1;");
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

    #[test]
    fn enum_detection_super_not_enum_returns_empty() {
        let r = super::enum_constants_from_static_fields("test.Color", "Object", &[]);
        assert!(r.is_empty());
    }

    #[test]
    fn enum_detection_extends_enum_static_final_self_type_returns_constants() {
        let static_fields = vec![
            ("test.Color".to_string(), "RED".to_string(), 0x18u32),
            ("test.Color".to_string(), "GREEN".to_string(), 0x18u32),
            ("int".to_string(), "other".to_string(), 0x18u32),
        ];
        let r = super::enum_constants_from_static_fields("test.Color", "Enum", &static_fields);
        assert_eq!(r, ["RED", "GREEN"]);
    }

    #[test]
    fn enum_detection_non_static_final_ignored() {
        let static_fields = vec![
            ("test.Color".to_string(), "RED".to_string(), 0x8u32),
        ];
        let r = super::enum_constants_from_static_fields("test.Color", "Enum", &static_fields);
        assert!(r.is_empty());
    }
}
