//! CLI: DEX to Java decompiler.

use std::fs;
use std::path::Path;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use dex_decompiler::{
    class_name_to_path, parse_dex, run_all_detectors, scan_pending_intents, Decompiler,
    DecompilerOptions, DexFile, EncodedMethod,
};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

/// Parse offset as decimal or 0x-prefixed hex.
fn parse_offset(s: &str) -> Result<u32, std::num::ParseIntError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex.trim(), 16)
    } else {
        s.parse::<u32>()
    }
}

/// Simple name: last component after the final dot (e.g. "TestExceptions" from "tests.androguard.TestExceptions").
fn simple_class_name(full: &str) -> &str {
    full.rsplit('.').next().unwrap_or(full)
}

/// Find the first EncodedMethod in the DEX for the given class and method name.
/// Tries exact class name first; if not found, matches any class with the same simple name
/// (so "tests.androguard.TestExceptions" also matches "androguard.test.TestExceptions" in the DEX).
fn find_method(dex: &DexFile, class_name: &str, method_name: &str) -> Option<EncodedMethod> {
    let want_simple = simple_class_name(class_name);

    // First pass: exact match
    for class_def_result in dex.class_defs() {
        let class_def = class_def_result.ok()?;
        let class_type = dex.get_type(class_def.class_idx).ok()?;
        let name = dex_decompiler::java::descriptor_to_java(&class_type);
        if name != class_name {
            continue;
        }
        if let Some(enc) = find_method_in_class(dex, &class_def, method_name) {
            return Some(enc);
        }
    }

    // Fallback: match by simple name (e.g. "TestExceptions" in any package)
    for class_def_result in dex.class_defs() {
        let class_def = class_def_result.ok()?;
        let class_type = dex.get_type(class_def.class_idx).ok()?;
        let name = dex_decompiler::java::descriptor_to_java(&class_type);
        if simple_class_name(&name) != want_simple {
            continue;
        }
        if let Some(enc) = find_method_in_class(dex, &class_def, method_name) {
            return Some(enc);
        }
    }
    None
}

fn find_method_in_class(
    dex: &DexFile,
    class_def: &dex_decompiler::ClassDef,
    method_name: &str,
) -> Option<EncodedMethod> {
    let class_data_opt = dex.get_class_data(class_def).ok()?;
    let class_data = class_data_opt.as_ref()?;
    for encoded in class_data
        .direct_methods
        .iter()
        .chain(class_data.virtual_methods.iter())
    {
        let info = dex.get_method_info(encoded.method_idx).ok()?;
        if info.name == method_name {
            return Some(encoded.clone());
        }
    }
    None
}

/// Format registers for emulator VM state (integers in hex).
fn format_registers_short_hex(regs: &[dex_decompiler::emulator::RegisterInfo]) -> String {
    regs.iter()
        .filter(|r| !matches!(r.value, dex_decompiler::emulator::Value::Unset))
        .map(|r| format!("{}={}", r.name, r.value.display_short_hex()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Run emulator step-by-step, printing each instruction and VM state (colored, hex for integers).
fn run_emulate_verbose(emu: &mut dex_decompiler::emulator::Emulator) -> Result<()> {
    while !emu.finished && emu.step_count < emu.max_steps {
        let result = match emu.step() {
            Ok(r) => r,
            Err(e) => {
                println!("{}", format!("Execution error: {}", e).red());
                break;
            }
        };
        let ins = &result.instruction;
        let snap = &result.state_after;
        println!(
            "{}   {}  {}  {}",
            format!("Step {}:", result.step_count).cyan().bold(),
            format!("0x{:04x}", ins.offset).yellow(),
            ins.mnemonic.green(),
            ins.operands.white()
        );
        println!("  {} {}", "->".dimmed(), result.description.white());
        let regs = format_registers_short_hex(&snap.registers);
        if !regs.is_empty() {
            println!("  {} {}", "Registers:".dimmed(), regs);
        }
        if !snap.heap.is_empty() {
            let heap_str: Vec<String> = snap
                .heap
                .iter()
                .map(|h| {
                    match &h.object {
                        dex_decompiler::emulator::HeapObjectKind::Array { element_type, values } => {
                            let vals: Vec<String> = values.iter().map(|v| v.display_short_hex()).take(5).collect();
                            let more = if values.len() > 5 { "..." } else { "" };
                            format!("@{}={}[{}]({}){}", h.index, element_type, values.len(), vals.join(", "), more)
                        }
                        dex_decompiler::emulator::HeapObjectKind::Instance { class, .. } => {
                            format!("@{}={}", h.index, class)
                        }
                    }
                })
                .collect();
            println!("  {} {}", "Heap:".dimmed(), heap_str.join(", "));
        }
        println!();
    }
    Ok(())
}

/// Run emulator with a progress bar; message shows current instruction and register state (hex).
fn run_emulate_progress(emu: &mut dex_decompiler::emulator::Emulator) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};
    let pb = ProgressBar::new(emu.max_steps as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .expect("template")
            .progress_chars("=>-"),
    );
    while !emu.finished && emu.step_count < emu.max_steps {
        let result = match emu.step() {
            Ok(r) => r,
            Err(e) => {
                pb.finish_with_message(format!("Error: {}", e));
                return Ok(());
            }
        };
        pb.set_position(result.step_count as u64);
        let ins = &result.instruction;
        let regs = format_registers_short_hex(&result.state_after.registers);
        let reg_short = if regs.len() > 60 { format!("{}...", &regs[..60]) } else { regs };
        let msg = format!("0x{:04x} {} {} | {}", ins.offset, ins.mnemonic, ins.operands, reg_short);
        pb.set_message(msg);
    }
    pb.finish_with_message(format!("Done ({} steps)", emu.step_count));
    Ok(())
}

/// Run emulator step-by-step; after each instruction print state and wait for Enter (colored, hex).
fn run_emulate_interactive(emu: &mut dex_decompiler::emulator::Emulator) -> Result<()> {
    use std::io::{self, BufRead, Write};
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let mut stdout = io::stdout();
    while !emu.finished && emu.step_count < emu.max_steps {
        let result = match emu.step() {
            Ok(r) => r,
            Err(e) => {
                println!("{}", format!("Execution error: {}", e).red());
                break;
            }
        };
        let ins = &result.instruction;
        let snap = &result.state_after;
        println!(
            "{}   {}  {}  {}",
            format!("Step {}:", result.step_count).cyan().bold(),
            format!("0x{:04x}", ins.offset).yellow(),
            ins.mnemonic.green(),
            ins.operands.white()
        );
        println!("  {} {}", "->".dimmed(), result.description.white());
        let regs = format_registers_short_hex(&snap.registers);
        if !regs.is_empty() {
            println!("  {} {}", "Registers:".dimmed(), regs);
        }
        if !snap.heap.is_empty() {
            let heap_str: Vec<String> = snap
                .heap
                .iter()
                .map(|h| {
                    match &h.object {
                        dex_decompiler::emulator::HeapObjectKind::Array { element_type, values } => {
                            let vals: Vec<String> = values.iter().map(|v| v.display_short_hex()).take(5).collect();
                            let more = if values.len() > 5 { "..." } else { "" };
                            format!("@{}={}[{}]({}){}", h.index, element_type, values.len(), vals.join(", "), more)
                        }
                        dex_decompiler::emulator::HeapObjectKind::Instance { class, .. } => {
                            format!("@{}={}", h.index, class)
                        }
                    }
                })
                .collect();
            println!("  {} {}", "Heap:".dimmed(), heap_str.join(", "));
        }
        print!("  {} ", "[Enter to continue, q+Enter to stop]".dimmed());
        stdout.flush()?;
        let mut line = String::new();
        stdin.read_line(&mut line)?;
        if line.trim().eq_ignore_ascii_case("q") {
            println!("{}", "Stopped by user.".yellow());
            break;
        }
        println!();
    }
    Ok(())
}

/// Split params: use semicolon as top-level separator so array params can contain commas.
/// E.g. "5;10" = two ints, "[B]1,2,3;[B]0,0" = two byte arrays.
fn split_params_top_level(s: &str) -> Vec<String> {
    s.split(';')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Parse one array token e.g. "[1,2,3]", "[B]0,1,2", or "[B]1,2,3,4,5" (no trailing ]).
/// Returns (element_type, values).
fn parse_array_token(token: &str) -> Option<(String, Vec<dex_decompiler::emulator::Value>)> {
    let t = token.trim();
    if !t.starts_with('[') {
        return None;
    }
    let after_open = t[1..].trim_start();
    let (elem_ty, rest) = if let Some(close) = after_open.find(']') {
        let ty = after_open[..close].trim();
        let after = after_open[close + 1..].trim_start();
        match ty {
            "B" | "byte" => ("B".to_string(), after),
            "I" | "int" => ("I".to_string(), after),
            _ => {
                // "[1,2,3]" form: list is between [ and last ]
                if t.ends_with(']') {
                    ("I".to_string(), t[1..t.len() - 1].trim())
                } else {
                    ("I".to_string(), after_open)
                }
            }
        }
    } else {
        return None;
    };
    let values: Vec<dex_decompiler::emulator::Value> = if rest.is_empty() {
        vec![]
    } else {
        rest.split(',')
            .map(|s| {
                let s = s.trim().trim_end_matches(']');
                s.parse::<i32>()
                    .map(dex_decompiler::emulator::Value::Int)
                    .unwrap_or(dex_decompiler::emulator::Value::Int(0))
            })
            .collect()
    };
    Some((elem_ty, values))
}

/// Parse --emulate-params into (params, initial_heap). Supports int, long, string, null, and arrays:
/// "[1,2,3]" = int array, "[B]0,1,2" or "[byte]0,1,2" = byte array. Arrays are pushed to initial_heap
/// and params get Value::Ref(index).
fn parse_emulate_params(s: &str) -> (Vec<dex_decompiler::emulator::Value>, Vec<dex_decompiler::emulator::HeapObject>) {
    use dex_decompiler::emulator::{HeapObject, HeapObjectKind, Value};
    let tokens = split_params_top_level(s);
    let mut params = Vec::new();
    let mut initial_heap = Vec::new();
    for token in tokens {
        let t = token.trim();
        if t.eq_ignore_ascii_case("null") {
            params.push(Value::Null);
        } else if let Some((elem_ty, values)) = parse_array_token(t) {
            let obj = HeapObject {
                kind: HeapObjectKind::Array {
                    element_type: elem_ty.clone(),
                    values,
                },
            };
            initial_heap.push(obj);
            params.push(Value::Ref(initial_heap.len() - 1));
        } else if let Ok(v) = t.parse::<i32>() {
            params.push(Value::Int(v));
        } else if let Ok(v) = t.parse::<i64>() {
            params.push(Value::Long(v));
        } else {
            params.push(Value::Str(t.trim_matches('"').to_string()));
        }
    }
    (params, initial_heap)
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Emulate: run method with given params and print console output + return value.
    if let Some(ref emulate_spec) = args.emulate {
        let (class_name, method_name) = match emulate_spec.split_once('#') {
            Some((c, m)) => (c.trim(), m.trim()),
            None => anyhow::bail!("--emulate must be CLASS#METHOD (e.g. com.example.Main#foo)"),
        };
        let mut encoded = None;
        let mut dex = None;
        for path in &args.input {
            let data = fs::read(path).with_context(|| format!("read {}", path))?;
            let d = parse_dex(&data).context("parse DEX")?;
            if let Some(enc) = find_method(&d, class_name, method_name) {
                encoded = Some(enc);
                dex = Some(d);
                break;
            }
        }
        let (dex, encoded) = match (dex, encoded) {
            (Some(d), Some(e)) => (d, e),
            _ => anyhow::bail!(
                "method {}#{} not found in any of {} DEX file(s)",
                class_name,
                method_name,
                args.input.len()
            ),
        };
        let decompiler = Decompiler::new(&dex);
        let (params, initial_heap) = args
            .emulate_params
            .as_deref()
            .map(parse_emulate_params)
            .unwrap_or_else(|| (Vec::new(), Vec::new()));
        let mut emu = decompiler
            .build_emulator(&encoded, params.clone(), initial_heap)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        let max_steps = args.emulate_max_steps.unwrap_or(10_000);
        emu.max_steps = max_steps;

        println!("{}", format!("=== Emulate {}#{} ===", class_name, method_name).cyan().bold());
        if !params.is_empty() {
            println!("{} {:?}", "Params:".dimmed(), params);
        }
        println!("{} {}", "Max steps:".dimmed(), max_steps);
        println!();

        if args.emulate_interactive {
            run_emulate_interactive(&mut emu)?;
        } else if args.emulate_verbose {
            run_emulate_verbose(&mut emu)?;
        } else if args.emulate_progress {
            run_emulate_progress(&mut emu)?;
        } else {
            match emu.run_to_end() {
                Ok(()) => {}
                Err(e) => println!("{}", format!("Execution error: {}", e).red()),
            }
        }

        if !emu.console_output.is_empty() {
            println!("\n{}", "--- Console output ---".dimmed());
            for line in &emu.console_output {
                print!("{}", line);
            }
            println!();
        }

        if let Some(ref v) = emu.return_value {
            println!("{}", "--- Return value ---".dimmed());
            println!("{}", v.display_short_hex());
        }
        if let Some(ref e) = emu.exception {
            println!("{}", "--- Exception ---".dimmed());
            println!("{}", e.red());
        }

        println!("{}", "--- Summary ---".dimmed());
        println!("Steps: {}", emu.step_count);
        println!("Finished: {}", emu.finished);
        return Ok(());
    }

    // Data flow / tainting: show reads and writes for a value in a method.
    // With multiple DEX inputs (e.g. classes.dex, classes2.dex), the method is searched in order.
    if let Some(ref taint_method) = args.taint_method {
        let (class_name, method_name) = match taint_method.split_once('#') {
            Some((c, m)) => (c.trim(), m.trim()),
            None => anyhow::bail!("--taint-method must be CLASS#METHOD (e.g. com.example.Main#onCreate)"),
        };
        let mut encoded = None;
        let mut dex = None;
        for path in &args.input {
            let data = fs::read(path).with_context(|| format!("read {}", path))?;
            let d = parse_dex(&data).context("parse DEX")?;
            if let Some(enc) = find_method(&d, class_name, method_name) {
                encoded = Some(enc);
                dex = Some(d);
                break;
            }
        }
        let (dex, encoded) = match (dex, encoded) {
            (Some(d), Some(e)) => (d, e),
            _ => anyhow::bail!(
                "method {}#{} not found in any of {} DEX file(s): {}",
                class_name,
                method_name,
                args.input.len(),
                args.input.join(", ")
            ),
        };
        let decompiler = Decompiler::new(&dex);
        let owned = decompiler
            .value_flow_analysis(&encoded)
            .context("value_flow_analysis (method has no code?)")?;

        let (result, title) = if !args.taint_api.is_empty() {
            let result = owned.value_flow_from_api_sources(&args.taint_api);
            let title = format!("Value flow from API sources: {}", args.taint_api.join(", "));
            (result, title)
        } else if let (Some(taint_offset), Some(taint_reg)) = (
            args.taint_offset.as_ref().and_then(|s| parse_offset(s).ok()),
            args.taint_reg,
        ) {
            let result = owned.analysis().value_flow_from_seed(taint_offset, taint_reg);
            let title = format!("Value flow from seed (offset=0x{:x}, reg=v{})", taint_offset, taint_reg);
            (result, title)
        } else {
            anyhow::bail!(
                "with --taint-method specify either --taint-offset and --taint-reg, or --taint-api PATTERN (e.g. --taint-api getLastLocation)"
            );
        };

        println!("{}", title);
        println!("  Writes (defs): {} locations", result.writes.len());
        for (off, reg) in &result.writes {
            println!("    0x{:04x}  v{}", off, reg);
        }
        println!("  Reads (uses): {} locations", result.reads.len());
        for (off, reg) in &result.reads {
            println!("    0x{:04x}  v{}", off, reg);
        }
        return Ok(());
    }

    // PendingIntent vulnerability scan: iterate all methods in all DEX files.
    if args.scan_pending_intent {
        let mut all_findings = Vec::new();
        for path in &args.input {
            let data = fs::read(path).with_context(|| format!("read {}", path))?;
            let dex = parse_dex(&data).context("parse DEX")?;
            let decompiler = Decompiler::new(&dex);
            for class_def_result in dex.class_defs() {
                let class_def = match class_def_result {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let class_type = match dex.get_type(class_def.class_idx) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                let class_name = dex_decompiler::java::descriptor_to_java(&class_type);
                let class_data = match dex.get_class_data(&class_def) {
                    Ok(Some(cd)) => cd,
                    _ => continue,
                };
                for encoded in class_data
                    .direct_methods
                    .iter()
                    .chain(class_data.virtual_methods.iter())
                {
                    if encoded.code_off == 0 {
                        continue;
                    }
                    let method_info = match dex.get_method_info(encoded.method_idx) {
                        Ok(mi) => mi,
                        Err(_) => continue,
                    };
                    let method_name = method_info.name.to_string();
                    let owned = match decompiler.value_flow_analysis(encoded) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let findings = scan_pending_intents(&owned, &class_name, &method_name);
                    all_findings.extend(findings);
                }
            }
        }
        println!("PendingIntent scan: {} finding(s)", all_findings.len());
        for f in &all_findings {
            let risk = if f.base_intent_empty && f.dangerous_destination {
                "RISK"
            } else if f.base_intent_empty || f.dangerous_destination {
                "review"
            } else {
                "ok"
            };
            println!(
                "  [{}] {}#{} @ 0x{:x}  base_empty={} dest={}",
                risk,
                f.class_name,
                f.method_name,
                f.invoke_offset,
                f.base_intent_empty,
                f.destination_kind
            );
        }
        return Ok(());
    }

    // Vulnerability scan: run all detectors (intent spoofing, RCE, logging, SQL, WebView, secrets, IPC) on every method.
    if args.scan_vulns {
        let mut all_findings = Vec::new();
        for path in &args.input {
            let data = fs::read(path).with_context(|| format!("read {}", path))?;
            let dex = parse_dex(&data).context("parse DEX")?;
            let decompiler = Decompiler::new(&dex);
            for class_def_result in dex.class_defs() {
                let class_def = match class_def_result {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let class_type = match dex.get_type(class_def.class_idx) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                let class_name = dex_decompiler::java::descriptor_to_java(&class_type);
                let class_data = match dex.get_class_data(&class_def) {
                    Ok(Some(cd)) => cd,
                    _ => continue,
                };
                for encoded in class_data
                    .direct_methods
                    .iter()
                    .chain(class_data.virtual_methods.iter())
                {
                    if encoded.code_off == 0 {
                        continue;
                    }
                    let method_info = match dex.get_method_info(encoded.method_idx) {
                        Ok(mi) => mi,
                        Err(_) => continue,
                    };
                    let method_name = method_info.name.to_string();
                    let owned = match decompiler.value_flow_analysis(encoded) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let findings = run_all_detectors(
                        &owned,
                        &class_name,
                        &method_name,
                        if args.taint_api.is_empty() {
                            None
                        } else {
                            Some(&args.taint_api)
                        },
                    );
                    all_findings.extend(findings);
                }
            }
        }
        println!("Vulnerability scan: {} finding(s)", all_findings.len());
        for f in &all_findings {
            println!(
                "  [{}] {}#{}  sink @ 0x{:x}  {}",
                f.category,
                f.class_name,
                f.method_name,
                f.sink_offset,
                f.sink_desc
            );
        }
        return Ok(());
    }

    // Decompile: use first DEX file (multi-DEX is supported for taint mode above).
    let path = &args.input[0];
    let data = fs::read(path).with_context(|| format!("read {}", path))?;
    let dex = parse_dex(&data).context("parse DEX")?;
    let options = DecompilerOptions {
        only_package: args.only_package,
        exclude: args.exclude.clone(),
        show_bytecode: args.show_bytecode,
    };
    let decompiler = Decompiler::with_options(&dex, options.clone());

    if let Some(ref out_dir) = args.output_dir {
        let base_path = Path::new(out_dir);
        let pb = ProgressBar::new(0);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{bar:40.cyan/blue}] {pos}/{len} {msg}")?
                .progress_chars("=>-"),
        );
        let included = decompiler
            .collect_included_classes()
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let total = included.len();
        if total == 0 {
            pb.finish_with_message("no classes to decompile");
            return Ok(());
        }
        pb.set_length(total as u64);
        pb.set_message("starting…");
        // DexFile is not Send (uses Rc), so we share raw bytes and parse once per worker.
        let data = Arc::new(data);
        let options = options.clone();
        let pb_shared = Arc::new(pb);
        // Writer thread: write files on the fly as they are decompiled.
        let (tx, rx) = mpsc::channel::<(std::path::PathBuf, String, String)>();
        let write_error: Arc<Mutex<Option<anyhow::Error>>> = Arc::new(Mutex::new(None));
        let write_error_clone = Arc::clone(&write_error);
        let pb_writer = Arc::clone(&pb_shared);
        let writer_handle = thread::spawn(move || {
            while let Ok((full_dir, file_name, class_java)) = rx.recv() {
                if write_error_clone.lock().unwrap().is_some() {
                    continue;
                }
                if let Err(e) = fs::create_dir_all(&full_dir)
                    .with_context(|| format!("create dir {}", full_dir.display()))
                {
                    *write_error_clone.lock().unwrap() = Some(e);
                    continue;
                }
                let file_path = full_dir.join(&file_name);
                if let Err(e) =
                    fs::write(&file_path, class_java).with_context(|| format!("write {}", file_path.display()))
                {
                    *write_error_clone.lock().unwrap() = Some(e);
                    continue;
                }
                pb_writer.inc(1);
            }
        });
        let tx = Arc::new(tx);
        // Use more chunks than workers for better load balance (slow classes don't leave others idle).
        let num_workers = rayon::current_num_threads().max(1);
        let num_chunks = (num_workers * 4).max(1);
        let chunk_size = (total + num_chunks - 1) / num_chunks;
        let chunked: Vec<Vec<(_, String)>> = included
            .chunks(chunk_size.max(1))
            .map(|c| c.to_vec())
            .collect();
        let results: Vec<Result<()>> = chunked
            .par_iter()
            .flat_map(|chunk| {
                let dex = parse_dex(data.as_ref()).expect("DEX already parsed");
                let d = Decompiler::with_options(&dex, options.clone());
                let tx = Arc::clone(&tx);
                let pb = Arc::clone(&pb_shared);
                chunk
                    .iter()
                    .map(|(class_def, class_name)| {
                        pb.set_message(class_name.clone());
                        let java =
                            d.decompile_class(class_def).map_err(|e| anyhow::anyhow!("{}", e))?;
                        let (rel_dir, file_name) = class_name_to_path(class_name);
                        let full_dir = base_path.join(rel_dir);
                        tx.send((full_dir, file_name, java))
                            .map_err(|e| anyhow::anyhow!("writer thread dropped: {}", e))?;
                        Ok(())
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        drop(tx);
        writer_handle
            .join()
            .map_err(|_| anyhow::anyhow!("writer thread panicked"))?;
        if let Some(e) = write_error.lock().unwrap().take() {
            return Err(e);
        }
        for r in results {
            r?;
        }
        pb_shared.finish_with_message("done");
    } else {
        let java = decompiler.decompile().context("decompile")?;
        if let Some(ref out_path) = args.output {
            fs::write(Path::new(out_path), java).with_context(|| format!("write {}", out_path))?;
        } else {
            print!("{}", java);
        }
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[command(name = "dex-decompile", version, about = "DEX to Java decompiler (pure Rust)")]
struct Args {
    /// Input DEX file path(s). May be repeated for multi-DEX apps (e.g. classes.dex, classes2.dex).
    /// Taint mode searches for CLASS#METHOD in each file in order; decompile uses the first file.
    #[arg(short, long, required = true, num_args = 1..)]
    input: Vec<String>,

    /// Output Java file (single file; default: stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// Output directory: dump all classes with package structure (e.g. out/com/example/MyClass.java)
    #[arg(short = 'd', long = "output-dir")]
    output_dir: Option<String>,

    /// Only decompile classes in this package (e.g. com.example). Classes in subpackages are included.
    #[arg(long = "only-package")]
    only_package: Option<String>,

    /// Exclude classes in this package (e.g. android). May be repeated. Supports trailing . or .*
    #[arg(long)]
    exclude: Vec<String>,

    /// Data flow / tainting: show where value (offset, reg) is read/written in method CLASS#METHOD.
    /// Use with --taint-offset and --taint-reg. Offset can be decimal or 0x-prefixed hex.
    #[arg(long = "taint-method", value_name = "CLASS#METHOD")]
    taint_method: Option<String>,

    /// Instruction byte offset for taint seed (decimal or 0x hex, e.g. 0 or 0x4).
    #[arg(long = "taint-offset", value_name = "OFFSET")]
    taint_offset: Option<String>,

    /// Register number for taint seed (e.g. 0 for v0).
    #[arg(long = "taint-reg", value_name = "REG")]
    taint_reg: Option<u32>,

    /// Taint returns of Android API methods (e.g. getLastLocation, FusedLocationProviderClient.getLastLocation).
    /// Use with --taint-method. May be repeated. Matches if the resolved method ref contains the pattern.
    #[arg(long = "taint-api", value_name = "PATTERN")]
    taint_api: Vec<String>,

    /// Scan all methods for PendingIntent creation sites (PITracker-like). Reports base Intent emptiness and destination.
    #[arg(long = "scan-pending-intent")]
    scan_pending_intent: bool,

    /// Emit raw DEX instructions as comments before each method body (for debugging).
    #[arg(long = "show-bytecode")]
    show_bytecode: bool,

    /// Run all vulnerability detectors on every method (intent spoofing, RCE dynamic loading, insecure logging, SQL, WebView, hardcoded secrets, IPC). Optional: combine with --taint-api to add logging sources.
    #[arg(long = "scan-vulns")]
    scan_vulns: bool,

    /// Emulate method CLASS#METHOD with optional params; print console output and return value to stdout.
    #[arg(long = "emulate", value_name = "CLASS#METHOD")]
    emulate: Option<String>,

    /// Comma-separated parameter values for --emulate (e.g. "5,10" or "\"hello\",42"). Strings can be quoted.
    #[arg(long = "emulate-params", value_name = "VALS")]
    emulate_params: Option<String>,

    /// Maximum emulation steps (default: 10000). Use with --emulate.
    #[arg(long = "emulate-max-steps", value_name = "N")]
    emulate_max_steps: Option<usize>,

    /// Emulation verbose mode: print every instruction and VM state (registers, heap) after each step.
    #[arg(long = "emulate-verbose")]
    emulate_verbose: bool,

    /// Emulation progress bar: show step count and current instruction + registers in the bar message.
    #[arg(long = "emulate-progress")]
    emulate_progress: bool,

    /// Emulation step-by-step: after each instruction, print state and wait for Enter before continuing.
    #[arg(long = "emulate-interactive")]
    emulate_interactive: bool,
}
