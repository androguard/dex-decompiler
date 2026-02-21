//! CLI: DEX to Java decompiler.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;
use dex_decompiler::{
    parse_dex, scan_pending_intents, Decompiler, DecompilerOptions, DexFile, EncodedMethod,
};
use indicatif::{ProgressBar, ProgressStyle};

/// Parse offset as decimal or 0x-prefixed hex.
fn parse_offset(s: &str) -> Result<u32, std::num::ParseIntError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex.trim(), 16)
    } else {
        s.parse::<u32>()
    }
}

/// Find the first EncodedMethod in the DEX for the given class and method name.
fn find_method(dex: &DexFile, class_name: &str, method_name: &str) -> Option<EncodedMethod> {
    for class_def_result in dex.class_defs() {
        let class_def = class_def_result.ok()?;
        let class_type = dex.get_type(class_def.class_idx).ok()?;
        let name = dex_decompiler::java::descriptor_to_java(&class_type);
        if name != class_name {
            continue;
        }
        let class_data_opt = dex.get_class_data(&class_def).ok()?;
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
    }
    None
}

fn main() -> Result<()> {
    let args = Args::parse();

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

    // Decompile: use first DEX file (multi-DEX is supported for taint mode above).
    let path = &args.input[0];
    let data = fs::read(path).with_context(|| format!("read {}", path))?;
    let dex = parse_dex(&data).context("parse DEX")?;
    let options = DecompilerOptions {
        only_package: args.only_package,
        exclude: args.exclude.clone(),
        show_bytecode: args.show_bytecode,
    };
    let decompiler = Decompiler::with_options(&dex, options);

    if let Some(ref out_dir) = args.output_dir {
        let path = Path::new(out_dir);
        let pb = ProgressBar::new(0);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{bar:40.cyan/blue}] {pos}/{len} {msg}")?
                .progress_chars("=>-"),
        );
        pb.set_message("starting…");
        decompiler
            .decompile_to_dir_with_progress(path, Some(&mut |current, total, class_name| {
                pb.set_length(total as u64);
                pb.set_position(current as u64);
                pb.set_message(class_name.to_string());
            }))
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        pb.finish_with_message("done");
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
}
