//! CLI: DEX to Java decompiler.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;
use dex_decompiler::{parse_dex, Decompiler, DecompilerOptions};
use indicatif::{ProgressBar, ProgressStyle};

fn main() -> Result<()> {
    let args = Args::parse();
    let data = fs::read(&args.input).with_context(|| format!("read {}", args.input))?;
    let dex = parse_dex(&data).context("parse DEX")?;
    let options = DecompilerOptions {
        only_package: args.only_package,
        exclude: args.exclude.clone(),
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
    /// Input DEX file path
    #[arg(short, long)]
    input: String,

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
}
