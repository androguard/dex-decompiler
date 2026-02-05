# dex-decompiler

<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">DEX-DECOMPILER</h2>

A **DEX to Java decompiler** in pure Rust. It parses DEX files, disassembles Dalvik bytecode, and emits Java-like source with structured control flow.

## Features

- **Pure Rust**: No JVM or external tools.
- **DEX parsing**: Full parsing of DEX format (header, string_ids, type_ids, proto_ids, field_ids, method_ids, class_defs, class_data_item, code_item) via [dex-parser](https://github.com/androguard/dex-parser/tree/main/dexparser-rs).
- **Disassembly**: Uses [dex-bytecode](https://github.com/androguard/dex-bytecode) for linear-sweep Dalvik instruction decoding and CFG (basic blocks).
- **Structured control flow**: if/else, `while (!cond)` and `while (true)` with break, **packed-switch / sparse-switch** → `switch (var) { case … default: … }`, break/continue where applicable.
- **SSA-style IR**: Versioned vars, type inference (params, return, propagation), invoke simplification (invoke + move-result + return → single return), dead-assign pass with method-wide used regs.
- **Java emission**: Class and method signatures, field declarations, method bodies as Java-like source; optional raw DEX instruction listing as comments before each method.
- **Library API**: Parse DEX, decompile classes/methods, and get **per-method bytecode and CFG** (nodes/edges) for visualization or tooling.

## Dependencies

- [dex-bytecode](https://github.com/androguard/dex-bytecode) – Dalvik disassembly and CFG (basic blocks, switch expansion).
- [dex-parser](https://github.com/androguard/dex-parser/tree/main/dexparser-rs) – DEX file parsing.

Both are pulled from GitHub in `Cargo.toml`; no local paths required.

## Build

```bash
cargo build --release
```

## Usage

### CLI

```bash
# Decompile a DEX file to stdout
cargo run --bin dex-decompile -- -i classes.dex

# Decompile to a single Java file
cargo run --bin dex-decompile -- -i classes.dex -o Main.java

# Decompile to a directory with package structure (e.g. out/com/example/MyClass.java)
cargo run --bin dex-decompile -- -i classes.dex -d out

# Only decompile classes in a package (and subpackages)
cargo run --bin dex-decompile -- -i classes.dex -d out --only-package com.example

# Exclude packages (may be repeated; supports trailing . or .*)
cargo run --bin dex-decompile -- -i classes.dex -d out --exclude android. --exclude kotlin.
```

| Option | Short | Description |
|--------|--------|-------------|
| `--input` | `-i` | Input DEX file path (required). |
| `--output` | `-o` | Output Java file (single file); default: stdout. |
| `--output-dir` | `-d` | Output directory: one `.java` per class under package structure. |
| `--only-package` | | Only decompile classes in this package (e.g. `com.example`). Subpackages included. |
| `--exclude` | | Exclude classes in this package (e.g. `android.`). Repeatable. |

When `--output-dir` is set, progress is shown per class. When both `-o` and `-d` are omitted, decompiled Java is printed to stdout.

### Library

```rust
use dex_decompiler::{parse_dex, Decompiler, DecompilerOptions, CfgEdgeInfo, CfgNodeInfo, MethodBytecodeRow};

let data = std::fs::read("classes.dex")?;
let dex = parse_dex(&data)?;

// Decompile entire DEX or with filters
let options = DecompilerOptions {
    only_package: Some("com.example".into()),
    exclude: vec!["android.".into()],
};
let decompiler = Decompiler::with_options(&dex, options);
let java = decompiler.decompile()?;

// Per-method bytecode and CFG (for graphs, web UI, etc.)
let encoded = /* EncodedMethod from class_data */;
let (rows, nodes, edges) = decompiler.get_method_bytecode_and_cfg(encoded)?;
// rows: Vec<MethodBytecodeRow> { offset, mnemonic, operands }
// nodes: Vec<CfgNodeInfo> { id, start_offset, end_offset, label }
// edges: Vec<CfgEdgeInfo> { from_id, to_id }
```

### Python bindings

A [PyO3](https://pyo3.rs/) / [maturin](https://www.maturin.rs/) crate in **`dex-decompiler-py/`** exposes the decompiler to Python:

```bash
cd dex-decompiler-py && maturin build --release && pip install target/wheels/dex_decompiler-*.whl
```

```python
import dex_decompiler

dex = dex_decompiler.parse_dex(open("classes.dex", "rb").read())
java_src = dex.decompile()
dex.decompile_to_dir("out/")
method_java = dex.decompile_method("com.example.MainActivity", "onCreate")
bytecode_rows, cfg_nodes, cfg_edges = dex.get_method_bytecode_and_cfg("com.example.MainActivity", "onCreate")
```

See [dex-decompiler-py/README.md](dex-decompiler-py/README.md) for full API and installation options.

## Tests

Tests mirror [androguard decompiler tests](https://github.com/androguard/androguard/tree/master/tests):

- **Graph / RPO**: `src/decompile/graph.rs` – immediate dominators and reverse post-order (Tarjan, Cross, LinearVit, etc.).
- **Dataflow**: `tests/decompiler/dataflow.rs` – reach-def, def-use, group_variables (GCD, IfBool).
- **Control flow**: `tests/decompiler/control_flow.rs` – return, if/else, while, loop exit.
- **Equivalence**: `tests/decompiler/equivalence.rs` – parse-fail, minimal DEX, try/catch comment, switch packed cases. Optional tests for simplification and arrays run only if androguard test data exists under `tests/data/APK/` (Test.dex, FillArrays.dex).

```bash
cargo test
cargo test -- --ignored   # with fixture DEXs
```

## References

- [Android DEX format](https://source.android.com/docs/core/runtime/dex-format)
- [Dalvik bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode)
- [androguard decompiler](https://github.com/androguard/androguard/tree/master/androguard/decompiler)
- [jadx](https://github.com/skylot/jadx/tree/master/jadx-core/src/main/java/jadx)

## License

Same as the repository (see [LICENSE](LICENSE)).
