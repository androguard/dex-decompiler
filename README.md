# dex-decompiler

<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">DEX-DECOMPILER</h2>

A **DEX → Java** decompiler in pure Rust. Decompile DEX/APK files, pull a single class fast, search cross-refs, and scan for common Android issues — no JVM required.

## Install

```bash
cargo build --release --bin dex-decompile
# binary: target/release/dex-decompile
```

Always use `--release` for real APKs.

## Quick start

```bash
# Decompile an APK into a package tree
./target/release/dex-decompile -i app.apk -d out/

# Decompile a DEX to stdout
./target/release/dex-decompile -i classes.dex

# One class → one Java file
./target/release/dex-decompile -i classes.dex -o Main.java

# Only your package (skip android./kotlin./…)
./target/release/dex-decompile -i app.apk -d out/ \
  --only-package com.example --exclude android. --exclude kotlin.
```

## Fast lookups (ASC-style)

Locate one class or search references without a full decompile:

```bash
# Slice + decompile a single class from an APK
./target/release/dex-decompile -i app.apk --getclass com.example.Main -o Main.java

# Find string / type / method / field references
./target/release/dex-decompile -i app.apk \
  --findrefs string --findrefs-value token

./target/release/dex-decompile -i app.apk \
  --findrefs method --findrefs-value onCreate \
  --findrefs-class com.example.Main --fast-xref
```

## Security scans

```bash
# Built-in vulnerability detectors
./target/release/dex-decompile -i app.apk --scan-vulns

# Native Semgrep-style rules (general Android + OWASP MASTG)
./target/release/dex-decompile -i app.apk --scan-semgrep

# Global taint solver → JSON report
./target/release/dex-decompile -i app.apk \
  --taint-solve --taint-output issues.json
```

## Useful options

| Flag | What it does |
|------|----------------|
| `-i` / `--input` | DEX and/or APK path(s); repeatable for multi-DEX |
| `-d` / `--output-dir` | Write one `.java` per class under package dirs |
| `-o` / `--output` | Write a single Java file (or use stdout) |
| `--only-package` | Limit to a package (and subpackages) |
| `--exclude` | Skip a package prefix (repeatable) |
| `--deobf` | Rename short / invalid identifiers |
| `--show-bytecode` | Comment raw Dalvik before each method |
| `--getclass` | Fast single-class decompile |
| `--findrefs` | Fast cross-refs (`string` \| `type` \| `method` \| `field`) |
| `--scan-vulns` / `--scan-semgrep` / `--taint-solve` | Analysis modes (no full tree emit) |

```bash
./target/release/dex-decompile -i app.apk -d out/ --deobf --show-bytecode
./target/release/dex-decompile -i app.apk -d out/ -m fallback   # restructure|simple|fallback
```

## Python

```bash
cd dex-decompiler-py
python3 -m venv .venv && source .venv/bin/activate
pip install maturin && maturin develop --release
```

### Decompile

```python
import dex_decompiler

with open("classes.dex", "rb") as f:
    dex = dex_decompiler.parse_dex(f.read())

# Whole DEX → one Java string
print(dex.decompile())

# Filters (same idea as --only-package / --exclude)
print(dex.decompile_with_options(
    only_package="com.example",
    exclude=["android.", "kotlin."],
))

# Package tree on disk (like -d out/)
dex.decompile_to_dir("out/")

# One method
print(dex.decompile_method("com.example.MainActivity", "onCreate"))

# Inspect
for name in dex.class_names():
    print(name)
```

### Bytecode + CFG

```python
rows, nodes, edges = dex.get_method_bytecode_and_cfg(
    "com.example.MainActivity", "onCreate"
)
for row in rows[:5]:
    print(hex(row["offset"]), row["mnemonic"], row["operands"])
```

### ASC fast path (DEX or APK bytes)

Module-level helpers work on raw DEX **or** APK bytes — no full parse required for a single class:

```python
apk = open("app.apk", "rb").read()

# Single-class decompile (like --getclass)
print(dex_decompiler.getclass(apk, "com.example.Main"))

# Minimal DEX slice only
minimal = dex_decompiler.slice_class(apk, "com.example.Main")

# Cross-refs (like --findrefs)
for site in dex_decompiler.findrefs(apk, "string", "token"):
    print(site["class_name"], site["method_name"], hex(site["file_offset"]))

for site in dex_decompiler.findrefs(
    apk, "method", "onCreate",
    class_name="com.example.Main",
    fuzzy_class=False,
):
    print(site)
```

On an already-parsed DEX:

```python
print(dex.getclass("com.example.Main"))
for site in dex.find_string_xrefs("token"):
    print(site)
for site in dex.find_method_xrefs(
    class_name="com.example.Main", method_name="onCreate"
):
    print(site)
```

### Renames, scans, taint

```python
java = dex.decompile_with_renames(
    package_renames={"com.example": "com.myname"},
    class_renames={"com.example.Main": "com.myname.MainActivity"},
    method_renames={"com.example.Main#onCreate": "myOnCreate"},
    field_renames={"com.example.Main#count": "mCount"},
    variable_renames={"com.example.Main#onCreate": {"p0": "context"}},
)

for finding in dex.scan_vulns():
    print(finding)

report = dex.taint_solve()  # optional config kwargs; returns issue report
```

Runnable CLI-style example: `python dex-decompiler-py/examples/decompile_example.py -i app.apk -d out/`. Full API: [dex-decompiler-py/README.md](dex-decompiler-py/README.md).

## Library (Rust)

```rust
use dex_decompiler::{parse_dex, Decompiler, DecompilerOptions};

let dex = parse_dex(&std::fs::read("classes.dex")?)?;
let java = Decompiler::with_options(
    &dex,
    DecompilerOptions {
        only_package: Some("com.example".into()),
        ..Default::default()
    },
)
.decompile()?;
```

## Benchmark vs Droid ASC

Compare our CLI, Python bindings, and upstream [droidasc](https://github.com/MG1937/ASC):

```bash
cargo build --release --bin dex-decompile
python3 scripts/bench_asc_compare.py --install-asc --install-py
```

## Dependencies

- [dex-parser](https://github.com/androguard/dex-parser) — DEX parse, fastref, `DexSlicer`
- [dex-bytecode](https://github.com/androguard/dex-bytecode) — Dalvik decode + CFG
- [apk-parser](https://github.com/androguard/apk-parser) — lazy ZIP / DEX entry probe

## How the decompiler works

```
  ┌─────────────┐
  │  DEX bytes  │
  └──────┬──────┘
         │
         v  dex-parser
  ┌─────────────┐     ┌──────────────────┐
  │  DexFile    │────>│ header, strings, │
  │  (in-memory)│     │ types, methods,   │
  │             │     │ class_defs, code  │
  └──────┬──────┘     └──────────────────┘
         │
         v  dex-bytecode (decode_all)
  ┌─────────────┐
  │ Instruction │   Raw Dalvik: const/4, move, if-eqz, invoke-virtual, ...
  │   stream    │
  └──────┬──────┘
         │
         v  basic_blocks + CFG (MethodCfg)
  ┌─────────────┐     ┌─────────────────────────────────────────┐
  │  CFG       │────>│ Blocks, edges, loop headers,              │
  │  (per meth)│     │ instruction_offsets per block            │
  └──────┬──────┘     └─────────────────────────────────────────┘
         │
         v  instructions_to_ir (per block)
  ┌─────────────┐     ┌─────────────────────────────────────────┐
  │  IR        │────>│ Assign { dst, rhs }, Expr, Return, Raw    │
  │  (IrStmt)  │     │ VarId(reg, ver), Call, PendingResult       │
  └──────┬──────┘     └─────────────────────────────────────────┘
         │
         v  PassRunner (InvokeChain, SsaRename, DeadAssign)
  ┌─────────────┐     invoke+move-result+return → Return(Call)
  │  IR (clean) │     dead stores removed (with method-wide used regs)
  └──────┬──────┘
         │
         v  build_regions (if/else, while, switch)
  ┌─────────────┐     ┌─────────────────────────────────────────┐
  │  Region     │────>│ Tree: Block, If(cond,then,else),          │
  │  tree       │     │ Loop(header, body), Switch(cases, default)│
  └──────┬──────┘     └─────────────────────────────────────────┘
         │
         v  emit_region + codegen_ir_lines
  ┌─────────────┐
  │  Java-like  │     Class/method signatures, fields, bodies
  │  source     │     (type inference + var names from IR)
  └─────────────┘
```

**Value flow / tainting** (optional): from the same CFG and a per-instruction read/write map, reaching definitions and def-use/use-def are computed. Given a seed `(offset, reg)`, `value_flow_from_seed` returns all program points that **read** or **write** that value—including when the value is **returned**, **passed to a function** (invoke arg), or copied through moves. **API-source tainting**: `value_flow_from_api_sources(patterns)` treats every `move-result` that receives the return of a matching `invoke` (e.g. `FusedLocationProviderClient.getLastLocation()`) as a seed. **Multi-DEX**: the CLI accepts multiple `-i` inputs; taint mode searches for `CLASS#METHOD` in each DEX in order.

## Features

- **Pure Rust**: No JVM or external tools.
- **DEX parsing**: Full parsing of DEX format (header, string_ids, type_ids, proto_ids, field_ids, method_ids, class_defs, class_data_item, code_item) via [dex-parser](https://github.com/androguard/dex-parser/tree/main/dexparser-rs).
- **Disassembly**: Uses [dex-bytecode](https://github.com/androguard/dex-bytecode) for linear-sweep Dalvik instruction decoding and CFG (basic blocks).
- **Structured control flow**: if/else, `while (!cond)` and `while (true)` with break/continue, **for loops** (init; cond; update), **packed-switch / sparse-switch** → `switch (var) { case … default: … }`.
- **SSA-style IR**: Versioned vars, type inference (params, return, propagation), dead-assign pass with method-wide used regs.
- **Java emission**: Class and method signatures, field declarations, method bodies as Java-like source; optional raw DEX instruction listing as comments before each method.
- **Imports**: Per-class import block; short names in body (e.g. `java.lang.String` → `String`).
- **Try/catch**: From DEX try_item and encoded_catch_handler; body wrapped in `try { … } catch (Type e) { … }` with type names.
- **Enum**: Class extends `java.lang.Enum` and has static final fields of its own type → emitted as `enum Name { A, B, C; … }` (constants first, then `;`, then other members).
- **Annotations**: Class annotations from annotations_directory_item → `@Name` before the class.
- **Constructors**: Emitted as `ClassName(params)` (not `void <init>()`); parameterless `<init>()` in body → `super();`.
- **Anonymous Thread inlining**: Pattern `X.<init>(args);` + `X.start();` → inlined `new Thread() { public void run() { … } }.start();` with inner `run()` body and capture replacement (e.g. `val$o` → outer variable); **synchronized** blocks from monitor-enter/exit; unreachable exception-handler lines after `return;` stripped.
- **Library API**: Parse DEX, decompile classes/methods, **find_method**, get **per-method bytecode and CFG** (nodes/edges) for visualization or tooling.
- **Value flow / tainting**: Reaching definitions, def-use/use-def, propagation from seed or from API sources (e.g. `getLastLocation`).
- **Vulnerability detectors**: PendingIntent scan (`--scan-pending-intent`), full scan (`--scan-vulns`: intent spoofing, RCE, insecure logging, SQL injection, WebView, hardcoded-secrets, IPC), **native Semgrep** (`--scan-semgrep`: general Android rules + [OWASP MASTG](https://github.com/OWASP/mastg/tree/master/rules) via SSA/value-flow + Java/XML patterns).
- **Global taint solver (Mariana Trench–style)**: JSON models (sources / sinks / propagations / sanitizers), rules by kind, call-graph + interprocedural fixpoint, traces, JSON issue report (`--taint-solve`). Includes a port of MT’s **74 end-to-end cases** under `tests/data/mariana_trench/` (`cargo test --test mariana_trench_e2e`).
- **Progress**: With `--output-dir`, progress bar shows current class being decompiled.
- **ASC fast path**: On-demand `findrefs` / `getclass` without full APK inflate or a global xref index (see [Acknowledgments](#acknowledgments--asc-fast-path)).

## Simplifications

Method bodies and IR are simplified so output looks like idiomatic Java.

### IR passes (before emission)

- **InvokeChainPass**: `invoke(...); vN = <result>; return vN;` → `return method(args);`; `invoke(...); vN = <result>;` → `vN = method(args);`; `invoke(...); return;` left as call + return.
- **ConstructorMergePass**: `vN = new Foo();` + `vN.<init>(args);` → `vN = new Foo(args);` (when in same block).
- **SsaRenamePass**: SSA-style versioned variables.
- **DeadAssignPass**: Removes dead stores (with method-wide used regs).
- **ExprSimplifyPass**: `v0 = v0 + 1` → `v0++`, `v0 = v0 + x` → `v0 += x`; removes redundant self-assigns.

### Method-body simplifications (after emission)

- **Invoke + move-result + return**: `invoke(...); vN = <result>; return vN;` → `return method(args);`.
- **Invoke + move-result**: `invoke(...); vN = <result>;` → `vN = method(args);`.
- **Invoke + return void**: `invoke(...); return;` → `method(args); return;`.
- **Ternary**: `if (cond) { return a; } else { return b; }` → `return cond ? a : b;`.
- **String concatenation**: `new StringBuilder(); sb.append(a); sb.append(b); s = sb.toString();` → `s = a + b;` (and `return sb.toString();` → `return a + b;`).
- **Arithmetic**: `x + -N` → `x - N`.
- **Constructors**: In constructor bodies only, `receiver.<init>();` (no args) → `super();`.
- **Synchronized**: `try { /* monitor-enter(lock) */ … /* monitor-exit */ } catch (Throwable …)` → `synchronized (lock) { … }` (run after try/catch wrapping).
- **Unreachable code**: Lines after `return;` with greater indent are skipped until `}` or `} catch`.
- **Unreachable exception junk** (in inlined Thread run): After `return;`, lines containing `/* move-exception */`, `/* monitor-exit(...) */`, or `throw …;` are removed.

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Acknowledgments / ASC fast path

The on-demand search and single-class slice paths (`--findrefs`, `--getclass`, and the matching library/WASM/Python APIs) adapt algorithms from **Droid ASC**, presented at **Black Hat Europe 2026 Arsenal**:

> WeiMin Cheng (MG1937), Zhihan Lin (0chencc).  
> *Droid ASC: R8 Compiler Optimization as a DeCompiler Primitive.*  
> Black Hat Europe 2026 Arsenal.  
> Tool / source: <https://github.com/MG1937/ASC>

**Design thesis (ASC):** a compiled DEX is already an index, so building another global cross-reference database is wasted work. Query the artifact on demand.

Algorithms used here (Rust ports across `apk-parser`, `dex-parser`, and this crate; see `docs/ASC_FASTPATH_PLAN.md`):

| Algorithm | Role |
|-----------|------|
| **Central-directory DEX probe** | Locate root `classes*.dex` entries by scanning the ZIP CD for `classes` (`memmem`) with a namelist fallback, instead of eagerly listing/inflating the whole archive. |
| **Smallest-first lazy inflate + early exit** | Inflate candidate DEX entries ordered by ascending compressed size; stop as soon as `dex_defines_class` hits (`--getclass`). |
| **DEX 041 logical containers** | Split multi-DEX containers (`dex\n041`) and normalize headers the way ASC names `classes.dex!classesN.dex`. |
| **String locator (contiguity + MUTF-8)** | Resolve string queries via sorted/contiguous `string_data` layout (with full fallback) after encoding the needle as MUTF-8. |
| **Type / method / field locators** | Map queries to pool indices using type→string maps and class/name member indexes (`MemberQuery`, exact or fuzzy class). |
| **Raw `code_item` reference scan** | Find `(opcode, pool_idx)` sites by scanning code bytes (opcode masks / `memchr` for single-op), not by full instruction decode. |
| **O(1) instruction→method locator** | 16-byte bucket table + payload-aware boundary walk with a per-method resume cursor (`InsnLocator`), including R8 shared-code `Owner::Many`. |
| **Minimal in-memory DEX reconstruction** | Harvest one class and its transitive pool deps, rewrite operands via `DexBuilder::pool_maps()`, emit a spec-valid slice (`DexSlicer`) for decompilation. |

We deliberately **do not** port ASC’s unimplemented partial-Deflate / Huffman bitstream probe, CPython regex/bigint scanners, or a second non-canonical DEX writer—canonical pools and checksums come from `dex-parser::DexBuilder`.
