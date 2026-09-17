# dex-decompiler Python bindings

Python bindings for [dex-decompiler](https://github.com/androguard/dex-decompiler) (DEX to Java decompiler in pure Rust), built with [PyO3](https://pyo3.rs/) and [maturin](https://www.maturin.rs/).

## Requirements

- Python 3.8+
- Rust (for building from source)
- [maturin](https://www.maturin.rs/) (`pip install maturin`)

## Installation

From the repo root (parent of `dex-decompiler-py`):

```bash
cd dex-decompiler-py
maturin build --release
pip install target/wheels/dex_decompiler-*.whl
```

Or install in development mode:

```bash
maturin develop --release
```

If you use Python 3.14 and PyO3 does not support it yet, you can try building with the stable ABI:

```bash
PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 maturin build --release
```

## Example

A runnable example is in **`examples/decompile_example.py`**. After installing the package:

```bash
# From dex-decompiler-py (or use path to any DEX file)
maturin develop --release
python examples/decompile_example.py -i ../testdata/classes.dex --list-classes
python examples/decompile_example.py -i ../testdata/classes.dex -o out.java
python examples/decompile_example.py -i ../testdata/classes.dex -d out/
python examples/decompile_example.py -i ../testdata/classes.dex --method "androguard.test.MainActivity#onCreate"
python examples/decompile_example.py -i ../testdata/classes.dex --cfg "androguard.test.MainActivity#onCreate"
python examples/decompile_example.py -i ../testdata/decompiler_fixtures/classes.dex \
  --getclass com.androguard.decompilefixtures.ConstFixtures
python examples/decompile_example.py -i ../testdata/androguard_test_classes.dex \
  --findrefs string --findrefs-value Test
```

Options: `-o` single file, `-d` directory (package layout), `--only-package`, `--exclude`, `--list-classes`, `--list-strings`, `--method CLASS#METHOD`, `--cfg CLASS#METHOD`, `--getclass CLASS`, `--findrefs {string,type,method,field}` + `--findrefs-value`, optional `--findrefs-class` / `--findrefs-fuzzy-class`.

## Usage

```python
import dex_decompiler

# Parse a DEX file (bytes)
with open("classes.dex", "rb") as f:
    data = f.read()
dex = dex_decompiler.parse_dex(data)

# Decompile entire DEX to Java source
java_src = dex.decompile()

# Decompile with filters
java_src = dex.decompile_with_options(
    only_package="com.example",
    exclude=["android.", "kotlin."],
)

# Decompile to a directory (package layout)
dex.decompile_to_dir("out/")

# List strings and class names
strings = dex.strings()
class_names = dex.class_names()

# Decompile a single method
method_java = dex.decompile_method("com.example.MainActivity", "onCreate")

# Get bytecode listing and CFG for a method
bytecode_rows, cfg_nodes, cfg_edges = dex.get_method_bytecode_and_cfg(
    "com.example.MainActivity", "onCreate"
)
# bytecode_rows: list of dicts with "offset", "mnemonic", "operands"
# cfg_nodes: list of dicts with "id", "start_offset", "end_offset", "label"
# cfg_edges: list of dicts with "from_id", "to_id"

# ASC fast path: findrefs / getclass (DEX or APK bytes)
sites = dex_decompiler.findrefs(data, "string", "token")
sites = dex_decompiler.findrefs(
    data, "method", "onCreate", class_name="com.example.Main", fuzzy_class=False
)
java = dex_decompiler.getclass(data, "com.example.Main")
minimal_dex = dex_decompiler.slice_class(data, "com.example.Main")

# Same APIs on a parsed DexFile
sites = dex.find_string_xrefs("token")
sites = dex.find_method_xrefs(class_name="com.example.Main", method_name="onCreate")
callers = dex.find_method_callers_fast(method_idx=42)
```

## API

- **`parse_dex(data: bytes) -> DexFile`** — Parse raw DEX bytes and return a `DexFile` wrapper. Raises `ValueError` on parse error.
- **`getclass(data: bytes, class_name: str) -> str`** — Locate class in DEX/APK, slice a minimal DEX, decompile only it (ASC getclass).
- **`slice_class(data: bytes, class_name: str) -> bytes`** — Same early-exit path, returns the sliced DEX bytes.
- **`findrefs(data, kind, value, class_name=None, fuzzy_class=False) -> list[dict]`** — ASC findrefs over DEX/APK. `kind` is `string` \| `type` \| `method` \| `field`.
- **`to_dalvik(class_name: str) -> str`** — Normalize Java/Dalvik class names to `L…;` descriptors.

- **`DexFile`**
  - **`decompile() -> str`** — Decompile entire DEX to a single Java source string.
  - **`decompile_with_options(only_package=None, exclude=None) -> str`** — Same as `decompile()` with optional package filter and exclude list.
  - **`decompile_to_dir(base_path: str)`** — Decompile into a directory with package structure (e.g. `out/com/example/MyClass.java`).
  - **`strings() -> list[str]`** — Return string pool (by index order).
  - **`class_names() -> list[str]`** — Return Java class names (e.g. `com.example.MainActivity`).
  - **`decompile_method(class_name: str, method_name: str) -> str`** — Decompile one method. Raises `ValueError` if not found.
  - **`get_method_bytecode_and_cfg(class_name: str, method_name: str) -> (list, list, list)`** — Bytecode rows and CFG (nodes, edges) for a method. Raises `ValueError` if not found.
  - **`find_string_xrefs(needle) -> list[dict]`** / **`find_type_xrefs(needle)`** — ASC string/type reference sites.
  - **`find_method_xrefs(class_name=None, method_name=None, exact_class=True)`** / **`find_field_xrefs(...)`** — ASC member reference sites.
  - **`find_method_callers(method_idx)`** / **`find_method_callers_fast(method_idx)`** — Caller lookup (slow vs ASC fast).
  - **`getclass(class_name)`** / **`slice_class(class_name)`** — Single-class slice + decompile on this DEX.
  - **`scan_vulns()`** / **`taint_solve(...)`** / **`export_json(...)`** / **`emulate(...)`** — Analysis helpers.

## License

Apache-2.0 (same as dex-decompiler).
