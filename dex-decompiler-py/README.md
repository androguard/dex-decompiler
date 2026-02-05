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
```

Options: `-o` single file, `-d` directory (package layout), `--only-package`, `--exclude`, `--list-classes`, `--list-strings`, `--method CLASS#METHOD`, `--cfg CLASS#METHOD`.

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
```

## API

- **`parse_dex(data: bytes) -> DexFile`** — Parse raw DEX bytes and return a `DexFile` wrapper. Raises `ValueError` on parse error.

- **`DexFile`**
  - **`decompile() -> str`** — Decompile entire DEX to a single Java source string.
  - **`decompile_with_options(only_package=None, exclude=None) -> str`** — Same as `decompile()` with optional package filter and exclude list.
  - **`decompile_to_dir(base_path: str)`** — Decompile into a directory with package structure (e.g. `out/com/example/MyClass.java`).
  - **`strings() -> list[str]`** — Return string pool (by index order).
  - **`class_names() -> list[str]`** — Return Java class names (e.g. `com.example.MainActivity`).
  - **`decompile_method(class_name: str, method_name: str) -> str`** — Decompile one method. Raises `ValueError` if not found.
  - **`get_method_bytecode_and_cfg(class_name: str, method_name: str) -> (list, list, list)`** — Bytecode rows and CFG (nodes, edges) for a method. Raises `ValueError` if not found.

## License

Apache-2.0 (same as dex-decompiler).
