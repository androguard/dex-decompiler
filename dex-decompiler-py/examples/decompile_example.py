#!/usr/bin/env python3
"""Example: use dex_decompiler to parse a DEX file and decompile to Java."""

import argparse
import sys
from pathlib import Path

try:
    import dex_decompiler
except ImportError:
    print("dex_decompiler not installed. From dex-decompiler-py run:")
    print("  maturin develop --release")
    print("  python examples/decompile_example.py -i path/to/classes.dex")
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Decompile a DEX file using dex_decompiler")
    parser.add_argument("-i", "--input", required=True, help="Input DEX file path")
    parser.add_argument("-o", "--output", help="Output Java file (single file)")
    parser.add_argument("-d", "--output-dir", help="Output directory (package layout)")
    parser.add_argument("--only-package", help="Only decompile this package (e.g. com.example)")
    parser.add_argument("--exclude", action="append", default=[], help="Exclude package (repeatable)")
    parser.add_argument("--list-classes", action="store_true", help="List class names and exit")
    parser.add_argument("--list-strings", action="store_true", help="List first N strings and exit")
    parser.add_argument("--method", help="Decompile single method: CLASS#METHOD (e.g. com.example.Main#onCreate)")
    parser.add_argument("--cfg", help="Show bytecode + CFG for method: CLASS#METHOD")
    args = parser.parse_args()

    path = Path(args.input)
    if not path.is_file():
        print(f"Error: not a file: {path}", file=sys.stderr)
        sys.exit(1)

    data = path.read_bytes()
    try:
        dex = dex_decompiler.parse_dex(data)
    except ValueError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.list_classes:
        for name in dex.class_names():
            print(name)
        return

    if args.list_strings:
        for i, s in enumerate(dex.strings()[:50]):
            print(f"{i}: {s!r}")
        print("...")
        return

    if args.method:
        part = args.method.split("#", 1)
        if len(part) != 2:
            print("--method must be CLASS#METHOD", file=sys.stderr)
            sys.exit(1)
        class_name, method_name = part[0].strip(), part[1].strip()
        try:
            java = dex.decompile_method(class_name, method_name)
            print(java)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if args.cfg:
        part = args.cfg.split("#", 1)
        if len(part) != 2:
            print("--cfg must be CLASS#METHOD", file=sys.stderr)
            sys.exit(1)
        class_name, method_name = part[0].strip(), part[1].strip()
        try:
            rows, nodes, edges = dex.get_method_bytecode_and_cfg(class_name, method_name)
            print(f"# Bytecode ({len(rows)} instructions)")
            for r in rows:
                print(f"  {r['offset']:04x}: {r['mnemonic']} {r['operands']}")
            print(f"\n# CFG nodes: {len(nodes)}, edges: {len(edges)}")
            for n in nodes:
                print(f"  node {n['id']}: {n['start_offset']:04x}-{n['end_offset']:04x} {n['label'][:60]!r}")
            for e in edges:
                print(f"  edge {e['from_id']} -> {e['to_id']}")
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Full or filtered decompile
    if args.only_package or args.exclude:
        java_src = dex.decompile_with_options(
            only_package=args.only_package,
            exclude=args.exclude or None,
        )
    else:
        java_src = dex.decompile()

    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        dex.decompile_to_dir(str(out_dir))
        print(f"Decompiled to directory: {out_dir}", file=sys.stderr)
    elif args.output:
        Path(args.output).write_text(java_src, encoding="utf-8")
        print(f"Wrote: {args.output}", file=sys.stderr)
    else:
        print(java_src)


if __name__ == "__main__":
    main()
