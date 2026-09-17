#!/usr/bin/env python3
"""Merge general.yml + mastg/* into rules/semgrep/android/all.yml (and droid2web copy)."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERAL = ROOT / "rules/semgrep/android/general.yml"
MASTG = ROOT / "rules/semgrep/android/mastg"
OUT_DEX = ROOT / "rules/semgrep/android/all.yml"
OUT_WEB = ROOT.parent / "droid2web/web/rules/semgrep-all.yml"


def extract_rules_block(text: str) -> str:
    lines = text.splitlines(True)
    for i, line in enumerate(lines):
        if re.match(r"^rules:\s*$", line):
            return "".join(lines[i + 1 :])
    return text


def main() -> int:
    parts = [extract_rules_block(GENERAL.read_text())]
    for p in sorted(MASTG.glob("*")):
        if p.suffix not in (".yml", ".yaml"):
            continue
        parts.append(f"\n  # --- from {p.name} ---\n")
        parts.append(extract_rules_block(p.read_text()))

    header = (
        "# All Android Semgrep rules for droid2web / dex-decompiler (WASM-safe single file).\n"
        "# Combines general.yml (MobHunt-style) + OWASP MASTG Android rules.\n"
        "# Regenerate: python3 scripts/merge_semgrep_rules.py\n"
        "#\n"
    )
    out = header + "rules:\n" + "".join(parts)
    ids = re.findall(r"^\s+- id:\s*(\S+)", out, re.M)
    if len(ids) != len(set(ids)):
        print("error: duplicate rule ids", file=sys.stderr)
        return 1
    OUT_DEX.write_text(out)
    print(f"wrote {OUT_DEX} ({len(ids)} rules)")
    if OUT_WEB.parent.is_dir():
        OUT_WEB.write_text(out)
        print(f"wrote {OUT_WEB}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
