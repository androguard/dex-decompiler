#!/usr/bin/env python3
"""Compare ASC fast-path: Rust CLI vs Python bindings vs upstream Droid ASC.

Upstream: https://github.com/MG1937/ASC
Paper/talk: Black Hat Europe 2026 Arsenal —
  "Droid ASC: R8 Compiler Optimization as a DeCompiler Primitive"

Tools measured (same getclass / findrefs workloads):
  1. dex-decompile — our Rust release binary
  2. dex_decompiler — our PyO3 Python bindings
  3. droidasc — upstream ASC CLI

Examples:
  python3 scripts/bench_asc_compare.py --install-asc

  python3 scripts/bench_asc_compare.py --install-asc \\
    --apk /path/to/app.apk \\
    --class com.example.Main \\
    --string token \\
    --runs 5 --json-out /tmp/asc_bench.json

  # Skip upstream ASC; still compare Rust CLI vs Python bindings
  python3 scripts/bench_asc_compare.py --skip-asc

  # Point at a specific Python that has dex_decompiler installed
  python3 scripts/bench_asc_compare.py --py-python dex-decompiler-py/.venv/bin/python
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_APK = ROOT / "testdata" / "bugbazaar" / "bugbazaar.apk"
DEFAULT_CLASS = "com.google.firebase.FirebaseApp"
DEFAULT_STRING = "Firebase"
DEFAULT_TYPE = "Lcom/google/firebase/FirebaseApp;"
DEFAULT_METHOD = "getInstance"
DEFAULT_METHOD_CLASS = "com.google.firebase.FirebaseApp"
DEFAULT_FIELD = "instances"
ASC_REPO_URL = "https://github.com/MG1937/ASC.git"
CACHE_DIR = ROOT / "scripts" / ".cache" / "asc_bench"
PY_VENV_CANDIDATES = [
    ROOT / "dex-decompiler-py" / ".venv" / "bin" / "python",
    ROOT / "dex-decompiler-py" / ".venv" / "Scripts" / "python.exe",
]


@dataclass
class Sample:
    wall_ms: float
    max_rss_kb: Optional[float]
    exit_code: int
    stdout_bytes: int
    stderr_bytes: int


@dataclass
class BenchResult:
    tool: str
    workload: str
    samples: list[Sample]

    @property
    def wall_ms_mean(self) -> float:
        return statistics.fmean(s.wall_ms for s in self.samples)

    @property
    def wall_ms_stdev(self) -> float:
        if len(self.samples) < 2:
            return 0.0
        return statistics.stdev(s.wall_ms for s in self.samples)

    @property
    def rss_kb_mean(self) -> Optional[float]:
        vals = [s.max_rss_kb for s in self.samples if s.max_rss_kb is not None]
        return statistics.fmean(vals) if vals else None


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def resolve_our_bin(explicit: Optional[str]) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            raise SystemExit(f"--dex-decompile not found: {p}")
        return p
    release = ROOT / "target" / "release" / "dex-decompile"
    debug = ROOT / "target" / "debug" / "dex-decompile"
    if release.is_file():
        return release
    if debug.is_file():
        eprint("warning: using debug dex-decompile; prefer --release for fair timing")
        return debug
    eprint("building release dex-decompile …")
    subprocess.check_call(
        ["cargo", "build", "--release", "--bin", "dex-decompile"],
        cwd=ROOT,
    )
    return release


def _python_has_dex_decompiler(py: Path) -> bool:
    try:
        r = subprocess.run(
            [str(py), "-c", "import dex_decompiler"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return r.returncode == 0
    except OSError:
        return False


def resolve_py_python(explicit: Optional[str], install: bool) -> Optional[Path]:
    """Return a Python interpreter that can `import dex_decompiler`, or None."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend(PY_VENV_CANDIDATES)
    candidates.append(Path(sys.executable))

    for c in candidates:
        if c.is_file() and _python_has_dex_decompiler(c):
            return c

    if not install:
        return None

    # Build/install bindings into dex-decompiler-py/.venv
    venv = ROOT / "dex-decompiler-py" / ".venv"
    py = venv / ("Scripts" if platform.system() == "Windows" else "bin") / "python"
    if not py.is_file():
        eprint(f"creating Python bindings venv at {venv}")
        subprocess.check_call([sys.executable, "-m", "venv", str(venv)])
        subprocess.check_call(
            [str(py), "-m", "pip", "install", "-q", "--upgrade", "pip", "maturin"]
        )
    eprint("maturin develop --release (dex-decompiler-py) …")
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env.setdefault("PYO3_USE_ABI3_FORWARD_COMPATIBILITY", "1")
    subprocess.check_call(
        [str(py), "-m", "maturin", "develop", "--release"],
        cwd=ROOT / "dex-decompiler-py",
        env=env,
    )
    if not _python_has_dex_decompiler(py):
        raise SystemExit("failed to install dex_decompiler Python bindings")
    return py


def ensure_asc(
    asc_bin: Optional[str],
    asc_repo: Optional[str],
    install: bool,
) -> list[str]:
    """Return argv prefix to invoke ASC CLI."""
    if asc_bin:
        p = Path(asc_bin)
        if p.is_file() or which(asc_bin):
            return [str(p) if p.is_file() else asc_bin]
        raise SystemExit(f"--asc-bin not found: {asc_bin}")

    if which("droidasc"):
        return ["droidasc"]

    repo = Path(asc_repo) if asc_repo else CACHE_DIR / "ASC"
    if not (repo / "main.py").is_file():
        if not install:
            raise SystemExit(
                "droidasc not on PATH and no ASC checkout found.\n"
                "Install with:  pip install droidasc\n"
                "Or re-run with:  --install-asc\n"
                "Or pass:         --asc-repo /path/to/ASC  /  --asc-bin droidasc"
            )
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        if repo.exists():
            shutil.rmtree(repo)
        eprint(f"cloning {ASC_REPO_URL} → {repo}")
        subprocess.check_call(
            ["git", "clone", "--depth", "1", ASC_REPO_URL, str(repo)]
        )

    venv = CACHE_DIR / "venv"
    py = venv / ("Scripts" if platform.system() == "Windows" else "bin") / "python"
    if not py.is_file():
        eprint(f"creating venv at {venv}")
        subprocess.check_call([sys.executable, "-m", "venv", str(venv)])
        subprocess.check_call(
            [str(py), "-m", "pip", "install", "-q", "--upgrade", "pip"]
        )
        eprint(f"pip install -e {repo}")
        subprocess.check_call([str(py), "-m", "pip", "install", "-q", "-e", str(repo)])

    droidasc = venv / ("Scripts" if platform.system() == "Windows" else "bin") / "droidasc"
    if droidasc.is_file():
        return [str(droidasc)]
    return [str(py), str(repo / "main.py")]


def time_argv() -> Optional[list[str]]:
    time_bin = which("gtime") or (
        "/usr/bin/time" if Path("/usr/bin/time").is_file() else which("time")
    )
    if not time_bin:
        return None
    system = platform.system()
    if system == "Darwin":
        return [time_bin, "-l"]
    return [time_bin, "-f", "MAXRSS_KB %M"]


def parse_rss_kb(stderr: str, system: str) -> Optional[float]:
    for line in stderr.splitlines():
        line = line.strip()
        if system == "Darwin" and "maximum resident set size" in line:
            parts = line.split()
            if parts:
                try:
                    return float(parts[0]) / 1024.0
                except ValueError:
                    pass
        if line.startswith("MAXRSS_KB "):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                pass
    return None


def run_once(cmd: Sequence[str], cwd: Optional[Path] = None) -> Sample:
    wrapper = time_argv()
    full = list(wrapper) + list(cmd) if wrapper else list(cmd)
    t0 = time.perf_counter()
    proc = subprocess.run(
        full,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    wall_ms = (time.perf_counter() - t0) * 1000.0
    stderr = proc.stderr.decode("utf-8", errors="replace")
    rss = parse_rss_kb(stderr, platform.system()) if wrapper else None
    return Sample(
        wall_ms=wall_ms,
        max_rss_kb=rss,
        exit_code=proc.returncode,
        stdout_bytes=len(proc.stdout),
        stderr_bytes=len(proc.stderr),
    )


def bench(
    tool: str,
    workload: str,
    cmd: Sequence[str],
    runs: int,
    warmup: int,
) -> BenchResult:
    eprint(f"  [{tool}] {workload}")
    eprint(f"    cmd: {' '.join(cmd)}")
    for _ in range(warmup):
        s = run_once(cmd)
        if s.exit_code != 0:
            eprint(f"    warmup failed exit={s.exit_code}")
    samples: list[Sample] = []
    for i in range(runs):
        s = run_once(cmd)
        samples.append(s)
        rss = f" rss={s.max_rss_kb:.0f}KiB" if s.max_rss_kb is not None else ""
        eprint(f"    run {i + 1}/{runs}: {s.wall_ms:8.1f} ms  exit={s.exit_code}{rss}")
        if s.exit_code != 0:
            eprint(f"    warning: non-zero exit for {tool}/{workload}")
    return BenchResult(tool=tool, workload=workload, samples=samples)


def our_cli_getclass(bin_path: Path, apk: Path, class_name: str, out: Path) -> list[str]:
    return [
        str(bin_path),
        "-i",
        str(apk),
        "--getclass",
        class_name,
        "-o",
        str(out),
    ]


def our_cli_findrefs(
    bin_path: Path,
    apk: Path,
    kind: str,
    value: str,
    class_name: Optional[str],
    fuzzy: bool,
) -> list[str]:
    cmd = [
        str(bin_path),
        "-i",
        str(apk),
        "--findrefs",
        kind,
        "--findrefs-value",
        value,
    ]
    if class_name:
        cmd += ["--findrefs-class", class_name]
    if fuzzy:
        cmd.append("--findrefs-fuzzy-class")
    return cmd


def py_driver_script(tmp: Path) -> Path:
    """Write a tiny driver that invokes dex_decompiler APIs from argv."""
    path = tmp / "py_asc_driver.py"
    path.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import argparse
            import sys
            from pathlib import Path

            import dex_decompiler


            def main() -> int:
                ap = argparse.ArgumentParser()
                ap.add_argument("apk")
                sub = ap.add_subparsers(dest="cmd", required=True)

                g = sub.add_parser("getclass")
                g.add_argument("class_name")
                g.add_argument("-o", "--output", required=True)

                f = sub.add_parser("findrefs")
                f.add_argument("kind", choices=["string", "type", "method", "field"])
                f.add_argument("value")
                f.add_argument("--class-name", default=None)
                f.add_argument("--fuzzy-class", action="store_true")

                args = ap.parse_args()
                data = Path(args.apk).read_bytes()

                if args.cmd == "getclass":
                    java = dex_decompiler.getclass(data, args.class_name)
                    Path(args.output).write_text(java, encoding="utf-8")
                    return 0

                sites = dex_decompiler.findrefs(
                    data,
                    args.kind,
                    args.value,
                    class_name=args.class_name,
                    fuzzy_class=args.fuzzy_class,
                )
                # Touch results so work isn't optimized away; print a short summary.
                print(f"{len(sites)} site(s)")
                for s in sites[:5]:
                    print(
                        f"  {s.get('class_name')}#{s.get('method_name')} "
                        f"@0x{s.get('file_offset', 0):x}"
                    )
                return 0


            if __name__ == "__main__":
                raise SystemExit(main())
            """
        )
    )
    return path


def py_getclass(
    py: Path, driver: Path, apk: Path, class_name: str, out: Path
) -> list[str]:
    return [
        str(py),
        str(driver),
        str(apk),
        "getclass",
        class_name,
        "-o",
        str(out),
    ]


def py_findrefs(
    py: Path,
    driver: Path,
    apk: Path,
    kind: str,
    value: str,
    class_name: Optional[str],
    fuzzy: bool,
) -> list[str]:
    cmd = [str(py), str(driver), str(apk), "findrefs", kind, value]
    if class_name:
        cmd += ["--class-name", class_name]
    if fuzzy:
        cmd.append("--fuzzy-class")
    return cmd


def asc_getclass(asc: list[str], apk: Path, class_name: str, out: Path) -> list[str]:
    return [*asc, "getclass", str(apk), class_name, "-o", str(out)]


def asc_findrefs(
    asc: list[str],
    apk: Path,
    kind: str,
    value: str,
    class_name: Optional[str],
    fuzzy: bool,
) -> list[str]:
    cmd = [*asc, "findrefs", str(apk), kind, value]
    if class_name:
        cmd += ["--class", class_name]
    if fuzzy:
        cmd.append("--fuzzy-class")
    return cmd


def fmt_ms(mean: float, stdev: float) -> str:
    if stdev > 0:
        return f"{mean:8.1f} ± {stdev:5.1f}"
    return f"{mean:8.1f}         "


def fmt_rss(r: Optional[BenchResult]) -> str:
    if r is None or r.rss_kb_mean is None:
        return "—"
    return f"{r.rss_kb_mean / 1024:.1f} MiB"


def print_table(results: list[BenchResult]) -> None:
    by_wl: dict[str, dict[str, BenchResult]] = {}
    for r in results:
        by_wl.setdefault(r.workload, {})[r.tool] = r

    tools_present = sorted({r.tool for r in results})
    # Preferred column order
    order = ["rust-cli", "rust-py", "droidasc"]
    cols = [t for t in order if t in tools_present] + [
        t for t in tools_present if t not in order
    ]

    print()
    header = f"{'workload':<22}"
    for t in cols:
        header += f" {t + ' (ms)':>18}"
    if "droidasc" in cols and "rust-cli" in cols:
        header += f" {'cli/ASC':>9}"
    if "droidasc" in cols and "rust-py" in cols:
        header += f" {'py/ASC':>9}"
    print(header)
    print("-" * len(header))

    for wl, tools in by_wl.items():
        row = f"{wl:<22}"
        for t in cols:
            r = tools.get(t)
            if r:
                row += f" {fmt_ms(r.wall_ms_mean, r.wall_ms_stdev):>18}"
            else:
                row += f" {'—':>18}"
        asc = tools.get("droidasc")
        if asc and "rust-cli" in cols:
            cli = tools.get("rust-cli")
            if cli and cli.wall_ms_mean > 0:
                row += f" {asc.wall_ms_mean / cli.wall_ms_mean:8.2f}x"
            else:
                row += f" {'—':>9}"
        if asc and "rust-py" in cols:
            py = tools.get("rust-py")
            if py and py.wall_ms_mean > 0:
                row += f" {asc.wall_ms_mean / py.wall_ms_mean:8.2f}x"
            else:
                row += f" {'—':>9}"
        print(row)

    print()
    print("RSS (mean max resident set):")
    rss_header = f"{'workload':<22}"
    for t in cols:
        rss_header += f" {t:>12}"
    print(rss_header)
    print("-" * len(rss_header))
    for wl, tools in by_wl.items():
        row = f"{wl:<22}"
        for t in cols:
            row += f" {fmt_rss(tools.get(t)):>12}"
        print(row)

    print()
    print(
        "cli/ASC and py/ASC = ASC_ms / ours_ms (>1 means we are faster). "
        "rust-cli = dex-decompile binary; rust-py = dex_decompiler Python bindings; "
        "droidasc = upstream ASC."
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--apk", type=Path, default=DEFAULT_APK)
    ap.add_argument("--class", dest="class_name", default=DEFAULT_CLASS)
    ap.add_argument("--string", dest="string_value", default=DEFAULT_STRING)
    ap.add_argument("--type", dest="type_value", default=DEFAULT_TYPE)
    ap.add_argument("--method", dest="method_value", default=DEFAULT_METHOD)
    ap.add_argument("--method-class", dest="method_class", default=DEFAULT_METHOD_CLASS)
    ap.add_argument("--field", dest="field_value", default=DEFAULT_FIELD)
    ap.add_argument("--field-class", dest="field_class", default=None)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--dex-decompile", default=None, help="Path to our release binary")
    ap.add_argument(
        "--py-python",
        default=None,
        help="Python interpreter with dex_decompiler installed",
    )
    ap.add_argument(
        "--install-py",
        action="store_true",
        help="maturin develop --release into dex-decompiler-py/.venv if missing",
    )
    ap.add_argument(
        "--skip-py",
        action="store_true",
        help="Do not bench Python bindings",
    )
    ap.add_argument("--asc-bin", default=None, help="droidasc binary or python entry")
    ap.add_argument("--asc-repo", default=None, help="Path to MG1937/ASC checkout")
    ap.add_argument(
        "--install-asc",
        action="store_true",
        help="Clone + pip install ASC into scripts/.cache if missing",
    )
    ap.add_argument(
        "--skip-asc",
        action="store_true",
        help="Do not bench upstream droidasc",
    )
    ap.add_argument(
        "--workloads",
        default="getclass,findrefs-string,findrefs-type,findrefs-method,findrefs-field",
        help="Comma-separated subset of workloads",
    )
    ap.add_argument("--json-out", type=Path, default=None)
    args = ap.parse_args()

    if not args.apk.is_file():
        raise SystemExit(f"APK not found: {args.apk}")

    our = resolve_our_bin(args.dex_decompile)

    py: Optional[Path] = None
    if not args.skip_py:
        py = resolve_py_python(args.py_python, args.install_py)
        if py is None:
            eprint(
                "warning: dex_decompiler Python bindings not found; "
                "skipping rust-py (use --install-py or --py-python)"
            )

    asc_cmd: Optional[list[str]] = None
    if not args.skip_asc:
        try:
            asc_cmd = ensure_asc(args.asc_bin, args.asc_repo, args.install_asc)
        except SystemExit as e:
            eprint(f"warning: {e}")
            eprint("continuing without droidasc")

    wanted = {w.strip() for w in args.workloads.split(",") if w.strip()}
    results: list[BenchResult] = []

    with tempfile.TemporaryDirectory(prefix="asc_bench_") as tmp:
        tmp_path = Path(tmp)
        cli_out = tmp_path / "cli.java"
        py_out = tmp_path / "py.java"
        asc_out = tmp_path / "asc.java"
        driver = py_driver_script(tmp_path) if py else None

        # Each workload: (name, rust-cli cmd, rust-py cmd|None, droidasc cmd|None)
        workloads: list[
            tuple[str, list[str], Optional[list[str]], Optional[list[str]]]
        ] = []

        def add(
            name: str,
            cli: list[str],
            kind: Optional[str] = None,
            value: Optional[str] = None,
            class_name: Optional[str] = None,
            fuzzy: bool = False,
            getclass: bool = False,
        ) -> None:
            py_cmd = None
            if py and driver:
                if getclass:
                    py_cmd = py_getclass(py, driver, args.apk, args.class_name, py_out)
                else:
                    assert kind is not None and value is not None
                    py_cmd = py_findrefs(
                        py, driver, args.apk, kind, value, class_name, fuzzy
                    )
            asc_w = None
            if asc_cmd:
                if getclass:
                    asc_w = asc_getclass(asc_cmd, args.apk, args.class_name, asc_out)
                else:
                    assert kind is not None and value is not None
                    asc_w = asc_findrefs(
                        asc_cmd, args.apk, kind, value, class_name, fuzzy
                    )
            workloads.append((name, cli, py_cmd, asc_w))

        if "getclass" in wanted:
            add(
                "getclass",
                our_cli_getclass(our, args.apk, args.class_name, cli_out),
                getclass=True,
            )
        if "findrefs-string" in wanted:
            add(
                "findrefs-string",
                our_cli_findrefs(
                    our, args.apk, "string", args.string_value, None, False
                ),
                kind="string",
                value=args.string_value,
            )
        if "findrefs-type" in wanted:
            add(
                "findrefs-type",
                our_cli_findrefs(our, args.apk, "type", args.type_value, None, False),
                kind="type",
                value=args.type_value,
            )
        if "findrefs-method" in wanted:
            add(
                "findrefs-method",
                our_cli_findrefs(
                    our,
                    args.apk,
                    "method",
                    args.method_value,
                    args.method_class,
                    False,
                ),
                kind="method",
                value=args.method_value,
                class_name=args.method_class,
            )
        if "findrefs-field" in wanted:
            add(
                "findrefs-field",
                our_cli_findrefs(
                    our,
                    args.apk,
                    "field",
                    args.field_value,
                    args.field_class,
                    False,
                ),
                kind="field",
                value=args.field_value,
                class_name=args.field_class,
            )

        eprint(f"APK:      {args.apk} ({args.apk.stat().st_size / 1e6:.1f} MB)")
        eprint(f"rust-cli: {our}")
        eprint(f"rust-py:  {py if py else '(skipped)'}")
        eprint(f"droidasc: {' '.join(asc_cmd) if asc_cmd else '(skipped)'}")
        eprint(f"runs:     {args.runs}  warmup: {args.warmup}")
        eprint()

        for name, cli_cmd, py_cmd, asc_w in workloads:
            results.append(
                bench("rust-cli", name, cli_cmd, args.runs, args.warmup)
            )
            if py_cmd:
                results.append(
                    bench("rust-py", name, py_cmd, args.runs, args.warmup)
                )
            if asc_w:
                results.append(
                    bench("droidasc", name, asc_w, args.runs, args.warmup)
                )

    print_table(results)

    if args.json_out:
        payload = {
            "apk": str(args.apk),
            "apk_bytes": args.apk.stat().st_size,
            "rust_cli": str(our),
            "rust_py": str(py) if py else None,
            "droidasc": asc_cmd,
            "results": [
                {
                    "tool": r.tool,
                    "workload": r.workload,
                    "wall_ms_mean": r.wall_ms_mean,
                    "wall_ms_stdev": r.wall_ms_stdev,
                    "rss_kb_mean": r.rss_kb_mean,
                    "samples": [asdict(s) for s in r.samples],
                }
                for r in results
            ],
        }
        args.json_out.write_text(json.dumps(payload, indent=2))
        print(f"wrote {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
