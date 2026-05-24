"""Benchmark the scanner and render the charts used in the README.

    python benchmarks/benchmark.py

Needs matplotlib (`pip install matplotlib`). matplotlib is NOT required to run the
scanner itself -- only to regenerate these charts. The PNGs are committed so a
reader doesn't have to run anything.
"""

import shutil
import sys
import tempfile
import time
from pathlib import Path

# Make `scanner` importable when run as `python benchmarks/benchmark.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.engine import (
    _scan_parallel,
    _scan_sequential,
    iter_files,
    resolve_workers,
    scan_folder,
)
from scanner.rules import RULES

OUT = Path(__file__).resolve().parent
REPO = OUT.parent

SAMPLE = "\n".join([
    "import os, hashlib",
    'api_key = "sk_live_ABCDEF1234567890XYZ"',
    "os.system(user_cmd)",
    'url = "http://internal.corp/api"',
    "# TODO security: revisit auth",
    "cursor.execute('SELECT * FROM t WHERE id=' + uid)",
] * 2)


def _plt():
    # Imported lazily so worker processes never pay to import matplotlib.
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    return plt


def build(n):
    root = Path(tempfile.mkdtemp())
    for i in range(n):
        d = root / ("pkg%d" % (i // 100))
        d.mkdir(exist_ok=True)
        (d / ("mod%d.py" % i)).write_text(SAMPLE, encoding="utf-8")
    return root


def best(fn, runs):
    b = float("inf")
    for _ in range(runs):
        s = time.perf_counter()
        fn()
        b = min(b, time.perf_counter() - s)
    return b


def bench_scaling(sizes):
    # Compare the raw scan phase: forced-sequential vs forced-parallel. This shows
    # the true crossover and why the tool only auto-parallelises past a threshold.
    rules = [r for r in RULES if r.enabled]
    seq, par = [], []
    for n in sizes:
        root = build(n)
        files = list(iter_files(root))
        workers = resolve_workers(None, n)
        runs = 2 if n <= 2000 else 1
        seq.append(best(lambda: _scan_sequential(root, files, rules), runs))
        par.append(best(lambda: _scan_parallel(root, files, rules, workers), runs))
        shutil.rmtree(root, ignore_errors=True)
        print("n=%-5d seq=%.3fs  par=%.3fs  speedup=%.2fx" % (n, seq[-1], par[-1], seq[-1] / par[-1]))
    return seq, par


def chart_scaling(sizes, seq, par):
    plt = _plt()
    fig, ax = plt.subplots(figsize=(7, 4.2), dpi=120)
    ax.plot(sizes, seq, "o-", color="#e5484d", label="sequential (1 process)")
    ax.plot(sizes, par, "o-", color="#3b82f6", label="parallel (all cores)")
    ax.axvline(3000, color="#8b93a0", linestyle="--", linewidth=1)
    ax.text(3000, ax.get_ylim()[1] * 0.95, " auto-switch (~3000 files)",
            color="#8b93a0", va="top", fontsize=9)
    ax.set_xlabel("files scanned")
    ax.set_ylabel("seconds (lower is better)")
    ax.set_title("Scan time: sequential vs parallel (process pool)")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT / "scan_scaling.png", facecolor="white")
    plt.close(fig)


def chart_speedup(sizes, seq, par):
    plt = _plt()
    speed = [s / p for s, p in zip(seq, par)]
    fig, ax = plt.subplots(figsize=(7, 4.2), dpi=120)
    bars = ax.bar([f"{s:,}" for s in sizes], speed, color="#3b82f6")
    for b, v in zip(bars, speed):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.1f}x", ha="center", va="bottom")
    ax.set_xlabel("files scanned")
    ax.set_ylabel("speedup vs sequential")
    ax.set_title("Parallel speedup by tree size")
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT / "speedup.png", facecolor="white")
    plt.close(fig)


def chart_modes():
    # Runtime of each mode on the sample project (scan + writing the reports).
    # Only --online touches the network; the rest are within noise of each other.
    import contextlib
    import io
    import tempfile

    from scanner.reporter import (
        print_findings,
        write_html_report,
        write_json_report,
        write_markdown_report,
    )

    sp = REPO / "sample-project"
    tmp = Path(tempfile.mkdtemp())
    sink = io.StringIO()

    def run(online=False, verbose=False, html=False):
        findings = scan_folder(sp, offline=not online)
        with contextlib.redirect_stdout(sink):
            print_findings(findings, verbose=verbose)
        write_json_report(findings, tmp / "f.json")
        write_markdown_report(findings, tmp / "f.md")
        if html:
            write_html_report(findings, tmp / "f.html")

    modes = [
        ("default", lambda: run(), 5),
        ("-v", lambda: run(verbose=True), 5),
        ("--html", lambda: run(html=True), 5),
        ("--online", lambda: run(online=True), 1),
    ]
    labels, times = [], []
    for name, fn, runs in modes:
        ms = best(fn, runs) * 1000
        labels.append(name)
        times.append(ms)
        print("%-9s %.1f ms" % (name, ms))

    plt = _plt()
    fig, ax = plt.subplots(figsize=(7, 4.2), dpi=120)
    colors = ["#3b82f6", "#3b82f6", "#3b82f6", "#f5a623"]
    bars = ax.bar(labels, times, color=colors)
    for b, v in zip(bars, times):
        ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.0f} ms", ha="center", va="bottom")
    ax.set_ylabel("milliseconds (sample-project)")
    ax.set_title("Runtime by mode (only --online uses the network)")
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(OUT / "mode_runtime.png", facecolor="white")
    plt.close(fig)
    shutil.rmtree(tmp, ignore_errors=True)


def main():
    sizes = [500, 1000, 2000, 4000, 8000]
    seq, par = bench_scaling(sizes)
    chart_scaling(sizes, seq, par)
    chart_speedup(sizes, seq, par)
    chart_modes()
    print("charts written to", OUT)


if __name__ == "__main__":
    main()
