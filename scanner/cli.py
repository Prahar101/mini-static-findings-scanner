"""Mini Static Findings Scanner - CLI.

Installed as the `scanner` command (see pyproject.toml), e.g.:
    scanner ./sample-project
    scanner ./sample-project --online          # enable OSV dependency CVE lookups
    scanner ./sample-project --disable-rule "Insecure HTTP URL"
    scanner ./sample-project --enable-rule "Broad CORS Policy"
    scanner ./sample-project --config scanner.config.json
    scanner --list-rules

Also runnable without installing via `python main.py ...`.

If --config is not given, a scanner.config.json in the current directory is
loaded automatically when present.
"""

import argparse
import json
import sys
import webbrowser
from pathlib import Path
from typing import List

from scanner.engine import scan_folder
from scanner.reporter import (
    print_findings,
    write_html_report,
    write_json_report,
    write_markdown_report,
    write_sarif_report,
)
from scanner.rules import RULES

DEFAULT_CONFIG = "scanner.config.json"


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="scanner", description="Mini Static Findings Scanner")
    parser.add_argument("path", nargs="?", help="Folder path to scan")
    parser.add_argument("--json", default="findings.json", help="JSON report path (default: findings.json)")
    parser.add_argument("--md", default="findings-report.md",
                        help="Markdown report path (default: findings-report.md). "
                             "Named to avoid clobbering FINDINGS.md on case-insensitive filesystems.")
    parser.add_argument("--sarif", nargs="?", const="findings.sarif", default=None,
                        help="Also write a SARIF report (default path: findings.sarif)")
    parser.add_argument("--html", nargs="?", const="findings.html", default=None,
                        help="Write an interactive HTML review UI and open it (default: findings.html)")
    parser.add_argument("--min-confidence", type=float, default=None,
                        help="Drop findings below this confidence (0.0-1.0)")
    parser.add_argument("--online", action="store_true",
                        help="Enable OSV dependency CVE lookups (off by default; makes network calls)")
    parser.add_argument("-j", "--jobs", type=int, default=None, metavar="N",
                        help="Parallel worker threads for scanning (default: auto-detect)")
    parser.add_argument("--config", help="JSON config to enable/disable rules and set defaults")
    parser.add_argument("--enable-rule", action="append", default=[], metavar="NAME",
                        help="Run only this rule (repeatable; allowlist). Merges with config.")
    parser.add_argument("--disable-rule", action="append", default=[], metavar="NAME",
                        help="Turn off this rule (repeatable; denylist). Merges with config.")
    parser.add_argument("--list-rules", action="store_true",
                        help="Print available rule names and exit.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show CWE, confidence, and remediation under each finding.")
    return parser.parse_args(argv)


def load_config(path: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Error: could not read config '{path}': {exc}")


def select_rules(all_rules: List, cfg: dict) -> List:
    """Apply enable/disable lists from config.

    - enabled_rules (allowlist): if non-empty, ONLY these rules run.
    - disabled_rules (denylist): these rules are turned off.
    Unknown rule names are warned about (typo protection).
    """
    known = {r.name for r in all_rules}
    enabled = cfg.get("enabled_rules") or []
    disabled = cfg.get("disabled_rules") or []
    for name in list(enabled) + list(disabled):
        if name not in known:
            print(f"Warning: config references unknown rule '{name}'", file=sys.stderr)

    selected = [r for r in all_rules if r.name in set(enabled)] if enabled else list(all_rules)
    disabled_set = set(disabled)
    return [r for r in selected if r.name not in disabled_set]


def main(argv=None) -> int:
    args = parse_args(argv)

    if args.list_rules:
        width = max(len(r.name) for r in RULES)
        print("Available rules (disable with: --disable-rule \"<name>\"):\n")
        for r in RULES:
            print(f'  {r.name:<{width}}  [{r.severity}]')
        return 0

    if not args.path:
        raise SystemExit("Error: a folder path is required (or use --list-rules)")

    target = Path(args.path)
    if not target.exists():
        raise SystemExit(f"Error: path does not exist: {target}")
    if not target.is_dir():
        raise SystemExit(f"Error: path is not a folder: {target}")

    config_path = args.config
    if config_path is None and Path(DEFAULT_CONFIG).is_file():
        config_path = DEFAULT_CONFIG
        print(f"Using config: {DEFAULT_CONFIG}")

    cfg: dict = load_config(config_path) if config_path else {}

    min_confidence = args.min_confidence
    if min_confidence is None and "min_confidence" in cfg:
        min_confidence = float(cfg["min_confidence"])
    if min_confidence is None:
        min_confidence = 0.0

    # CLI --enable-rule / --disable-rule merge with (and extend) the config lists.
    cfg = dict(cfg)
    cfg["enabled_rules"] = list(cfg.get("enabled_rules") or []) + list(args.enable_rule)
    cfg["disabled_rules"] = list(cfg.get("disabled_rules") or []) + list(args.disable_rule)
    rules: List = select_rules(RULES, cfg)

    findings = scan_folder(
        target,
        rules=rules,
        min_confidence=min_confidence,
        offline=not args.online,
        jobs=args.jobs,
    )

    print_findings(findings, verbose=args.verbose)

    json_path = Path(args.json)
    write_json_report(findings, json_path)
    print(f"Wrote JSON report: {json_path}")

    md_path = Path(args.md)
    write_markdown_report(findings, md_path)
    print(f"Wrote Markdown report: {md_path}")

    if args.sarif:
        sarif_path = Path(args.sarif)
        write_sarif_report(findings, sarif_path)
        print(f"Wrote SARIF report: {sarif_path}")

    if args.html:
        html_path = Path(args.html)
        write_html_report(findings, html_path)
        uri = html_path.resolve().as_uri()
        print(f"Wrote HTML report: {html_path}")
        print(f"  Open in browser: {uri}")
        try:
            webbrowser.open(uri)
        except Exception:
            pass  # best-effort; the link is already on the console if it didn't open
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
