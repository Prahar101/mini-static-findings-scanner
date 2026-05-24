"""Convenience entry point so the tool runs without installing:

    python main.py ./sample-project

The real CLI lives in scanner/cli.py (also installed as the `scanner` command).
Names are re-exported here so existing imports/tests keep working.
"""

from scanner.cli import DEFAULT_CONFIG, load_config, main, parse_args, select_rules

__all__ = ["main", "parse_args", "select_rules", "load_config", "DEFAULT_CONFIG"]

if __name__ == "__main__":
    raise SystemExit(main())
