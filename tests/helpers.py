"""Shared test helpers."""

import tempfile
from pathlib import Path
from typing import Dict, List

from scanner.engine import scan_folder
from scanner.schema import Finding


def scan_files(files: Dict[str, str], **kwargs) -> List[Finding]:
    """Write `files` (relpath -> content) into a temp dir and scan it.

    SCA is disabled by default so these tests never touch the network.
    """
    kwargs.setdefault("run_sca", False)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, content in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return scan_folder(root, **kwargs)


def rules_for(findings: List[Finding], path: str) -> set:
    return {f.rule for f in findings if f.file == path}
