"""Tests for the scanner's own hardening (ReDoS guard, symlink containment)."""

import tempfile
import unittest
from pathlib import Path

from scanner.engine import MAX_LINE_LENGTH, scan_folder


class TestReDoSGuard(unittest.TestCase):
    def test_long_line_is_truncated(self):
        start = 'app.use(cors({ origin: "*" }));'
        tail = "x" * (MAX_LINE_LENGTH * 4) + 'const api_key = "sk_live_ABCDEF1234567890XYZ";'
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "a.js").write_text(start + tail, encoding="utf-8")
            rules = {f.rule for f in scan_folder(Path(t), run_sca=False)}
        self.assertIn("Broad CORS Policy", rules)    # near the start -> scanned
        self.assertNotIn("Hardcoded Secret", rules)  # past the cap -> never reaches a regex


class TestSymlinkContainment(unittest.TestCase):
    def test_symlink_outside_root_is_skipped(self):
        secret = 'const api_key = "sk_live_ABCDEF1234567890XYZ";'
        with tempfile.TemporaryDirectory() as out_t, tempfile.TemporaryDirectory() as root_t:
            outside = Path(out_t) / "secret.js"
            outside.write_text(secret, encoding="utf-8")
            root = Path(root_t)
            (root / "normal.js").write_text('app.use(cors({ origin: "*" }));', encoding="utf-8")
            link = root / "link.js"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation not permitted on this platform")

            files = {f.file for f in scan_folder(root, run_sca=False)}
        self.assertIn("normal.js", files)       # regular files still scanned
        self.assertNotIn("link.js", files)      # symlink escaping the tree is skipped


if __name__ == "__main__":
    unittest.main()
