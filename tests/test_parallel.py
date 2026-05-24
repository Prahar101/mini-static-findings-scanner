import tempfile
import unittest
from pathlib import Path

from scanner.engine import _scan_parallel, _scan_sequential, iter_files, resolve_workers
from scanner.rules import RULES
from tests.helpers import scan_files


def _key(findings):
    return sorted((f.file, f.line, f.rule, f.severity) for f in findings)


class TestParallelScanning(unittest.TestCase):
    def test_jobs_flag_is_deterministic(self):
        files = {f"pkg/mod{i}.py": "eval(user_input)\nos.system('ls')\n" for i in range(20)}
        self.assertEqual(_key(scan_files(files, jobs=1)), _key(scan_files(files, jobs=8)))
        self.assertTrue(scan_files(files, jobs=1))

    def test_process_pool_matches_sequential(self):
        # Exercise the real process pool directly (bypassing the size threshold).
        content = ("eval(user_input)\nos.system('ls')\n"
                   'api_key = "sk_live_ABCDEF1234567890XYZ"\n')
        rules = [r for r in RULES if r.enabled]
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for i in range(60):
                (root / f"mod{i}.py").write_text(content, encoding="utf-8")
            files = list(iter_files(root))
            sequential = _scan_sequential(root, files, rules)
            parallel = _scan_parallel(root, files, rules, 4)
        self.assertTrue(sequential)
        self.assertEqual(_key(sequential), _key(parallel))

    def test_resolve_workers(self):
        self.assertEqual(resolve_workers(4, 100), 4)            # explicit wins
        self.assertGreaterEqual(resolve_workers(None, 100), 1)  # auto is sane


if __name__ == "__main__":
    unittest.main()
