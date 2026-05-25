import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import main as cli
from scanner import sca
from scanner.engine import MAX_FILE_BYTES, MAX_LINE_LENGTH, scan_folder

SECRET = 'api_key = "sk_live_ABCDEF1234567890XYZ"'


def write(root, rel, content, encoding="utf-8"):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content, encoding=encoding)
    return p


class TestFileEdgeCases(unittest.TestCase):
    def test_empty_folder(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(scan_folder(Path(t), run_sca=False), [])

    def test_binary_text_extension_does_not_crash(self):
        with tempfile.TemporaryDirectory() as t:
            write(t, "a.py", bytes(range(256)) * 200)  
            scan_folder(Path(t), run_sca=False)  

    def test_binary_nontext_extension_skipped(self):
        with tempfile.TemporaryDirectory() as t:
            write(t, "img.png", b"\x89PNG\r\n" + bytes(range(256)))
            self.assertEqual(scan_folder(Path(t), run_sca=False), [])

    def test_ignored_dirs_skipped(self):
        with tempfile.TemporaryDirectory() as t:
            for d in (".git", "node_modules", "dist", "build"):
                write(t, f"{d}/a.py", SECRET)
            self.assertEqual(scan_folder(Path(t), run_sca=False), [])

    def test_duplicate_findings_deduped(self):
        with tempfile.TemporaryDirectory() as t:
            write(t, "c.py", SECRET)  
            findings = scan_folder(Path(t), run_sca=False)
            secrets = [f for f in findings if f.line == 1 and f.category == "Secrets"]
            self.assertEqual(len(secrets), 1)

    def test_huge_file_skipped(self):
        with tempfile.TemporaryDirectory() as t:
            write(t, "big.py", SECRET + "\n" + ("x = 1\n" * (MAX_FILE_BYTES // 6 + 500)))
            self.assertEqual(scan_folder(Path(t), run_sca=False), [])  

    def test_huge_single_line_truncated(self):
        with tempfile.TemporaryDirectory() as t:
            write(t, "a.py", 'os.system("x")' + "a" * (MAX_LINE_LENGTH * 3))
            findings = scan_folder(Path(t), run_sca=False)
            self.assertIn("Dangerous Code Execution", {f.rule for f in findings})

    def test_unicode_file(self):
        with tempfile.TemporaryDirectory() as t:
            write(t, "u.py", '# 日本語 \U0001f680\n' + SECRET + "\n")
            self.assertIn("Hardcoded Secret", {f.rule for f in scan_folder(Path(t), run_sca=False)})

    def test_permission_denied_file(self):
        with tempfile.TemporaryDirectory() as t:
            write(t, "a.py", SECRET)
            with mock.patch("pathlib.Path.read_text", side_effect=PermissionError("denied")):
                self.assertEqual(scan_folder(Path(t), run_sca=False), [])  

    def test_broken_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            write(t, "real.py", "eval(user_input)")
            try:
                (root / "link.py").symlink_to(root / "missing.py")
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not permitted on this platform")
            findings = scan_folder(root, run_sca=False)  
            self.assertIn("real.py", {f.file for f in findings})


class TestManifestEdgeCases(unittest.TestCase):
    def test_malformed_package_json(self):
        with tempfile.TemporaryDirectory() as t:
            p = write(t, "package.json", "{ not valid json ")
            self.assertEqual(sca.parse_package_json(p, "package.json"), [])
            scan_folder(Path(t), offline=True)  

    def test_malformed_requirements(self):
        with tempfile.TemporaryDirectory() as t:
            p = write(t, "requirements.txt", "===garbage\n!!!\n\n# comment\nflask==1.0.0\n-e .\n@@@\n")
            names = {d.name for d in sca.parse_requirements(p, "requirements.txt")}
            self.assertIn("flask", names)  

    def test_online_with_no_internet(self):
        with mock.patch.object(sca.urllib.request, "urlopen", side_effect=OSError("no network")):
            self.assertEqual(sca.query_osv("flask", "PyPI", "1.0.0"), [])  
            with tempfile.TemporaryDirectory() as t:
                write(t, "requirements.txt", "flask==1.0.0\n")
                findings = sca.scan_dependencies(Path(t), offline=False)
        self.assertFalse(any(f.rule == "Vulnerable Dependency" for f in findings))


class TestCliEdgeCases(unittest.TestCase):
    def _run(self, argv):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return cli.main(argv)

    def test_missing_path(self):
        with self.assertRaises(SystemExit):
            self._run([])

    def test_nonexistent_path(self):
        with self.assertRaises(SystemExit):
            self._run(["/no/such/path/xyz123"])

    def test_path_is_a_file(self):
        with tempfile.TemporaryDirectory() as t:
            f = write(t, "f.py", "x = 1")
            with self.assertRaises(SystemExit):
                self._run([str(f)])

    def test_bad_min_confidence(self):
        with self.assertRaises(SystemExit):
            self._run(["x", "--min-confidence", "abc"])

    def test_unknown_flag(self):
        with self.assertRaises(SystemExit):
            self._run(["x", "--definitely-not-a-flag"])

    def test_list_rules_needs_no_path(self):
        self.assertEqual(self._run(["--list-rules"]), 0)


if __name__ == "__main__":
    unittest.main()
