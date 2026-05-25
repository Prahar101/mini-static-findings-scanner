import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import main as cli


def _run(argv):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return cli.main(argv)


class TestOutputSelection(unittest.TestCase):
    def _project(self, tmp):
        (tmp / "a.py").write_text("eval(user_input)\n", encoding="utf-8")

    def _run_in(self, tmp, argv):
        cwd = os.getcwd()
        os.chdir(tmp)
        try:
            return _run(argv)
        finally:
            os.chdir(cwd)

    def test_no_flag_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            self._project(tmp)
            rc = self._run_in(tmp, [str(tmp)])
            self.assertEqual(rc, 0)
            self.assertTrue((tmp / "findings.json").exists())
            self.assertTrue((tmp / "findings-report.md").exists())
            self.assertFalse((tmp / "findings.sarif").exists())
            self.assertFalse((tmp / "findings.html").exists())

    def test_sarif_flag_writes_only_sarif(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            self._project(tmp)
            rc = self._run_in(tmp, [str(tmp), "--sarif"])
            self.assertEqual(rc, 0)
            self.assertTrue((tmp / "findings.sarif").exists())
            self.assertFalse((tmp / "findings.json").exists())
            self.assertFalse((tmp / "findings-report.md").exists())

    def test_html_flag_writes_only_html(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            self._project(tmp)
            with mock.patch("scanner.cli.webbrowser.open", return_value=True):
                rc = self._run_in(tmp, [str(tmp), "--html"])
            self.assertEqual(rc, 0)
            self.assertTrue((tmp / "findings.html").exists())
            self.assertFalse((tmp / "findings.json").exists())
            self.assertFalse((tmp / "findings-report.md").exists())

    def test_json_with_explicit_path(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            self._project(tmp)
            rc = self._run_in(tmp, [str(tmp), "--json", "out.json"])
            self.assertEqual(rc, 0)
            self.assertTrue((tmp / "out.json").exists())
            self.assertFalse((tmp / "findings.json").exists())
            self.assertFalse((tmp / "findings-report.md").exists())


if __name__ == "__main__":
    unittest.main()
