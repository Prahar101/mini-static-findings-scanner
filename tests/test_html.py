import json
import re
import tempfile
import unittest
from pathlib import Path

from scanner.reporter import write_html_report
from scanner.schema import Finding


def _findings():
    return [
        Finding(rule="Hardcoded Secret", severity="HIGH", category="Secrets",
                file="src/config.js", line=12, message="Possible hardcoded secret",
                evidence="api_key='x'", remediation="Use a vault.", cwe="CWE-798",
                confidence=0.95, language="JavaScript"),
    ]


class TestHtmlReport(unittest.TestCase):
    def test_writes_self_contained_html(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / "report.html"
            write_html_report(_findings(), out)
            html = out.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Possible hardcoded secret", html)
        self.assertNotIn("__DATA__", html)  # placeholder was substituted

    def test_embedded_data_is_valid_json(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / "report.html"
            write_html_report(_findings(), out)
            html = out.read_text(encoding="utf-8")
        m = re.search(r"const DATA=(\[.*?\]);", html, re.DOTALL)
        self.assertIsNotNone(m)
        data = json.loads(m.group(1).replace("<\\/", "</"))
        self.assertEqual(data[0]["rule"], "Hardcoded Secret")

    def test_empty_findings(self):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / "report.html"
            write_html_report([], out)
            html = out.read_text(encoding="utf-8")
        self.assertIn("const DATA=[];", html)


if __name__ == "__main__":
    unittest.main()
