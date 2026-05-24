import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scanner import sca


def _write(tmp: Path, name: str, content: str) -> Path:
    p = tmp / name
    p.write_text(content, encoding="utf-8")
    return p


FAKE_VULN = {
    "id": "GHSA-xxxx",
    "aliases": ["CVE-2099-0001"],
    "summary": "Test vulnerability",
    "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-79"]},
    "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}],
}


class TestManifestParsing(unittest.TestCase):
    def test_parse_requirements_pinned_and_unpinned(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            p = _write(tmp, "requirements.txt",
                       "flask==1.0.0\nrequests>=2.0\n# comment\ncertifi\n-e .\n")
            deps = sca.parse_requirements(p, "requirements.txt")
            by_name = {d.name: d for d in deps}
            self.assertTrue(by_name["flask"].pinned)
            self.assertEqual(by_name["flask"].version, "1.0.0")
            self.assertFalse(by_name["requests"].pinned)
            self.assertIsNone(by_name["certifi"].version)

    def test_normalize_npm_version(self):
        self.assertEqual(sca._normalize_npm_version("1.2.3"), ("1.2.3", True))
        self.assertEqual(sca._normalize_npm_version("^1.2.3"), ("1.2.3", False))
        self.assertEqual(sca._normalize_npm_version("~4.0.0"), ("4.0.0", False))

    def test_parse_package_json(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            p = _write(tmp, "package.json",
                       '{"dependencies": {"lodash": "4.17.4"}, '
                       '"devDependencies": {"mocha": "^9.0.0"}}')
            deps = sca.parse_package_json(p, "package.json")
            names = {d.name for d in deps}
            self.assertEqual(names, {"lodash", "mocha"})


class TestSeverityMapping(unittest.TestCase):
    def test_severity_from_database_specific(self):
        self.assertEqual(sca._severity_from_osv({"database_specific": {"severity": "CRITICAL"}}), "HIGH")
        self.assertEqual(sca._severity_from_osv({"database_specific": {"severity": "MODERATE"}}), "MED")
        self.assertEqual(sca._severity_from_osv({"database_specific": {"severity": "LOW"}}), "LOW")

    def test_severity_default(self):
        self.assertEqual(sca._severity_from_osv({}), "MED")

    def test_first_fixed(self):
        self.assertEqual(sca._first_fixed(FAKE_VULN), "2.0.0")


class TestScanDependencies(unittest.TestCase):
    def test_pinned_vuln_reported(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            _write(tmp, "requirements.txt", "flask==1.0.0\n")
            with mock.patch.object(sca, "query_osv", return_value=[FAKE_VULN]):
                findings = sca.scan_dependencies(tmp)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "Vulnerable Dependency")
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("CVE-2099-0001", findings[0].message)
        self.assertIn("2.0.0", findings[0].remediation)

    def test_offline_skips_network(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            _write(tmp, "requirements.txt", "flask==1.0.0\ncertifi\n")
            with mock.patch.object(sca, "query_osv",
                                   side_effect=AssertionError("network used")):
                findings = sca.scan_dependencies(tmp, offline=True)
        rules = {f.rule for f in findings}
        self.assertEqual(rules, {"Unpinned Dependency"})

    def test_unpinned_reported_as_low(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            _write(tmp, "requirements.txt", "certifi\n")
            with mock.patch.object(sca, "query_osv", return_value=[]):
                findings = sca.scan_dependencies(tmp)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "LOW")
        self.assertEqual(findings[0].rule, "Unpinned Dependency")


if __name__ == "__main__":
    unittest.main()
