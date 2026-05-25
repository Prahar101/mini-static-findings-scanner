import json
import tempfile
import unittest
from pathlib import Path

from scanner.reporter import write_sarif_report
from scanner.schema import Finding


def _sample():
    return [
        Finding(rule="Hardcoded Secret", severity="HIGH", category="Secrets",
                file="src/config.js", line=12, message="Possible hardcoded secret",
                evidence="api_key = '...'", remediation="Use a vault.", cwe="CWE-798",
                confidence=0.95, language="JavaScript"),
        Finding(rule="Broad CORS Policy", severity="MED", category="Configuration",
                file="src/server.js", line=44, message="Broad CORS policy",
                evidence="origin: '*'", cwe="CWE-942", confidence=0.8, language="JavaScript"),
    ]


class TestSarif(unittest.TestCase):
    def _write_and_load(self, findings):
        with tempfile.TemporaryDirectory() as t:
            out = Path(t) / "out.sarif"
            write_sarif_report(findings, out)
            return json.loads(out.read_text(encoding="utf-8"))

    def test_envelope(self):
        doc = self._write_and_load(_sample())
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("$schema", doc)
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"],
                         "Mini Static Findings Scanner")

    def test_results_and_levels(self):
        doc = self._write_and_load(_sample())
        run = doc["runs"][0]
        self.assertEqual(len(run["results"]), 2)
        first = run["results"][0]
        self.assertEqual(first["ruleId"], "hardcoded-secret")
        self.assertEqual(first["level"], "error")  
        loc = first["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "src/config.js")
        self.assertEqual(loc["region"]["startLine"], 12)

    def test_rules_deduped(self):
        doc = self._write_and_load(_sample())
        rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
        self.assertEqual(sorted(rule_ids), ["broad-cors-policy", "hardcoded-secret"])

    def test_empty(self):
        doc = self._write_and_load([])
        self.assertEqual(doc["runs"][0]["results"], [])


if __name__ == "__main__":
    unittest.main()
