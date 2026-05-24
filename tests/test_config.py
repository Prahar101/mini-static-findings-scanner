import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import main as cli
from main import select_rules
from scanner.rules import RULES


class TestRuleConfig(unittest.TestCase):
    def test_empty_config_keeps_all_rules(self):
        self.assertEqual(len(select_rules(RULES, {})), len(RULES))

    def test_disabled_rules_removed(self):
        names = {r.name for r in select_rules(RULES, {"disabled_rules": ["Insecure HTTP URL"]})}
        self.assertNotIn("Insecure HTTP URL", names)
        self.assertIn("Broad CORS Policy", names)

    def test_enabled_rules_is_allowlist(self):
        selected = select_rules(RULES, {"enabled_rules": ["Broad CORS Policy"]})
        self.assertEqual([r.name for r in selected], ["Broad CORS Policy"])

    def test_enabled_then_disabled(self):
        cfg = {"enabled_rules": ["Broad CORS Policy", "Debug Mode Enabled"],
               "disabled_rules": ["Debug Mode Enabled"]}
        self.assertEqual([r.name for r in select_rules(RULES, cfg)], ["Broad CORS Policy"])

    def test_unknown_rule_name_does_not_crash(self):
        # Should warn (to stderr) but still return all rules.
        with contextlib.redirect_stderr(io.StringIO()):
            kept = select_rules(RULES, {"disabled_rules": ["Nope"]})
        self.assertEqual(len(kept), len(RULES))


class TestCliRuleToggles(unittest.TestCase):
    def _run(self, argv):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return cli.main(argv)

    def test_cli_disable_rule(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            (tmp / "a.js").write_text(
                'const url = "http://internal.corp/x";\napp.use(cors({ origin: "*" }));\n',
                encoding="utf-8")
            out = tmp / "out.json"
            rc = self._run([str(tmp), "--disable-rule", "Insecure HTTP URL",
                            "--json", str(out), "--md", str(tmp / "out.md")])
            self.assertEqual(rc, 0)
            rules = {f["rule"] for f in json.loads(out.read_text())["findings"]}
            self.assertNotIn("Insecure HTTP URL", rules)
            self.assertIn("Broad CORS Policy", rules)

    def test_cli_enable_rule_allowlist(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            (tmp / "a.js").write_text(
                'const url = "http://internal.corp/x";\napp.use(cors({ origin: "*" }));\n',
                encoding="utf-8")
            out = tmp / "out.json"
            self._run([str(tmp), "--enable-rule", "Broad CORS Policy",
                       "--json", str(out), "--md", str(tmp / "out.md")])
            rules = {f["rule"] for f in json.loads(out.read_text())["findings"]}
            self.assertEqual(rules, {"Broad CORS Policy"})

    def test_list_rules(self):
        rc = self._run(["--list-rules"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
