import unittest

from tests.helpers import rules_for, scan_files


class TestFalsePositiveHandling(unittest.TestCase):
    def test_placeholder_value_suppressed(self):
        f = scan_files({"c.js": 'const api_key = "your_api_key_here";'})
        self.assertNotIn("Hardcoded Secret", rules_for(f, "c.js"))

    def test_env_reference_suppressed(self):
        f = scan_files({"c.js": 'const password = `${process.env.DB_PASS}`;'})
        self.assertNotIn("Hardcoded Secret", rules_for(f, "c.js"))

    def test_localhost_http_suppressed(self):
        f = scan_files({"c.js": 'const url = "http://localhost:8080/health";'})
        self.assertNotIn("Insecure HTTP URL", rules_for(f, "c.js"))

    def test_real_http_url_still_flagged(self):
        f = scan_files({"c.js": 'const url = "http://api.internal.corp/v1";'})
        self.assertIn("Insecure HTTP URL", rules_for(f, "c.js"))

    def test_nosec_suppresses_line(self):
        f = scan_files({"c.py": 'password = "Sup3rS3cr3tValue123"  # nosec'})
        self.assertEqual(rules_for(f, "c.py"), set())

    def test_known_prefix_boosts_confidence(self):
        f = scan_files({"c.js": 'const api_key = "sk_live_ABCDEF1234567890XYZ";'})
        secret = [x for x in f if x.rule == "Hardcoded Secret"][0]
        self.assertGreaterEqual(secret.confidence, 0.9)

    def test_min_confidence_filters(self):
        files = {"c.js": 'const token = "abcdefgh";'}
        kept = scan_files(files, min_confidence=0.9)
        self.assertNotIn("Hardcoded Secret", rules_for(kept, "c.js"))

    def test_dangerous_call_in_comment_suppressed(self):
        f = scan_files({"a.py": "# eval(user_input) only mentioned in a comment\n"})
        self.assertNotIn("Dangerous Code Execution", rules_for(f, "a.py"))

    def test_dangerous_call_in_docstring_suppressed(self):
        f = scan_files({"a.py": 'doc = """\neval(x)\nexec(y)\nsubprocess.run(c, shell=True)\n"""\n'})
        self.assertNotIn("Dangerous Code Execution", rules_for(f, "a.py"))

    def test_real_dangerous_call_still_flagged(self):
        f = scan_files({"a.py": "eval(user_input)\n"})
        self.assertIn("Dangerous Code Execution", rules_for(f, "a.py"))


if __name__ == "__main__":
    unittest.main()
