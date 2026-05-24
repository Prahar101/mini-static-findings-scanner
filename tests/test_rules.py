import unittest

from tests.helpers import rules_for, scan_files


class TestRuleDetection(unittest.TestCase):
    def test_hardcoded_secret(self):
        f = scan_files({"config.js": 'const api_key = "sk_live_ABCDEF1234567890XYZ";'})
        self.assertIn("Hardcoded Secret", rules_for(f, "config.js"))

    def test_dangerous_code_execution(self):
        f = scan_files({"a.py": 'os.system("rm -rf /")\neval(user_input)'})
        self.assertIn("Dangerous Code Execution", rules_for(f, "a.py"))

    def test_disabled_tls_verification(self):
        f = scan_files({"a.py": "requests.get(url, verify=False)"})
        self.assertIn("Disabled TLS Verification", rules_for(f, "a.py"))

    def test_insecure_deserialization(self):
        f = scan_files({"a.py": "data = pickle.loads(blob)"})
        self.assertIn("Insecure Deserialization", rules_for(f, "a.py"))

    def test_yaml_safe_load_not_flagged(self):
        f = scan_files({"a.py": "cfg = yaml.safe_load(stream)"})
        self.assertNotIn("Insecure Deserialization", rules_for(f, "a.py"))

    def test_sql_injection(self):
        f = scan_files({"a.py": 'cursor.execute("SELECT * FROM t WHERE id = " + uid)'})
        self.assertIn("SQL Injection Risk", rules_for(f, "a.py"))

    def test_weak_crypto_requires_security_context(self):
        with_ctx = scan_files({"a.py": "h = hashlib.md5(password.encode())"})
        self.assertIn("Weak Cryptography", rules_for(with_ctx, "a.py"))

        without_ctx = scan_files({"a.py": "etag = hashlib.md5(open(f).read())"})
        self.assertNotIn("Weak Cryptography", rules_for(without_ctx, "a.py"))

    def test_broad_cors(self):
        f = scan_files({"server.js": 'app.use(cors({ origin: "*" }));'})
        self.assertIn("Broad CORS Policy", rules_for(f, "server.js"))

    def test_debug_mode(self):
        f = scan_files({"app.py": "app.run(debug=True)"})
        self.assertIn("Debug Mode Enabled", rules_for(f, "app.py"))

    def test_private_key(self):
        f = scan_files({"key.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n"})
        self.assertIn("Private Key Exposure", rules_for(f, "key.pem"))

    def test_suspicious_comment(self):
        f = scan_files({"x.py": "# TODO security: fix auth before launch"})
        self.assertIn("Suspicious Security Comment", rules_for(f, "x.py"))

    def test_ignored_dirs_are_skipped(self):
        f = scan_files({"node_modules/pkg/a.js": 'const api_key = "sk_live_LEAKED1234567890";'})
        self.assertEqual(f, [])

    def test_minimum_five_rules_available(self):
        from scanner.rules import RULES
        self.assertGreaterEqual(len(RULES), 5)


if __name__ == "__main__":
    unittest.main()
