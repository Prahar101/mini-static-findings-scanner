import unittest
from pathlib import Path

from scanner.languages import detect_language
from tests.helpers import scan_files


class TestLanguageDetection(unittest.TestCase):
    def test_extension_mapping(self):
        self.assertEqual(detect_language(Path("a.py")), "Python")
        self.assertEqual(detect_language(Path("a.js")), "JavaScript")
        self.assertEqual(detect_language(Path("a.tsx")), "TypeScript")
        self.assertEqual(detect_language(Path("a.go")), "Go")

    def test_dotenv(self):
        self.assertEqual(detect_language(Path(".env")), "Dotenv")
        self.assertEqual(detect_language(Path(".env.production")), "Dotenv")

    def test_unknown_extension(self):
        self.assertEqual(detect_language(Path("a.xyz")), "Other")

    def test_findings_are_tagged_with_language(self):
        findings = scan_files({
            "app.py": "eval(user_input)",
            "server.js": 'app.use(cors({ origin: "*" }));',
        })
        by_file = {f.file: f.language for f in findings}
        self.assertEqual(by_file["app.py"], "Python")
        self.assertEqual(by_file["server.js"], "JavaScript")


if __name__ == "__main__":
    unittest.main()
