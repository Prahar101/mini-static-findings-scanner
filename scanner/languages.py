"""Lightweight language detection by file extension.

Used to tag each finding with the language it came from and to produce a
per-language breakdown in reports. Extension-based (like GitHub Linguist's first
pass) -- deterministic, no content parsing, no dependencies.
"""

from pathlib import Path

EXTENSION_LANGUAGES = {
    ".py": "Python", ".pyw": "Python",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".rs": "Rust",
    ".html": "HTML", ".css": "CSS",
    ".json": "JSON", ".yaml": "YAML", ".yml": "YAML", ".toml": "TOML",
    ".sh": "Shell", ".bash": "Shell",
    ".ps1": "PowerShell",
    ".xml": "XML", ".md": "Markdown", ".txt": "Text",
    ".ini": "INI", ".conf": "Config", ".cfg": "Config", ".properties": "Properties",
    ".pem": "PEM", ".key": "Key", ".crt": "Certificate", ".cer": "Certificate",
    ".sql": "SQL",
}


def detect_language(path: Path) -> str:
    """Return the language/file-type name for a path, or 'Other' if unknown."""
    if path.name.lower().startswith(".env"):
        return "Dotenv"
    return EXTENSION_LANGUAGES.get(path.suffix.lower(), "Other")
