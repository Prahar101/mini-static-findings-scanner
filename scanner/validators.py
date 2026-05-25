import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List

from scanner.entropy import shannon_entropy
from scanner.schema import Rule


@dataclass
class MatchContext:
    line: str
    lines: List[str]
    line_index: int  
    rel_path: str
    rule: Rule
    match_text: str  


@dataclass
class ValidationResult:
    delta: float = 0.0
    suppress: bool = False
    reason: str = ""


# Prefixes of real provider tokens.
KNOWN_SECRET_PREFIXES = (
    "AKIA", "ASIA",                       # AWS access key id
    "ghp_", "gho_", "ghs_", "ghu_", "ghr_", "github_pat_",  # GitHub tokens
    "sk_live_", "sk_test_", "pk_live_", "rk_live_",          # Stripe
    "xoxb-", "xoxp-", "xoxa-", "xoxr-",  # Slack
    "AIza", "ya29.",                     # Google API / OAuth
    "SG.",                               # SendGrid
    "glpat-",                            # GitLab PAT
    "shpat_", "shpss_",                  # Shopify
    "eyJ",                               # JWT 
)

PRIVATE_KEY_MARKER = "-----BEGIN"

# Values that look like secrets but aren't.
PLACEHOLDER_TOKENS = (
    "your_", "your-", "yourkey", "changeme", "change_me", "placeholder",
    "example", "dummy", "sample", "redacted", "xxxx", "todo", "fixme",
    "<", ">", "{{", "}}", "...", "n/a", "none", "null", "test_key", "fake",
    "insert_", "replace_", "my_secret", "my_token", "my_api",
)

# Signs the value comes from the environment, not a hardcoded literal.
ENV_REFERENCE_PATTERNS = (
    re.compile(r"process\.env\b", re.IGNORECASE),
    re.compile(r"os\.environ", re.IGNORECASE),
    re.compile(r"os\.getenv", re.IGNORECASE),
    re.compile(r"import\.meta\.env", re.IGNORECASE),
    re.compile(r"\bgetenv\s*\(", re.IGNORECASE),
    re.compile(r"\$\{[^}]+\}"),          
    re.compile(r"\benv\[[\'\"]"),        
    re.compile(r"config\.(get|require)\s*\(", re.IGNORECASE),
)

# Hosts where an http:// link isn't really a transport risk.
BENIGN_URL_HOSTS = (
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "example.com", "example.org", "example.net",
    "w3.org", "www.w3.org", "schemas.xmlsoap.org", "schema.org",
    "xmlns", "purl.org", "ns.adobe.com",
)

# Inline suppression markers.
SUPPRESS_MARKERS = ("nosec", "scanner-ignore", "scanner:ignore", "noqa: scanner")

TEST_PATH_HINTS = ("test", "tests", "spec", "specs", "fixture", "fixtures",
                   "mock", "mocks", "example", "examples", "sample", "__tests__")

COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", "<!--")


def is_suppressed_inline(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in SUPPRESS_MARKERS)


def charset_classes(value: str) -> int:
    classes = 0
    if re.search(r"[a-z]", value):
        classes += 1
    if re.search(r"[A-Z]", value):
        classes += 1
    if re.search(r"[0-9]", value):
        classes += 1
    if re.search(r"[^A-Za-z0-9]", value):
        classes += 1
    return classes


def extract_value(line: str) -> str:
    """Best-effort extraction of the literal value on an assignment line."""
    quoted = re.findall(r"['\"]([^'\"]{3,})['\"]", line)
    if quoted:
        return max(quoted, key=len)
    after = re.split(r"[:=]", line, maxsplit=1)
    if len(after) == 2:
        return after[1].strip().strip("'\";,")
    return line.strip()


def is_comment_line(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(COMMENT_PREFIXES)


def _looks_sequential_or_repeated(value: str) -> bool:
    if len(set(value)) <= 2 and len(value) >= 4:
        return True  # e.g. "aaaa", "abab"
    sequences = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop")
    low = value.lower()
    return any(low in seq for seq in sequences if len(low) >= 4)


def v_secret_prefix(ctx: MatchContext) -> ValidationResult:
    value = extract_value(ctx.line)
    if PRIVATE_KEY_MARKER in ctx.line:
        return ValidationResult(delta=0.4, reason="private-key marker present")
    if value.startswith(KNOWN_SECRET_PREFIXES):
        return ValidationResult(delta=0.4, reason="known provider secret prefix")
    return ValidationResult()


def v_entropy_charset(ctx: MatchContext) -> ValidationResult:
    value = extract_value(ctx.line)
    if len(value) < 8:
        return ValidationResult(delta=-0.2, reason="value too short to be a key")
    entropy = shannon_entropy(value)
    classes = charset_classes(value)
    if entropy >= 4.0 and classes >= 3:
        return ValidationResult(delta=0.25, reason=f"high entropy ({entropy:.1f}), {classes} charset classes")
    if entropy < 3.0 or classes <= 1:
        return ValidationResult(delta=-0.3, reason=f"low entropy ({entropy:.1f})/charset, likely not a secret")
    return ValidationResult()


def v_placeholder(ctx: MatchContext) -> ValidationResult:
    value = extract_value(ctx.line).lower()
    if any(token in value for token in PLACEHOLDER_TOKENS):
        return ValidationResult(suppress=True, reason="placeholder/dummy value")
    if _looks_sequential_or_repeated(value):
        return ValidationResult(suppress=True, reason="sequential/repeated filler value")
    return ValidationResult()


def v_env_reference(ctx: MatchContext) -> ValidationResult:
    if any(p.search(ctx.line) for p in ENV_REFERENCE_PATTERNS):
        return ValidationResult(suppress=True, reason="value sourced from environment, not hardcoded")
    return ValidationResult()


def v_benign_url(ctx: MatchContext) -> ValidationResult:
    urls = re.findall(r"http://([^\s'\"/:]+)", ctx.line, flags=re.IGNORECASE)
    if not urls:
        return ValidationResult()
    if all(any(host in u for host in BENIGN_URL_HOSTS) for u in urls):
        return ValidationResult(suppress=True, reason="benign/local/schema URL")
    if "xmlns" in ctx.line.lower():
        return ValidationResult(suppress=True, reason="XML namespace URI, not a request")
    return ValidationResult()


def v_in_comment(ctx: MatchContext) -> ValidationResult:
    if is_comment_line(ctx.line):
        return ValidationResult(delta=-0.15, reason="match is inside a comment")
    return ValidationResult()


def _inside_triple_quote(lines: List[str], idx: int) -> bool:
    in_str = False
    delim = None
    for line in lines[:idx]:
        pos = 0
        while True:
            best, best_pos = None, -1
            for d in ('"""', "'''"):
                p = line.find(d, pos)
                if p != -1 and (best_pos == -1 or p < best_pos):
                    best, best_pos = d, p
            if best is None:
                break
            if not in_str:
                in_str, delim = True, best
            elif delim == best:
                in_str, delim = False, None
            pos = best_pos + 3
    return in_str


def v_code_context(ctx: MatchContext) -> ValidationResult:
    if is_comment_line(ctx.line):
        return ValidationResult(suppress=True, reason="match is in a comment, not code")
    if _inside_triple_quote(ctx.lines, ctx.line_index):
        return ValidationResult(suppress=True, reason="match is inside a string/docstring, not code")
    return ValidationResult()


def v_test_path(ctx: MatchContext) -> ValidationResult:
    parts = re.split(r"[/\\.]", ctx.rel_path.lower())
    if any(hint in parts for hint in TEST_PATH_HINTS):
        return ValidationResult(delta=-0.2, reason="file looks like test/example code")
    return ValidationResult()


VALIDATORS: Dict[str, Callable[[MatchContext], ValidationResult]] = {
    "secret_prefix": v_secret_prefix,
    "entropy_charset": v_entropy_charset,
    "placeholder": v_placeholder,
    "env_reference": v_env_reference,
    "benign_url": v_benign_url,
    "in_comment": v_in_comment,
    "code_context": v_code_context,
    "test_path": v_test_path,
}


def evaluate(ctx: MatchContext) -> ValidationResult:
    total = 0.0
    reasons: List[str] = []
    for name in ctx.rule.validators:
        validator = VALIDATORS.get(name)
        if validator is None:
            continue
        result = validator(ctx)
        if result.suppress:
            return ValidationResult(suppress=True, reason=result.reason)
        total += result.delta
        if result.reason:
            reasons.append(result.reason)
    return ValidationResult(delta=total, reason="; ".join(reasons))
