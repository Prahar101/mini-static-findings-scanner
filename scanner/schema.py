"""Core data structures for the scanner.

Plain dataclasses describing a detection rule and a finding. They are not
"models" in the machine-learning sense; the scanner is fully deterministic and
heuristic, so every finding traces back to a rule you can read.
"""

from dataclasses import dataclass, field
from typing import List, Optional

# Severity labels match the assignment's example output exactly: HIGH / MED / LOW.
HIGH = "HIGH"
MED = "MED"
LOW = "LOW"

# Lower number sorts first (most severe on top).
SEVERITY_ORDER = {HIGH: 0, MED: 1, LOW: 2}


@dataclass(frozen=True)
class Rule:
    name: str
    description: str
    severity: str
    category: str
    detection_type: str  # "regex", "filename", or "entropy_context"
    patterns: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    cwe: Optional[str] = None

    # Entropy detection tuning (used by entropy_context rules).
    entropy_threshold: Optional[float] = None

    # Context gating: a regex match only fires if one of these keywords appears within `context_window` lines of the match. Empty list = no gating.
    context_keywords: List[str] = field(default_factory=list)
    context_window: int = 0

    # If any of these appear on the matched line, the match is suppressed.
    negative_keywords: List[str] = field(default_factory=list)

    # Names of validator functions (see validators.py) applied after a match to adjust confidence or suppress false positives.
    validators: List[str] = field(default_factory=list)

    # Starting confidence (0..1) before validators adjust it.
    confidence_base: float = 0.7

    # Allows a config file to switch a rule off without deleting it.
    enabled: bool = True


@dataclass
class Finding:
    rule: str
    severity: str
    category: str
    file: str
    line: int
    message: str
    evidence: str
    remediation: Optional[str] = None
    cwe: Optional[str] = None
    confidence: float = 1.0
    language: Optional[str] = None
