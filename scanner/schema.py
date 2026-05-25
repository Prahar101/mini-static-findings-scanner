#Core data structures for the scanner.

from dataclasses import dataclass, field
from typing import List, Optional

# Severity labels match the assignment's example output exactly: HIGH / MED / LOW.
HIGH = "HIGH"
MED = "MED"
LOW = "LOW"
SEVERITY_ORDER = {HIGH: 0, MED: 1, LOW: 2}

@dataclass(frozen=True)
class Rule:
    name: str
    description: str
    severity: str
    category: str
    detection_type: str  
    patterns: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    cwe: Optional[str] = None

    
    entropy_threshold: Optional[float] = None

    context_keywords: List[str] = field(default_factory=list)
    context_window: int = 0

    negative_keywords: List[str] = field(default_factory=list)

    validators: List[str] = field(default_factory=list)
    
    confidence_base: float = 0.7

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
