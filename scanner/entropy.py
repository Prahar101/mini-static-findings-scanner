import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def has_secret_context(line: str) -> bool:
    keywords = ["api", "key", "token", "secret", "password", "passwd", "credential", "auth"]
    lowered = line.lower()
    return any(keyword in lowered for keyword in keywords)
