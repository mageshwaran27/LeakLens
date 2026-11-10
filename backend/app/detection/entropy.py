"""Shannon entropy + helpers. Entropy is a signal, never sole proof."""
from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def charset_score(s: str) -> float:
    if not s:
        return 0.0
    cats = sum([
        any(c.islower() for c in s),
        any(c.isupper() for c in s),
        any(c.isdigit() for c in s),
        any(not c.isalnum() for c in s),
    ])
    return cats / 4.0
