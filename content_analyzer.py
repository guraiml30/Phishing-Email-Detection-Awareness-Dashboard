"""Content / social-engineering language analysis."""
import re

from .config import CONTENT_RULES
from .models import Finding


def analyze_content(subject, body):
    text = f"{subject or ''}\n{body or ''}"
    findings = []
    for rule, pts, pattern, why in CONTENT_RULES:
        m = re.search(pattern, text, re.I)
        if m:
            findings.append(Finding("CONTENT", rule, pts, f'matched "{m.group(0)[:60]}"', why))
    if text.count("!") >= 3:
        findings.append(Finding("CONTENT", "Excessive exclamation marks", 2,
                                f"{text.count('!')} found", "Hype punctuation is common in scams."))
    words = re.findall(r"[A-Za-z]{4,}", text)
    if len(words) >= 8 and sum(w.isupper() for w in words) / len(words) > 0.25:
        findings.append(Finding("CONTENT", "Excessive capitalisation", 3,
                                "many ALL-CAPS words", "Shouting adds false urgency."))
    return findings
