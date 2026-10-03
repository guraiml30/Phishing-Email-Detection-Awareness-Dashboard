"""Shared data structure: every detection rule returns a Finding."""
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    category: str   # URL | SENDER | CONTENT
    rule: str       # short rule name
    points: int     # risk points contributed
    detail: str     # what exactly was seen
    why: str        # plain-English explanation (explainability)

    def to_dict(self):
        return asdict(self)
