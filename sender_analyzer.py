"""Sender / header analysis."""
import re
from email.utils import parseaddr

from .config import BRANDS, FREEMAIL, SENSITIVE_ROLE_WORDS, SUSPICIOUS_TLDS
from .models import Finding
from .url_analyzer import LEET, registered_domain


def analyze_sender(sender, reply_to=""):
    name, addr = parseaddr(sender or "")
    if "@" not in addr:
        return [Finding("SENDER", "Missing or invalid sender address", 10,
                        sender or "(empty)", "Legitimate mail always has a well-formed sender address.")]
    local, domain = addr.rsplit("@", 1)
    domain = domain.lower()
    reg = registered_domain(domain)
    f = []

    def add(rule, pts, detail, why):
        f.append(Finding("SENDER", rule, pts, detail, why))

    norm = domain.translate(LEET)
    for brand, official in BRANDS.items():
        if reg in official:
            continue
        if brand in norm:
            add(f"Look-alike sender domain ({brand})", 20, addr,
                f"'{reg}' imitates {brand} but is not one of its real domains.")
            break
        if re.search(rf"\b{brand}\b", name.lower()):
            kind = "free-mail address" if domain in FREEMAIL else f"unrelated domain '{reg}'"
            add(f"Display-name spoofing ({brand})", 15, f"{name} <{addr}>",
                f"Display name claims {brand} but the address is a {kind}.")
            break
    if domain in FREEMAIL and re.search(SENSITIVE_ROLE_WORDS, name.lower()):
        add("Official-sounding name on free mail", 6, f"{name} <{addr}>",
            "Companies send official notices from their own domain, not free mail.")
    if domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        add("Suspicious sender TLD", 8, domain, "Cheap TLDs are frequently abused.")
    if "xn--" in domain:
        add("Punycode sender domain", 8, domain, "May use look-alike Unicode characters.")
    if domain.count("-") >= 2:
        add("Hyphen-heavy sender domain", 4, domain, "Typical of made-up look-alike domains.")
    if len(re.findall(r"\d", local)) >= 5:
        add("Digit-heavy sender name", 4, local, "Auto-generated addresses often contain many digits.")
    if reply_to:
        _, rt = parseaddr(reply_to)
        if "@" in rt and registered_domain(rt.rsplit("@", 1)[1].lower()) != reg:
            add("Reply-To mismatch", 10, f"from {reg}, replies go to {rt}",
                "Replies are silently redirected to a different domain.")
    return f
