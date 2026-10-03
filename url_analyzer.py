"""URL analysis. Purely static: it NEVER visits or resolves a URL."""
import ipaddress
import re
from urllib.parse import urlparse

from .config import BRANDS, SHORTENERS, SUSPICIOUS_TLDS
from .models import Finding

URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"')\]]+""", re.I)
LINK_RE = re.compile(r"""<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>""", re.I | re.S)
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"})
LOGIN_WORDS = re.compile(r"(login|signin|verify|secure|update|account|password|confirm)", re.I)


def extract_urls(text):
    urls = [u.rstrip(".,;:!?") for u in URL_RE.findall(text or "")]
    return list(dict.fromkeys(urls))  # unique, keep order


def registered_domain(host):
    """Approximate registrable domain (good enough for teaching; not a full PSL)."""
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in {"co", "com", "org", "gov", "ac", "net"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_url(url):
    raw = url if re.match(r"https?://", url, re.I) else "http://" + url
    short = url if len(url) <= 50 else url[:47] + "..."
    try:
        p = urlparse(raw)
        host = (p.hostname or "").lower()
    except ValueError:
        return [Finding("URL", "Malformed URL", 8, short, "Broken URLs are often crafted to evade filters.")]
    if not host:
        return [Finding("URL", "Malformed URL", 8, short, "No valid host could be read.")]

    f = []
    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1]

    def add(rule, pts, why):
        f.append(Finding("URL", rule, pts, short, why))

    if _is_ip(host):
        add("IP address instead of domain", 15, "Real services use domain names; raw IPs hide the owner.")
    else:
        if reg in SHORTENERS:
            add("URL shortener", 8, "Shorteners hide the true destination.")
        if tld in SUSPICIOUS_TLDS:
            add("Suspicious TLD", 8, f".{tld} is heavily abused for throwaway domains.")
        if "xn--" in host:
            add("Punycode / homograph domain", 8, "Look-alike Unicode characters can imitate real brands.")
        if len(host.split(".")) - len(reg.split(".")) >= 3:
            add("Excessive subdomains", 4, "Long subdomain chains hide the real domain at the end.")
        if host.count("-") >= 3:
            add("Many hyphens in domain", 4, "Hyphen-stuffed names such as secure-login-update-x are typical of phishing.")
        norm = host.translate(LEET)
        for brand, official in BRANDS.items():
            if brand in norm and reg not in official:
                add(f"Brand impersonation ({brand})", 20,
                    f"Domain contains '{brand}' but belongs to '{reg}', not the real {brand} domain.")
                break
    if "@" in p.netloc:
        add("'@' in URL", 10, "Text before '@' is ignored by browsers; it disguises the real host.")
    if p.scheme == "http":
        add("Not using HTTPS", 4, "Unencrypted links are risky, especially on login pages.")
    if len(url) > 100:
        add("Very long URL", 3, "Long URLs can bury the real destination.")
    if LOGIN_WORDS.search((p.path or "") + "?" + (p.query or "")):
        add("Login/verify keywords in path", 3, "Paths like /verify or /login are common in credential-theft lures.")
    return f


def find_link_mismatches(html):
    """Detect <a href="real">shown-text.com</a> where the two domains differ."""
    out = []
    for href, text in LINK_RE.findall(html or ""):
        visible = re.sub(r"<[^>]+>", "", text).strip()
        m = URL_RE.search(visible) or re.search(r"\b[\w-]+\.(com|net|org|edu|in)\b", visible, re.I)
        if not m:
            continue
        shown = m.group(0)
        shown_host = (urlparse(shown if "://" in shown else "http://" + shown).hostname or "")
        real_host = urlparse(href).hostname or ""
        if shown_host and real_host and registered_domain(shown_host) != registered_domain(real_host):
            out.append(Finding("URL", "Link text does not match destination", 12,
                               f"shows {shown_host}, goes to {real_host}",
                               "Displayed link text differs from the real target: a deliberate deception."))
    return out


def analyze_urls(text):
    """Return (urls, findings) for a whole message body (raw, may contain HTML)."""
    urls = extract_urls(text)
    findings = []
    for u in urls:
        findings.extend(analyze_url(u))
    findings.extend(find_link_mismatches(text))
    return urls, findings
