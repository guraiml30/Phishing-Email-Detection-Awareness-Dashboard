"""Safe email-file parsing. HTML is never rendered, only read as text."""
import html
import re
from email import policy
from email.parser import BytesParser

MAX_BYTES = 200_000


def strip_html(text):
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text or "")
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def parse_email_file(data: bytes) -> dict:
    if len(data) > MAX_BYTES:
        raise ValueError(f"File too large (limit {MAX_BYTES // 1000} KB).")
    msg = BytesParser(policy=policy.default).parsebytes(data)
    body = ""
    try:
        part = msg.get_body(preferencelist=("plain", "html"))
        body = part.get_content() if part else ""
    except Exception:
        body = ""
    if not body.strip():
        body = data.decode("utf-8", "replace")
    return {"sender": str(msg.get("From", "")), "reply_to": str(msg.get("Reply-To", "")),
            "subject": str(msg.get("Subject", "")), "body": body}
