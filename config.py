"""Central configuration: word lists, weights, thresholds. Tune detection here."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "data" / "history.db"
DATASET_PATH = ROOT / "data" / "sample_emails.csv"
MODEL_PATH = ROOT / "models" / "phish_model.joblib"

# Max points each category may add (stops one category dominating).
CATEGORY_CAPS = {"URL": 40, "SENDER": 35, "CONTENT": 40}

# (upper_limit_exclusive, label); anything >= last limit is HIGH.
THRESHOLDS = [(15, "SAFE"), (35, "LOW RISK"), (60, "SUSPICIOUS")]
HIGH_LABEL = "HIGH RISK / LIKELY PHISHING"

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "zip", "mov", "win", "loan", "work",
                   "gq", "tk", "ml", "cf", "ga", "icu", "monster", "rest"}
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
            "proton.me", "aol.com", "mail.com"}
SENSITIVE_ROLE_WORDS = r"\b(support|security|billing|helpdesk|admin|service)\b"

# brand -> its legitimate registered domains
BRANDS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "netflix": {"netflix.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com"},
    "facebook": {"facebook.com", "meta.com"},
    "dhl": {"dhl.com"},
}

# (rule, points, regex, why)
CONTENT_RULES = [
    ("Urgency language", 6,
     r"\b(urgent(ly)?|immediately|act now|right away|within \d+ (hours?|minutes?)|expires? (today|soon|in)|last (chance|warning)|final notice)\b",
     "Attackers create time pressure so you act before thinking."),
    ("Threat / fear language", 8,
     r"\b(account (will be|has been) (suspended|closed|locked|terminated|disabled)|legal action|permanently (deleted|closed)|unauthori[sz]ed (access|activity|login)|suspicious (activity|sign[- ]?in))\b",
     "Threats of account loss or legal trouble are a classic social-engineering tactic."),
    ("Credential / identity request", 10,
     r"\b(verify your (account|identity|password)|confirm your (password|credentials|identity|account)|update your (payment|billing|password|account)|log ?in to (verify|confirm|restore)|enter your (password|otp|pin|card))\b",
     "Legitimate companies rarely ask you to confirm credentials through an email link."),
    ("Sensitive data mentioned", 4,
     r"\b(password|otp|one[- ]time (code|password)|pin|ssn|social security|cvv|card number)\b",
     "Emails that mention secrets deserve extra scrutiny (also appears in genuine reset mails)."),
    ("Reward / prize lure", 6,
     r"\b(you (have )?won|winner|claim your (prize|reward|gift)|free gift|lottery|congratulations)\b",
     "Unexpected prizes are bait used to lure clicks."),
    ("Financial lure", 5,
     r"\b(wire transfer|gift cards?|bitcoin|crypto|refund|invoice attached|payment (failed|declined|overdue))\b",
     "Payment-related pretexts are commonly used for fraud."),
    ("Generic greeting", 3,
     r"\b(dear (customer|user|client|member|valued|sir|madam)|valued customer)\b",
     "Mass phishing rarely knows your real name."),
    ("Click / open pressure", 4,
     r"\b(click (here|the link|below)|open the attachment|download the attached)\b",
     "Direct calls to click or open files push you toward the malicious step."),
]

BASE_RECOMMENDATIONS = {
    "SAFE": ["No strong phishing indicators found. Still verify unexpected requests through an official channel."],
    "LOW RISK": ["Minor indicators found. Review the flagged items before acting on the email."],
    "SUSPICIOUS": ["Do not click links or open attachments until verified.",
                   "Contact the sender through a known official channel (not details from this email)."],
    HIGH_LABEL: ["Do NOT click links, open attachments or reply.",
                 "Report it to your IT/security team or use 'Report phishing' in your mail client.",
                 "If you already entered a password, change it immediately and enable MFA.",
                 "Delete the email after reporting."],
}
CATEGORY_TIPS = {
    "URL": "Hover over links to see the real destination; type the official address yourself instead of clicking.",
    "SENDER": "Check the actual sender address (not just the display name) and any Reply-To mismatch.",
    "CONTENT": "Pressure and fear are manipulation tactics: pause, breathe, verify independently.",
}
