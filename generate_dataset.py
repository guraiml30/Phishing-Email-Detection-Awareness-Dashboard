"""Generate a SYNTHETIC labelled dataset (label 1 = phishing, 0 = legitimate).
All domains use reserved documentation names (example.com/.net/.org, 192.0.2.x),
so nothing here points at a real website or person."""

import csv
import random
from pathlib import Path

random.seed(42)
OUT = Path(__file__).resolve().parents[1] / "data" / "sample_emails.csv"
BRANDS = ["PayPal", "Microsoft", "Amazon", "Netflix", "Apple", "Google"]
NAMES = ["Asha", "Ravi", "Maria", "John", "Priya", "Liam", "Sara", "Omar"]


def lookalike(b):
    b = b.lower()
    return random.choice([b.replace("l", "1").replace("o", "0"), b + "-support", b + "-secure", "secure-" + b])


PH_SUBJECTS = ["URGENT: Your {b} account will be suspended", "Action required: verify your {b} password",
               "{b} security alert - unusual sign-in", "Final notice: payment failed",
               "Congratulations! You have won a free gift", "Your {b} account has been locked"]
PH_BODIES = [
    "Dear customer,\n\nWe detected unauthorized activity on your {b} account. Your account will be suspended within 24 hours unless you verify your password immediately.\n\nClick here to confirm your identity: {u}\n\n{b} Security Team",
    "Dear user, your payment failed and your {b} subscription will be closed. Update your payment information now: {u}\nFinal notice!!!",
    "Congratulations!!! You have won a {b} gift card. Claim your reward before it expires today: {u}",
    "Suspicious sign-in detected. Log in to verify your account right away or your account has been locked permanently: {u}",
    "Valued customer, a refund of $249 is waiting. Confirm your credentials to receive it: {u}. Act now.",
]
LEGIT_SUBJECTS = ["Team meeting moved to Thursday", "Your order receipt #{n}", "Library book due reminder",
                  "Weekly newsletter: campus events", "Project update - sprint review",
                  "Password reset requested", "Assignment {n} feedback available"]
LEGIT_BODIES = [
    "Hi {p}, the team meeting has moved to Thursday 3 PM in room 204. Agenda: https://www.example.com/agenda. Thanks!",
    "Hello {p}, thank you for your order. Your receipt is available at https://www.example.com/receipts/{n}. Have a great day.",
    "Hi {p}, this is a friendly reminder that your library book is due next week. Renew at https://www.example.org/library.",
    "Hello {p}, here are this week's campus events: a coding club meetup, a career talk and a movie night. Details: https://www.example.edu/events",
    "Hi {p}, you asked to reset your password. If this was you, use https://accounts.example.com/reset within an hour; otherwise ignore this email.",
    "Hi {p}, your feedback for assignment {n} is now available in the course portal. Please review before Monday's class.",
]


def phishing_row(i):
    b = random.choice(BRANDS)
    dom = lookalike(b)
    n = random.randint(100, 999)
    url = random.choice([f"http://{dom}.example.net/login/verify?id={n}",
                         f"http://192.0.2.{random.randint(1, 250)}/secure/update",
                         f"http://{b.lower()}.account-verify.example.net/confirm/{n}"])
    sender = random.choice([f"{b} Support <security@{dom}.example.net>",
                            f"{b} Team <{b.lower()}.help{n}@gmail.com>",
                            f"{b} Alerts <alert@{dom}.example.org>"])
    return [sender, random.choice(["", "reply-desk@example.org"]),
            random.choice(PH_SUBJECTS).format(b=b),
            random.choice(PH_BODIES).format(b=b, u=url), 1]


def legit_row(i):
    p, n = random.choice(NAMES), random.randint(1000, 9999)
    sender = random.choice([f"{p} Kumar <{p.lower()}@example.edu>", f"Accounts <no-reply@accounts.example.com>",
                            f"Library <desk@example.org>", f"Team Lead <lead@example.com>"])
    return [sender, "", random.choice(LEGIT_SUBJECTS).format(n=n),
            random.choice(LEGIT_BODIES).format(p=p, n=n), 0]


rows = [phishing_row(i) for i in range(120)] + [legit_row(i) for i in range(120)]
random.shuffle(rows)
OUT.parent.mkdir(exist_ok=True)
with open(OUT, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["sender", "reply_to", "subject", "body", "label"])
    w.writerows(rows)
print(f"Wrote {len(rows)} synthetic emails to {OUT}")
