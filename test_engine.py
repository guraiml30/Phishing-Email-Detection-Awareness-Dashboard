# pyright: reportMissingImports=false
# pylint: disable=import-error

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phishguard import database
from phishguard.parser import parse_email_file
from phishguard.scorer import analyze_email, classify
from phishguard.sender_analyzer import analyze_sender
from phishguard.url_analyzer import analyze_url, find_link_mismatches

PHISH = dict(
    sender="PayPal Support <security@paypa1-secure.example.net>",
    subject="URGENT: Your PayPal account will be suspended",
    body="Dear customer, unauthorized activity detected. Verify your password immediately: "
         "http://paypa1-secure.example.net/login/verify?id=1",
    reply_to="help@example.org")
LEGIT = dict(
    sender="Priya <priya@example.edu>", subject="Team meeting moved to Thursday",
    body="Hi, the meeting is at 3 PM in room 204. Agenda: https://www.example.com/agenda. Thanks!")


def rules(findings):
    return {f.rule for f in findings}


class TestUrl(unittest.TestCase):
    def test_ip(self):
        self.assertIn("IP address instead of domain", rules(analyze_url("http://192.0.2.10/login")))

    def test_brand_lookalike(self):
        self.assertTrue(any("Brand impersonation" in r for r in rules(analyze_url("https://paypa1-help.example.net"))))

    def test_official_brand_ok(self):
        self.assertFalse(any("Brand" in r for r in rules(analyze_url("https://www.paypal.com/help"))))

    def test_shortener_and_at(self):
        self.assertIn("URL shortener", rules(analyze_url("https://bit.ly/x")))
        self.assertIn("'@' in URL", rules(analyze_url("http://www.example.com@evil.example.net/")))

    def test_link_mismatch(self):
        h = '<a href="http://evil.example.net/x">www.example.com</a>'
        self.assertEqual(len(find_link_mismatches(h)), 1)


class TestSender(unittest.TestCase):
    def test_display_spoof_freemail(self):
        self.assertTrue(any("Display-name" in r for r in rules(analyze_sender("PayPal Support <x@gmail.com>"))))

    def test_reply_to_mismatch(self):
        self.assertIn("Reply-To mismatch", rules(analyze_sender("A <a@example.com>", "b@example.org")))

    def test_invalid(self):
        self.assertIn("Missing or invalid sender address", rules(analyze_sender("nobody")))


class TestScoring(unittest.TestCase):
    def test_phish_high(self):
        r = analyze_email(**PHISH)
        self.assertEqual(r["label"], "HIGH RISK / LIKELY PHISHING")
        self.assertGreaterEqual(r["score"], 60)

    def test_legit_safe(self):
        self.assertEqual(analyze_email(**LEGIT)["label"], "SAFE")

    def test_thresholds(self):
        self.assertEqual([classify(s) for s in (0, 15, 35, 60)],
                         ["SAFE", "LOW RISK", "SUSPICIOUS", "HIGH RISK / LIKELY PHISHING"])

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            analyze_email()


class TestParserDb(unittest.TestCase):
    def test_eml(self):
        raw = b"From: A <a@example.com>\nSubject: Hi\n\nHello there"
        d = parse_email_file(raw)
        self.assertEqual(d["subject"], "Hi")
        self.assertIn("Hello", d["body"])

    def test_too_large(self):
        with self.assertRaises(ValueError):
            parse_email_file(b"x" * 300_000)

    def test_db_roundtrip_and_injection_safe(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "h.db"
            evil = "x'); DROP TABLE analyses;--"
            database.save_analysis(evil, "s", "b", analyze_email(**LEGIT), path=p)
            rows = database.fetch_all(p)
            self.assertEqual(rows[0]["sender"], evil)
            database.clear_history(p)
            self.assertEqual(database.fetch_all(p), [])


if __name__ == "__main__":
    unittest.main()
