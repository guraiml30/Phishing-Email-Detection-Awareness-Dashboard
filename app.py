"""Phishing Email Detection & Awareness Dashboard (Streamlit). Run: streamlit run app.py"""
import json
import sys
from collections import Counter
from pathlib import Path

# Make the local src/ package importable at runtime, and suppress VS Code/Pyright
# warnings for that project-local package path.
# pyright: reportMissingImports=false
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import pandas as pd
import streamlit as st

from phishguard import database
from phishguard.parser import parse_email_file
from phishguard.scorer import analyze_email

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="wide")
st.title("🛡️ Phishing Email Detection & Awareness Dashboard")
st.caption("Educational, defensive tool. It analyses text only and never opens links or sends anything.")

page = st.sidebar.radio("Navigate", ["Analyze", "Dashboard", "History", "Learn"])

SAMPLES = {
    "(none)": ("", "", "", ""),
    "Sample phishing (fictional)": (
        "PayPal Support <security@paypa1-secure.example.net>", "help@example.org",
        "URGENT: Your PayPal account will be suspended",
        "Dear customer,\n\nWe detected unauthorized activity. Verify your password immediately: "
        "http://paypa1-secure.example.net/login/verify?id=123\n\nPayPal Security Team"),
    "Sample legitimate": (
        "Priya <priya@example.edu>", "", "Team meeting moved to Thursday",
        "Hi, the meeting is at 3 PM in room 204. Agenda: https://www.example.com/agenda. Thanks!"),
}

if page == "Analyze":
    choice = st.selectbox("Load a safe sample", list(SAMPLES))
    s0, r0, subj0, b0 = SAMPLES[choice]
    up = st.file_uploader("Or upload a sample .txt / .eml (never a real attachment)", type=["txt", "eml"])
    if up is not None:
        try:
            d = parse_email_file(up.getvalue())
            s0, r0, subj0, b0 = d["sender"], d["reply_to"], d["subject"], d["body"]
        except ValueError as e:
            st.error(str(e))
    sender = st.text_input("Sender", s0, key=f"s{choice}{up.name if up else ''}")
    reply_to = st.text_input("Reply-To (optional)", r0, key=f"r{choice}{up.name if up else ''}")
    subject = st.text_input("Subject", subj0, key=f"j{choice}{up.name if up else ''}")
    body = st.text_area("Email body", b0, height=220, key=f"b{choice}{up.name if up else ''}")
    c1, c2 = st.columns(2)
    use_ml = c1.checkbox("Blend in optional ML model (if trained)")
    save = c2.checkbox("Save to history", value=True)

    if st.button("Analyze", type="primary"):
        try:
            res = analyze_email(sender, subject, body, reply_to, use_ml)
        except ValueError as e:
            st.warning(str(e))
            st.stop()
        if save:
            database.save_analysis(sender, subject, body, res)
        label = res["label"]
        banner = {"SAFE": st.success, "LOW RISK": st.info, "SUSPICIOUS": st.warning}.get(label, st.error)
        banner(f"**{label}**")
        m1, m2, m3 = st.columns(3)
        m1.metric("Risk score", f"{res['score']}/100")
        m2.metric("Findings", len(res["findings"]))
        m3.metric("URLs found", len(res["urls"]))
        st.progress(res["score"] / 100)
        if use_ml and res["ml_probability"] is None:
            st.caption("ML model not found. Run `python -m phishguard.ml_model` (see README).")
        st.subheader("Score by category")
        st.bar_chart(pd.Series(res["category_scores"]))
        st.subheader("Why this result?")
        if res["findings"]:
            st.dataframe(pd.DataFrame(res["findings"])[["category", "rule", "points", "detail", "why"]],
                         use_container_width=True, hide_index=True)
        else:
            st.write("No suspicious indicators triggered.")
        if res["urls"]:
            with st.expander("URLs extracted (not visited)"):
                for u in res["urls"]:
                    st.code(u.replace("http", "hxxp"), language=None)  # defanged
        st.subheader("Recommendations")
        for r in res["recommendations"]:
            st.markdown(f"- {r}")

elif page in ("Dashboard", "History"):
    rows = database.fetch_all()
    if not rows:
        st.info("No analyses yet. Analyze an email first.")
        st.stop()
    df = pd.DataFrame(rows)
    df["ts"] = pd.to_datetime(df["ts"])
    if page == "Dashboard":
        k1, k2, k3 = st.columns(3)
        k1.metric("Emails analyzed", len(df))
        k2.metric("Average risk score", f"{df['score'].mean():.0f}")
        k3.metric("High-risk share", f"{(df['label'].str.startswith('HIGH')).mean() * 100:.0f}%")
        st.subheader("Classifications")
        st.bar_chart(df["label"].value_counts())
        st.subheader("Risk score over time")
        st.line_chart(df.sort_values("ts").set_index("ts")["score"])
        st.subheader("Most triggered rules")
        cnt = Counter(r for js in df["findings"] for r in json.loads(js))
        if cnt:
            st.bar_chart(pd.Series(cnt).sort_values(ascending=False).head(10))
    else:
        st.dataframe(df[["ts", "sender", "subject", "score", "label"]], use_container_width=True, hide_index=True)
        st.download_button("Download CSV", df.to_csv(index=False), "history.csv", "text/csv")
        if st.checkbox("I understand this deletes all history") and st.button("Clear history"):
            database.clear_history()
            st.rerun()

else:
    st.header("📚 Phishing Awareness")
    with st.expander("Common red flags", expanded=True):
        st.markdown("""
- **Urgency or fear**: "act now", "account suspended".
- **Mismatched sender**: display name says a brand, address says otherwise.
- **Suspicious links**: look-alike domains, IP addresses, shorteners, link text that differs from the target.
- **Requests for secrets**: passwords, OTPs, card numbers.
- **Too good to be true**: prizes and unexpected refunds.
- **Generic greeting** and unexpected attachments.""")
    with st.expander("What to do"):
        st.markdown("""
1. Stop and do not click. 2. Verify using an official website or phone number you already trust.
3. Report to IT/security. 4. If you clicked or entered data: change passwords, enable MFA, tell IT.""")
    st.subheader("Quick quiz")
    QUIZ = [("An email from 'Amazon Support <help@gmail.com>' asks you to confirm your card. What is the key red flag?",
             ["Polite tone", "Brand name on a free-mail address", "It has a subject line"], 1,
             "Real companies send from their own domain, not free mail."),
            ("Which link is most suspicious?",
             ["https://www.example.com/help", "http://192.0.2.5/login", "https://docs.example.org"], 1,
             "Raw IP addresses hide who owns the site."),
            ("You get 'Final notice: act within 2 hours'. Best response?",
             ["Click quickly", "Reply with your password", "Verify via the official site or phone"], 2,
             "Urgency is a manipulation tactic; verify independently.")]
    for i, (q, opts, ans, why) in enumerate(QUIZ):
        pick = st.radio(q, opts, index=None, key=f"q{i}")
        if pick is not None:
            (st.success if opts.index(pick) == ans else st.error)(why)
