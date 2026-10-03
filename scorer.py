"""Combines analyzers into one explainable risk score and classification."""
from .config import (BASE_RECOMMENDATIONS, CATEGORY_CAPS, CATEGORY_TIPS,
                     HIGH_LABEL, THRESHOLDS)
from .content_analyzer import analyze_content
from .parser import strip_html
from .sender_analyzer import analyze_sender
from .url_analyzer import analyze_urls


def classify(score):
    for limit, label in THRESHOLDS:
        if score < limit:
            return label
    return HIGH_LABEL


def analyze_email(sender="", subject="", body="", reply_to="", use_ml=False):
    if not (sender.strip() or subject.strip() or body.strip()):
        raise ValueError("Please provide at least a sender, subject or body.")
    urls, url_f = analyze_urls(body)
    findings = url_f + analyze_sender(sender, reply_to) + analyze_content(subject, strip_html(body))

    cat_scores = {c: 0 for c in CATEGORY_CAPS}
    for f in findings:
        cat_scores[f.category] += f.points
    cat_scores = {c: min(v, CATEGORY_CAPS[c]) for c, v in cat_scores.items()}
    rule_score = min(100, sum(cat_scores.values()))

    ml_prob = None
    score = rule_score
    if use_ml:
        from . import ml_model
        ml_prob = ml_model.predict_proba(sender, subject, body)
        if ml_prob is not None:
            score = round(0.7 * rule_score + 0.3 * ml_prob * 100)

    label = classify(score)
    recs = list(BASE_RECOMMENDATIONS[label])
    recs += [CATEGORY_TIPS[c] for c, v in cat_scores.items() if v > 0]
    return {
        "score": int(score), "label": label, "rule_score": rule_score,
        "ml_probability": ml_prob, "category_scores": cat_scores,
        "findings": [f.to_dict() for f in sorted(findings, key=lambda x: -x.points)],
        "urls": urls, "recommendations": recs,
    }
