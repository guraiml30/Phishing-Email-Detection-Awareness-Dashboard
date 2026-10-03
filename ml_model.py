"""OPTIONAL machine-learning layer (TF-IDF + Logistic Regression).
Trained on SYNTHETIC data, so treat it as a learning demo, not a production model."""
from .config import DATASET_PATH, MODEL_PATH

_model = None


def _text(sender, subject, body):
    return f"{sender} {subject} {body}"


def train(dataset=DATASET_PATH, model_path=MODEL_PATH):
    import joblib
    import pandas as pd
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import make_pipeline

    df = pd.read_csv(dataset).fillna("")
    X = (df["sender"] + " " + df["subject"] + " " + df["body"]).tolist()
    Xtr, Xte, ytr, yte = train_test_split(X, df["label"], test_size=0.25, random_state=42, stratify=df["label"])
    pipe = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), min_df=2, lowercase=True),
                         LogisticRegression(max_iter=1000))
    pipe.fit(Xtr, ytr)
    print(classification_report(yte, pipe.predict(Xte), target_names=["legit", "phishing"]))
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, model_path)
    print("Saved model to", model_path)


def predict_proba(sender, subject, body):
    """Return P(phishing) or None if no trained model / sklearn is available."""
    global _model
    try:
        if _model is None:
            import joblib
            if not MODEL_PATH.exists():
                return None
            _model = joblib.load(MODEL_PATH)
        return float(_model.predict_proba([_text(sender, subject, body)])[0][1])
    except Exception:
        return None


if __name__ == "__main__":
    train()
