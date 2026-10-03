"""REST API for the phishing analyzer. Run: uvicorn api:app  (docs at /docs)"""
import sys
from pathlib import Path

# Make the local package importable when running this module directly.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from fastapi import FastAPI, HTTPException  # type: ignore[import-not-found]
from pydantic import BaseModel, Field  # type: ignore[import-not-found]

from phishguard import database  # type: ignore[import-not-found]
from phishguard.scorer import analyze_email  # type: ignore[import-not-found]

app = FastAPI(title="PhishGuard API", version="1.0",
              description="Defensive, educational phishing email analysis. Static analysis only.")


class EmailIn(BaseModel):
    sender: str = Field("", max_length=320)
    reply_to: str = Field("", max_length=320)
    subject: str = Field("", max_length=500)
    body: str = Field("", max_length=200_000)
    use_ml: bool = False
    save: bool = False


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
def analyze(e: EmailIn):
    try:
        res = analyze_email(e.sender, e.subject, e.body, e.reply_to, e.use_ml)
    except ValueError as err:
        raise HTTPException(status_code=422, detail=str(err))
    if e.save:
        database.save_analysis(e.sender, e.subject, e.body, res)
    return res


@app.get("/history")
def history(limit: int = 50):
    return database.fetch_all()[: max(1, min(limit, 500))]