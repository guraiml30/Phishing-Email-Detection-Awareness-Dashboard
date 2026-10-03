"""SQLite history. Uses parameterised queries only (prevents SQL injection)."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .config import DB_PATH


@contextmanager
def _conn(path=None):
    path = path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    try:
        with c:  # commit on success, rollback on error
            yield c
    finally:
        c.close()  # releases the file lock (needed on Windows)


def init_db(path=None):
    with _conn(path) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS analyses(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, sender TEXT, subject TEXT,
            score INTEGER, label TEXT, findings TEXT, preview TEXT)""")


def save_analysis(sender, subject, body, result, path=None):
    init_db(path)
    with _conn(path) as c:
        c.execute("INSERT INTO analyses(ts,sender,subject,score,label,findings,preview) VALUES(?,?,?,?,?,?,?)",
                  (datetime.now(timezone.utc).isoformat(timespec="seconds"), sender, subject,
                   result["score"], result["label"],
                   json.dumps([f["rule"] for f in result["findings"]]), (body or "")[:200]))


def fetch_all(path=None):
    init_db(path)
    with _conn(path) as c:
        return [dict(r) for r in c.execute("SELECT * FROM analyses ORDER BY id DESC").fetchall()]


def clear_history(path=None):
    init_db(path)
    with _conn(path) as c:
        c.execute("DELETE FROM analyses")