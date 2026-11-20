"""Local SQLite storage. Scan history and feedback never leave this machine."""
import json, os, sqlite3
from collections import Counter
from contextlib import closing
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("AUREL_DB") or os.path.join(ROOT, "data", "aurel.db")


def connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, url TEXT, level TEXT, score INT, ts TEXT, source TEXT, domain TEXT, result TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY, url TEXT, scan_id INT, kind TEXT, ts TEXT)")
    return c


def save_scan(r, source="web"):
    with closing(connect()) as c, c:
        return c.execute("INSERT INTO scans (url,level,score,ts,source,domain,result) VALUES (?,?,?,?,?,?,?)",
                         (r["url"], r["level"], r["score"], datetime.now().isoformat(timespec="seconds"), source, r["registered_domain"], json.dumps(r))).lastrowid


def history(q=None, level=None, domain=None, limit=100):
    sql, args = "SELECT id,url,level,score,ts,source,result FROM scans WHERE 1=1", []
    if q:
        sql += " AND url LIKE ? ESCAPE '\\'"; args.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if level in ("low", "medium", "high"):
        sql += " AND level=?"; args.append(level)
    if domain:
        sql += " AND domain=?"; args.append(domain)
    with closing(connect()) as c:
        rows = c.execute(sql + " ORDER BY id DESC LIMIT ?", args + [min(int(limit), 200)]).fetchall()
    return [{**dict(r), "result": json.loads(r["result"])} for r in rows]


def clear():
    with closing(connect()) as c, c:
        c.execute("DELETE FROM scans")


def add_feedback(url, scan_id, kind):
    with closing(connect()) as c, c:
        c.execute("INSERT INTO feedback (url,scan_id,kind,ts) VALUES (?,?,?,?)", (url, scan_id, kind, datetime.now().isoformat(timespec="seconds")))


def stats():
    with closing(connect()) as c:
        rows = c.execute("SELECT level,score,ts,source,url,result FROM scans").fetchall()
        fb = c.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
    levels = Counter(r["level"] for r in rows)
    ind = Counter(f["indicator"].split(" (")[0].split(" of '")[0] for r in rows for f in json.loads(r["result"])["findings"])
    today = datetime.now().date()
    days = {(today - timedelta(d)).isoformat(): 0 for d in range(6, -1, -1)}
    for r in rows:
        if r["ts"][:10] in days:
            days[r["ts"][:10]] += 1
    recent = [{k: r[k] for k in ("url", "level", "score", "ts", "source")} for r in sorted(rows, key=lambda r: r["ts"], reverse=True)[:6]]
    return {"total": len(rows), "levels": {k: levels.get(k, 0) for k in ("low", "medium", "high")}, "top_indicators": ind.most_common(6),
            "per_day": days, "recent": recent, "avg_score": round(sum(r["score"] for r in rows) / len(rows), 1) if rows else 0,
            "feedback": fb, "sources": dict(Counter(r["source"] for r in rows))}
