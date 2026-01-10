# db_store.py
import sqlite3, json
from typing import Dict

DB_PATH = "alerts.db"

def init_db(path=DB_PATH):
    conn = sqlite3.connect(path, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        src TEXT,
        dst TEXT,
        reason TEXT,
        ciphertext_json TEXT
    );
    """)
    conn.commit()
    return conn

def save_encrypted_alert(conn, ts: str, src: str, dst: str, reason: str, ciphertext_dict: Dict):
    cur = conn.cursor()
    cur.execute("INSERT INTO alerts (ts, src, dst, reason, ciphertext_json) VALUES (?, ?, ?, ?, ?)",
                (ts, src, dst, reason, json.dumps(ciphertext_dict)))
    conn.commit()
    return cur.lastrowid

def fetch_all_alerts(conn):
    cur = conn.cursor()
    cur.execute("SELECT id, ts, src, dst, reason, ciphertext_json FROM alerts ORDER BY id DESC")
    rows = cur.fetchall()
    out = []
    for r in rows:
        obj = {"id": r[0], "ts": r[1], "src": r[2], "dst": r[3], "reason": r[4], "ciphertext": json.loads(r[5])}
        out.append(obj)
    return out
