import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect("/var/lib/audit/records.db")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS audits (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        passed INTEGER,
        failed INTEGER,
        report_path TEXT
    )
    """)
    conn.close()

def log_audit(results: list):
    conn = sqlite3.connect("/var/lib/audit/records.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audits VALUES (?, ?, ?, ?, ?)",
        (
            None,
            datetime.now().isoformat(),
            sum(1 for r in results if r["status"] == "PASS"),
            sum(1 for r in results if r["status"] == "FAIL"),
            f"/var/log/audit-{datetime.now().date()}.html"
        )
    )
    conn.commit()
    conn.close()
