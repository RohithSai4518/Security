"""
SQLite-backed Alert Store and Notification Dispatcher.
"""

import sqlite3
import datetime
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class Alert:
    timestamp: str
    source_ip: str
    severity: str
    category: str
    rule_id: str
    summary: str
    raw_event: str

class AlertManager:
    """Manages alert storage, retrieval, and statistics."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self._conn:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source_ip TEXT,
                    severity TEXT,
                    category TEXT,
                    rule_id TEXT,
                    summary TEXT,
                    raw_event TEXT
                )
            """)

    def add_alert(self, alert: Alert):
        with self._conn:
            self._conn.execute("""
                INSERT INTO security_alerts (timestamp, source_ip, severity, category, rule_id, summary, raw_event)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.timestamp,
                alert.source_ip,
                alert.severity,
                alert.category,
                alert.rule_id,
                alert.summary,
                alert.raw_event
            ))

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        self._conn.row_factory = sqlite3.Row
        cursor = self._conn.execute("SELECT * FROM security_alerts ORDER BY id DESC")
        return [dict(row) for row in cursor.fetchall()]

    def get_severity_summary(self) -> Dict[str, int]:
        cursor = self._conn.execute("SELECT severity, COUNT(*) FROM security_alerts GROUP BY severity")
        counts = {row[0]: row[1] for row in cursor.fetchall()}
        return {
            "CRITICAL": counts.get("CRITICAL", 0),
            "HIGH": counts.get("HIGH", 0),
            "MEDIUM": counts.get("MEDIUM", 0),
            "LOW": counts.get("LOW", 0),
        }

    def get_top_attackers(self, limit: int = 5) -> List[Dict[str, Any]]:
        cursor = self._conn.execute("""
            SELECT source_ip, COUNT(*) as count 
            FROM security_alerts 
            WHERE source_ip != 'UNKNOWN'
            GROUP BY source_ip 
            ORDER BY count DESC 
            LIMIT ?
        """, (limit,))
        return [{"ip": row[0], "alert_count": row[1]} for row in cursor.fetchall()]

