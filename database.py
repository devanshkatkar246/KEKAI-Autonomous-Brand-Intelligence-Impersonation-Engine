import sqlite3
import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional

DB_PATH = Path("./brand_protection.db").resolve()


def get_db_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initializes SQLite database schema for fingerprint store and case timeline event logs.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_type TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            ip_address TEXT,
            registrar TEXT,
            phash TEXT,
            dhash TEXT,
            target_brand TEXT,
            confidence REAL,
            intent_label TEXT,
            intent_confidence REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata_json TEXT
        )
    """)

    # Check for migration if columns do not exist in existing table
    cursor.execute("PRAGMA table_info(assets)")
    columns = [row["name"] for row in cursor.fetchall()]
    if "intent_label" not in columns:
        cursor.execute("ALTER TABLE assets ADD COLUMN intent_label TEXT")
    if "intent_confidence" not in columns:
        cursor.execute("ALTER TABLE assets ADD COLUMN intent_confidence REAL")
    if "sources_json" not in columns:
        cursor.execute("ALTER TABLE assets ADD COLUMN sources_json TEXT")
    if "is_known_phishing" not in columns:
        cursor.execute("ALTER TABLE assets ADD COLUMN is_known_phishing INTEGER DEFAULT 0")
    if "provenance_json" not in columns:
        cursor.execute("ALTER TABLE assets ADD COLUMN provenance_json TEXT")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_asset_id ON assets(asset_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip ON assets(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_phash ON assets(phash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_brand ON assets(target_brand)")

    # Timeline event audit log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_timeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            description TEXT NOT NULL,
            metadata_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_events ON case_timeline_events(case_id)")
    cursor.execute("""CREATE TABLE IF NOT EXISTS abuse_snapshots (snapshot_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, fingerprint TEXT NOT NULL, snapshot_json TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS abuse_approvals (approval_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, status TEXT NOT NULL, approved_by TEXT, approved_at TIMESTAMP, expires_at TIMESTAMP, revoked_at TIMESTAMP)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS abuse_submissions (submission_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, snapshot_id TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE, state TEXT NOT NULL, provider_report_id TEXT, error_code TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    cursor.execute("PRAGMA table_info(abuse_submissions)")
    cols=[r['name'] for r in cursor.fetchall()]
    if 'lease_expires_at' not in cols: cursor.execute("ALTER TABLE abuse_submissions ADD COLUMN lease_expires_at TIMESTAMP")

    conn.commit()
    conn.close()

def abuse_execute(sql, values=()):
    init_db(); conn=get_db_connection(); cur=conn.cursor(); cur.execute(sql, values); conn.commit(); conn.close()

def abuse_one(sql, values=()):
    init_db(); conn=get_db_connection(); cur=conn.cursor(); cur.execute(sql, values); row=cur.fetchone(); conn.close(); return dict(row) if row else None


def insert_scanned_asset(
    asset_type: str,
    asset_id: str,
    ip_address: Optional[str] = None,
    registrar: Optional[str] = None,
    phash: Optional[str] = None,
    dhash: Optional[str] = None,
    target_brand: Optional[str] = None,
    confidence: Optional[float] = None,
    intent_label: Optional[str] = None,
    intent_confidence: Optional[float] = None,
    metadata: Optional[Dict[str, Any]] = None
):
    """
    Inserts or updates a scanned asset fingerprint in SQLite.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM assets WHERE asset_id = ? AND asset_type = ?", (asset_id, asset_type))
    row = cursor.fetchone()

    meta_str = json.dumps(metadata or {})

    if row:
        cursor.execute("""
            UPDATE assets SET
                ip_address = COALESCE(?, ip_address),
                registrar = COALESCE(?, registrar),
                phash = COALESCE(?, phash),
                dhash = COALESCE(?, dhash),
                target_brand = COALESCE(?, target_brand),
                confidence = COALESCE(?, confidence),
                intent_label = COALESCE(?, intent_label),
                intent_confidence = COALESCE(?, intent_confidence),
                metadata_json = ?
            WHERE id = ?
        """, (ip_address, registrar, phash, dhash, target_brand, confidence, intent_label, intent_confidence, meta_str, row["id"]))
    else:
        cursor.execute("""
            INSERT INTO assets (asset_type, asset_id, ip_address, registrar, phash, dhash, target_brand, confidence, intent_label, intent_confidence, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (asset_type, asset_id, ip_address, registrar, phash, dhash, target_brand, confidence, intent_label, intent_confidence, meta_str))

    conn.commit()
    conn.close()


def fetch_all_assets() -> List[Dict[str, Any]]:
    """
    Fetches all recorded asset fingerprints from SQLite.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "asset_type": r["asset_type"],
            "asset_id": r["asset_id"],
            "ip_address": r["ip_address"],
            "registrar": r["registrar"],
            "phash": r["phash"],
            "dhash": r["dhash"],
            "target_brand": r["target_brand"],
            "confidence": r["confidence"],
            "intent_label": r["intent_label"] if "intent_label" in r.keys() else None,
            "intent_confidence": r["intent_confidence"] if "intent_confidence" in r.keys() else None,
            "created_at": r["created_at"],
            "metadata": json.loads(r["metadata_json"] or "{}")
        })
    return results


def log_case_event(case_id: str, event_type: str, description: str, metadata: Optional[Dict[str, Any]] = None):
    """
    Logs an append-only timeline event for a case.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    meta_str = json.dumps(metadata or {})
    cursor.execute("""
        INSERT INTO case_timeline_events (case_id, event_type, description, metadata_json)
        VALUES (?, ?, ?, ?)
    """, (case_id, event_type, description, meta_str))
    conn.commit()
    conn.close()


def fetch_case_timeline(case_id: str) -> List[Dict[str, Any]]:
    """
    Fetches chronological timeline events for a given case_id.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM case_timeline_events
        WHERE case_id = ? OR case_id = 'default'
        ORDER BY id ASC
    """, (case_id,))
    rows = cursor.fetchall()
    conn.close()

    events = []
    for r in rows:
        events.append({
            "id": r["id"],
            "case_id": r["case_id"],
            "event_type": r["event_type"],
            "description": r["description"],
            "metadata": json.loads(r["metadata_json"] or "{}"),
            "created_at": r["created_at"]
        })
    return events
