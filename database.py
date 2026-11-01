"""
DocShield Bharat Database Layer (database.py)
Supports Supabase PostgreSQL (ap-south-1 Mumbai region recommended) in production and automatically
falls back to local SQLite when DATABASE_URL is not configured.
All timestamps are recorded in Indian Standard Time (IST, UTC+05:30).
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from config import Config

IST_TZ = timezone(timedelta(hours=5, minutes=30))

# Optional PostgreSQL driver (installed via requirements.txt in production)
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False


def use_postgres() -> bool:
    """Return True if a PostgreSQL DATABASE_URL is configured and psycopg2 is installed."""
    return bool(Config.DATABASE_URL and Config.DATABASE_URL.startswith(("postgres://", "postgresql://")) and HAS_PSYCOPG2)


def get_connection():
    """Return a database connection (PostgreSQL in production, SQLite in local fallback)."""
    if use_postgres():
        return psycopg2.connect(Config.DATABASE_URL)
    conn = sqlite3.connect(Config.LOCAL_SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> str:
    """Initialize the document_scans table in PostgreSQL or SQLite."""
    conn = get_connection()
    try:
        if use_postgres():
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS document_scans (
                        id SERIAL PRIMARY KEY,
                        original_filename VARCHAR(255) NOT NULL,
                        stored_path VARCHAR(512) NOT NULL,
                        storage_backend VARCHAR(50) DEFAULT 'local',
                        file_type VARCHAR(20) NOT NULL,
                        file_size_bytes INTEGER NOT NULL,
                        sha256_hash VARCHAR(64) NOT NULL,
                        is_duplicate BOOLEAN DEFAULT FALSE,
                        duplicate_of_id INTEGER,
                        extracted_text TEXT,
                        extracted_name VARCHAR(255),
                        extracted_dates TEXT,
                        extracted_doc_numbers TEXT,
                        pdf_metadata TEXT,
                        fraud_indicators TEXT,
                        risk_score INTEGER NOT NULL DEFAULT 0,
                        risk_level VARCHAR(20) NOT NULL DEFAULT 'Low Risk',
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE INDEX IF NOT EXISTS idx_document_scans_sha256 ON document_scans(sha256_hash);
                """)
            conn.commit()
            return "PostgreSQL (Supabase India ap-south-1)"
        else:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS document_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_filename TEXT NOT NULL,
                    stored_path TEXT NOT NULL,
                    storage_backend TEXT DEFAULT 'local',
                    file_type TEXT NOT NULL,
                    file_size_bytes INTEGER NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    is_duplicate INTEGER DEFAULT 0,
                    duplicate_of_id INTEGER,
                    extracted_text TEXT,
                    extracted_name TEXT,
                    extracted_dates TEXT,
                    extracted_doc_numbers TEXT,
                    pdf_metadata TEXT,
                    fraud_indicators TEXT,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    risk_level TEXT NOT NULL DEFAULT 'Low Risk',
                    created_at TEXT NOT NULL
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_document_scans_sha256 ON document_scans(sha256_hash);")
            conn.commit()
            return "SQLite (Local Fallback)"
    finally:
        conn.close()


def _deserialize_row(row_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Parse JSON string fields into Python lists/dicts for templates."""
    result = dict(row_dict)
    result["is_duplicate"] = bool(result.get("is_duplicate"))
    for field, default in [
        ("extracted_dates", []),
        ("extracted_doc_numbers", []),
        ("pdf_metadata", {}),
        ("fraud_indicators", []),
    ]:
        raw_val = result.get(field)
        if isinstance(raw_val, str) and raw_val.strip():
            try:
                result[field] = json.loads(raw_val)
            except json.JSONDecodeError:
                result[field] = default
        elif raw_val is None:
            result[field] = default
    return result


def find_by_sha256(sha256_hash: str) -> Optional[Dict[str, Any]]:
    """Check if a document with the exact same SHA-256 hash was previously scanned."""
    conn = get_connection()
    try:
        if use_postgres():
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT * FROM document_scans WHERE sha256_hash = %s ORDER BY id ASC LIMIT 1",
                    (sha256_hash,),
                )
                row = cur.fetchone()
                return _deserialize_row(row) if row else None
        else:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM document_scans WHERE sha256_hash = ? ORDER BY id ASC LIMIT 1",
                (sha256_hash,),
            )
            row = cur.fetchone()
            return _deserialize_row(dict(row)) if row else None
    finally:
        conn.close()


def insert_scan_record(record: Dict[str, Any]) -> int:
    """Save a completed document scan record with IST timestamp and return its ID."""
    conn = get_connection()
    dates_json = json.dumps(record.get("extracted_dates", []))
    doc_nums_json = json.dumps(record.get("extracted_doc_numbers", []))
    metadata_json = json.dumps(record.get("pdf_metadata", {}))
    indicators_json = json.dumps(record.get("fraud_indicators", []))
    now_ist = datetime.now(IST_TZ).strftime("%d/%m/%Y %I:%M:%S %p IST")

    try:
        if use_postgres():
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO document_scans (
                        original_filename, stored_path, storage_backend, file_type,
                        file_size_bytes, sha256_hash, is_duplicate, duplicate_of_id,
                        extracted_text, extracted_name, extracted_dates,
                        extracted_doc_numbers, pdf_metadata, fraud_indicators,
                        risk_score, risk_level
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        record["original_filename"],
                        record["stored_path"],
                        record.get("storage_backend", "local"),
                        record["file_type"],
                        record["file_size_bytes"],
                        record["sha256_hash"],
                        bool(record.get("is_duplicate", False)),
                        record.get("duplicate_of_id"),
                        record.get("extracted_text", ""),
                        record.get("extracted_name"),
                        dates_json,
                        doc_nums_json,
                        metadata_json,
                        indicators_json,
                        int(record.get("risk_score", 0)),
                        record.get("risk_level", "Low Risk"),
                    ),
                )
                scan_id = cur.fetchone()[0]
            conn.commit()
            return scan_id
        else:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO document_scans (
                    original_filename, stored_path, storage_backend, file_type,
                    file_size_bytes, sha256_hash, is_duplicate, duplicate_of_id,
                    extracted_text, extracted_name, extracted_dates,
                    extracted_doc_numbers, pdf_metadata, fraud_indicators,
                    risk_score, risk_level, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["original_filename"],
                    record["stored_path"],
                    record.get("storage_backend", "local"),
                    record["file_type"],
                    record["file_size_bytes"],
                    record["sha256_hash"],
                    1 if record.get("is_duplicate", False) else 0,
                    record.get("duplicate_of_id"),
                    record.get("extracted_text", ""),
                    record.get("extracted_name"),
                    dates_json,
                    doc_nums_json,
                    metadata_json,
                    indicators_json,
                    int(record.get("risk_score", 0)),
                    record.get("risk_level", "Low Risk"),
                    now_ist,
                ),
            )
            scan_id = cur.lastrowid
            conn.commit()
            return scan_id
    finally:
        conn.close()


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve a single scan record by its primary key ID."""
    conn = get_connection()
    try:
        if use_postgres():
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM document_scans WHERE id = %s", (scan_id,))
                row = cur.fetchone()
                return _deserialize_row(row) if row else None
        else:
            cur = conn.cursor()
            cur.execute("SELECT * FROM document_scans WHERE id = ?", (scan_id,))
            row = cur.fetchone()
            return _deserialize_row(dict(row)) if row else None
    finally:
        conn.close()


def list_scans(limit: int = 100, risk_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve recent document scans, optionally filtered by risk level."""
    conn = get_connection()
    try:
        if use_postgres():
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if risk_filter in ("Low Risk", "Medium Risk", "High Risk"):
                    cur.execute(
                        "SELECT * FROM document_scans WHERE risk_level = %s ORDER BY id DESC LIMIT %s",
                        (risk_filter, limit),
                    )
                else:
                    cur.execute("SELECT * FROM document_scans ORDER BY id DESC LIMIT %s", (limit,))
                return [_deserialize_row(r) for r in cur.fetchall()]
        else:
            cur = conn.cursor()
            if risk_filter in ("Low Risk", "Medium Risk", "High Risk"):
                cur.execute(
                    "SELECT * FROM document_scans WHERE risk_level = ? ORDER BY id DESC LIMIT ?",
                    (risk_filter, limit),
                )
            else:
                cur.execute("SELECT * FROM document_scans ORDER BY id DESC LIMIT ?", (limit,))
            return [_deserialize_row(dict(r)) for r in cur.fetchall()]
    finally:
        conn.close()


def get_dashboard_stats() -> Dict[str, int]:
    """Compute aggregate statistics for the dashboard summary cards."""
    scans = list_scans(limit=1000)
    stats = {
        "total": len(scans),
        "low_risk": sum(1 for s in scans if s["risk_level"] == "Low Risk"),
        "medium_risk": sum(1 for s in scans if s["risk_level"] == "Medium Risk"),
        "high_risk": sum(1 for s in scans if s["risk_level"] == "High Risk"),
        "duplicates": sum(1 for s in scans if s["is_duplicate"]),
    }
    return stats
