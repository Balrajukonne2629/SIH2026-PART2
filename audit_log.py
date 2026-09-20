"""Append-Only Hash-Chained Audit Logger (PRD Addendum Section 4 Step 5).
Records tamper-evident compliance audit entries into SQLite table audit_ledger.
Each entry links cryptographically to the preceding entry's entryHash.
Provides standalone verify_chain() to detect any retrospective modifications.
Accepts legacy logfile parameter for backward compatibility with existing callers.
"""
import datetime
import hashlib
import json
import pathlib
from typing import Optional, Tuple
import database

BASE = pathlib.Path(__file__).parent.resolve()
DEFAULT_LOG_FILE = BASE / "audit_log.jsonl"
GENESIS_PREV_HASH = "0" * 64

def compute_entry_hash(entry_data: dict) -> str:
    """Computes SHA256 over canonical JSON of all entry fields excluding entryHash."""
    canonical_dict = {k: v for k, v in entry_data.items() if k != "entryHash"}
    canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

def get_last_entry(logfile: pathlib.Path = DEFAULT_LOG_FILE) -> Optional[dict]:
    """Reads the last entry of the sqlite log to retrieve the previous entryHash."""
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM audit_ledger ORDER BY id DESC LIMIT 1')
    row = cur.fetchone()
    conn.close()
    if row:
        return {
            "entry_id": row["entry_id"],
            "timestamp": row["timestamp"],
            "device_hostname": row["device_hostname"],
            "config_file_hash": row["config_file_hash"],
            "audit_results": json.loads(row["audit_results"]) if row["audit_results"] else {},
            "remediation_summary": json.loads(row["remediation_summary"]) if row["remediation_summary"] is not None else None,
            "prevEntryHash": row["prevEntryHash"],
            "entryHash": row["entryHash"]
        }
    return None

def create_audit_entry(csm: dict,
                       evals: dict,
                       raw_config_text: str,
                       remediation_summary: Optional[dict] = None,
                       logfile: pathlib.Path = DEFAULT_LOG_FILE) -> dict:
    """Builds a new hash-chained audit entry, computing prevEntryHash and entryHash."""
    last_entry = get_last_entry(logfile)
    prev_hash = last_entry["entryHash"] if last_entry and "entryHash" in last_entry else GENESIS_PREV_HASH

    now = datetime.datetime.now(datetime.timezone.utc)
    ts = now.isoformat()
    config_hash = hashlib.sha256(raw_config_text.encode("utf-8")).hexdigest()

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute('SELECT COUNT(*) FROM audit_ledger')
    existing_count = cur.fetchone()[0]
    conn.close()
    
    seq = existing_count + 1

    # Form minimal clean audit_results dict: {rule_id: status}
    audit_results = {rid: data["status"] for rid, data in evals.items()}

    entry_core = {
        "entry_id": f"AUDIT-{config_hash[:10]}-{int(now.timestamp())}-{now.microsecond:06d}-SEQ{seq:04d}",
        "timestamp": ts,
        "device_hostname": csm.get("device", {}).get("hostname", "unknown"),
        "config_file_hash": config_hash,
        "audit_results": audit_results,
        "remediation_summary": remediation_summary,
        "prevEntryHash": prev_hash
    }

    entry_hash = compute_entry_hash(entry_core)
    entry_core["entryHash"] = entry_hash
    return entry_core

def append_audit_entry(entry: dict, logfile: pathlib.Path = DEFAULT_LOG_FILE) -> str:
    """Appends an audit entry into SQLite.
    
    Uses sort_keys=True for JSON columns so that json.loads → json.dumps(sort_keys=True)
    in verify_chain produces the same canonical bytes as compute_entry_hash used at creation.
    """
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO audit_ledger 
        (entry_id, timestamp, device_hostname, config_file_hash, audit_results, remediation_summary, prevEntryHash, entryHash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        entry.get("entry_id"),
        entry.get("timestamp"),
        entry.get("device_hostname"),
        entry.get("config_file_hash"),
        json.dumps(entry.get("audit_results"), sort_keys=True),
        json.dumps(entry.get("remediation_summary"), sort_keys=True),
        entry.get("prevEntryHash"),
        entry.get("entryHash")
    ))
    conn.commit()
    conn.close()
    return entry["entryHash"]

def verify_chain(logfile: pathlib.Path = DEFAULT_LOG_FILE) -> Tuple[bool, str, int]:
    """Re-walks entire log table, recalculates all hashes, and verifies prevEntryHash linkage.
    Returns (is_valid, message, broken_entry_index).
    """
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM audit_ledger ORDER BY id ASC')
    rows = cur.fetchall()
    conn.close()
    
    if not rows:
        return False, "Log table is empty.", -1

    expected_prev = GENESIS_PREV_HASH
    for idx, row in enumerate(rows):
        try:
            entry = {
                "entry_id": row["entry_id"],
                "timestamp": row["timestamp"],
                "device_hostname": row["device_hostname"],
                "config_file_hash": row["config_file_hash"],
                "audit_results": json.loads(row["audit_results"]) if row["audit_results"] else {},
                "remediation_summary": json.loads(row["remediation_summary"]) if row["remediation_summary"] is not None else None,
                "prevEntryHash": row["prevEntryHash"],
                "entryHash": row["entryHash"]
            }
        except Exception as err:
            return False, f"Row parse error on entry {idx + 1}: {err}", idx + 1

        stored_entry_hash = entry.get("entryHash")
        stored_prev_hash = entry.get("prevEntryHash")

        # 1. Verify prevEntryHash links to previous record
        if stored_prev_hash != expected_prev:
            return (
                False,
                f"Broken chain at entry {idx + 1} ({entry.get('entry_id', 'unknown')}): "
                f"prevEntryHash mismatch. Expected '{expected_prev[:16]}...', found '{str(stored_prev_hash)[:16]}...'",
                idx + 1
            )

        # 2. Recalculate entryHash over fields
        computed_hash = compute_entry_hash(entry)
        if computed_hash != stored_entry_hash:
            return (
                False,
                f"Tamper detected at entry {idx + 1} ({entry.get('entry_id', 'unknown')}): "
                f"payload modified! Stored hash '{str(stored_entry_hash)[:16]}...' does not match recomputed hash '{computed_hash[:16]}...'",
                idx + 1
            )

        expected_prev = stored_entry_hash

    return True, f"All {len(rows)} log entries verified successfully. Hash chain intact.", 0
