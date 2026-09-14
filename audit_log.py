"""Append-Only Hash-Chained Audit Logger (PRD Addendum Section 4 Step 5).
Records tamper-evident compliance audit entries into audit_log.jsonl.
Each entry links cryptographically to the preceding entry's entryHash.
Provides standalone verify_chain() to detect any retrospective modifications.
"""
import datetime
import hashlib
import json
import pathlib
from typing import Optional, Tuple

BASE = pathlib.Path(__file__).parent.resolve()
DEFAULT_LOG_FILE = BASE / "audit_log.jsonl"
GENESIS_PREV_HASH = "0" * 64

def compute_entry_hash(entry_data: dict) -> str:
    """Computes SHA256 over canonical JSON of all entry fields excluding entryHash."""
    canonical_dict = {k: v for k, v in entry_data.items() if k != "entryHash"}
    canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

def get_last_entry(logfile: pathlib.Path = DEFAULT_LOG_FILE) -> Optional[dict]:
    """Reads the last line of the jsonl log to retrieve the previous entryHash."""
    if not logfile.exists():
        return None
    lines = [l.strip() for l in logfile.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not lines:
        return None
    try:
        return json.loads(lines[-1])
    except Exception:
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

    existing_count = 0
    if logfile.exists():
        existing_count = len([l for l in logfile.read_text(encoding="utf-8").splitlines() if l.strip()])
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
    """Appends an audit entry as a single line of JSON to audit_log.jsonl."""
    line = json.dumps(entry, sort_keys=True)
    with logfile.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    return entry["entryHash"]

def verify_chain(logfile: pathlib.Path = DEFAULT_LOG_FILE) -> Tuple[bool, str, int]:
    """Re-walks entire logfile, recalculates all hashes, and verifies prevEntryHash linkage.
    Returns (is_valid, message, broken_entry_index).
    """
    if not logfile.exists():
        return False, f"Log file '{logfile.name}' does not exist.", -1

    lines = [l.strip() for l in logfile.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not lines:
        return False, "Log file is empty.", -1

    expected_prev = GENESIS_PREV_HASH
    for idx, raw_line in enumerate(lines):
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError as err:
            return False, f"JSON parse error on entry {idx + 1}: {err}", idx + 1

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

    return True, f"All {len(lines)} log entries verified successfully. Hash chain intact.", 0
