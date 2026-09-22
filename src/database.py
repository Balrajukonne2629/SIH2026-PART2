import sqlite3
import json
import pathlib
import datetime
import hashlib
import os
import secrets
import uuid
from threading import Lock
from typing import Optional, Dict, Any, List, Tuple

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "auditor.db"

# Runtime state files
LOG_FILE = DATA_DIR / "audit_log.jsonl"
TRUSTED_FILE = DATA_DIR / "trusted_mappings.json"
PENDING_FILE = DATA_DIR / "pending_suggestions.json"

db_lock = Lock()

def get_connection():
    DATA_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def hash_password(password: str, salt_hex: Optional[str] = None) -> Tuple[str, str]:
    """Derives PBKDF2-HMAC-SHA256 key with 600,000 iterations using Python standard library.
    Returns (password_hash_hex, salt_hex).
    Never stores or logs plaintext passwords.
    """
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    return dk.hex(), salt.hex()

def migrate_schema_add_ownership(conn: sqlite3.Connection):
    """Idempotently and non-destructively adds nullable owner_user_id to audit tables."""
    cur = conn.cursor()
    # audit_sessions
    cur.execute("PRAGMA table_info(audit_sessions)")
    session_cols = [row[1] for row in cur.fetchall()]
    if "owner_user_id" not in session_cols:
        cur.execute("ALTER TABLE audit_sessions ADD COLUMN owner_user_id TEXT DEFAULT NULL")

    # audit_ledger
    cur.execute("PRAGMA table_info(audit_ledger)")
    ledger_cols = [row[1] for row in cur.fetchall()]
    if "owner_user_id" not in ledger_cols:
        cur.execute("ALTER TABLE audit_ledger ADD COLUMN owner_user_id TEXT DEFAULT NULL")
    conn.commit()

def migrate_schema_add_trusted_library_fields(conn: sqlite3.Connection):
    """Idempotently and non-destructively adds vendor, status, created_at, updated_at to trusted_mappings
    and vendor to pending_suggestions. Backfills existing rows with inferred vendor ('cisco'/'juniper')."""
    cur = conn.cursor()
    # trusted_mappings
    cur.execute("PRAGMA table_info(trusted_mappings)")
    tm_cols = [row[1] for row in cur.fetchall()]
    if "vendor" not in tm_cols:
        cur.execute("ALTER TABLE trusted_mappings ADD COLUMN vendor TEXT DEFAULT NULL")
    if "status" not in tm_cols:
        cur.execute("ALTER TABLE trusted_mappings ADD COLUMN status TEXT DEFAULT 'approved'")
    if "created_at" not in tm_cols:
        cur.execute("ALTER TABLE trusted_mappings ADD COLUMN created_at TEXT DEFAULT NULL")
    if "updated_at" not in tm_cols:
        cur.execute("ALTER TABLE trusted_mappings ADD COLUMN updated_at TEXT DEFAULT NULL")

    # pending_suggestions
    cur.execute("PRAGMA table_info(pending_suggestions)")
    ps_cols = [row[1] for row in cur.fetchall()]
    if "vendor" not in ps_cols:
        cur.execute("ALTER TABLE pending_suggestions ADD COLUMN vendor TEXT DEFAULT NULL")

    # Backfill vendor in trusted_mappings if NULL
    cur.execute("SELECT vendor_rule_id, vendor FROM trusted_mappings WHERE vendor IS NULL")
    for row in cur.fetchall():
        vrid = row[0] or ""
        inferred = "juniper" if (vrid.startswith("JUNOS-") or vrid.startswith("JUNIPER-")) else "cisco"
        cur.execute("UPDATE trusted_mappings SET vendor = ? WHERE vendor_rule_id = ?", (inferred, vrid))

    # Backfill vendor in pending_suggestions if NULL from suggestion JSON
    cur.execute("SELECT suggestion_id, suggestion, vendor FROM pending_suggestions WHERE vendor IS NULL")
    for row in cur.fetchall():
        sid, raw_sug = row[0], row[1]
        inferred = "cisco"
        try:
            if raw_sug:
                sug_data = json.loads(raw_sug)
                if "vendor" in sug_data and sug_data["vendor"]:
                    inferred = sug_data["vendor"]
                else:
                    new_rule = sug_data.get("suggested_new_rule") or {}
                    vrid = new_rule.get("vendor_rule_id") or ""
                    if vrid.startswith("JUNOS-") or vrid.startswith("JUNIPER-"):
                        inferred = "juniper"
        except Exception:
            pass
        cur.execute("UPDATE pending_suggestions SET vendor = ? WHERE suggestion_id = ?", (inferred, sid))

    conn.commit()

def migrate_schema_add_audit_reports(conn: sqlite3.Connection):
    """Idempotently and non-destructively creates audit_reports and audit_report_edits tables and indices."""
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS audit_reports (
            report_id TEXT PRIMARY KEY,
            audit_entry_id TEXT UNIQUE NOT NULL,
            session_id TEXT NOT NULL,
            vendor TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            system_snapshot TEXT NOT NULL,
            editable_content TEXT NOT NULL,
            FOREIGN KEY(audit_entry_id) REFERENCES audit_ledger(entry_id)
        )
    ''')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_audit_reports_entry_id ON audit_reports(audit_entry_id)')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_audit_reports_session_id ON audit_reports(session_id)')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS audit_report_edits (
            edit_id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            field_path TEXT NOT NULL,
            previous_value TEXT,
            new_value TEXT,
            edited_by TEXT NOT NULL,
            edited_at TEXT NOT NULL,
            FOREIGN KEY(report_id) REFERENCES audit_reports(report_id)
        )
    ''')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_audit_report_edits_rep_ver ON audit_report_edits(report_id, version)')
    conn.commit()

def seed_default_users(conn: sqlite3.Connection):
    """Provisions default accounts when users table is empty with PBKDF2 hashes."""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] > 0:
        return

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    seed_specs = [
        {
            "username": "secops_reviewer",
            "role": "reviewer",
            "is_authorized_approver": 1,
            "env_var": "INITIAL_REVIEWER_PASSWORD",
        },
        {
            "username": "netadmin_uploader",
            "role": "uploader",
            "is_authorized_approver": 0,
            "env_var": "INITIAL_UPLOADER_PASSWORD",
        },
        {
            "username": "auditor_viewer",
            "role": "viewer",
            "is_authorized_approver": 0,
            "env_var": "INITIAL_VIEWER_PASSWORD",
        },
    ]

    for spec in seed_specs:
        env_pw = os.environ.get(spec["env_var"])
        if env_pw:
            raw_pw = env_pw
        else:
            raw_pw = secrets.token_urlsafe(24)
            print(f"[BOOTSTRAP NOTICE] No {spec['env_var']} set. Provisioned '{spec['username']}' with generated initial password: {raw_pw}")
        pw_hash, salt = hash_password(raw_pw)
        cur.execute('''
            INSERT INTO users (user_id, username, password_hash, salt, role, is_authorized_approver, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        ''', (str(uuid.uuid4()), spec["username"], pw_hash, salt, spec["role"], spec["is_authorized_approver"], now_iso))
    conn.commit()

def initialize_database():
    with db_lock:
        conn = get_connection()
        cur = conn.cursor()
        
        # Schema
        cur.execute('''
            CREATE TABLE IF NOT EXISTS audit_sessions (
                session_id TEXT PRIMARY KEY,
                csm TEXT,
                evals TEXT,
                raw_config_text TEXT,
                filename TEXT,
                config_file_hash TEXT,
                created_at TEXT
            )
        ''')
        
        cur.execute('''
            CREATE TABLE IF NOT EXISTS trusted_mappings (
                vendor_rule_id TEXT PRIMARY KEY,
                common_rule_id TEXT,
                internalTitle TEXT,
                csmFieldChecked TEXT,
                condition TEXT,
                configuration_evidence TEXT,
                check_focus TEXT,
                frameworkMappings TEXT,
                version_info TEXT
            )
        ''')
        
        cur.execute('''
            CREATE TABLE IF NOT EXISTS pending_suggestions (
                suggestion_id TEXT PRIMARY KEY,
                timestamp TEXT,
                status TEXT,
                suggestion TEXT,
                reviewed_by TEXT,
                reviewed_at TEXT
            )
        ''')
        
        cur.execute('''
            CREATE TABLE IF NOT EXISTS audit_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id TEXT UNIQUE,
                timestamp TEXT,
                device_hostname TEXT,
                config_file_hash TEXT,
                audit_results TEXT,
                remediation_summary TEXT,
                prevEntryHash TEXT,
                entryHash TEXT
            )
        ''')

        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('uploader', 'reviewer', 'viewer')),
                is_authorized_approver INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        ''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')

        # Apply schema migrations for ownership
        migrate_schema_add_ownership(conn)
        # Apply schema migrations for trusted library
        migrate_schema_add_trusted_library_fields(conn)
        # Apply schema migrations for audit reports
        migrate_schema_add_audit_reports(conn)
        
        # Check legacy file migration
        cur.execute('SELECT COUNT(*) FROM audit_ledger')
        if cur.fetchone()[0] == 0 and LOG_FILE.exists():
            migrate_ledger(conn)
            
        cur.execute('SELECT COUNT(*) FROM trusted_mappings')
        if cur.fetchone()[0] == 0 and TRUSTED_FILE.exists():
            migrate_trusted_mappings(conn)
            
        cur.execute('SELECT COUNT(*) FROM pending_suggestions')
        if cur.fetchone()[0] == 0 and PENDING_FILE.exists():
            migrate_pending_suggestions(conn)

        # Seed default users
        seed_default_users(conn)
            
        conn.commit()
        conn.close()

def migrate_ledger(conn):
    lines = [l.strip() for l in LOG_FILE.read_text(encoding="utf-8").splitlines() if l.strip()]
    cur = conn.cursor()
    for line in lines:
        try:
            entry = json.loads(line)
            remed = json.dumps(entry["remediation_summary"]) if "remediation_summary" in entry else None
            cur.execute('''
                INSERT INTO audit_ledger 
                (entry_id, timestamp, device_hostname, config_file_hash, audit_results, remediation_summary, prevEntryHash, entryHash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry.get("entry_id"),
                entry.get("timestamp"),
                entry.get("device_hostname"),
                entry.get("config_file_hash"),
                json.dumps(entry.get("audit_results")),
                remed,
                entry.get("prevEntryHash"),
                entry.get("entryHash")
            ))
        except Exception as e:
            print(f"Error migrating ledger entry: {e}")

def migrate_trusted_mappings(conn):
    try:
        entries = json.loads(TRUSTED_FILE.read_text(encoding="utf-8"))
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(trusted_mappings)")
        cols = [row[1] for row in cur.fetchall()]
        has_vendor = "vendor" in cols
        for entry in entries:
            vrid = entry.get("vendor_rule_id", "")
            vendor = entry.get("vendor") or ("juniper" if (vrid.startswith("JUNOS-") or vrid.startswith("JUNIPER-")) else "cisco")
            status = entry.get("status", "approved")
            v_info = entry.get("version_info", {})
            approved_at = v_info.get("approved_at") if isinstance(v_info, dict) else None

            if has_vendor:
                cur.execute('''
                    INSERT OR REPLACE INTO trusted_mappings 
                    (vendor_rule_id, common_rule_id, internalTitle, csmFieldChecked, condition, configuration_evidence, check_focus, frameworkMappings, version_info, vendor, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    vrid,
                    entry.get("common_rule_id"),
                    entry.get("internalTitle"),
                    entry.get("csmFieldChecked"),
                    entry.get("condition"),
                    json.dumps(entry.get("configuration_evidence", [])),
                    json.dumps(entry.get("check_focus", [])),
                    json.dumps(entry.get("frameworkMappings", [])),
                    json.dumps(v_info),
                    vendor,
                    status,
                    approved_at,
                    approved_at
                ))
            else:
                cur.execute('''
                    INSERT OR REPLACE INTO trusted_mappings 
                    (vendor_rule_id, common_rule_id, internalTitle, csmFieldChecked, condition, configuration_evidence, check_focus, frameworkMappings, version_info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    vrid,
                    entry.get("common_rule_id"),
                    entry.get("internalTitle"),
                    entry.get("csmFieldChecked"),
                    entry.get("condition"),
                    json.dumps(entry.get("configuration_evidence", [])),
                    json.dumps(entry.get("check_focus", [])),
                    json.dumps(entry.get("frameworkMappings", [])),
                    json.dumps(v_info)
                ))
    except Exception as e:
        print(f"Error migrating trusted mappings: {e}")

def migrate_pending_suggestions(conn):
    try:
        entries = json.loads(PENDING_FILE.read_text(encoding="utf-8"))
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(pending_suggestions)")
        cols = [row[1] for row in cur.fetchall()]
        has_vendor = "vendor" in cols
        for entry in entries:
            sug = entry.get("suggestion", {})
            vendor = entry.get("vendor") or (sug.get("vendor") if isinstance(sug, dict) else None)
            if not vendor:
                vrid = sug.get("suggested_new_rule", {}).get("vendor_rule_id", "") if isinstance(sug, dict) else ""
                vendor = "juniper" if (vrid.startswith("JUNOS-") or vrid.startswith("JUNIPER-")) else "cisco"

            if has_vendor:
                cur.execute('''
                    INSERT OR REPLACE INTO pending_suggestions 
                    (suggestion_id, timestamp, status, suggestion, reviewed_by, reviewed_at, vendor)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    entry.get("suggestion_id"),
                    entry.get("timestamp"),
                    entry.get("status"),
                    json.dumps(sug),
                    entry.get("reviewed_by"),
                    entry.get("reviewed_at"),
                    vendor
                ))
            else:
                cur.execute('''
                    INSERT OR REPLACE INTO pending_suggestions 
                    (suggestion_id, timestamp, status, suggestion, reviewed_by, reviewed_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    entry.get("suggestion_id"),
                    entry.get("timestamp"),
                    entry.get("status"),
                    json.dumps(sug),
                    entry.get("reviewed_by"),
                    entry.get("reviewed_at")
                ))
    except Exception as e:
        print(f"Error migrating pending suggestions: {e}")

def create_user(
    username: str,
    role: str,
    password: Optional[str] = None,
    password_hash: Optional[str] = None,
    salt: Optional[str] = None,
    is_authorized_approver: int = 0,
    is_active: int = 1,
    user_id: Optional[str] = None,
    created_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Creates a user record. Passwords are safe-hashed using PBKDF2-HMAC-SHA256."""
    if not username or not username.strip():
        raise ValueError("Username cannot be empty.")
    if role not in ("uploader", "reviewer", "viewer"):
        raise ValueError(f"Invalid role: '{role}'. Must be uploader, reviewer, or viewer.")

    if password is not None:
        password_hash, salt = hash_password(password)
    elif password_hash is None or salt is None:
        raise ValueError("Must provide either 'password' or both 'password_hash' and 'salt'.")

    uid = user_id or str(uuid.uuid4())
    created_ts = created_at or datetime.datetime.now(datetime.timezone.utc).isoformat()

    with db_lock:
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute('''
                INSERT INTO users (user_id, username, password_hash, salt, role, is_authorized_approver, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (uid, username.strip(), password_hash, salt, role, int(is_authorized_approver), int(is_active), created_ts))
            conn.commit()
        finally:
            conn.close()

    return {
        "user_id": uid,
        "username": username.strip(),
        "password_hash": password_hash,
        "salt": salt,
        "role": role,
        "is_authorized_approver": int(is_authorized_approver),
        "is_active": int(is_active),
        "created_at": created_ts,
    }

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieves a user by username using case-insensitive match (COLLATE NOCASE)."""
    if not username or not username.strip():
        return None
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),))
        row = cur.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a user by user_id UUID."""
    if not user_id:
        return None
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return dict(row)
        return None
    finally:
        conn.close()

def list_users() -> List[Dict[str, Any]]:
    """Lists all user records."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM users ORDER BY created_at ASC")
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def save_session(session_data):
    with db_lock:
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute('''
                INSERT OR REPLACE INTO audit_sessions 
                (session_id, csm, evals, raw_config_text, filename, config_file_hash, created_at, owner_user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_data["session_id"],
                json.dumps(session_data["csm"]),
                json.dumps(session_data["evals"]),
                session_data["raw_config_text"],
                session_data["filename"],
                session_data["config_file_hash"],
                session_data["created_at"],
                session_data.get("owner_user_id")
            ))
            conn.commit()
        finally:
            conn.close()

def get_session(session_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM audit_sessions WHERE session_id = ?', (session_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        row_keys = row.keys()
        return {
            "session_id": row["session_id"],
            "csm": json.loads(row["csm"]),
            "evals": json.loads(row["evals"]),
            "raw_config_text": row["raw_config_text"],
            "filename": row["filename"],
            "config_file_hash": row["config_file_hash"],
            "created_at": row["created_at"],
            "owner_user_id": row["owner_user_id"] if "owner_user_id" in row_keys else None
        }
    return None

def _row_to_trusted_mapping(row: sqlite3.Row) -> Dict[str, Any]:
    row_keys = row.keys()
    v_info = json.loads(row["version_info"]) if row["version_info"] else {}
    vrid = row["vendor_rule_id"]
    inferred_vendor = "juniper" if (vrid.startswith("JUNOS-") or vrid.startswith("JUNIPER-")) else "cisco"
    return {
        "vendor_rule_id": vrid,
        "common_rule_id": row["common_rule_id"],
        "internalTitle": row["internalTitle"],
        "csmFieldChecked": row["csmFieldChecked"],
        "condition": row["condition"],
        "configuration_evidence": json.loads(row["configuration_evidence"]) if row["configuration_evidence"] else [],
        "check_focus": json.loads(row["check_focus"]) if row["check_focus"] else [],
        "frameworkMappings": json.loads(row["frameworkMappings"]) if row["frameworkMappings"] else [],
        "version_info": v_info,
        "vendor": row["vendor"] if ("vendor" in row_keys and row["vendor"]) else inferred_vendor,
        "status": row["status"] if ("status" in row_keys and row["status"]) else "approved",
        "created_at": row["created_at"] if ("created_at" in row_keys and row["created_at"]) else v_info.get("approved_at"),
        "updated_at": row["updated_at"] if ("updated_at" in row_keys and row["updated_at"]) else v_info.get("approved_at"),
    }

def get_trusted_mapping(vendor_rule_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a trusted mapping by vendor_rule_id."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM trusted_mappings WHERE vendor_rule_id = ?", (vendor_rule_id,))
        row = cur.fetchone()
        if row:
            return _row_to_trusted_mapping(row)
        return None
    finally:
        conn.close()

def list_trusted_mappings(vendor: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists trusted mappings, optionally filtered by vendor and/or status."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM trusted_mappings")
        rows = cur.fetchall()
        results = [_row_to_trusted_mapping(r) for r in rows]
        if vendor:
            v_clean = vendor.strip().lower()
            results = [r for r in results if (r.get("vendor") or "").lower() == v_clean]
        if status:
            s_clean = status.strip().lower()
            results = [r for r in results if (r.get("status") or "").lower() == s_clean]
        return results
    finally:
        conn.close()

def delete_trusted_mapping(vendor_rule_id: str) -> bool:
    """Deletes/retires a trusted mapping by vendor_rule_id. Returns True if deleted, False if not found."""
    with db_lock:
        conn = get_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT 1 FROM trusted_mappings WHERE vendor_rule_id = ?", (vendor_rule_id,))
            if not cur.fetchone():
                return False
            cur.execute("DELETE FROM trusted_mappings WHERE vendor_rule_id = ?", (vendor_rule_id,))
            conn.commit()
            return True
        finally:
            conn.close()

def _row_to_pending_suggestion(row: sqlite3.Row) -> Dict[str, Any]:
    row_keys = row.keys()
    sug = json.loads(row["suggestion"]) if row["suggestion"] else {}
    vrid = sug.get("suggested_new_rule", {}).get("vendor_rule_id", "") if isinstance(sug, dict) else ""
    inferred_vendor = "juniper" if (vrid.startswith("JUNOS-") or vrid.startswith("JUNIPER-")) else "cisco"
    row_vendor = row["vendor"] if "vendor" in row_keys else None
    sug_vendor = sug.get("vendor") if isinstance(sug, dict) else None
    final_vendor = row_vendor or sug_vendor or inferred_vendor
    return {
        "suggestion_id": row["suggestion_id"],
        "timestamp": row["timestamp"],
        "status": row["status"],
        "suggestion": sug,
        "reviewed_by": row["reviewed_by"],
        "reviewed_at": row["reviewed_at"],
        "vendor": final_vendor,
    }

def get_pending_suggestion(suggestion_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a pending suggestion record by suggestion_id."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM pending_suggestions WHERE suggestion_id = ?", (suggestion_id,))
        row = cur.fetchone()
        if row:
            return _row_to_pending_suggestion(row)
        return None
    finally:
        conn.close()

def list_pending_suggestions(vendor: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists pending suggestions, optionally filtered by vendor and/or status."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM pending_suggestions ORDER BY timestamp DESC")
        rows = cur.fetchall()
        results = [_row_to_pending_suggestion(r) for r in rows]
        if vendor:
            v_clean = vendor.strip().lower()
            results = [r for r in results if (r.get("vendor") or "").lower() == v_clean]
        if status:
            s_clean = status.strip().lower()
            results = [r for r in results if (r.get("status") or "").lower() == s_clean]
        return results
    finally:
        conn.close()


# --- Audit Report Persistence (Phase 3D.2) ---

def _row_to_audit_report_dict(row: sqlite3.Row, edit_rows: List[sqlite3.Row]) -> Dict[str, Any]:
    system_snap = json.loads(row["system_snapshot"]) if row["system_snapshot"] else {}
    editable_content = json.loads(row["editable_content"]) if row["editable_content"] else {}

    edits = []
    for er in edit_rows:
        prev_v = er["previous_value"]
        try:
            prev_v = json.loads(prev_v) if prev_v is not None else None
        except Exception:
            pass
        new_v = er["new_value"]
        try:
            new_v = json.loads(new_v) if new_v is not None else None
        except Exception:
            pass

        edits.append({
            "edit_id": er["edit_id"],
            "report_id": er["report_id"],
            "version": int(er["version"]),
            "field_path": er["field_path"],
            "previous_value": prev_v,
            "new_value": new_v,
            "edited_by": er["edited_by"],
            "edited_at": er["edited_at"],
        })

    return {
        "report_id": row["report_id"],
        "audit_entry_id": row["audit_entry_id"],
        "session_id": row["session_id"],
        "vendor": row["vendor"],
        "version": int(row["version"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "created_by": row["created_by"],
        "device_metadata": system_snap.get("device_metadata", {}),
        "configuration_metadata": system_snap.get("configuration_metadata", {}),
        "frameworks": system_snap.get("frameworks", []),
        "remediation": system_snap.get("remediation", []),
        "conflict_warnings": system_snap.get("conflict_warnings", []),
        "ai_mapping_provenance": system_snap.get("ai_mapping_provenance", []),
        "editable_content": editable_content,
        "edit_metadata": edits,
    }


def save_audit_report(report_data: Any) -> Dict[str, Any]:
    """Persists a new canonical AuditReport into SQLite.

    Hard Invariants:
    1. Enforces SQLite foreign key audit_entry_id -> audit_ledger(entry_id).
    2. Enforces uniqueness of report_id and audit_entry_id (One Audit = One Canonical Report).
    3. Saves system_snapshot as an immutable baseline snapshot.
    """
    if hasattr(report_data, "to_dict"):
        r_dict = report_data.to_dict()
    elif isinstance(report_data, dict):
        r_dict = report_data
    else:
        raise TypeError(f"Expected AuditReport or dict, got {type(report_data).__name__}")

    system_snapshot = json.dumps({
        "device_metadata": r_dict.get("device_metadata", {}),
        "configuration_metadata": r_dict.get("configuration_metadata", {}),
        "frameworks": r_dict.get("frameworks", []),
        "remediation": r_dict.get("remediation", []),
        "conflict_warnings": r_dict.get("conflict_warnings", []),
        "ai_mapping_provenance": r_dict.get("ai_mapping_provenance", []),
    }, sort_keys=True)

    editable_content = json.dumps(r_dict.get("editable_content", {}), sort_keys=True)

    with db_lock:
        conn = get_connection()
        cur = conn.cursor()
        try:
            # Check if canonical report for this audit_entry_id already exists
            cur.execute("SELECT report_id FROM audit_reports WHERE audit_entry_id = ?", (r_dict["audit_entry_id"],))
            existing_row = cur.fetchone()
            if existing_row:
                import src.audit_report as audit_report
                raise audit_report.DuplicateReportError(
                    f"A canonical report '{existing_row[0]}' already exists for audit entry '{r_dict['audit_entry_id']}'."
                )

            cur.execute('''
                INSERT INTO audit_reports
                (report_id, audit_entry_id, session_id, vendor, version, created_at, updated_at, created_by, system_snapshot, editable_content)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                r_dict["report_id"],
                r_dict["audit_entry_id"],
                r_dict["session_id"],
                r_dict["vendor"],
                int(r_dict.get("version", 1)),
                r_dict["created_at"],
                r_dict["updated_at"],
                r_dict.get("created_by", "system"),
                system_snapshot,
                editable_content
            ))

            for edit in r_dict.get("edit_metadata", []):
                cur.execute('''
                    INSERT INTO audit_report_edits
                    (edit_id, report_id, version, field_path, previous_value, new_value, edited_by, edited_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    edit["edit_id"],
                    r_dict["report_id"],
                    int(edit["version"]),
                    edit["field_path"],
                    json.dumps(edit["previous_value"]) if edit["previous_value"] is not None else None,
                    json.dumps(edit["new_value"]) if edit["new_value"] is not None else None,
                    edit["edited_by"],
                    edit["edited_at"]
                ))
            conn.commit()
        finally:
            conn.close()

    return r_dict


def get_audit_report(report_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an AuditReport by its report_id, including complete edit provenance history."""
    if not report_id:
        return None
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM audit_reports WHERE report_id = ?", (report_id,))
        row = cur.fetchone()
        if not row:
            return None
        cur.execute(
            "SELECT * FROM audit_report_edits WHERE report_id = ? ORDER BY version ASC, edited_at ASC",
            (report_id,)
        )
        edit_rows = cur.fetchall()
        return _row_to_audit_report_dict(row, edit_rows)
    finally:
        conn.close()


def get_audit_report_by_entry_id(audit_entry_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves the canonical AuditReport for a given audit_entry_id."""
    if not audit_entry_id:
        return None
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM audit_reports WHERE audit_entry_id = ?", (audit_entry_id,))
        row = cur.fetchone()
        if not row:
            return None
        cur.execute(
            "SELECT * FROM audit_report_edits WHERE report_id = ? ORDER BY version ASC, edited_at ASC",
            (row["report_id"],)
        )
        edit_rows = cur.fetchall()
        return _row_to_audit_report_dict(row, edit_rows)
    finally:
        conn.close()


def record_report_edit(
    report_id: str,
    field_path: str,
    new_value: Any,
    edited_by: str,
    expected_version: int
) -> Dict[str, Any]:
    """Records a human edit to an audit report with optimistic concurrency protection.

    Hard Invariants:
    1. Validates field_path against human-editable allowlist.
    2. Enforces expected_version == current_version. If stale, rejects without modifying state.
    3. Leaves system_snapshot and audit_ledger completely untouched.
    4. Increments version and records immutable ReportEdit in audit_report_edits.
    """
    import src.audit_report as audit_report

    # 1. Path allowlist validation
    audit_report.validate_editable_field_path(field_path)

    if not edited_by or not str(edited_by).strip():
        raise ValueError("edited_by must be a non-empty authenticated user identifier.")

    with db_lock:
        conn = get_connection()
        cur = conn.cursor()
        try:
            # 2. Fetch current report row
            cur.execute("SELECT * FROM audit_reports WHERE report_id = ?", (report_id,))
            row = cur.fetchone()
            if not row:
                raise audit_report.ReportNotFoundError(f"AuditReport '{report_id}' not found.")

            current_version = int(row["version"])

            # 3. Optimistic concurrency check (Mandatory Adjustment 3)
            if expected_version != current_version:
                raise audit_report.StaleReportVersionError(
                    f"Stale report edit rejected: caller expected version {expected_version}, "
                    f"but current report version is {current_version}."
                )

            # 4. Extract and update editable_content
            raw_content = json.loads(row["editable_content"]) if row["editable_content"] else {}
            content_obj = audit_report.HumanEditableContent.from_dict(raw_content)

            previous_value = content_obj.get_field(field_path)
            content_obj.set_field(field_path, new_value)

            new_version = current_version + 1
            edit_id = str(uuid.uuid4())
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

            # 5. Insert edit record into audit_report_edits
            cur.execute('''
                INSERT INTO audit_report_edits
                (edit_id, report_id, version, field_path, previous_value, new_value, edited_by, edited_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                edit_id,
                report_id,
                new_version,
                field_path,
                json.dumps(previous_value) if previous_value is not None else None,
                json.dumps(new_value) if new_value is not None else None,
                edited_by.strip(),
                now_iso
            ))

            # 6. Update audit_reports (system_snapshot is explicitly NOT modified!)
            updated_content_json = json.dumps(content_obj.to_dict(), sort_keys=True)
            cur.execute('''
                UPDATE audit_reports
                SET editable_content = ?, version = ?, updated_at = ?
                WHERE report_id = ?
            ''', (
                updated_content_json,
                new_version,
                now_iso,
                report_id
            ))

            conn.commit()
        finally:
            conn.close()

    updated_rep = get_audit_report(report_id)
    if not updated_rep:
        raise audit_report.ReportNotFoundError(f"AuditReport '{report_id}' not found after update.")
    return updated_rep


def list_report_edits(report_id: str) -> List[Dict[str, Any]]:
    """Returns the full edit history for an audit report ordered chronologically."""
    if not report_id:
        return []
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT * FROM audit_report_edits WHERE report_id = ? ORDER BY version ASC, edited_at ASC",
            (report_id,)
        )
        rows = cur.fetchall()
        edits = []
        for r in rows:
            prev_v = r["previous_value"]
            try:
                prev_v = json.loads(prev_v) if prev_v is not None else None
            except Exception:
                pass
            new_v = r["new_value"]
            try:
                new_v = json.loads(new_v) if new_v is not None else None
            except Exception:
                pass

            edits.append({
                "edit_id": r["edit_id"],
                "report_id": r["report_id"],
                "version": int(r["version"]),
                "field_path": r["field_path"],
                "previous_value": prev_v,
                "new_value": new_v,
                "edited_by": r["edited_by"],
                "edited_at": r["edited_at"],
            })
        return edits
    finally:
        conn.close()
