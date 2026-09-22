import os
import pathlib
import json
import sqlite3
import datetime
import pytest

import database
import audit_log
from main import app
from fastapi.testclient import TestClient

client = TestClient(app)

def setup_module(module):
    database.DB_PATH = database.DATA_DIR / "test_auditor.db"
    if database.DB_PATH.exists():
        os.remove(database.DB_PATH)
    database.initialize_database()

def teardown_module(module):
    import gc
    gc.collect()
    if database.DB_PATH.exists():
        try:
            os.remove(database.DB_PATH)
        except OSError:
            pass

def test_initialization():
    assert database.DB_PATH.exists()
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cur.fetchall()]
    assert "audit_sessions" in tables
    assert "trusted_mappings" in tables
    assert "pending_suggestions" in tables
    assert "audit_ledger" in tables
    conn.close()

def test_audit_session_persistence():
    session_data = {
        "session_id": "test-session-123",
        "csm": {"device": {"hostname": "r1"}},
        "evals": {"CISCO-001": {"status": "Pass"}},
        "raw_config_text": "hostname r1\n",
        "filename": "test.txt",
        "config_file_hash": "abcdef",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
    database.save_session(session_data)
    loaded = database.get_session("test-session-123")
    assert loaded is not None
    assert loaded["csm"]["device"]["hostname"] == "r1"
    assert loaded["config_file_hash"] == "abcdef"

def test_trusted_mapping_persistence():
    import ai_suggester
    
    # store pending
    sug_id = ai_suggester.store_suggestion({
        "raw_line": "test line",
        "suggested_new_rule": {
            "internalTitle": "Test Rule",
            "csmFieldChecked": "csm.test",
            "condition": "not_null"
        }
    })
    
    # approve it
    ai_suggester.approve_suggestion(sug_id, "admin", "approve")
    
    # check db
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM trusted_mappings")
    rows = cur.fetchall()
    assert len(rows) > 0
    
    # Test reject does not change
    sug_id2 = ai_suggester.store_suggestion({
        "raw_line": "test line 2",
        "suggested_new_rule": {
            "internalTitle": "Test Rule 2",
            "csmFieldChecked": "csm.test2",
            "condition": "not_null"
        }
    })
    ai_suggester.approve_suggestion(sug_id2, "admin", "reject")
    cur.execute("SELECT * FROM pending_suggestions WHERE suggestion_id = ?", (sug_id2,))
    assert cur.fetchone()["status"] == "rejected"
    
    cur.execute("SELECT COUNT(*) FROM trusted_mappings")
    assert cur.fetchone()[0] == len(rows)  # Still same size
    
    conn.close()

def test_audit_record_ledger_persistence():
    import audit_log
    entry = audit_log.create_audit_entry(
        {"device": {"hostname": "r2"}},
        {"CISCO-001": {"status": "Fail"}},
        "hostname r2\n"
    )
    audit_log.append_audit_entry(entry)
    
    valid, msg, broken_idx = audit_log.verify_chain()
    assert valid is True, msg

def test_duplicate_finalization_safety():
    import audit_log
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM audit_ledger")
    initial_count = cur.fetchone()[0]
    conn.close()

    entry = audit_log.create_audit_entry(
        {"device": {"hostname": "r3"}},
        {"CISCO-001": {"status": "Pass"}},
        "hostname r3\n"
    )
    # 1. First append succeeds
    h1 = audit_log.append_audit_entry(entry)
    assert h1 == entry["entryHash"]

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM audit_ledger")
    assert cur.fetchone()[0] == initial_count + 1
    conn.close()

    # 2. Attempt identical finalization (same entry_id)
    with pytest.raises(sqlite3.IntegrityError):
        audit_log.append_audit_entry(entry)
    import gc
    gc.collect()

    # 3. Ledger entry count does not increase
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM audit_ledger")
    assert cur.fetchone()[0] == initial_count + 1
    conn.close()

    # 4. Hash chain remains intact and valid
    valid, msg, _ = audit_log.verify_chain()
    assert valid is True, msg
    gc.collect()

def test_users_table_and_columns():
    """Verify users table creation and exact required columns."""
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    assert cur.fetchone() is not None, "Table 'users' must exist"

    cur.execute("PRAGMA table_info(users)")
    cols = {row[1]: {"type": row[2], "notnull": row[3], "pk": row[5]} for row in cur.fetchall()}
    conn.close()

    required_cols = {
        "user_id", "username", "password_hash", "salt",
        "role", "is_authorized_approver", "is_active", "created_at"
    }
    for col in required_cols:
        assert col in cols, f"Missing required column '{col}' in users table"
    assert cols["user_id"]["pk"] == 1, "user_id must be primary key"
    assert cols["username"]["notnull"] == 1, "username must be NOT NULL"
    assert cols["password_hash"]["notnull"] == 1, "password_hash must be NOT NULL"

def test_owner_user_id_columns_nullable():
    """Verify owner_user_id exists as a nullable column on audit_sessions and audit_ledger."""
    conn = database.get_connection()
    cur = conn.cursor()

    cur.execute("PRAGMA table_info(audit_sessions)")
    session_cols = {row[1]: {"notnull": row[3]} for row in cur.fetchall()}
    assert "owner_user_id" in session_cols, "owner_user_id must exist in audit_sessions"
    assert session_cols["owner_user_id"]["notnull"] == 0, "owner_user_id in audit_sessions must be nullable"

    cur.execute("PRAGMA table_info(audit_ledger)")
    ledger_cols = {row[1]: {"notnull": row[3]} for row in cur.fetchall()}
    assert "owner_user_id" in ledger_cols, "owner_user_id must exist in audit_ledger"
    assert ledger_cols["owner_user_id"]["notnull"] == 0, "owner_user_id in audit_ledger must be nullable"
    conn.close()

def test_seed_users_and_approver_constraint():
    """Verify that exactly the 3 expected seed accounts are created with exactly one authorized approver."""
    users = database.list_users()
    usernames = {u["username"] for u in users}
    assert usernames >= {"secops_reviewer", "netadmin_uploader", "auditor_viewer"}

    reviewer = database.get_user_by_username("secops_reviewer")
    uploader = database.get_user_by_username("netadmin_uploader")
    viewer = database.get_user_by_username("auditor_viewer")

    assert reviewer is not None
    assert reviewer["role"] == "reviewer"
    assert reviewer["is_authorized_approver"] == 1
    assert reviewer["is_active"] == 1

    assert uploader is not None
    assert uploader["role"] == "uploader"
    assert uploader["is_authorized_approver"] == 0
    assert uploader["is_active"] == 1

    assert viewer is not None
    assert viewer["role"] == "viewer"
    assert viewer["is_authorized_approver"] == 0
    assert viewer["is_active"] == 1

    # Exactly one user in the database must have is_authorized_approver = 1
    approvers = [u for u in users if u["is_authorized_approver"] == 1]
    assert len(approvers) == 1, f"Expected exactly 1 authorized approver, found {len(approvers)}"
    assert approvers[0]["username"] == "secops_reviewer"

def test_no_plaintext_passwords_persisted():
    """Verify that no seed or created user stores plaintext passwords."""
    users = database.list_users()
    for u in users:
        pw_hash = u["password_hash"]
        salt = u["salt"]
        # SHA-256 output is 64 hex characters
        assert len(pw_hash) == 64, f"password_hash for {u['username']} must be 64 hex characters"
        # 16-byte salt is 32 hex characters
        assert len(salt) == 32, f"salt for {u['username']} must be 32 hex characters"
        # Must not match common plaintext strings
        assert pw_hash not in ("password", "admin", "secret", "123456", u["username"])
        assert salt != pw_hash

def test_create_user_and_get_user_by_username():
    """Verify create_user() and get_user_by_username() / get_user_by_id()."""
    created = database.create_user(
        username="qa_auditor",
        role="viewer",
        password="ValidTestPassword#2026!"
    )
    assert created["username"] == "qa_auditor"
    assert created["role"] == "viewer"
    assert created["is_authorized_approver"] == 0
    assert len(created["password_hash"]) == 64
    assert created["password_hash"] != "ValidTestPassword#2026!"

    fetched = database.get_user_by_username("qa_auditor")
    assert fetched is not None
    assert fetched["user_id"] == created["user_id"]
    assert fetched["username"] == "qa_auditor"
    assert fetched["password_hash"] == created["password_hash"]

    by_id = database.get_user_by_id(created["user_id"])
    assert by_id is not None
    assert by_id["username"] == "qa_auditor"

def test_duplicate_and_case_insensitive_username_uniqueness():
    """Verify unique constraint and case-insensitive username collision rejection."""
    # 1. Exact duplicate rejected
    with pytest.raises(sqlite3.IntegrityError):
        database.create_user(username="secops_reviewer", role="viewer", password="AnotherPassword123!")

    # 2. Case-insensitive duplicate rejected (COLLATE NOCASE)
    with pytest.raises(sqlite3.IntegrityError):
        database.create_user(username="SECOPS_REVIEWER", role="uploader", password="AnotherPassword123!")

    with pytest.raises(sqlite3.IntegrityError):
        database.create_user(username="NetAdmin_Uploader", role="viewer", password="AnotherPassword123!")

    # 3. get_user_by_username matches case-insensitively
    u = database.get_user_by_username("SECOPS_REVIEWER")
    assert u is not None
    assert u["username"].lower() == "secops_reviewer"

def test_role_constraint():
    """Verify that role check constraint rejects invalid roles."""
    with pytest.raises(ValueError):
        database.create_user(username="invalid_role_user", role="superadmin", password="TestPassword123!")

    with pytest.raises(ValueError):
        database.create_user(username="invalid_role_user2", role="root", password="TestPassword123!")

def test_repeated_initialize_database_idempotent():
    """Verify that repeated calls to initialize_database() are safe, non-destructive, and idempotent."""
    users_before = len(database.list_users())

    # Call initialize_database multiple times
    database.initialize_database()
    database.initialize_database()
    database.initialize_database()

    users_after = len(database.list_users())
    assert users_after == users_before, "Repeated initialize_database() must not duplicate users"

def test_audit_session_and_ledger_owner_preservation():
    """Verify session save/get preserves owner_user_id and ledger hash-chain stays valid."""
    session_data = {
        "session_id": "test-session-owned",
        "csm": {"device": {"hostname": "r4"}},
        "evals": {"CISCO-001": {"status": "Pass"}},
        "raw_config_text": "hostname r4\n",
        "filename": "test_owned.txt",
        "config_file_hash": "1122334455",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "owner_user_id": "user-uuid-12345"
    }
    database.save_session(session_data)
    loaded = database.get_session("test-session-owned")
    assert loaded is not None
    assert loaded["owner_user_id"] == "user-uuid-12345"

    # Hash chain in audit_log remains completely valid
    valid, msg, _ = audit_log.verify_chain()
    assert valid is True, msg


