"""API Integration Tests for AI Model Manager (Chunk 2A: REST API).
Verifies:
1. Authentication & RBAC on GET /api/model/status (401 unauth, 200 viewer/uploader/reviewer)
2. Authentication & RBAC on POST /api/model/mode (401 unauth, 403 viewer/uploader/reviewer without approver, 200 approver reviewer)
3. Mode switching: FAST, QUALITY, AUTO, OVERRIDE
4. Allowlist validation: arbitrary models rejected (400), shorthand 'qwen2.5:7b' rejected (400)
5. Missing/invalid mode payload rejection (400/422)
6. Offline resilience: Ollama unreachable -> status 200 with ollama_alive=False, fallback_active=True
7. Security boundaries: zero impact on reviewer identity, trusted mappings, and display-only remediation
"""
import pytest
from unittest.mock import patch, MagicMock
import urllib.error
from fastapi.testclient import TestClient

import auth
import database
import main
from main import app
import ai_model_manager
from ai_model_manager import (
    ModelMode,
    DEFAULT_FAST_MODEL,
    DEFAULT_QUALITY_MODEL,
    DETERMINISTIC_MODEL,
    MODEL_ALLOWLIST
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_model_manager_state():
    """Ensures test isolation by resetting model manager mode between tests."""
    database.initialize_database()
    manager = ai_model_manager.get_model_manager()
    manager.reset_mode()
    yield
    manager.reset_mode()


@pytest.fixture
def viewer_token():
    return auth.create_access_token(
        user_id="usr-viewer-01",
        username="auditor_viewer",
        role="viewer",
        is_authorized_approver=False,
    )


@pytest.fixture
def uploader_token():
    return auth.create_access_token(
        user_id="usr-uploader-01",
        username="netadmin_uploader",
        role="uploader",
        is_authorized_approver=False,
    )


@pytest.fixture
def reviewer_token():
    return auth.create_access_token(
        user_id="usr-reviewer-01",
        username="secops_reviewer",
        role="reviewer",
        is_authorized_approver=True,
    )


@pytest.fixture
def reviewer_non_approver_token():
    return auth.create_access_token(
        user_id="usr-reviewer-non-approver",
        username="secops_junior_reviewer",
        role="reviewer",
        is_authorized_approver=False,
    )


# --- 1. Authentication & RBAC: GET /api/model/status ---

def test_status_missing_token_returns_401():
    res = client.get("/api/model/status")
    assert res.status_code == 401
    assert "Authorization" in res.json().get("detail", "") or "detail" in res.json()


def test_status_invalid_token_returns_401():
    res = client.get("/api/model/status", headers={"Authorization": "Bearer invalid.jwt.token"})
    assert res.status_code == 401


def test_status_accessible_by_viewer(viewer_token):
    res = client.get("/api/model/status", headers={"Authorization": f"Bearer {viewer_token}"})
    assert res.status_code == 200
    data = res.json()
    assert "mode" in data
    assert "effective_model" in data
    assert "hardware_profile" in data
    assert "available_models" in data
    assert "ollama_alive" in data
    assert "fallback_active" in data


def test_status_accessible_by_uploader(uploader_token):
    res = client.get("/api/model/status", headers={"Authorization": f"Bearer {uploader_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["configured_mode"] in ["auto", "fast", "quality", "override", "deterministic_only"]


def test_status_accessible_by_reviewer(reviewer_token):
    res = client.get("/api/model/status", headers={"Authorization": f"Bearer {reviewer_token}"})
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data["hardware_profile"]["total_ram_gb"], (int, float))
    assert isinstance(data["available_models"], list)


# --- 2. Authentication & RBAC: POST /api/model/mode ---

def test_mode_missing_token_returns_401():
    res = client.post("/api/model/mode", json={"mode": "fast"})
    assert res.status_code == 401


def test_mode_invalid_token_returns_401():
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": "Bearer not-a-valid-token"},
        json={"mode": "fast"}
    )
    assert res.status_code == 401


def test_mode_forbidden_for_viewer(viewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"mode": "fast"}
    )
    assert res.status_code == 403
    assert "Forbidden" in res.json().get("detail", "")


def test_mode_forbidden_for_uploader(uploader_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {uploader_token}"},
        json={"mode": "fast"}
    )
    assert res.status_code == 403
    assert "Forbidden" in res.json().get("detail", "")


def test_mode_forbidden_for_reviewer_without_approver(reviewer_non_approver_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_non_approver_token}"},
        json={"mode": "fast"}
    )
    assert res.status_code == 403
    assert "Forbidden" in res.json().get("detail", "")


def test_mode_allowed_for_authorized_reviewer(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "fast"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data.get("success") is True
    assert data.get("mode") == "fast"


# --- 3. Operational Mode Transitions ---

def test_switch_to_fast_mode(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "fast"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["configured_mode"] == "fast"
    assert data["effective_model"] == DEFAULT_FAST_MODEL

    # Verify GET status immediately reflects the mode
    status_res = client.get("/api/model/status", headers={"Authorization": f"Bearer {reviewer_token}"})
    assert status_res.status_code == 200
    assert status_res.json()["configured_mode"] == "fast"
    assert status_res.json()["effective_model"] == DEFAULT_FAST_MODEL


def test_switch_to_quality_mode(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "quality"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["configured_mode"] == "quality"
    assert data["effective_model"] == DEFAULT_QUALITY_MODEL


def test_switch_to_auto_mode(reviewer_token):
    # First set to fast, then switch back to auto
    client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "fast"}
    )
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "auto"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["configured_mode"] == "auto"
    assert data["override_model"] is None


def test_switch_to_override_mode_with_valid_model(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "override", "override_model": DEFAULT_FAST_MODEL}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["configured_mode"] == "override"
    assert data["override_model"] == DEFAULT_FAST_MODEL
    assert data["effective_model"] == DEFAULT_FAST_MODEL


def test_switch_to_override_mode_with_quality_tag(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "override", "override_model": DEFAULT_QUALITY_MODEL}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["configured_mode"] == "override"
    assert data["override_model"] == DEFAULT_QUALITY_MODEL
    assert data["effective_model"] == DEFAULT_QUALITY_MODEL


# --- 4. Input Validation & Strict Allowlisting ---

def test_override_with_arbitrary_unapproved_model_rejected(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "override", "override_model": "gpt-4o"}
    )
    assert res.status_code == 400
    assert "Invalid override model" in res.json().get("detail", "")


def test_override_with_shorthand_qwen_rejected(reviewer_token):
    """Verifies that shorthand 'qwen2.5:7b' is rejected with explicit guidance."""
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "override", "override_model": "qwen2.5:7b"}
    )
    assert res.status_code == 400
    detail = res.json().get("detail", "")
    assert "qwen2.5:7b-instruct-q4_K_M" in detail


def test_override_without_specifying_model_rejected(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "override"}
    )
    assert res.status_code == 400
    assert "override_model tag must be specified" in res.json().get("detail", "")


def test_invalid_mode_value_rejected(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "turbo_unsupported"}
    )
    assert res.status_code == 400
    assert "Invalid mode" in res.json().get("detail", "")


def test_missing_mode_field_rejected(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"not_a_mode": "test"}
    )
    # FastAPI returns 422 for missing required body fields
    assert res.status_code == 422


# --- 5. Ollama Offline Resilience ---

def test_ollama_offline_status_resilience(reviewer_token):
    """When Ollama is offline, GET /api/model/status reports fallback state without failing."""
    manager = ai_model_manager.get_model_manager()
    with patch.object(manager, "is_ollama_alive", return_value=False):
        res = client.get("/api/model/status", headers={"Authorization": f"Bearer {reviewer_token}"})
        assert res.status_code == 200
        data = res.json()
        assert data["ollama_alive"] is False
        assert data["fallback_active"] is True
        assert data["fallback_reason"] == "ollama_offline"


# --- 6. Safety & Boundary Integrity ---

def test_model_mode_change_does_not_affect_auth_or_trusted_mappings(reviewer_token):
    """Asserts that changing AI model mode does not modify reviewer permissions or trusted rules."""
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM trusted_mappings")
    count_before = cur.fetchone()[0]
    conn.close()

    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "fast"}
    )
    assert res.status_code == 200

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM trusted_mappings")
    count_after = cur.fetchone()[0]
    conn.close()

    assert count_before == count_after, "Model mode mutation must NEVER touch trusted_mappings table!"


# --- 7. Chunk 2A.1: Runtime Configuration Precedence & Synchronization ---

def test_precedence_case_a_api_fast_with_env_qwen(reviewer_token, monkeypatch):
    """Case A: API sets FAST while OLLAMA_MODEL=qwen. Actual inference must use llama3.2:1b."""
    monkeypatch.setenv("OLLAMA_MODEL", DEFAULT_QUALITY_MODEL)

    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "fast"}
    )
    assert res.status_code == 200

    manager = ai_model_manager.get_model_manager()
    status = client.get("/api/model/status", headers={"Authorization": f"Bearer {reviewer_token}"}).json()
    assert status["effective_model"] == DEFAULT_FAST_MODEL

    with patch("urllib.request.urlopen") as mock_url:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"response": "test rationale explanation", "eval_count": 10, "eval_duration": 1000000000}'
        mock_resp.__enter__.return_value = mock_resp
        mock_url.return_value = mock_resp

        resp = manager.generate("Test prompt")
        assert resp.model_used == DEFAULT_FAST_MODEL


def test_precedence_case_b_api_quality_with_env_llama(reviewer_token, monkeypatch):
    """Case B: API sets QUALITY while OLLAMA_MODEL=llama. Actual inference must use qwen2.5:7b-instruct-q4_K_M."""
    monkeypatch.setenv("OLLAMA_MODEL", DEFAULT_FAST_MODEL)

    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "quality"}
    )
    assert res.status_code == 200

    manager = ai_model_manager.get_model_manager()
    status = client.get("/api/model/status", headers={"Authorization": f"Bearer {reviewer_token}"}).json()
    assert status["effective_model"] == DEFAULT_QUALITY_MODEL

    with patch("urllib.request.urlopen") as mock_url:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"response": "test rationale explanation", "eval_count": 10, "eval_duration": 1000000000}'
        mock_resp.__enter__.return_value = mock_resp
        mock_url.return_value = mock_resp

        resp = manager.generate("Test prompt")
        assert resp.model_used == DEFAULT_QUALITY_MODEL


def test_precedence_case_c_api_override_llama_with_env_qwen(reviewer_token, monkeypatch):
    """Case C: API sets OVERRIDE with llama while OLLAMA_MODEL=qwen. Both status and inference must use llama."""
    monkeypatch.setenv("OLLAMA_MODEL", DEFAULT_QUALITY_MODEL)

    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "override", "override_model": DEFAULT_FAST_MODEL}
    )
    assert res.status_code == 200

    manager = ai_model_manager.get_model_manager()
    status = client.get("/api/model/status", headers={"Authorization": f"Bearer {reviewer_token}"}).json()
    assert status["override_model"] == DEFAULT_FAST_MODEL
    assert status["effective_model"] == DEFAULT_FAST_MODEL

    with patch("urllib.request.urlopen") as mock_url:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"response": "test rationale explanation", "eval_count": 10, "eval_duration": 1000000000}'
        mock_resp.__enter__.return_value = mock_resp
        mock_url.return_value = mock_resp

        resp = manager.generate("Test prompt")
        assert resp.model_used == DEFAULT_FAST_MODEL


def test_precedence_case_d_api_override_qwen_with_env_llama(reviewer_token, monkeypatch):
    """Case D: API sets OVERRIDE with qwen while OLLAMA_MODEL=llama. Both status and inference must use qwen."""
    monkeypatch.setenv("OLLAMA_MODEL", DEFAULT_FAST_MODEL)

    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "override", "override_model": DEFAULT_QUALITY_MODEL}
    )
    assert res.status_code == 200

    manager = ai_model_manager.get_model_manager()
    status = client.get("/api/model/status", headers={"Authorization": f"Bearer {reviewer_token}"}).json()
    assert status["override_model"] == DEFAULT_QUALITY_MODEL
    assert status["effective_model"] == DEFAULT_QUALITY_MODEL

    with patch("urllib.request.urlopen") as mock_url:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"response": "test rationale explanation", "eval_count": 10, "eval_duration": 1000000000}'
        mock_resp.__enter__.return_value = mock_resp
        mock_url.return_value = mock_resp

        resp = manager.generate("Test prompt")
        assert resp.model_used == DEFAULT_QUALITY_MODEL


def test_precedence_case_e_api_override_invalid_model_rejected(reviewer_token):
    """Case E: API rejects invalid override model with 400; manager generate falls back safely."""
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "override", "override_model": "untrusted_arbitrary_tag"}
    )
    assert res.status_code == 400
    assert "Invalid override model" in res.json().get("detail", "")

    # Manager direct call with invalid override safely returns fallback
    manager = ai_model_manager.get_model_manager()
    resp = manager.generate("Test prompt", mode=ModelMode.OVERRIDE, override_name="untrusted_tag", fallback_text="SAFE_FALLBACK")
    assert resp.is_fallback is True
    assert resp.text == "SAFE_FALLBACK"
    assert resp.fallback_reason == "invalid_override_model"


def test_precedence_case_f_environment_bootstrap_no_api_change(monkeypatch):
    """Case F: Manager initializes from supported environment variables when no API change has occurred."""
    monkeypatch.setenv("AI_MODEL_MODE", "quality")
    test_manager = ai_model_manager.AIModelManager()
    assert test_manager.active_mode == ModelMode.QUALITY
    assert test_manager.get_status()["effective_model"] == DEFAULT_QUALITY_MODEL

    monkeypatch.setenv("AI_MODEL_MODE", "override")
    monkeypatch.setenv("OLLAMA_MODEL", DEFAULT_FAST_MODEL)
    test_manager_override = ai_model_manager.AIModelManager()
    assert test_manager_override.active_mode == ModelMode.OVERRIDE
    assert test_manager_override.override_model == DEFAULT_FAST_MODEL
    assert test_manager_override.get_status()["effective_model"] == DEFAULT_FAST_MODEL


def test_precedence_case_g_runtime_api_change_overrides_bootstrap(reviewer_token, monkeypatch):
    """Case G: Runtime API reviewer action overrides startup environment bootstrap."""
    monkeypatch.setenv("AI_MODEL_MODE", "quality")
    manager = ai_model_manager.get_model_manager()
    manager.reset_mode(from_env=True)
    assert manager.active_mode == ModelMode.QUALITY

    # Reviewer changes to FAST via API
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "fast"}
    )
    assert res.status_code == 200
    assert manager.active_mode == ModelMode.FAST

    status = client.get("/api/model/status", headers={"Authorization": f"Bearer {reviewer_token}"}).json()
    assert status["configured_mode"] == "fast"
    assert status["effective_model"] == DEFAULT_FAST_MODEL


def test_precedence_case_h_no_runtime_caller_reads_env_vars():
    """Case H: Asserts that callers (ai_suggester, remediation_engine) do not read AI_MODEL_MODE or OLLAMA_MODEL."""
    import inspect
    import ai_suggester
    import remediation_engine

    suggester_src = inspect.getsource(ai_suggester._generate_rationale_ai)
    assert 'os.getenv("AI_MODEL_MODE")' not in suggester_src
    assert 'os.getenv("OLLAMA_MODEL")' not in suggester_src

    remediation_src = inspect.getsource(remediation_engine.explain_failure_ai)
    assert 'os.getenv("AI_MODEL_MODE")' not in remediation_src
    assert 'os.getenv("OLLAMA_MODEL")' not in remediation_src
