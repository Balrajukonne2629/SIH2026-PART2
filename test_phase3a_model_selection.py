"""Phase 3A: Hardware-Adaptive AI Model Selection — Focused Test Suite.

Covers all required behaviors per Phase 3A spec:
 1. Fast mode selection
 2. Quality mode selection
 3. Auto mode selection (low RAM, high RAM, GPU variants)
 4. User-selected model (override with valid model)
 5. Invalid model rejection
 6. deterministic_only mode — completely bypasses Ollama
 7. Ollama unavailable → deterministic fallback
 8. Model unavailable (404) → deterministic fallback
 9. Timeout → deterministic fallback
10. Malformed AI response → deterministic fallback
11. AI refusal → preserve safe behavior (fallback)
12. Compliance cannot be decided by AI (structural invariant)
13. RBAC: mode change requires authorized reviewer
14. Security: loopback restriction, no arbitrary model execution
"""
import inspect
import io
import unittest
from unittest.mock import patch, MagicMock
import urllib.error

import ai_model_manager
from ai_model_manager import (
    AIModelManager,
    ModelMode,
    WorkloadType,
    HardwareProfile,
    ModelResponse,
    MODEL_ALLOWLIST,
    DEFAULT_FAST_MODEL,
    DEFAULT_QUALITY_MODEL,
    DETERMINISTIC_MODEL,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1–5: Model Selection Modes
# ─────────────────────────────────────────────────────────────────────────────

class TestFastModeSelection(unittest.TestCase):
    """Req 1 & 4: Fast mode prefers the lightweight configured model."""

    def setUp(self):
        self.mgr = AIModelManager()

    def test_fast_selects_llama32_1b(self):
        self.assertEqual(self.mgr.select_model(mode=ModelMode.FAST), DEFAULT_FAST_MODEL)
        self.assertEqual(DEFAULT_FAST_MODEL, "llama3.2:1b")

    def test_fast_mode_set_mode_accepted(self):
        ok, err = self.mgr.set_mode("fast")
        self.assertTrue(ok)
        self.assertIsNone(err)
        self.assertEqual(self.mgr.active_mode, ModelMode.FAST)

    @patch("urllib.request.urlopen")
    def test_fast_mode_generate_uses_llama(self, mock_url):
        mock_url.return_value.__enter__ = lambda s: s
        mock_url.return_value.read.return_value = (
            b'{"response": "some rationale text here.", "eval_count": 10, "eval_duration": 1000000000}'
        )
        self.mgr.set_mode("fast")
        res = self.mgr.generate("test prompt", fallback_text="fb")
        self.assertEqual(res.model_used, DEFAULT_FAST_MODEL)
        self.assertFalse(res.is_fallback)


class TestQualityModeSelection(unittest.TestCase):
    """Req 1 & 5: Quality mode prefers the stronger configured model."""

    def setUp(self):
        self.mgr = AIModelManager()

    def test_quality_selects_qwen25_7b(self):
        self.assertEqual(self.mgr.select_model(mode=ModelMode.QUALITY), DEFAULT_QUALITY_MODEL)
        self.assertEqual(DEFAULT_QUALITY_MODEL, "qwen2.5:7b-instruct-q4_K_M")

    def test_quality_mode_set_mode_accepted(self):
        ok, err = self.mgr.set_mode("quality")
        self.assertTrue(ok)
        self.assertIsNone(err)
        self.assertEqual(self.mgr.active_mode, ModelMode.QUALITY)

    @patch("urllib.request.urlopen")
    def test_quality_mode_generate_uses_qwen(self, mock_url):
        mock_url.return_value.__enter__ = lambda s: s
        mock_url.return_value.read.return_value = (
            b'{"response": "detailed quality rationale.", "eval_count": 20, "eval_duration": 2000000000}'
        )
        self.mgr.set_mode("quality")
        res = self.mgr.generate("test prompt", fallback_text="fb")
        self.assertEqual(res.model_used, DEFAULT_QUALITY_MODEL)
        self.assertFalse(res.is_fallback)


class TestAutoModeSelection(unittest.TestCase):
    """Req 1 & 3: Auto mode hardware-aware routing."""

    def setUp(self):
        self.mgr = AIModelManager()

    def _profile(self, avail_ram, has_gpu=False, gpu_type="none", vram=0.0):
        return HardwareProfile(
            total_ram_gb=16.0,
            available_ram_gb=avail_ram,
            cpu_cores=8,
            cpu_threads=16,
            has_gpu=has_gpu,
            gpu_type=gpu_type,
            vram_gb=vram,
            gpu_name="test_gpu" if has_gpu else "none",
        )

    def test_auto_low_ram_unmapped_mapping_selects_fast(self):
        with patch.object(self.mgr, "probe_hardware", return_value=self._profile(3.4)):
            model = self.mgr.select_model(mode=ModelMode.AUTO, workload=WorkloadType.UNMAPPED_LINE_MAPPING)
            self.assertEqual(model, DEFAULT_FAST_MODEL)

    def test_auto_low_ram_remediation_explanation_selects_deterministic(self):
        with patch.object(self.mgr, "probe_hardware", return_value=self._profile(3.4)):
            model = self.mgr.select_model(mode=ModelMode.AUTO, workload=WorkloadType.REMEDIATION_EXPLANATION)
            self.assertEqual(model, DETERMINISTIC_MODEL)

    def test_auto_high_ram_selects_quality(self):
        with patch.object(self.mgr, "probe_hardware", return_value=self._profile(12.0)):
            model = self.mgr.select_model(mode=ModelMode.AUTO, workload=WorkloadType.UNMAPPED_LINE_MAPPING)
            self.assertEqual(model, DEFAULT_QUALITY_MODEL)

    def test_auto_dedicated_gpu_6gb_vram_selects_quality(self):
        with patch.object(self.mgr, "probe_hardware", return_value=self._profile(3.0, True, "dedicated", 8.0)):
            model = self.mgr.select_model(mode=ModelMode.AUTO, workload=WorkloadType.REMEDIATION_EXPLANATION)
            self.assertEqual(model, DEFAULT_QUALITY_MODEL)

    def test_auto_dedicated_gpu_insufficient_vram_falls_to_ram_check(self):
        # GPU with only 4 GB VRAM, but 8 GB RAM available → quality via RAM path
        with patch.object(self.mgr, "probe_hardware", return_value=self._profile(8.0, True, "dedicated", 4.0)):
            model = self.mgr.select_model(mode=ModelMode.AUTO, workload=WorkloadType.UNMAPPED_LINE_MAPPING)
            self.assertEqual(model, DEFAULT_QUALITY_MODEL)

    def test_auto_ollama_offline_generate_falls_back(self):
        """Auto selection is irrelevant when Ollama is down — generate() always falls back."""
        with patch.object(self.mgr, "probe_hardware", return_value=self._profile(12.0)):
            with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
                self.mgr.set_mode("auto")
                res = self.mgr.generate("prompt", fallback_text="FALLBACK")
                self.assertTrue(res.is_fallback)
                self.assertEqual(res.text, "FALLBACK")


# ─────────────────────────────────────────────────────────────────────────────
# 4 & 6: User-Selected Model (override) & Invalid Model Rejection
# ─────────────────────────────────────────────────────────────────────────────

class TestUserSelectedModel(unittest.TestCase):
    """Req 1 (override mode) & 6: User-selected model validated against allowlist."""

    def setUp(self):
        self.mgr = AIModelManager()

    def test_override_valid_llama_accepted(self):
        ok, err = self.mgr.set_mode("override", "llama3.2:1b")
        self.assertTrue(ok)
        self.assertIsNone(err)
        self.assertEqual(self.mgr.active_mode, ModelMode.OVERRIDE)
        self.assertEqual(self.mgr.override_model, "llama3.2:1b")

    def test_override_valid_qwen_accepted(self):
        ok, err = self.mgr.set_mode("override", "qwen2.5:7b-instruct-q4_K_M")
        self.assertTrue(ok)
        self.assertIsNone(err)
        self.assertEqual(self.mgr.override_model, "qwen2.5:7b-instruct-q4_K_M")

    def test_override_select_model_returns_override(self):
        self.mgr.set_mode("override", DEFAULT_FAST_MODEL)
        model = self.mgr.select_model()
        self.assertEqual(model, DEFAULT_FAST_MODEL)


class TestInvalidModelRejection(unittest.TestCase):
    """Req 6: Reject unsupported model names — no arbitrary model execution."""

    def setUp(self):
        self.mgr = AIModelManager()

    def test_arbitrary_string_rejected(self):
        ok, err = self.mgr.set_mode("override", "gpt-4o")
        self.assertFalse(ok)
        self.assertIn("Invalid override model", err)

    def test_command_injection_attempt_rejected(self):
        ok, err = self.mgr.set_mode("override", "llama3.2:1b; evil_cmd")
        self.assertFalse(ok)
        self.assertIn("Invalid override model", err)

    def test_qwen_shorthand_rejected_with_guidance(self):
        ok, err = self.mgr.set_mode("override", "qwen2.5:7b")
        self.assertFalse(ok)
        self.assertIn("qwen2.5:7b-instruct-q4_K_M", err)

    def test_override_without_model_rejected(self):
        ok, err = self.mgr.set_mode("override")
        self.assertFalse(ok)
        self.assertIn("override_model", err)

    def test_resolve_override_model_rejects_unlisted(self):
        model, reason = self.mgr.resolve_override_model("arbitrary_model")
        self.assertIsNone(model)
        self.assertEqual(reason, "invalid_override_model")

    def test_generate_with_unlisted_model_param_falls_back(self):
        """Passing an unlisted model string directly to generate() must also fall back."""
        with patch("urllib.request.urlopen"):  # should never be called
            res = self.mgr.generate("test", model="evil_model", fallback_text="SAFE")
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.fallback_reason, "model_not_allowlisted")
        self.assertEqual(res.text, "SAFE")


# ─────────────────────────────────────────────────────────────────────────────
# Req 7: deterministic_only mode
# ─────────────────────────────────────────────────────────────────────────────

class TestDeterministicOnlyMode(unittest.TestCase):
    """Req 1 & 7: deterministic_only completely bypasses Ollama/LLM calls."""

    def setUp(self):
        self.mgr = AIModelManager()

    def test_deterministic_only_mode_enum_exists(self):
        self.assertEqual(ModelMode.DETERMINISTIC_ONLY.value, "deterministic_only")

    def test_deterministic_only_set_mode_accepted(self):
        ok, err = self.mgr.set_mode("deterministic_only")
        self.assertTrue(ok)
        self.assertIsNone(err)
        self.assertEqual(self.mgr.active_mode, ModelMode.DETERMINISTIC_ONLY)

    def test_deterministic_only_select_model_returns_deterministic(self):
        model = self.mgr.select_model(mode=ModelMode.DETERMINISTIC_ONLY)
        self.assertEqual(model, DETERMINISTIC_MODEL)

    def test_deterministic_only_generate_never_calls_ollama(self):
        self.mgr.set_mode("deterministic_only")
        with patch("urllib.request.urlopen") as mock_url:
            res = self.mgr.generate("anything", fallback_text="DETERMINISTIC_RESULT")
            mock_url.assert_not_called()  # Ollama must NEVER be contacted
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.model_used, DETERMINISTIC_MODEL)
        self.assertEqual(res.text, "DETERMINISTIC_RESULT")

    def test_deterministic_only_fallback_reason_in_status(self):
        self.mgr.set_mode("deterministic_only")
        with patch.object(self.mgr, "is_ollama_alive", return_value=True):
            status = self.mgr.get_status()
        self.assertTrue(status["fallback_active"])
        self.assertEqual(status["fallback_reason"], "deterministic_mode_selected")
        self.assertEqual(status["effective_model"], DETERMINISTIC_MODEL)

    def test_deterministic_only_in_allowlist_modes(self):
        valid_modes = [m.value for m in ModelMode]
        self.assertIn("deterministic_only", valid_modes)


# ─────────────────────────────────────────────────────────────────────────────
# Req 8: Failure Handling & Deterministic Fallback
# ─────────────────────────────────────────────────────────────────────────────

class TestFailureHandlingFallbacks(unittest.TestCase):
    """Req 8: All failure modes produce deterministic fallback, never PASS/FAIL decision."""

    def setUp(self):
        self.mgr = AIModelManager()

    @patch("urllib.request.urlopen")
    def test_ollama_unavailable_falls_back(self, mock_url):
        mock_url.side_effect = urllib.error.URLError("connection refused")
        res = self.mgr.generate("test", model=DEFAULT_FAST_MODEL, fallback_text="FALLBACK")
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.fallback_reason, "connection_refused")
        self.assertEqual(res.text, "FALLBACK")

    @patch("urllib.request.urlopen")
    def test_model_unavailable_404_falls_back(self, mock_url):
        mock_url.side_effect = urllib.error.HTTPError(
            url="http://127.0.0.1:11434/api/generate",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=io.BytesIO(b'{"error":"model not found"}'),
        )
        res = self.mgr.generate("test", model=DEFAULT_QUALITY_MODEL, fallback_text="FALLBACK")
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.fallback_reason, "model_not_found_404")
        self.assertEqual(res.text, "FALLBACK")

    @patch("urllib.request.urlopen")
    def test_timeout_falls_back(self, mock_url):
        mock_url.side_effect = TimeoutError("timed out")
        res = self.mgr.generate("test", model=DEFAULT_FAST_MODEL, fallback_text="FALLBACK")
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.fallback_reason, "timeout")
        self.assertEqual(res.text, "FALLBACK")

    @patch("urllib.request.urlopen")
    def test_malformed_json_falls_back(self, mock_url):
        mock_url.return_value.__enter__ = lambda s: s
        mock_url.return_value.read.return_value = b"not valid JSON {{["
        res = self.mgr.generate("test", model=DEFAULT_FAST_MODEL, fallback_text="FALLBACK")
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.fallback_reason, "malformed_response")
        self.assertEqual(res.text, "FALLBACK")

    @patch("urllib.request.urlopen")
    def test_ai_refusal_falls_back(self, mock_url):
        mock_url.return_value.__enter__ = lambda s: s
        mock_url.return_value.read.return_value = (
            b'{"response": "I cannot assist with this request.", '
            b'"eval_count": 10, "eval_duration": 1000000000}'
        )
        res = self.mgr.generate("test", model=DEFAULT_FAST_MODEL, fallback_text="FALLBACK")
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.fallback_reason, "safety_refusal")
        self.assertEqual(res.text, "FALLBACK")

    @patch("urllib.request.urlopen")
    def test_empty_response_falls_back(self, mock_url):
        mock_url.return_value.__enter__ = lambda s: s
        mock_url.return_value.read.return_value = (
            b'{"response": "", "eval_count": 0, "eval_duration": 100000000}'
        )
        res = self.mgr.generate("test", model=DEFAULT_FAST_MODEL, fallback_text="FALLBACK")
        self.assertTrue(res.is_fallback)
        self.assertIn(res.fallback_reason, ("empty_response", "safety_refusal"))
        self.assertEqual(res.text, "FALLBACK")

    def test_override_invalid_model_generates_fallback_immediately(self):
        """Invalid override must fall back before any network call."""
        with patch("urllib.request.urlopen") as mock_url:
            res = self.mgr.generate(
                "test",
                mode=ModelMode.OVERRIDE,
                override_name="not_in_allowlist",
                fallback_text="SAFE_FALLBACK",
            )
            mock_url.assert_not_called()
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.fallback_reason, "invalid_override_model")
        self.assertEqual(res.text, "SAFE_FALLBACK")


# ─────────────────────────────────────────────────────────────────────────────
# Req 8 (last bullet) & structural: AI cannot decide compliance
# ─────────────────────────────────────────────────────────────────────────────

class TestComplianceAuthorityInvariant(unittest.TestCase):
    """Req 8 & invariant: No AI failure may become a compliance PASS/FAIL decision.
    AI is advisory only — deterministic engine retains final authority.
    """

    def test_model_manager_never_writes_trusted_mappings(self):
        src = inspect.getsource(ai_model_manager)
        self.assertNotIn("trusted_mappings.json", src)
        self.assertNotIn("INSERT INTO trusted_mappings", src)
        self.assertNotIn("INSERT OR REPLACE INTO trusted_mappings", src)

    def test_model_manager_cannot_mutate_reviewer_approval(self):
        src = inspect.getsource(ai_model_manager)
        self.assertNotIn("approve_suggestion", src)
        self.assertNotIn("UPDATE pending_suggestions", src)

    def test_model_manager_has_zero_device_execution(self):
        src = inspect.getsource(ai_model_manager)
        forbidden = [
            "paramiko", "netmiko", "pexpect", "telnetlib",
            "subprocess.Popen", "os.system", "subprocess.run",
        ]
        for term in forbidden:
            self.assertNotIn(term, src, f"Forbidden execution primitive found: {term}")

    def test_ai_fallback_text_not_compliance_verdict(self):
        """Fallback text is always the caller-supplied string, never 'PASS' or 'FAIL'."""
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
            mgr = AIModelManager()
            res = mgr.generate("compliance check prompt", fallback_text="DISPLAY_ONLY_RATIONALE")
        # The returned text is the caller's fallback, not a compliance verdict
        self.assertNotIn(res.text, ("PASS", "FAIL", "COMPLIANT", "NON-COMPLIANT"))
        self.assertTrue(res.is_fallback)

    def test_deterministic_model_in_allowlist_prevents_compliance_bypass(self):
        """DETERMINISTIC_MODEL must be in the allowlist so it cannot be smuggled as arbitrary input."""
        self.assertIn(DETERMINISTIC_MODEL, MODEL_ALLOWLIST)

    def test_all_supported_models_are_allowlisted(self):
        """The spec-required model set must exactly match the allowlist keys."""
        required = {"llama3.2:1b", "qwen2.5:7b-instruct-q4_K_M", "deterministic_only"}
        self.assertEqual(required, set(MODEL_ALLOWLIST.keys()))


# ─────────────────────────────────────────────────────────────────────────────
# Req 9: Security Constraints
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityConstraints(unittest.TestCase):
    """Req 9: Loopback-only, no arbitrary models, no secrets via API response."""

    def test_ssrf_external_url_sanitized_to_loopback(self):
        mgr = AIModelManager(base_url="http://169.254.169.254:11434")
        self.assertEqual(mgr.base_url, "http://127.0.0.1:11434")

    def test_ssrf_remote_attacker_sanitized(self):
        mgr = AIModelManager(base_url="https://evil.attacker.com:11434")
        self.assertEqual(mgr.base_url, "http://127.0.0.1:11434")

    def test_valid_loopbacks_preserved(self):
        mgr_lh = AIModelManager(base_url="http://localhost:11434")
        self.assertEqual(mgr_lh.base_url, "http://localhost:11434")

        mgr_ip = AIModelManager(base_url="http://127.0.0.1:11434")
        self.assertEqual(mgr_ip.base_url, "http://127.0.0.1:11434")

    def test_arbitrary_model_string_never_sent_to_ollama(self):
        """An unlisted model must never reach urllib.request.urlopen."""
        mgr = AIModelManager()
        with patch("urllib.request.urlopen") as mock_url:
            mgr.generate("test", model="evil:cmd_injection", fallback_text="safe")
            mock_url.assert_not_called()

    def test_get_status_does_not_expose_internal_secrets(self):
        """Status dict must not contain token/secret/password/key fields."""
        mgr = AIModelManager()
        with patch.object(mgr, "is_ollama_alive", return_value=False):
            status = mgr.get_status()
        secret_keys = {"token", "secret", "password", "api_key", "private_key"}
        for key in status.keys():
            self.assertNotIn(key.lower(), secret_keys)


# ─────────────────────────────────────────────────────────────────────────────
# Req 10 (API contract): deterministic_only mode via API + RBAC
# ─────────────────────────────────────────────────────────────────────────────

import pytest
from fastapi.testclient import TestClient
import auth
import database
import main
from main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_manager():
    database.initialize_database()
    mgr = ai_model_manager.get_model_manager()
    mgr.reset_mode()
    yield
    mgr.reset_mode()


@pytest.fixture
def reviewer_token():
    return auth.create_access_token(
        user_id="usr-rev-3a-01",
        username="sec_reviewer_3a",
        role="reviewer",
        is_authorized_approver=True,
    )


@pytest.fixture
def viewer_token():
    return auth.create_access_token(
        user_id="usr-view-3a-01",
        username="viewer_3a",
        role="viewer",
        is_authorized_approver=False,
    )


def test_api_set_deterministic_only_mode(reviewer_token):
    """POST /api/model/mode with deterministic_only must succeed for authorized reviewer."""
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "deterministic_only"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["configured_mode"] == "deterministic_only"
    assert data["effective_model"] == DETERMINISTIC_MODEL
    assert data["fallback_active"] is True
    assert data["fallback_reason"] == "deterministic_mode_selected"


def test_api_deterministic_only_status_reflects_mode(reviewer_token):
    """After setting deterministic_only, GET /api/model/status must reflect it."""
    client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "deterministic_only"},
    )
    res = client.get("/api/model/status", headers={"Authorization": f"Bearer {reviewer_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["configured_mode"] == "deterministic_only"
    assert data["effective_model"] == DETERMINISTIC_MODEL


def test_api_viewer_cannot_set_deterministic_only(viewer_token):
    """RBAC: viewer must not be able to change mode."""
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"mode": "deterministic_only"},
    )
    assert res.status_code == 403


def test_api_invalid_mode_rejected(reviewer_token):
    """Unsupported mode strings must be rejected with HTTP 400."""
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "turbo_unknown"},
    )
    assert res.status_code == 400
    assert "Invalid mode" in res.json().get("detail", "")


def test_api_fast_mode_effective_model(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "fast"},
    )
    assert res.status_code == 200
    assert res.json()["effective_model"] == DEFAULT_FAST_MODEL


def test_api_quality_mode_effective_model(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "quality"},
    )
    assert res.status_code == 200
    assert res.json()["effective_model"] == DEFAULT_QUALITY_MODEL


def test_api_override_with_valid_model(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "override", "override_model": DEFAULT_FAST_MODEL},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["configured_mode"] == "override"
    assert data["override_model"] == DEFAULT_FAST_MODEL
    assert data["effective_model"] == DEFAULT_FAST_MODEL


def test_api_override_with_invalid_model_rejected(reviewer_token):
    res = client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "override", "override_model": "gpt-4-turbo"},
    )
    assert res.status_code == 400
    assert "Invalid override model" in res.json().get("detail", "")


def test_api_ollama_offline_fallback_reported(reviewer_token):
    """When Ollama is offline, status must report fallback_active=True without crashing."""
    mgr = ai_model_manager.get_model_manager()
    with patch.object(mgr, "is_ollama_alive", return_value=False):
        res = client.get("/api/model/status", headers={"Authorization": f"Bearer {reviewer_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["ollama_alive"] is False
    assert data["fallback_active"] is True
    assert data["fallback_reason"] == "ollama_offline"


def test_api_model_change_does_not_touch_trusted_mappings(reviewer_token):
    """Mode change must not write to trusted_mappings — compliance authority is untouched."""
    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM trusted_mappings")
    before = cur.fetchone()[0]
    conn.close()

    client.post(
        "/api/model/mode",
        headers={"Authorization": f"Bearer {reviewer_token}"},
        json={"mode": "deterministic_only"},
    )

    conn = database.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM trusted_mappings")
    after = cur.fetchone()[0]
    conn.close()

    assert before == after, "Model mode change must NEVER touch trusted_mappings!"


if __name__ == "__main__":
    unittest.main()
