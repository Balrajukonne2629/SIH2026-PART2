"""Comprehensive Test Suite for AI Model Manager (Chunk 1 Backend Core).
Verifies:
1. Mode selection (FAST, QUALITY, AUTO, OVERRIDE)
2. Strict model allowlisting & invalid override rejection
3. Hardware probe and memory/GPU threshold logic
4. Workload awareness (unmapped line vs remediation explanation)
5. Failure modes & fallback (connection refused, 404, timeout, refusal, malformed JSON)
6. Security boundaries: zero direct write to trusted mappings, zero bypass of reviewer approval,
   display-only remediation, SSRF loopback sanitization.
7. Telemetry & metadata correctness.
"""
import unittest
from unittest.mock import patch, MagicMock
import urllib.error
import io
import inspect

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
    DETERMINISTIC_MODEL
)


class TestModelSelection(unittest.TestCase):
    def setUp(self):
        self.manager = AIModelManager()

    def test_1_fast_mode_selects_llama32_1b(self):
        model = self.manager.select_model(mode=ModelMode.FAST)
        self.assertEqual(model, DEFAULT_FAST_MODEL)
        self.assertEqual(model, "llama3.2:1b")

    def test_2_quality_mode_selects_qwen25_7b(self):
        model = self.manager.select_model(mode=ModelMode.QUALITY)
        self.assertEqual(model, DEFAULT_QUALITY_MODEL)
        self.assertEqual(model, "qwen2.5:7b-instruct-q4_K_M")

    def test_3_invalid_override_rejected_safely(self):
        # Arbitrary string injection attempt
        model, fallback_reason = self.manager.resolve_override_model("arbitrary_model; evil_cmd")
        self.assertIsNone(model)
        self.assertEqual(fallback_reason, "invalid_override_model")

        # Shorthand qwen tag that 404s in Ollama must not be allowed without exact tag
        model, fallback_reason = self.manager.resolve_override_model("qwen2.5:7b")
        self.assertIsNone(model)
        self.assertEqual(fallback_reason, "invalid_override_model")

    def test_valid_override_accepted(self):
        model, reason = self.manager.resolve_override_model("llama3.2:1b")
        self.assertEqual(model, "llama3.2:1b")
        self.assertIsNone(reason)

        model, reason = self.manager.resolve_override_model("qwen2.5:7b-instruct-q4_K_M")
        self.assertEqual(model, "qwen2.5:7b-instruct-q4_K_M")
        self.assertIsNone(reason)


class TestHardwareAwareAutoSelection(unittest.TestCase):
    def setUp(self):
        self.manager = AIModelManager()

    def test_4_auto_low_memory_cpu_does_not_select_quality_for_explanation(self):
        # Mock CPU-only host with 3.4 GB free RAM (like the current benchmark machine)
        low_mem_profile = HardwareProfile(
            total_ram_gb=16.0,
            available_ram_gb=3.4,
            cpu_cores=10,
            cpu_threads=12,
            has_gpu=False,
            gpu_type="none",
            vram_gb=0.0,
            gpu_name="none"
        )
        with patch.object(self.manager, "probe_hardware", return_value=low_mem_profile):
            # For remediation_explanation on low-RAM CPU, must degrade to deterministic fallback
            model = self.manager.select_model(
                mode=ModelMode.AUTO,
                workload=WorkloadType.REMEDIATION_EXPLANATION
            )
            self.assertEqual(model, DETERMINISTIC_MODEL)

            # For unmapped_line_mapping, FAST is allowed
            model_map = self.manager.select_model(
                mode=ModelMode.AUTO,
                workload=WorkloadType.UNMAPPED_LINE_MAPPING
            )
            self.assertEqual(model_map, DEFAULT_FAST_MODEL)

    def test_5_auto_sufficient_memory_cpu_selects_quality(self):
        # Mock CPU host with 12.0 GB free RAM
        high_mem_profile = HardwareProfile(
            total_ram_gb=32.0,
            available_ram_gb=12.0,
            cpu_cores=16,
            cpu_threads=32,
            has_gpu=False,
            gpu_type="none",
            vram_gb=0.0,
            gpu_name="none"
        )
        with patch.object(self.manager, "probe_hardware", return_value=high_mem_profile):
            model = self.manager.select_model(
                mode=ModelMode.AUTO,
                workload=WorkloadType.REMEDIATION_EXPLANATION
            )
            self.assertEqual(model, DEFAULT_QUALITY_MODEL)

    def test_6_auto_dedicated_gpu_with_sufficient_vram_selects_quality(self):
        # Mock discrete NVIDIA GPU with 8.0 GB VRAM
        gpu_profile = HardwareProfile(
            total_ram_gb=16.0,
            available_ram_gb=3.0,
            cpu_cores=8,
            cpu_threads=16,
            has_gpu=True,
            gpu_type="dedicated",
            vram_gb=8.0,
            gpu_name="NVIDIA GeForce RTX 4060"
        )
        with patch.object(self.manager, "probe_hardware", return_value=gpu_profile):
            model = self.manager.select_model(
                mode=ModelMode.AUTO,
                workload=WorkloadType.REMEDIATION_EXPLANATION
            )
            self.assertEqual(model, DEFAULT_QUALITY_MODEL)


class TestOllamaInvocationAndFallbacks(unittest.TestCase):
    def setUp(self):
        self.manager = AIModelManager()

    @patch("urllib.request.urlopen")
    def test_7_connection_refused_triggers_fallback(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("[WinError 10061] No connection could be made")
        res = self.manager.generate(
            prompt="test prompt",
            model="llama3.2:1b",
            mode=ModelMode.FAST,
            fallback_text="default fallback rationale"
        )
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.fallback_reason, "connection_refused")
        self.assertEqual(res.text, "default fallback rationale")
        self.assertEqual(res.tokens_per_sec, 0.0)

    @patch("urllib.request.urlopen")
    def test_8_http_404_model_not_found_triggers_fallback(self, mock_urlopen):
        err = urllib.error.HTTPError(
            url="http://127.0.0.1:11434/api/generate",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=io.BytesIO(b'{"error":"model not found"}')
        )
        mock_urlopen.side_effect = err
        res = self.manager.generate(
            prompt="test prompt",
            model="qwen2.5:7b-instruct-q4_K_M",
            mode=ModelMode.QUALITY,
            fallback_text="default fallback rationale"
        )
        err.close()
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.fallback_reason, "model_not_found_404")
        self.assertEqual(res.text, "default fallback rationale")

    @patch("urllib.request.urlopen")
    def test_9_timeout_triggers_fallback(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError("timed out")
        res = self.manager.generate(
            prompt="test prompt",
            model="llama3.2:1b",
            mode=ModelMode.FAST,
            fallback_text="default fallback rationale"
        )
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.fallback_reason, "timeout")
        self.assertEqual(res.text, "default fallback rationale")

    @patch("urllib.request.urlopen")
    def test_10_safety_refusal_triggers_fallback(self, mock_urlopen):
        refusal_payload = b'{"response": "I can\'t assist with writing a technical audit report that contains factual procedural sentences", "eval_count": 20, "eval_duration": 1000000000}'
        mock_resp = MagicMock()
        mock_resp.read.return_value = refusal_payload
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = self.manager.generate(
            prompt="test prompt",
            model="llama3.2:1b",
            mode=ModelMode.FAST,
            fallback_text="default fallback rationale"
        )
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.fallback_reason, "safety_refusal")
        self.assertEqual(res.text, "default fallback rationale")

    @patch("urllib.request.urlopen")
    def test_11_malformed_json_triggers_fallback(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'Not valid JSON {[['
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = self.manager.generate(
            prompt="test prompt",
            model="llama3.2:1b",
            mode=ModelMode.FAST,
            fallback_text="default fallback rationale"
        )
        self.assertTrue(res.is_fallback)
        self.assertEqual(res.fallback_reason, "malformed_response")
        self.assertEqual(res.text, "default fallback rationale")

    @patch("urllib.request.urlopen")
    def test_successful_inference_returns_telemetry(self, mock_urlopen):
        success_payload = b'{"response": "Valid technical rationale explanation.", "prompt_eval_count": 50, "eval_count": 25, "eval_duration": 2000000000}'
        mock_resp = MagicMock()
        mock_resp.read.return_value = success_payload
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = self.manager.generate(
            prompt="Explain rule",
            model="llama3.2:1b",
            mode=ModelMode.FAST,
            fallback_text="fallback"
        )
        self.assertFalse(res.is_fallback)
        self.assertIsNone(res.fallback_reason)
        self.assertEqual(res.text, "Valid technical rationale explanation.")
        self.assertEqual(res.prompt_tokens, 50)
        self.assertEqual(res.output_tokens, 25)
        self.assertEqual(res.tokens_per_sec, 12.5)


class TestSecurityBoundaries(unittest.TestCase):
    def test_12_model_manager_cannot_write_trusted_mappings(self):
        src = inspect.getsource(ai_model_manager)
        self.assertNotIn("trusted_mappings.json", src)
        self.assertNotIn("INSERT INTO trusted_mappings", src)
        self.assertNotIn("INSERT OR REPLACE INTO trusted_mappings", src)

    def test_13_model_manager_cannot_bypass_reviewer_approval(self):
        src = inspect.getsource(ai_model_manager)
        # Model manager must not contain any approval mutation functions
        self.assertNotIn("approve_suggestion", src)
        self.assertNotIn("UPDATE pending_suggestions", src)

    def test_14_remediation_remains_display_only(self):
        src = inspect.getsource(ai_model_manager)
        forbidden = ["paramiko", "netmiko", "pexpect", "telnetlib", "subprocess.Popen", "os.system"]
        for term in forbidden:
            self.assertNotIn(term, src)

    def test_ssrf_sanitization_forces_loopback(self):
        # Attempting to supply external/cloud metadata URL must be sanitized back to loopback
        mgr_evil = AIModelManager(base_url="http://169.254.169.254:11434")
        self.assertEqual(mgr_evil.base_url, "http://127.0.0.1:11434")

        mgr_remote = AIModelManager(base_url="https://remote-attacker-server.com:11434")
        self.assertEqual(mgr_remote.base_url, "http://127.0.0.1:11434")

        # Valid loopbacks preserved
        mgr_local = AIModelManager(base_url="http://localhost:11434")
        self.assertEqual(mgr_local.base_url, "http://localhost:11434")


if __name__ == "__main__":
    unittest.main()
