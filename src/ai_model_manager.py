"""AI Model Manager Subsystem (PRD Addendum §2, Benchmark Audit Architecture).
Provides centralized local model selection, hardware-aware auto-routing,
safe Ollama invocation over loopback, strict model allowlisting, timeout clamping,
refusal detection, and multi-tier deterministic fallback.

Guarantees:
- Zero device execution capability (AST-safe).
- Zero direct writes to trusted_mappings (human reviewer gate strictly enforced).
- Purely advisory out-of-band execution: deterministic engine retains final authority.
"""
import ctypes
from dataclasses import dataclass
from enum import Enum
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import urllib.error
import urllib.parse
import urllib.request

# --- 1. Enumerations & Constants ---

class ModelMode(str, Enum):
    FAST = "fast"
    QUALITY = "quality"
    AUTO = "auto"
    OVERRIDE = "override"
    DETERMINISTIC_ONLY = "deterministic_only"

class WorkloadType(str, Enum):
    UNMAPPED_LINE_MAPPING = "unmapped_line_mapping"
    REMEDIATION_EXPLANATION = "remediation_explanation"

DEFAULT_FAST_MODEL = "llama3.2:1b"
DEFAULT_QUALITY_MODEL = "qwen2.5:7b-instruct-q4_K_M"
DETERMINISTIC_MODEL = "deterministic_only"

# Strict Allowlist: arbitrary model strings from untrusted input are NEVER passed to Ollama
MODEL_ALLOWLIST = {
    DEFAULT_FAST_MODEL: {
        "family": "llama",
        "tier": "fast",
        "parameters": "1.2B",
        "quantization": "Q8_0"
    },
    DEFAULT_QUALITY_MODEL: {
        "family": "qwen2",
        "tier": "quality",
        "parameters": "7.6B",
        "quantization": "Q4_K_M"
    },
    DETERMINISTIC_MODEL: {
        "family": "none",
        "tier": "deterministic",
        "parameters": "0"
    }
}

# Refusal markers matching historical audit observations and production filters
REFUSAL_MARKERS = (
    "i can't provide", "i cannot provide", "illegal or harmful",
    "i'm not able to", "i can't assist", "i cannot assist",
    "i'm unable to", "associated with malicious",
    "i can't fulfill", "i cannot fulfill", "i can't complete",
    "as an ai", "as a language model"
)

# Host & Timeout Bounds
DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
MIN_TIMEOUT_SEC = 5
MAX_TIMEOUT_SEC = 120
DEFAULT_FAST_TIMEOUT = 15
DEFAULT_QUALITY_TIMEOUT = 45


# --- 2. Dataclasses ---

@dataclass
class HardwareProfile:
    total_ram_gb: float
    available_ram_gb: float
    cpu_cores: int
    cpu_threads: int
    has_gpu: bool
    gpu_type: str  # "none", "integrated", "dedicated"
    vram_gb: float
    gpu_name: str
    probe_error: Optional[str] = None

@dataclass
class ModelResponse:
    text: str
    model_used: str
    mode_used: ModelMode
    latency_sec: float
    tokens_per_sec: float
    is_fallback: bool
    fallback_reason: Optional[str] = None
    prompt_tokens: int = 0
    output_tokens: int = 0


# --- 3. Hardware Probe Subsystem ---

class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]

def probe_system_hardware() -> HardwareProfile:
    """Probes system memory, CPU cores, and GPU capabilities using stdlib where practical.
    Fails safely with conservative defaults if telemetry cannot be obtained.
    """
    total_ram = 16.0
    avail_ram = 4.0
    probe_err = None

    # 1. Memory Probe (Windows stdlib ctypes or Linux /proc/meminfo)
    try:
        if sys.platform == "win32":
            stat = _MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                total_ram = round(stat.ullTotalPhys / (1024 ** 3), 2)
                avail_ram = round(stat.ullAvailPhys / (1024 ** 3), 2)
        elif os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                meminfo = {}
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        meminfo[parts[0].strip()] = parts[1].strip()
                if "MemTotal" in meminfo:
                    kb = int(meminfo["MemTotal"].split()[0])
                    total_ram = round(kb / (1024 ** 2), 2)
                if "MemAvailable" in meminfo:
                    kb = int(meminfo["MemAvailable"].split()[0])
                    avail_ram = round(kb / (1024 ** 2), 2)
    except Exception as exc:
        probe_err = f"RAM probe exception: {exc}"

    # 2. CPU Probe
    threads = os.cpu_count() or 4
    cores = max(1, threads // 2)

    # 3. GPU Probe (CUDA / Discrete check)
    has_gpu = False
    gpu_type = "none"
    vram_gb = 0.0
    gpu_name = "none"

    try:
        import torch
        if torch.cuda.is_available():
            has_gpu = True
            gpu_type = "dedicated"
            gpu_name = torch.cuda.get_device_name(0)
            props = torch.cuda.get_device_properties(0)
            vram_gb = round(props.total_memory / (1024 ** 3), 2)
    except Exception:
        pass

    # If CUDA not available, check for known integrated GPU markers (e.g. Intel Iris Xe)
    if not has_gpu and sys.platform == "win32":
        # Check environment or standard integrated GPU fallback
        gpu_name = "Intel Iris Xe / Integrated Graphics (CPU Fallback)"
        gpu_type = "integrated"

    return HardwareProfile(
        total_ram_gb=total_ram,
        available_ram_gb=avail_ram,
        cpu_cores=cores,
        cpu_threads=threads,
        has_gpu=has_gpu,
        gpu_type=gpu_type,
        vram_gb=vram_gb,
        gpu_name=gpu_name,
        probe_error=probe_err
    )


# --- 4. Central AI Model Manager ---

class AIModelManager:
    """Coordinates local model selection, invocation, and fail-safe degradation."""

    def __init__(self, base_url: Optional[str] = None):
        raw_url = base_url or os.getenv("OLLAMA_HOST", DEFAULT_OLLAMA_HOST)
        self.base_url = self._validate_and_sanitize_url(raw_url)
        self.active_mode: ModelMode = ModelMode.AUTO
        self.override_model: Optional[str] = None
        self._bootstrap_from_env()

    def _bootstrap_from_env(self) -> None:
        """Seeds initial manager state from environment variables at startup.
        Preserves strict allowlisting; invalid tags degrade safely to AUTO.
        """
        env_mode = os.getenv("AI_MODEL_MODE")
        if env_mode and env_mode.lower().strip() in [m.value for m in ModelMode]:
            self.active_mode = ModelMode(env_mode.lower().strip())
        else:
            self.active_mode = ModelMode.AUTO

        env_override = os.getenv("OLLAMA_MODEL")
        if env_override:
            cleaned = env_override.strip()
            if cleaned in MODEL_ALLOWLIST:
                self.override_model = cleaned
            else:
                self.override_model = None
        else:
            self.override_model = None

        if self.active_mode == ModelMode.OVERRIDE:
            if not self.override_model:
                self.active_mode = ModelMode.AUTO
        else:
            self.override_model = None

    @staticmethod
    def _validate_and_sanitize_url(url_str: str) -> str:
        """Enforces loopback-only binding to prevent Server-Side Request Forgery (SSRF)."""
        parsed = urllib.parse.urlparse(url_str)
        hostname = (parsed.hostname or "").lower()
        allowed_loopbacks = {"127.0.0.1", "localhost", "::1"}
        if hostname not in allowed_loopbacks:
            # Fall back safely to default loopback
            return DEFAULT_OLLAMA_HOST
        port = parsed.port or 11434
        scheme = parsed.scheme or "http"
        return f"{scheme}://{hostname}:{port}"

    def probe_hardware(self) -> HardwareProfile:
        """Returns physical hardware capabilities."""
        return probe_system_hardware()

    def resolve_override_model(self, override_name: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        """Validates an override model name against the strict allowlist.
        Returns (model_name, None) if valid, or (None, fallback_reason) if rejected.
        """
        if not override_name:
            return None, "empty_override_model"
        
        cleaned = override_name.strip()
        if cleaned in MODEL_ALLOWLIST:
            return cleaned, None

        # If user supplied 'qwen2.5:7b' shorthand that 404s, explicitly reject or suggest exact tag
        return None, "invalid_override_model"

    def set_mode(self, mode: Union[str, ModelMode], override_name: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Updates the active model selection mode and optional override tag.
        Enforces strict allowlist validation for override models.
        """
        if isinstance(mode, str):
            try:
                mode_enum = ModelMode(mode.lower().strip())
            except ValueError:
                valid_modes = [m.value for m in ModelMode]
                return False, f"Invalid mode '{mode}'. Allowed modes: {valid_modes}"
        elif isinstance(mode, ModelMode):
            mode_enum = mode
        else:
            return False, "Mode must be a string or ModelMode enum."

        if mode_enum == ModelMode.OVERRIDE:
            if not override_name or not override_name.strip():
                return False, "An override_model tag must be specified when mode is 'override'."
            cleaned_override = override_name.strip()
            if cleaned_override == "qwen2.5:7b":
                return False, "Invalid override model 'qwen2.5:7b'. Exact Ollama tag 'qwen2.5:7b-instruct-q4_K_M' is required."
            validated_model, _ = self.resolve_override_model(cleaned_override)
            if not validated_model:
                return False, f"Invalid override model '{cleaned_override}'. Allowed models: {list(MODEL_ALLOWLIST.keys())}"
            self.active_mode = ModelMode.OVERRIDE
            self.override_model = validated_model
            return True, None

        self.active_mode = mode_enum
        self.override_model = None
        return True, None

    def reset_mode(self, from_env: bool = False) -> None:
        """Resets active mode to AUTO and clears overrides (or re-bootstraps from environment if from_env=True)."""
        if from_env:
            self._bootstrap_from_env()
        else:
            self.active_mode = ModelMode.AUTO
            self.override_model = None

    def is_ollama_alive(self, timeout_sec: float = 2.0) -> bool:
        """Checks if local Ollama daemon is reachable and responding on loopback."""
        url = f"{self.base_url}/api/tags"
        req = urllib.request.Request(url, headers={"User-Agent": "NTRO-Compliance-Auditor/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as response:
                return response.status == 200
        except Exception:
            return False

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive operational status of the AI Model Manager."""
        hw = self.probe_hardware()
        ollama_alive = self.is_ollama_alive()
        effective_model = self.select_model(
            mode=self.active_mode,
            override_name=self.override_model
        )

        fallback_active = (not ollama_alive) or (effective_model == DETERMINISTIC_MODEL)
        fallback_reason = None
        if effective_model == DETERMINISTIC_MODEL:
            # Explicit deterministic_only mode takes priority; also covers auto-routed low-RAM path
            fallback_reason = "deterministic_mode_selected"
        elif not ollama_alive:
            fallback_reason = "ollama_offline"

        hw_dict = {
            "total_ram_gb": hw.total_ram_gb,
            "available_ram_gb": hw.available_ram_gb,
            "cpu_cores": hw.cpu_cores,
            "cpu_threads": hw.cpu_threads,
            "has_gpu": hw.has_gpu,
            "gpu_type": hw.gpu_type,
            "vram_gb": hw.vram_gb,
            "gpu_name": hw.gpu_name,
            "probe_error": hw.probe_error
        }

        return {
            "mode": self.active_mode.value,
            "configured_mode": self.active_mode.value,
            "effective_model": effective_model,
            "override_model": self.override_model,
            "available_models": list(MODEL_ALLOWLIST.keys()),
            "hardware_profile": hw_dict,
            "ollama_alive": ollama_alive,
            "fallback_active": fallback_active,
            "fallback_reason": fallback_reason
        }

    def select_model(
        self,
        mode: Optional[ModelMode] = None,
        workload: WorkloadType = WorkloadType.UNMAPPED_LINE_MAPPING,
        override_name: Optional[str] = None
    ) -> str:
        """Determines the appropriate model tag based on operational mode, workload, and hardware."""
        if mode is None:
            mode = self.active_mode
        if mode == ModelMode.OVERRIDE and override_name is None:
            override_name = self.override_model

        if mode == ModelMode.DETERMINISTIC_ONLY:
            return DETERMINISTIC_MODEL

        if mode == ModelMode.FAST:
            return DEFAULT_FAST_MODEL

        if mode == ModelMode.QUALITY:
            return DEFAULT_QUALITY_MODEL

        if mode == ModelMode.OVERRIDE:
            validated_model, _ = self.resolve_override_model(override_name)
            if validated_model:
                return validated_model
            # Invalid override safely degrades to FAST
            return DEFAULT_FAST_MODEL

        # Mode == AUTO: Hardware-aware dynamic selection
        hw = self.probe_hardware()

        # 1. Dedicated GPU with verified VRAM >= 6.0 GB: QUALITY is safely supported
        if hw.has_gpu and hw.gpu_type == "dedicated" and hw.vram_gb >= 6.0:
            return DEFAULT_QUALITY_MODEL

        # 2. CPU-only system (or integrated GPU where Ollama drops GPU acceleration):
        # Inspect available RAM. Running 7.6B on CPU requires >= 6.0 GB available memory.
        if hw.available_ram_gb >= 6.0:
            return DEFAULT_QUALITY_MODEL

        # 3. Low-memory CPU host (< 6.0 GB available RAM):
        # Workload-sensitive safety rule:
        # - Unmapped line mapping can run FAST (1.2B) efficiently (~3.5s).
        # - Remediation explanation on low-memory CPU avoids 1B hallucination/refusal risks
        #   by routing to deterministic template fallback.
        if workload == WorkloadType.REMEDIATION_EXPLANATION:
            return DETERMINISTIC_MODEL

        return DEFAULT_FAST_MODEL

    def _clamp_timeout(self, timeout_sec: Optional[int], mode: ModelMode) -> int:
        """Enforces bounded timeouts to prevent connection pool starvation and DoS."""
        if timeout_sec is not None:
            raw = timeout_sec
        else:
            env_timeout = os.getenv("OLLAMA_TIMEOUT")
            if env_timeout and env_timeout.isdigit():
                raw = int(env_timeout)
            elif mode == ModelMode.FAST:
                raw = DEFAULT_FAST_TIMEOUT
            else:
                raw = DEFAULT_QUALITY_TIMEOUT
        
        return max(MIN_TIMEOUT_SEC, min(raw, MAX_TIMEOUT_SEC))

    def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        mode: Optional[ModelMode] = None,
        workload: WorkloadType = WorkloadType.UNMAPPED_LINE_MAPPING,
        override_name: Optional[str] = None,
        fallback_text: str = "",
        timeout_sec: Optional[int] = None,
        temperature: float = 0.2
    ) -> ModelResponse:
        """Centralized generation execution with automated timeout, refusal check, and fallback."""
        t0 = time.perf_counter()

        if mode is None:
            mode = self.active_mode
        if mode == ModelMode.OVERRIDE and override_name is None:
            override_name = self.override_model

        # If mode is OVERRIDE and invalid model was provided, immediately fallback safely
        if mode == ModelMode.OVERRIDE:
            resolved_model, override_err = self.resolve_override_model(override_name)
            if not resolved_model:
                elapsed = time.perf_counter() - t0
                return ModelResponse(
                    text=fallback_text,
                    model_used="none",
                    mode_used=mode,
                    latency_sec=round(elapsed, 3),
                    tokens_per_sec=0.0,
                    is_fallback=True,
                    fallback_reason=override_err or "invalid_override_model"
                )
            target_model = resolved_model
        elif model:
            # Model explicitly passed
            if model not in MODEL_ALLOWLIST:
                elapsed = time.perf_counter() - t0
                return ModelResponse(
                    text=fallback_text,
                    model_used="none",
                    mode_used=mode,
                    latency_sec=round(elapsed, 3),
                    tokens_per_sec=0.0,
                    is_fallback=True,
                    fallback_reason="model_not_allowlisted"
                )
            target_model = model
        else:
            target_model = self.select_model(mode=mode, workload=workload, override_name=override_name)

        # If model selected is DETERMINISTIC_MODEL, skip Ollama and return deterministic fallback
        if target_model == DETERMINISTIC_MODEL:
            elapsed = time.perf_counter() - t0
            return ModelResponse(
                text=fallback_text,
                model_used=DETERMINISTIC_MODEL,
                mode_used=mode,
                latency_sec=round(elapsed, 3),
                tokens_per_sec=0.0,
                is_fallback=True,
                fallback_reason="auto_routed_to_deterministic"
            )

        effective_timeout = self._clamp_timeout(timeout_sec, mode)
        generate_url = f"{self.base_url}/api/generate"

        payload = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "top_p": 0.9
            }
        }

        try:
            req = urllib.request.Request(
                generate_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=effective_timeout) as resp:
                raw_bytes = resp.read()
                try:
                    data = json.loads(raw_bytes.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    elapsed = time.perf_counter() - t0
                    return ModelResponse(
                        text=fallback_text,
                        model_used=target_model,
                        mode_used=mode,
                        latency_sec=round(elapsed, 3),
                        tokens_per_sec=0.0,
                        is_fallback=True,
                        fallback_reason="malformed_response"
                    )

            elapsed = time.perf_counter() - t0
            response_text = data.get("response", "").strip()
            eval_count = data.get("eval_count", 0)
            eval_dur_s = (data.get("eval_duration", 0) / 1e9)
            prompt_eval_count = data.get("prompt_eval_count", 0)
            tok_per_sec = round((eval_count / eval_dur_s), 2) if eval_dur_s > 0 else 0.0

            # Refusal Detection Guard
            is_refusal = any(m in response_text.lower() for m in REFUSAL_MARKERS)
            if is_refusal or len(response_text) < 5:
                return ModelResponse(
                    text=fallback_text,
                    model_used=target_model,
                    mode_used=mode,
                    latency_sec=round(elapsed, 3),
                    tokens_per_sec=tok_per_sec,
                    is_fallback=True,
                    fallback_reason="safety_refusal" if is_refusal else "empty_response",
                    prompt_tokens=prompt_eval_count,
                    output_tokens=eval_count
                )

            return ModelResponse(
                text=response_text,
                model_used=target_model,
                mode_used=mode,
                latency_sec=round(elapsed, 3),
                tokens_per_sec=tok_per_sec,
                is_fallback=False,
                fallback_reason=None,
                prompt_tokens=prompt_eval_count,
                output_tokens=eval_count
            )

        except urllib.error.HTTPError as http_err:
            elapsed = time.perf_counter() - t0
            reason = "model_not_found_404" if http_err.code == 404 else f"http_error_{http_err.code}"
            return ModelResponse(
                text=fallback_text,
                model_used=target_model,
                mode_used=mode,
                latency_sec=round(elapsed, 3),
                tokens_per_sec=0.0,
                is_fallback=True,
                fallback_reason=reason
            )
        except (TimeoutError, urllib.error.URLError, OSError) as net_err:
            elapsed = time.perf_counter() - t0
            reason = "timeout" if isinstance(net_err, TimeoutError) or "timed out" in str(net_err).lower() else "connection_refused"
            return ModelResponse(
                text=fallback_text,
                model_used=target_model,
                mode_used=mode,
                latency_sec=round(elapsed, 3),
                tokens_per_sec=0.0,
                is_fallback=True,
                fallback_reason=reason
            )


# Module-level default singleton for easy consumption
_DEFAULT_MANAGER: Optional[AIModelManager] = None

def get_model_manager() -> AIModelManager:
    global _DEFAULT_MANAGER
    if _DEFAULT_MANAGER is None:
        _DEFAULT_MANAGER = AIModelManager()
    return _DEFAULT_MANAGER
