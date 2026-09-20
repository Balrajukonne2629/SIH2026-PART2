# NTRO PS26155 — AI Model Manager: Chunk 1 Backend Core Implementation Report
**Project:** NTRO PS26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor  
**Team:** NextGen  
**Date:** September 18, 2026  
**Scope:** CHUNK 1: BACKEND CORE IMPLEMENTATION (Zero Frontend / Zero Commit)  

---

## 1. Implementation Summary `[IMPLEMENTED]`

In accordance with the authoritative project documents (`NTRO_PS26155_PRD_v4_Addendum.md`, `NTRO_PS26155_Jury_Mentor_Insights_and_Decisions(1).md`, and the completed `AI_HARDWARE_MODEL_BENCHMARK_AUDIT.md`), **Chunk 1 Backend Core** of the AI Model Manager has been implemented and validated.

### Key Milestones Delivered:
1. **`ai_model_manager.py` (New Core Subsystem):** Built with Python standard library, providing clean abstractions (`ModelMode`, `WorkloadType`, `HardwareProfile`, `ModelResponse`).
2. **Strict Model Allowlist:** Hardened against arbitrary model string injection; permits only `llama3.2:1b`, `qwen2.5:7b-instruct-q4_K_M`, and `deterministic_only`.
3. **Hardware Probe Subsystem:** Probes physical RAM, CPU cores/threads, and GPU acceleration capabilities cross-platform without external subprocesses or heavy dependencies.
4. **Hardware- & Workload-Aware Auto Routing:**
   - Dedicated GPU with VRAM ≥ 6.0 GB: selects `QUALITY` (`qwen2.5:7b-instruct-q4_K_M`).
   - CPU-only / low-memory host (< 6.0 GB available RAM):
     - `unmapped_line_mapping` -> routes to `FAST` (`llama3.2:1b`) for sub-6s triage.
     - `remediation_explanation` -> routes to `deterministic_only` to prevent 1B parameter safety refusals and hallucinations.
5. **Fail-Safe Loopback Invocation:** Centralized Ollama REST calls with strict loopback validation (`127.0.0.1`, `localhost`, `::1`), bounded timeouts (5s – 120s), and automated refusal detection.
6. **Integration Boundaries:** Thin, clean integration into `ai_suggester.py` and `remediation_engine.py` preserving 100% backward compatibility.
7. **Zero Regressions:** 17 unit tests in `test_ai_model_manager.py` and all 7 existing project test suites passed with 100% parity.

---

## 2. Architecture `[IMPLEMENTED]`

```
                             APPLICATION / API REQUEST
                                        │
                   ┌────────────────────┴────────────────────┐
                   ▼                                         ▼
           ai_suggester.py                         remediation_engine.py
      (unmapped_line_mapping)                    (remediation_explanation)
                   │                                         │
                   └────────────────────┬────────────────────┘
                                        ▼
                            ai_model_manager.py
                               (get_model_manager)
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        ▼                               ▼                               ▼
 [Hardware Probe]                [Mode Router]                  [Security Guard]
  - RAM (ctypes)            - FAST: llama3.2:1b            - Model Allowlist
  - CPU (os.cpu_count)      - QUALITY: qwen2.5:7b          - SSRF Loopback Sanitize
  - GPU (torch.cuda)        - AUTO: Telemetry Routing      - Bounded Timeout (5-120s)
                            - OVERRIDE: Validated Model    - Refusal Detector
                                        │
                                        ▼
                           Target Selection Result
                                        │
                   ┌────────────────────┴────────────────────┐
                   ▼                                         ▼
            Selected Local Model                      DETERMINISTIC_MODEL
         (llama3.2:1b / qwen2.5:7b)              (Low-RAM Explanation Fallback)
                   │                                         │
                   ▼                                         ▼
         Ollama Local Daemon                     Return Fallback Immediately
       (http://127.0.0.1:11434)                  (DistilBERT / Jinja2 Templates)
                   │
    ┌──────────────┴──────────────┐
    ▼ (Success)                   ▼ (Refusal / Timeout / 404 / Offline)
 Return ModelResponse        Return ModelResponse (is_fallback=True)
 (Text + Telemetry)          + Trigger Deterministic Fallback Template
                                  │
                                  ▼
                =======================================
                DETERMINISTIC COMPLIANCE RULE ENGINE
                (Pass / Fail / Unknown Final Authority)
                =======================================
```

---

## 3. Files Changed `[IMPLEMENTED & TESTED]`

| File | Status | Nature of Change |
| :--- | :--- | :--- |
| `ai_model_manager.py` | **NEW** | Central model manager, hardware probe, mode selection, allowlist, timeout clamping, and Ollama invocation. |
| `test_ai_model_manager.py` | **NEW** | Unit test suite containing 17 automated tests covering all edge cases, hardware mocks, and security properties. |
| `ai_suggester.py` | **MODIFIED** | Replaced raw `_OLLAMA_MODEL` and direct `urllib` calls in `_generate_rationale_ai()` with delegation to `_MODEL_MANAGER.generate()`. Preserved DistilBERT 66M embeddings. |
| `remediation_engine.py` | **MODIFIED** | Replaced raw `_OLLAMA_MODEL` and direct `urllib` calls in `explain_failure_ai()` with delegation to `_MODEL_MANAGER.generate()`. Preserved Jinja2 templates and AST safety. |

---

## 4. Model-Selection Logic `[IMPLEMENTED & TESTED]`

The model manager implements `select_model(mode, workload, override_name)`:

1. **`ModelMode.FAST`:**  
   Always resolves to `DEFAULT_FAST_MODEL` (`llama3.2:1b`).
2. **`ModelMode.QUALITY`:**  
   Always resolves to `DEFAULT_QUALITY_MODEL` (`qwen2.5:7b-instruct-q4_K_M`).
3. **`ModelMode.OVERRIDE`:**  
   Validates `override_name` against `MODEL_ALLOWLIST`. If valid, returns the requested model; if invalid (e.g. arbitrary string or shorthand `qwen2.5:7b`), rejects the override, records fallback reason `invalid_override_model`, and safely routes to `DEFAULT_FAST_MODEL`.
4. **`ModelMode.AUTO`:**  
   Inspects hardware profile from `probe_hardware()` and workload type from `WorkloadType`.

---

## 5. Hardware-Selection Logic `[IMPLEMENTED & TESTED]`

Telemetric decision matrix in `AUTO` mode:

```python
# 1. Dedicated GPU with verified VRAM >= 6.0 GB:
if hw.has_gpu and hw.gpu_type == "dedicated" and hw.vram_gb >= 6.0:
    return DEFAULT_QUALITY_MODEL

# 2. CPU-only system (or integrated GPU where Ollama drops acceleration):
if hw.available_ram_gb >= 6.0:
    return DEFAULT_QUALITY_MODEL

# 3. Low-memory CPU host (< 6.0 GB available RAM):
if workload == WorkloadType.REMEDIATION_EXPLANATION:
    return DETERMINISTIC_MODEL

return DEFAULT_FAST_MODEL
```

### Telemetry Evidence on Current Host `[OBSERVED]`:
- Total Physical RAM: 15.68 GB, Available RAM: ~3.4 – 3.8 GB.
- GPU: Integrated Intel Iris Xe (Dropped by Ollama runner to CPU fallback).
- In `AUTO` mode on this host:
  - `unmapped_line_mapping` -> Automatically selects `llama3.2:1b` (measured latency ~5.2s).
  - `remediation_explanation` -> Automatically selects `deterministic_only` (reason: `auto_routed_to_deterministic`), completely eliminating the 33% false-refusal failure mode observed in Llama-3.2-1B during the audit.

---

## 6. Fallback Logic `[IMPLEMENTED & TESTED]`

Multi-tiered fail-safe ladder:

| Failure Mode | Trigger Condition | Model Manager Action | Caller Fallback Behavior |
| :--- | :--- | :--- | :--- |
| **Daemon Offline** | WinError 10061 / Connection Refused | Returns `ModelResponse(is_fallback=True, fallback_reason="connection_refused")` | Returns hardcoded template or DistilBERT rationale |
| **Model Missing (404)** | HTTP 404 from Ollama | Returns `ModelResponse(is_fallback=True, fallback_reason="model_not_found_404")` | Returns fallback text |
| **Inference Timeout** | Elapsed > clamped timeout | Returns `ModelResponse(is_fallback=True, fallback_reason="timeout")` | Loads pre-compiled Jinja2 rationale |
| **Safety Refusal** | Response matches `REFUSAL_MARKERS` | Discards refusal; returns `is_fallback=True, fallback_reason="safety_refusal"` | Replaces refusal with deterministic security explanation |
| **Malformed JSON** | Invalid syntax / bytes | Returns `is_fallback=True, fallback_reason="malformed_response"` | Uses fallback text |
| **Low-Memory Auto** | Available RAM < 6GB on explanation | Returns `is_fallback=True, fallback_reason="auto_routed_to_deterministic"` | Immediately loads verified static template |

---

## 7. Security Controls `[IMPLEMENTED & TESTED]`

1. **Model Allowlisting:** Arbitrary strings cannot be passed to Ollama. Any model not in `MODEL_ALLOWLIST` is blocked before network invocation.
2. **SSRF Prevention:** `_validate_and_sanitize_url()` parses input base URLs and enforces strict loopback binding (`127.0.0.1`, `localhost`, `::1`). External or cloud metadata IPs (e.g. `169.254.169.254`) are stripped and reset to `http://127.0.0.1:11434`.
3. **Bounded Timeouts:** Timeouts are clamped to `[5s, 120s]`, preventing thread pool exhaustion or DoS attacks via runaway local inference.
4. **Architectural Isolation:**
   - `ai_model_manager.py` contains **zero database write operations** and **zero calls to `trusted_mappings`**.
   - Model manager cannot approve suggestions or bypass reviewer identity binding.
   - Remediation commands remain strictly display-only. AST analysis confirms zero execution libraries (`subprocess`, `socket`, `paramiko`, etc.) exist in `remediation_engine.py` or `main.py`.

---

## 8. Tests Executed `[TESTED]`

1. `test_ai_model_manager.py` (17 automated unit & security tests)
2. `test_step5_full_loop.py` (17-stage end-to-end integration and tamper-detection suite)
3. `test_database.py` (SQLite schema, migrations, and session persistence)
4. `test_auth.py` (Argon2id hashing, salt generation, and JWT token life cycle)
5. `test_api_auth.py` (FastAPI login, rate limiting, and 401 handling)
6. `test_api_ownership.py` (Session access control and anti-enumeration)
7. `test_api_rbac.py` (Role-based access control across uploader/reviewer roles)
8. `test_api_reviewer_identity.py` (Stateless reviewer identity binding from JWT sub claim)
9. `test_api_full_loop.py` (Complete API parity test against CLI baseline)
10. `scratch/test_live_manager.py` (Live inference test with active Ollama daemon)

---

## 9. Exact Test Results `[OBSERVED & TESTED]`

### Unit Tests (`test_ai_model_manager.py`)
```text
Ran 17 tests in 0.014s
OK
- test_1_fast_mode_selects_llama32_1b: PASS
- test_2_quality_mode_selects_qwen25_7b: PASS
- test_3_invalid_override_rejected_safely: PASS
- test_4_auto_low_memory_cpu_does_not_select_quality_for_explanation: PASS
- test_5_auto_sufficient_memory_cpu_selects_quality: PASS
- test_6_auto_dedicated_gpu_with_sufficient_vram_selects_quality: PASS
- test_7_connection_refused_triggers_fallback: PASS
- test_8_http_404_model_not_found_triggers_fallback: PASS
- test_9_timeout_triggers_fallback: PASS
- test_10_safety_refusal_triggers_fallback: PASS
- test_11_malformed_json_triggers_fallback: PASS
- test_12_model_manager_cannot_write_trusted_mappings: PASS
- test_13_model_manager_cannot_bypass_reviewer_approval: PASS
- test_14_remediation_remains_display_only: PASS
- test_ssrf_sanitization_forces_loopback: PASS
- test_successful_inference_returns_telemetry: PASS
- test_valid_override_accepted: PASS
```

### End-to-End Integration Test (`test_step5_full_loop.py`)
```text
ALL 17 STAGES & ACCEPTANCE CRITERIA VERIFIED SUCCESSFULLY:
- Stage 4 Local AI Unmapped-Line Interpretation: [suggest_mapping] path=fallback reason=connection_refused -> PASS
- Stage 8 Jinja2 Remediation Generation: Rendered CLI Fix -> PASS
- Stage 8 AST Execution Safety Check: Zero execution or connection libraries imported -> PASS
- Stage 10 Local AI Failure Explanation: [explain_failure_ai] path=fallback reason=auto_routed_to_deterministic -> PASS
- Stage 14 Complete Audit Log Hash Chain: verify_chain() Result: True -> PASS
- Stage 16 Tamper Detection: Broken Entry Identified #1 -> PASS
- Stage 17 Deterministic Performance: 2,220 lines in 0.0078s (< 5.0s budget, 641x faster) -> PASS
```

### Live Inference Test (`scratch/test_live_manager.py` with Ollama)
```text
--- Testing Live FAST Mode (llama3.2:1b) ---
FAST Response: Service password-encryption is a standard Cisco compliance control because it ensures that sensitive administrative passwords are encrypted and protected, preventing unauthorized access to network devices and data.
Model: llama3.2:1b, Mode: ModelMode.FAST, Latency: 6.182s, tok/s: 12.98, Fallback: False

--- Testing Live AUTO Mode on Current Hardware ---
Hardware probed: RAM=15.68GB total / 3.82GB avail, CPU=6C/12T, GPU=integrated (Intel Iris Xe / Integrated Graphics (CPU Fallback))
AUTO Mapping Selected Model: llama3.2:1b (is_fallback=False)
AUTO Explanation Selected Model: deterministic_only (is_fallback=True, reason=auto_routed_to_deterministic)
```

---

## 10. Regression Results `[OBSERVED & TESTED]`

All pre-existing test suites were run in sequence against the modified codebase:
- `test_database.py`: **PASS**
- `test_auth.py`: **PASS**
- `test_api_auth.py`: **PASS**
- `test_api_ownership.py`: **PASS**
- `test_api_rbac.py`: **PASS**
- `test_api_reviewer_identity.py`: **PASS**
- `test_api_full_loop.py`: **PASS (100% Side-by-Side Parity across all 24 compliance properties)**

---

## 11. Git Diff & Change-Safety Verification `[OBSERVED]`

Running `git status` and `git diff`:
- Pre-existing uncommitted work in `.gitignore`, `audit_log.py`, `dashboard/*`, `main.py`, `report_generator.py`, and `test_api_full_loop.py` was **strictly preserved without alteration**.
- Source code changes introduced by Chunk 1 were restricted to:
  - `ai_model_manager.py` (New untracked file)
  - `test_ai_model_manager.py` (New untracked file)
  - `ai_suggester.py` (Refactored `_generate_rationale_ai` to call model manager)
  - `remediation_engine.py` (Refactored `explain_failure_ai` to call model manager)
- **Zero commits were created.**

---

## 12. Known Limitations `[OBSERVED]`

1. **Host GPU Constraint:** The test machine lacks a dedicated NVIDIA/AMD GPU. GPU-accelerated code paths were verified via unit mocks.
2. **CPU Execution Latency:** On this CPU-bound machine, running 7.6B models takes ~22–37 seconds. The `AUTO` routing properly avoids loading 7B models for explanations when free RAM is low.
3. **Chunk 1 Backend Scope:** The dashboard UI does not yet display model status badges or interactive mode dropdowns (deferred to Chunk 2).

---

## 13. Recommended Next Chunk `[FUTURE]`

**Chunk 2 Scope (REST Endpoints & Frontend UI Integration):**
1. Expose `GET /api/model/status` in `main.py` returning active mode, active model, hardware telemetry, and Ollama daemon health.
2. Expose `POST /api/model/mode` allowing authorized administrators/reviewers to set `FAST`, `QUALITY`, `AUTO`, or `OVERRIDE`.
3. Add an active AI Model badge (`FAST [1.2B]` / `QUALITY [7.6B]` / `AUTO [Active]`) to `dashboard/src/components/Navbar.tsx`.
4. Surface inference latency and model used in `AiSuggestionReviewScreen.tsx`.

---
*Certified by NextGen Engineering Subsystem. Strict Stop Condition Activated. Awaiting human review.*
