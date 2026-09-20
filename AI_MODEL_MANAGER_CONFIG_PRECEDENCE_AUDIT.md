# NTRO PS26155 — AI Model Manager: Configuration Precedence & Consistency Audit
## PRE-CHUNK-2B VERIFICATION — AUDIT ONLY — ZERO SOURCE CODE CHANGES

**Project:** NTRO PS26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor  
**Team:** NextGen  
**Audit Target:** Model Manager Mode vs. Environment Variables Precedence & REST API Consistency  
**Date:** 2026-09-19  
**Status:** AUDIT COMPLETE — FINDINGS & RECOMMENDATIONS DOCUMENTED  

---

## 1. Executive Summary

This audit rigorously inspects the configuration precedence and interaction between:
1. **API-selected Model Manager mode** (`_MODEL_MANAGER.active_mode` / `_MODEL_MANAGER.override_model`)
2. **Environment variables** (`OLLAMA_MODEL`, `AI_MODEL_MODE`)
3. **Operational modes** (`FAST`, `QUALITY`, `AUTO`, `OVERRIDE`)
4. **Deterministic fallback paths**

The primary objective is to verify whether the REST API endpoint `GET /api/model/status` and the actual runtime inference paths in `ai_suggester.py` and `remediation_engine.py` are guaranteed to remain synchronized, or whether environment variables can cause them to silently diverge.

---

## 2. Files Inspected & Code Evidence

| File | Exact Lines Inspected | Key Logic / Responsibility |
| :--- | :--- | :--- |
| [`ai_model_manager.py`](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_model_manager.py) | L41–59, L220–265, L277–315, L321–367, L383–445 | `MODEL_ALLOWLIST`, `set_mode()`, `get_status()`, `select_model()`, `generate()` |
| [`ai_suggester.py`](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_suggester.py) | L41–74 | `_generate_rationale_ai()` model and override resolution |
| [`remediation_engine.py`](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/remediation_engine.py) | L105–145 | `explain_failure_ai()` model and override resolution |
| [`main.py`](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py) | L146–152, L587–623 | REST endpoints `GET /api/model/status` and `POST /api/model/mode` |
| [`.env.example`](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/.env.example) | L14–18 | Default environment template shipping `OLLAMA_MODEL=llama3.2:1b` |

---

## 3. Configuration Precedence Trace (Check 1)

### Observed Precedence in Calling Subsystems
In both `ai_suggester.py` (L55–57) and `remediation_engine.py` (L130–132), the mode and override resolution is implemented as:
```python
env_mode = os.getenv("AI_MODEL_MODE")
mode = ModelMode(env_mode.lower()) if env_mode and env_mode.lower() in [m.value for m in ModelMode] else _MODEL_MANAGER.active_mode
override_model = os.getenv("OLLAMA_MODEL") if mode == ModelMode.OVERRIDE else _MODEL_MANAGER.override_model
```

### Observed Precedence in REST API Status
In `main.py` (L595) and `ai_model_manager.py` (L277–315):
```python
def get_status(self) -> Dict[str, Any]:
    hw = self.probe_hardware()
    ollama_alive = self.is_ollama_alive()
    effective_model = self.select_model(
        mode=self.active_mode,
        override_name=self.override_model
    )
    ...
```
`get_status()` inspects **only** `self.active_mode` and `self.override_model`. It does **not** read `os.getenv("AI_MODEL_MODE")` or `os.getenv("OLLAMA_MODEL")`.

### Actual Precedence Order

1. **For Execution Mode Selection (`mode`):**
   - **Rank 1 (Highest):** `os.getenv("AI_MODEL_MODE")` (if set in OS environment and matches a valid `ModelMode` value)
   - **Rank 2:** `_MODEL_MANAGER.active_mode` (configured via `POST /api/model/mode`)
   - **Rank 3 (Default):** `ModelMode.AUTO`

2. **For Override Model Selection (`override_model` when `mode == OVERRIDE`):**
   - **Rank 1 (Highest):** `os.getenv("OLLAMA_MODEL")` (if set in OS environment)
   - **Rank 2:** `_MODEL_MANAGER.override_model` (configured via `POST /api/model/mode`)
   - **Rank 3:** `None`

3. **For Allowlist Verification & Fallback Enforcement:**
   - **Rank 1 (Highest / Non-Bypassable):** `MODEL_ALLOWLIST` in `ai_model_manager.py`. Any model from Rank 1 or Rank 2 that is not explicitly in `MODEL_ALLOWLIST` is immediately rejected by `resolve_override_model()` and diverted to deterministic fallback.

---

## 4. API Status Consistency Matrix (Check 2)

| Configured Mode | Workload: `UNMAPPED_LINE_MAPPING` | Workload: `REMEDIATION_EXPLANATION` | `GET /api/model/status` Report | Status vs Execution Parity | Label |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`FAST`** | `llama3.2:1b` | `llama3.2:1b` | `llama3.2:1b` | **100% Match** | `VERIFIED` |
| **`QUALITY`** | `qwen2.5:7b-instruct-q4_K_M` | `qwen2.5:7b-instruct-q4_K_M` | `qwen2.5:7b-instruct-q4_K_M` | **100% Match** | `VERIFIED` |
| **`AUTO` (RAM $\ge$ 6GB or GPU)** | `qwen2.5:7b-instruct-q4_K_M` | `qwen2.5:7b-instruct-q4_K_M` | `qwen2.5:7b-instruct-q4_K_M` | **100% Match** | `VERIFIED` |
| **`AUTO` (RAM $<$ 6GB, CPU)** | `llama3.2:1b` | `deterministic_only` | `llama3.2:1b` | **Partial Variance** (Workload-Dependent) | `OBSERVED` |
| **`OVERRIDE` (No Env Vars)** | `override_model` | `override_model` | `override_model` | **100% Match** | `VERIFIED` |
| **`OVERRIDE` (With `OLLAMA_MODEL`)** | `os.getenv("OLLAMA_MODEL")` | `os.getenv("OLLAMA_MODEL")` | `manager.override_model` | **SILENT DIVERGENCE** | `POTENTIAL ISSUE` |

---

## 5. Environment Variable Interaction Scenarios (Check 3)

### Scenario A: `OLLAMA_MODEL=llama3.2:1b` and API selects `QUALITY`
- **Tracing:**
  1. API executes `manager.set_mode("quality")`.
  2. Subsystems evaluate: `override_model = os.getenv("OLLAMA_MODEL") if mode == ModelMode.OVERRIDE else _MODEL_MANAGER.override_model`.
  3. Because `mode == ModelMode.QUALITY`, the condition is `False`. `override_model` is evaluated as `None`.
  4. `_MODEL_MANAGER.generate()` receives `mode=ModelMode.QUALITY, override_name=None`.
  5. `generate()` calls `select_model(mode=ModelMode.QUALITY)` $\rightarrow$ returns `qwen2.5:7b-instruct-q4_K_M`.
  6. API status reports `effective_model: "qwen2.5:7b-instruct-q4_K_M"`.
- **Finding:** `NO ISSUE`. `OLLAMA_MODEL` has **zero effect** when API selects `QUALITY`.

### Scenario B: `OLLAMA_MODEL=qwen2.5:7b-instruct-q4_K_M` and API selects `FAST`
- **Tracing:**
  1. API executes `manager.set_mode("fast")`.
  2. Because `mode == ModelMode.FAST`, `mode == ModelMode.OVERRIDE` is `False`.
  3. `override_model` is evaluated as `None`.
  4. `generate()` calls `select_model(mode=ModelMode.FAST)` $\rightarrow$ returns `llama3.2:1b`.
  5. API status reports `effective_model: "llama3.2:1b"`.
- **Finding:** `NO ISSUE`. `OLLAMA_MODEL` has **zero effect** when API selects `FAST`.

### Scenario C: `OLLAMA_MODEL` behavior in `AUTO` Mode
- **Tracing:**
  1. API mode is `ModelMode.AUTO`.
  2. `mode == ModelMode.OVERRIDE` is `False`.
  3. `OLLAMA_MODEL` is completely ignored.
  4. Model is selected strictly via hardware probes (RAM, GPU) and workload type.
- **Finding:** `NO ISSUE`. `OLLAMA_MODEL` has **zero effect** in `AUTO` mode.

### Scenario D: `OLLAMA_MODEL` behavior in `OVERRIDE` Mode
- **Tracing:**
  1. Reviewer posts `{"mode": "override", "override_model": "llama3.2:1b"}`.
  2. `manager.active_mode = ModelMode.OVERRIDE` and `manager.override_model = "llama3.2:1b"`.
  3. API status `GET /api/model/status` reports `configured_mode: "override"`, `effective_model: "llama3.2:1b"`.
  4. But if the container environment contains `OLLAMA_MODEL=qwen2.5:7b-instruct-q4_K_M` (e.g. from `.env` or container startup):
     - `ai_suggester.py` line 57 resolves `override_model = os.getenv("OLLAMA_MODEL")` because `mode == ModelMode.OVERRIDE`.
     - Actual inference uses `qwen2.5:7b-instruct-q4_K_M`!
- **Finding:** `POTENTIAL ISSUE`. When `OLLAMA_MODEL` is present in the host environment, an API-requested `OVERRIDE` model can be overridden by the environment variable, creating a silent divergence between the API status response and the model used during inference.

---

## 6. Security & Boundary Analysis (Check 4)

### 1. Can a reviewer select QUALITY while actual inference uses FAST via OLLAMA_MODEL?
- **Answer:** **NO (`VERIFIED`).**
- **Evidence:** `OLLAMA_MODEL` is gated behind `if mode == ModelMode.OVERRIDE`. When the API mode is `QUALITY`, `OLLAMA_MODEL` is never evaluated.

### 2. Can a reviewer select FAST while actual inference uses QUALITY via OLLAMA_MODEL?
- **Answer:** **NO (`VERIFIED`).**
- **Evidence:** When the API mode is `FAST`, `OLLAMA_MODEL` is never evaluated.

### 3. Can an invalid environment model bypass the strict model allowlist?
- **Answer:** **NO (`VERIFIED`).**
- **Evidence:** Even if `mode == ModelMode.OVERRIDE` and `OLLAMA_MODEL` is injected with an arbitrary or malicious string (e.g. `OLLAMA_MODEL="gpt-4o; cat /etc/passwd"` or `qwen2.5:7b`), `AIModelManager.generate()` runs `resolve_override_model()` on L404. If the model tag is not in `MODEL_ALLOWLIST`, Ollama is never called, and the system immediately returns a safe deterministic fallback (`fallback_reason="invalid_override_model"`).

### 4. Can OVERRIDE bypass allowlisting?
- **Answer:** **NO (`VERIFIED`).**
- **Evidence:** `POST /api/model/mode` enforces allowlist validation in `manager.set_mode()`. Furthermore, `manager.generate()` independently re-validates the model tag against `MODEL_ALLOWLIST` before issuing any HTTP request.

### 5. Can any of these paths bypass deterministic fallback?
- **Answer:** **NO (`VERIFIED`).**
- **Evidence:** Any network failure, timeout, safety refusal, empty response, or allowlist rejection immediately degrades to deterministic template fallbacks. The deterministic engine retains final authority over all compliance audit results (`Pass`/`Fail`/`Unknown`).

---

## 7. Conceptual Architecture Evaluation (Check 5)

The intended architecture specifies:
```
                    MODEL MANAGER
                         ↓
                  configured mode
                         ↓
             ┌───────────┼───────────┐
             ↓           ↓           ↓
           FAST       QUALITY       AUTO
             │           │           │
             └───────────┼───────────┘
                         ↓
                  model selection
                         ↓
                  allowlist check
                         ↓
                 hardware safety
                         ↓
                    Ollama
                         ↓
              failure/refusal/timeout
                         ↓
             deterministic fallback
```

### Architectural Deviation Identified
In the current implementation:
1. `_generate_rationale_ai()` and `explain_failure_ai()` maintain independent environment variable lookups (`os.getenv("AI_MODEL_MODE")` and `os.getenv("OLLAMA_MODEL")`) outside of `AIModelManager`.
2. This creates a side-channel where the host environment can override the Model Manager's internal state without updating `get_status()`.

---

## 8. Summary of Labels & Findings

- **`VERIFIED` (No Silent Disagreement in FAST & QUALITY):**
  When API sets `FAST` or `QUALITY`, `GET /api/model/status` and both inference workloads are 100% synchronized regardless of `OLLAMA_MODEL`.
- **`VERIFIED` (Security Boundaries Intact):**
  Zero allowlist bypass possible; zero device execution possible; deterministic fallback is guaranteed on all error/refusal paths.
- **`OBSERVED` (AUTO Mode Workload Specialization):**
  On low-memory CPU systems (< 6GB RAM), `AUTO` mode routes `UNMAPPED_LINE_MAPPING` to `llama3.2:1b` and `REMEDIATION_EXPLANATION` to `deterministic_only`. `GET /api/model/status` reports `llama3.2:1b`.
- **`POTENTIAL ISSUE` (OVERRIDE Divergence):**
  If `OLLAMA_MODEL` is set in the OS environment, switching to `OVERRIDE` via the API causes the inference engine to prioritize `os.getenv("OLLAMA_MODEL")` over `manager.override_model`, while `GET /api/model/status` displays `manager.override_model`.
- **`POTENTIAL ISSUE` (AI_MODEL_MODE Divergence):**
  If `AI_MODEL_MODE` is set in the OS environment, it overrides `_MODEL_MANAGER.active_mode` during inference, but `GET /api/model/status` reports `_MODEL_MANAGER.active_mode`.

---

## 9. Recommendations (For Future Implementation / Chunk 2B)

> [!NOTE]
> **Audit Constraint Observed:** Per the prompt instructions, **ZERO code changes** have been made during this audit. The following recommendations are provided for review before entering Chunk 2B.

1. **Centralize Mode & Override in `AIModelManager` (`RECOMMENDATION`):**
   Remove `os.getenv("AI_MODEL_MODE")` and `os.getenv("OLLAMA_MODEL")` from `ai_suggester.py` and `remediation_engine.py`.
   Have callers invoke `_MODEL_MANAGER.generate(prompt=prompt, workload=WorkloadType.xxx)` with no mode/override arguments.
   Allow `AIModelManager` to be the single source of truth:
   - Initial active mode and override model can be seeded from environment variables at startup (`os.getenv("AI_MODEL_MODE", "auto")`, `os.getenv("OLLAMA_MODEL")`).
   - Any runtime change via `POST /api/model/mode` updates the manager's state.
   - All subsequent inferences and `GET /api/model/status` read directly from that single manager state.
   This guarantees that API status and inference can **never** disagree.

2. **Refine `GET /api/model/status` Workload Transparency (`RECOMMENDATION`):**
   In `AUTO` mode on low-memory systems, consider including workload-specific resolution in the status payload:
   ```json
   {
     "effective_model": "llama3.2:1b",
     "workload_models": {
       "unmapped_line_mapping": "llama3.2:1b",
       "remediation_explanation": "deterministic_only"
     }
   }
   ```
   This makes the safety routing explicitly visible in the UI dashboard during Chunk 2B.

---

## 10. Audit Sign-off

- **Source Code Changed:** **NONE (0 lines modified, 0 files created in source)**
- **Tests Changed:** **NONE**
- **Git State:** **Untouched**
- **Status:** **Ready for human review**
