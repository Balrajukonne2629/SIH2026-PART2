# NTRO PS26155 — Codebase Reality Audit
**Read-Only Architecture, Dependency, Security & Redundancy Reconnaissance (Phase 3R.0)**  
**Date:** September 20, 2026  
**Auditor:** NextGen Team (Agentic Audit Subsystem)  
**Status:** COMPLETE (Read-Only Baseline Established)

---

## 1. Audit Objective

This audit establishes an authoritative, empirical, and strictly verified baseline of the NTRO PS26155 codebase prior to initiating any refactoring or optimization under Phase 3R. In strict accordance with the **Absolute Read-Only Rule**, zero production files, configurations, database schemas, or tests were altered during this audit.

The primary objective is to separate verified fact from historical documentation drift and determine:
1. What code actually exists versus what is documented.
2. What components are actively exercised by production runtime and test pipelines.
3. Where the authoritative single source of truth resides for each architectural domain.
4. What redundancies, duplicate implementations, dead artifacts, and legacy paths exist.
5. What architectural boundaries, security fences, and compliance guarantees must **never be touched**.
6. An evidence-based, prioritized roadmap for subsequent Phase 3R refactoring iterations.

---

## 2. Audit Scope

The scope of this reconnaissance spans all backend modules, REST APIs, frontend codebases, persistence layers, machine learning models, configuration datasets, and test harnesses within the workspace:

- **Core Backend:** [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py), [cisco_auditor.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cisco_auditor.py), [audit_log.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/audit_log.py), [remediation_engine.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/remediation_engine.py), [report_generator.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/report_generator.py).
- **Security & Authorization:** [auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/auth.py), [database.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/database.py).
- **Compliance Architecture (Phases 3A.1 – 3A.5):** [compliance_framework.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_framework.py), [cis_benchmark_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cis_benchmark_cisco_iosxe.py), [disa_stig_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/disa_stig_cisco_iosxe.py), [compliance_aggregator.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_aggregator.py).
- **AI & Inference:** [ai_model_manager.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_model_manager.py), [ai_suggester.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_suggester.py).
- **Persistence:** SQLite (`data/auditor.db`), JSON/JSONL artifacts (`trusted_mappings.json`, `pending_suggestions.json`).
- **Frontend Applications:** Production dashboard (`dashboard/`), Prototype frontend (`arena-frontend/`).
- **Test Harnesses:** 17 Python test files, 2 Node.js test suites in dashboard.
- **Static Assets & Datasets:** `00_Project_Documentation` through `10_Additional_References`, `templates/remediation/`.

---

## 3. Current Git State

Inspection performed via `git status`, `git branch`, and `git log -n 10 --oneline`:

- **Current Branch:** `main` (Ahead of `origin/main` by 1 commit)
- **Current HEAD Commit:** `911e3fb` (`chore: complete Batch A dead artifact cleanup`)
- **Recent Git Log:**
  - `911e3fb` chore: complete Batch A dead artifact cleanup
  - `24e6d64` chore: freeze verified Cisco MVP baseline
  - `e2259a0` feat: add Ollama-generated rationale to ai_suggester and explain_failure_ai
  - `3c70965` checkpoint: Ollama-integrated remediation_engine.py, 0/7 refusal rate verified
- **Working Tree State:** Dirty (Active implementation files present in working directory from 3A.1 – 3A.5 and AI Model Manager).
- **Modified Tracked Files (16):**
  - `.gitignore`
  - `ai_suggester.py`
  - `audit_log.py`
  - `dashboard/package.json`
  - `dashboard/src/App.tsx`
  - `dashboard/src/api.ts`
  - `dashboard/src/components/AiSuggestionReviewScreen.tsx`
  - `dashboard/src/components/Navbar.tsx`
  - `dashboard/src/components/RemediationDetailScreen.tsx`
  - `dashboard/src/components/UploadScreen.tsx`
  - `dashboard/src/types.ts`
  - `main.py`
  - `remediation_engine.py`
  - `report_generator.py`
  - `test_api_full_loop.py`
  - `test_step5_full_loop.py`
- **Untracked Files / Directories (39):**
  - Architecture reports: `3A5_REST_API_IMPLEMENTATION_REPORT.md`, `MULTI_FRAMEWORK_COMPLIANCE_ARCHITECTURE.md`, `AI_HARDWARE_MODEL_BENCHMARK_AUDIT.md`, `AI_MODEL_MANAGER_CHUNK1_IMPLEMENTATION_REPORT.md`, `AI_MODEL_MANAGER_CHUNK2A_API_REPORT.md`, `AI_MODEL_MANAGER_CONFIG_PRECEDENCE_AUDIT.md`, `AI_MODEL_MANAGER_CONFIG_PRECEDENCE_FIX_REPORT.md`, `AI_RUNTIME_TRUTH_AND_TELEMETRY_AUDIT.md`, `NTRO_PS26155_PRD_v5_Consolidated.md`
  - Core subsystem modules: `ai_model_manager.py`, `auth.py`, `database.py`, `compliance_framework.py`, `cis_benchmark_cisco_iosxe.py`, `disa_stig_cisco_iosxe.py`, `compliance_aggregator.py`
  - Test suites: `test_ai_model_manager.py`, `test_api_auth.py`, `test_api_compliance.py`, `test_api_model_manager.py`, `test_api_ownership.py`, `test_api_rbac.py`, `test_api_reviewer_identity.py`, `test_auth.py`, `test_cis_benchmark.py`, `test_compliance_framework.py`, `test_database.py`, `test_disa_stig.py`, `test_docker_offline_auth.py`, `test_multi_framework_aggregation.py`
  - Frontend components & tests: `dashboard/src/components/AiModelManagerScreen.tsx`, `dashboard/src/components/LoginScreen.tsx`, `dashboard/test_frontend_auth.mjs`, `dashboard/test_frontend_model_manager.mjs`, `dashboard/Dockerfile`, `dashboard/nginx.conf`, `dashboard/.dockerignore`
  - Infrastructure: `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `.env.example`, `requirements.txt`, `skills-lock.json`
  - Other directories: `arena-frontend/`, `agent/`, `data/`, `graphify-out/`, `.agents/`, `.claude/`

---

## 4. Current Test Baseline

All test suites were executed in place without modifying any source code.

### 4.1 Backend Test Suites (Pytest & Standalone Scripts)

Total Pytest Tests Collected: **329** across all `test_*.py` files.

| Test File | Total Tests | Passed | Failed | Errors | Execution Duration | Root Cause / Note |
|---|---|---|---|---|---|---|
| [test_compliance_framework.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_compliance_framework.py) | 46 | 46 | 0 | 0 | 0.10s | Domain contracts, registry, AST safety, Cisco adapter parity |
| [test_disa_stig.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_disa_stig.py) | 39 | 39 | 0 | 0 | 0.10s | DISA-STIG catalog, 10 evaluators, 5-run determinism, AST safety |
| [test_cis_benchmark.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_cis_benchmark.py) | 32 | 32 | 0 | 0 | 0.08s | CIS catalog, 7 evaluators, determinism, parity |
| [test_api_model_manager.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_api_model_manager.py) | 31 | 31 | 0 | 0 | 66.79s | API model status, mode setting, RBAC gate, allowlist validation |
| [test_api_auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_api_auth.py) | 24 | 24 | 0 | 0 | 27.05s | `/api/auth/login`, `/api/auth/me`, timing defense, rate-limiting |
| [test_api_compliance.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_api_compliance.py) | 22 | 22 | 0 | 0 | 15.21s | `/api/compliance/frameworks`, `/api/compliance/evaluate` |
| [test_api_reviewer_identity.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_api_reviewer_identity.py) | 20 | 20 | 0 | 0 | 17.87s | Reviewer accountability, spoof prevention via JWT `sub` |
| [test_api_ownership.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_api_ownership.py) | 20 | 20 | 0 | 0 | 16.49s | Session resource isolation, anti-enumeration HTTP 404 |
| [test_auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_auth.py) | 20 | 20 | 0 | 0 | 19.94s | Pure Python HS256 JWT, Base64URL RFC 7515, PBKDF2-HMAC-SHA256 |
| [test_multi_framework_aggregation.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_multi_framework_aggregation.py) | 18 | 18 | 0 | 0 | 0.06s | Pass/Unknown rates, deduplication, conflict exception, determinism |
| [test_ai_model_manager.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_ai_model_manager.py) | 17 | 17 | 0 | 0 | 0.05s | Core AIModelManager logic, hardware probe, mode routing, fallback |
| [test_database.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_database.py) | 14 | 14 | 0 | 0 | 21.19s | SQLite schema, tables, migrations, seed users, transactions |
| [test_api_rbac.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_api_rbac.py) | 13 | 13 | 0 | 0 | 21.81s | Role enforcement (`viewer`, `uploader`, `reviewer`), approver gate |
| [test_docker_offline_auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_docker_offline_auth.py) | 12 | 0 | 12 | 0 | 49.86s | **Expected Failure:** Requires live Docker container on ports 8000/3000 (`WinError 10061: Connection refused`) |
| [test_ollama_integration.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_ollama_integration.py) | 1 | 0 | 0 | 1 | 0.04s | **Pytest Collection Error:** Function `test_offline_capability(model, prompt)` has positional parameters; collected as test without fixtures |
| [test_step5_full_loop.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_step5_full_loop.py) | Standalone | **17/17 stages PASS** | 0 | 0 | ~5s | Standalone script (`def main()`), verified 100% pass across all 17 integration stages |
| [test_api_full_loop.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_api_full_loop.py) | Standalone | **11/11 stages PASS** | 0 | 0 | ~6s | Standalone script (`def run_test()`), verified 100% side-by-side CLI-to-API parity |
| **Active Unit & Integration Pytest Suite** | **316** | **316** | **0** | **0** | **120.94s** | **100% Pass Rate for Unit/Integration Tests** |

### 4.2 Frontend Test & Build Baseline (Node.js & Vite)

Executed inside `dashboard/` directory:
- **Test Command:** `npm test -- --watchAll=false` (`node --no-warnings --experimental-strip-types --test test_frontend_auth.mjs test_frontend_model_manager.mjs`)
  - **Results:** **36 passed / 36 total tests (100% pass)** in 187.47ms.
    - Auth & Token Management tests: 16 passed.
    - Model Manager Frontend tests: 20 passed.
- **Build Command:** `npm run build` (`tsc && vite build`)
  - **TypeScript Compilation:** 0 errors.
  - **Vite Bundling:** Built cleanly in 24.04s (dist/index.html 0.85 kB, assets/index.js 271.95 kB, assets/index.css 30.93 kB).

---

## 5. Skill Inventory

In accordance with the reconnaissance requirement, the installed skill ecosystem was inspected.

### Skills Discovered
1. **Builtin Antigravity Skills:** `agy-customizations`, `antigravity-guide`, `migrate-workflows`.
2. **Ponytail Plugin Skills:** `ponytail`, `ponytail-audit`, `ponytail-debt`, `ponytail-gain`, `ponytail-help`, `ponytail-review`.
3. **Architecture & Visualization:** `archify`, `graphify`.
4. **Agent Skills Ecosystem:** 25 skills duplicated across 4 directories (`.agents/skills`, `.claude/skills`, `agent/skills`, `data/skills`): `api-and-interface-design`, `browser-testing-with-devtools`, `ci-cd-and-automation`, `code-review-and-quality`, `code-simplification`, `constraint-driven-development`, `context-engineering`, `debugging-and-error-recovery`, `deprecation-and-migration`, `documentation-and-adrs`, `doubt-driven-development`, `frontend-ui-engineering`, `git-workflow-and-versioning`, `idea-refine`, `incremental-implementation`, `interview-me`, `observability-and-instrumentation`, `performance-optimization`, `planning-and-task-breakdown`, `security-and-hardening`, `shipping-and-launch`, `source-driven-development`, `spec-driven-development`, `test-driven-development`, `using-agent-skills`.

### Skills Selected for Phase 3R.0 Audit
- `graphify`: Knowledge graph AST extraction and architectural dependency topology inspection.
- `code-review-and-quality`: Verification of code standards, coupling, and interface stability.
- `security-and-hardening`: Inspection of trust boundaries, JWT auth, timing defenses, and anti-enumeration.
- `ponytail-audit`: Identification of over-engineering, duplicate helpers, and dead code candidates.
- `doubt-driven-development`: Cross-examination of documented claims against real source implementation.

### Why Selected
These skills provide comprehensive read-only analytical coverage across dependency graph analysis, static safety verification, security boundary auditing, and documentation drift detection without mutating production code.

---

## 6. Repository Inventory

The codebase contains 58 code and document files at the top level and nested subsystems. Categorized according to the standard inventory schema (A through S):

| Cat | File / Path | Size | LOC | Purpose | Major Consumers | Production Status | Confidence |
|---|---|---|---|---|---|---|---|
| **A** | [cisco_auditor.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cisco_auditor.py) | 17.5 KB | 222 | Cisco IOS-XE parser, CSM normalizer, legacy rule evaluator | `main.py`, `compliance_framework.py`, tests | Active (Core) | HIGH |
| **B** | [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py) | 38.1 KB | 1018 | FastAPI application with 16 business endpoints | Frontend, TestClient | Active (Core API) | HIGH |
| **C** | [auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/auth.py) | 11.8 KB | 302 | Pure Python HS256 JWT & password verification | `main.py`, tests | Active (Auth Truth) | HIGH |
| **D** | [auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/auth.py) & [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py) | — | — | RBAC dependency `require_role()` & approver gate | All protected endpoints | Active (RBAC Truth) | HIGH |
| **E** | [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py) (`check_session_ownership`) | — | — | Resource ownership & anti-enumeration isolation | Session endpoints | Active (Ownership Truth) | HIGH |
| **F** | [database.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/database.py) | 14.0 KB | 388 | SQLite schema, PBKDF2 hashing, user seeding, sessions | `main.py`, `audit_log.py`, `ai_suggester.py` | Active (DB Truth) | HIGH |
| **G** | [compliance_framework.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_framework.py) | 18.0 KB | 447 | Neutral compliance domain model, registry, evidence | `main.py`, evaluators, aggregator | Active (Framework Truth) | HIGH |
| **H** | [cis_benchmark_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cis_benchmark_cisco_iosxe.py) | 27.9 KB | 632 | CIS Benchmark evaluator (7 controls) for Cisco IOS XE | Registry, `main.py` | Active (CIS Truth) | HIGH |
| **I** | [disa_stig_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/disa_stig_cisco_iosxe.py) | 39.7 KB | 871 | DISA-STIG evaluator (10 controls) for Cisco IOS XE | Registry, `main.py` | Active (STIG Truth) | HIGH |
| **J** | [compliance_aggregator.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_aggregator.py) | 14.9 KB | 361 | Multi-framework aggregation, scoring, conflict detection | `main.py`, tests | Active (Aggregator Truth) | HIGH |
| **K** | [ai_model_manager.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_model_manager.py) | 22.0 KB | 580 | Local model routing, hardware probe, Ollama client | `ai_suggester.py`, `remediation_engine.py` | Active (AI Model Truth) | HIGH |
| **K** | [ai_suggester.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_suggester.py) | 9.9 KB | 243 | DistilBERT cosine similarity & reviewer approval | `main.py`, tests | Active (AI Suggest Truth) | HIGH |
| **L** | [remediation_engine.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/remediation_engine.py) | 9.8 KB | 204 | Jinja2 template render, conflict check, AST check | `main.py`, tests | Active (Remediation Truth) | HIGH |
| **M** | [audit_log.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/audit_log.py) | 6.7 KB | 161 | Hash-chained audit logging (SQLite backed) | `main.py`, tests | Active (Ledger Truth) | HIGH |
| **M** | [report_generator.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/report_generator.py) | 14.3 KB | 338 | Tamper-evident PDF report generator & QR encoder | `main.py`, tests | Active (Report Truth) | HIGH |
| **N** | `dashboard/` | 3.5 MB | — | React + TS + Tailwind + Vite production frontend | End users, Docker | Active (Frontend Truth) | HIGH |
| **O** | `test_*.py` (17 files) | 265 KB | 6320 | Unit, integration, security, and full-loop test suite | CI / Local tests | Active (15/17 fully active) | HIGH |
| **P** | `scripts/` / internal | — | — | Ad-hoc helper scripts | Development | Active | HIGH |
| **Q** | `Dockerfile`, `docker-compose.yml`, `dashboard/Dockerfile` | 3.2 KB | 120 | Container deployment definitions | Deployments | Active | HIGH |
| **R** | `00_Project_Documentation/`, `*.md` reports | ~250 KB | — | PRD specifications, implementation reports | Engineers | Static documentation | HIGH |
| **S** | `arena-frontend/` | 1.8 MB | — | Monolithic prototype frontend (superseded by dashboard) | None | **CONFIRMED LEGACY / DEAD** | HIGH |
| **S** | `.claude/skills`, `agent/skills`, `data/skills` | ~2.5 MB | — | Triplicate redundant copies of `.agents/skills` | None | **CONFIRMED REDUNDANT** | HIGH |
| **S** | Root PPTX/PDF decks (4 files) | ~60 MB | — | Historical presentation decks in repo root | Human archive | Inert binary assets | HIGH |

---

## 7. Current Runtime Architecture

Tracing actual execution pathways directly from code yields the real flow:

```
[Configuration Ingestion]
        │
        ├── Raw CLI Text / File Upload (POST /api/audit/upload or /api/compliance/evaluate)
        ▼
[cisco_auditor.parse_cisco()]
        │  • Regex parsing, interface extraction, service mapping
        │  • Extracts unmapped lines (e.g., 'service call-home')
        │  • Populates raw_evidence list
        ▼
[Normalized CSM (dict)] ─────────► [database.save_session() in SQLite]
        │                                         │
        ├── Legacy Rule Evaluation                │ (via session_id)
        │   └─► cisco_auditor.evaluate_rules()    │
        │                                         ▼
        └── Multi-Framework Evaluation (POST /api/compliance/evaluate)
                │
                ├── FrameworkRegistry.get_evaluator("cis-cisco-iosxe")
                │       └─► CisCiscoIosXeEvaluator.evaluate(csm)
                │
                ├── FrameworkRegistry.get_evaluator("disa-stig-cisco-iosxe")
                │       └─► StigCiscoIosXeEvaluator.evaluate(csm)
                │
                ▼
        [List[EvaluationResult]] (Deterministic: Pass | Fail | Unknown + Evidence)
                │
                ▼
        [MultiFrameworkAggregator.aggregate()]
                │  • Deduplication & Conflict Detection (ConflictingControlEvaluationError)
                │  • Pass rate: Pass / (Pass + Fail)  [Unknown strictly excluded]
                │  • Deterministic sorting by framework_id and control_id
                ▼
        [MultiFrameworkAuditResult] ──► JSON API Response ──► [dashboard/ (React)]
```

### Authorization & Session Isolation Flow:
```
[Client Request with Authorization: Bearer <JWT>]
        │
        ▼
[FastAPI Dependency: get_current_user()]
        │  • Decodes & cryptographically verifies HS256 JWT using secret from .jwt_secret
        │  • Checks expiration (exp) and issuance (iat)
        │  • Returns verified claims: sub, username, role, is_authorized_approver
        ▼
[FastAPI Dependency: require_role(roles, require_approver)]
        │  • Asserts role is in allowed set
        │  • If require_approver=True: asserts is_authorized_approver == 1
        │  • Fails with HTTP 403 Forbidden
        ▼
[Resource Ownership: check_session_ownership()]
        │  • If role == 'reviewer': access granted to any session
        │  • If role == 'uploader': asserts session.owner_user_id == current_user['sub']
        │  • If mismatch: raises HTTP 404 (Anti-Enumeration Guard)
        ▼
[Execute Target Protected Route]
```

### AI Suggestion & Reviewer Gate Flow:
```
[Unmapped CLI Line] ──► POST /api/ai/suggest
        │
        ▼
[DistilBERT 66M (torch CPU)]
        │  • Computes embedding & cosine similarity against baseline rule contexts
        │  • If similarity >= 0.82 or matches known pattern (call-home, banner):
        │       Calls AIModelManager.generate() for plain-language rationale
        ▼
[Suggestion Generated] ──► Stored in SQLite pending_suggestions (status: 'pending')
        │
        ▼ (Human Reviewer Intervention Required)
[POST /api/ai/approve]
        │  • Caller MUST be role: 'reviewer' AND is_authorized_approver: 1
        │  • Reviewer identity derived STRICTLY from verified JWT claim current_user['sub']
        │  • Client-supplied reviewer_name in JSON body is discarded
        │  • Writes approved rule into SQLite trusted_mappings
        ▼
[Deterministic Re-Evaluation Triggered]
        │  • Evaluates newly trusted rule against active CSM deterministically
        ▼
[Updated Results Returned]
```

---

## 8. Backend Module Map

| Module | Primary Responsibility | Key Functions / Classes | Inbound Callers | Outbound Dependencies |
|---|---|---|---|---|
| [cisco_auditor.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cisco_auditor.py) | Lexical parsing & legacy MVP rules | `parse_cisco()`, `evaluate_rules()`, `resolve_csm_path()`, `eval_condition()` | `main.py`, `compliance_framework.py`, tests | `vendor_rule_mapping.json`, `labeled_test_config.txt` |
| [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py) | REST API, routing, auth gates | `login()`, `audit_upload()`, `evaluate_compliance()`, `get_current_user()`, `require_role()` | React dashboard, tests | All backend modules, `database`, `auth` |
| [auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/auth.py) | Cryptographic identity & token engine | `create_access_token()`, `decode_and_verify_jwt()`, `verify_password()`, `get_jwt_secret()` | `main.py`, tests | `database.hash_password`, `data/.jwt_secret` |
| [database.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/database.py) | SQLite persistence, schema, migrations | `initialize_database()`, `get_connection()`, `save_session()`, `get_user_by_username()` | `main.py`, `audit_log.py`, `ai_suggester.py`, `auth.py` | SQLite (`data/auditor.db`) |
| [compliance_framework.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_framework.py) | Compliance abstraction & contracts | `Framework`, `Control`, `Evidence`, `EvaluationResult`, `ComplianceStatus`, `FrameworkRegistry` | `main.py`, evaluators, aggregator | Python stdlib only |
| [cis_benchmark_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cis_benchmark_cisco_iosxe.py) | CIS Benchmark IOS-XE evaluator | `CisCiscoIosXeEvaluator`, `register_cis_cisco_iosxe()` | `main.py`, tests | `compliance_framework` |
| [disa_stig_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/disa_stig_cisco_iosxe.py) | DISA-STIG IOS-XE evaluator | `StigCiscoIosXeEvaluator`, `register_disa_stig_cisco_iosxe()` | `main.py`, tests | `compliance_framework` |
| [compliance_aggregator.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_aggregator.py) | Multi-framework aggregation & deduplication | `MultiFrameworkAggregator`, `FrameworkSummary`, `OverallMetrics` | `main.py`, tests | `compliance_framework` |
| [ai_model_manager.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_model_manager.py) | Centralized local model lifecycle & routing | `AIModelManager`, `probe_system_hardware()`, `get_model_manager()` | `main.py`, `ai_suggester.py`, `remediation_engine.py` | Ollama over HTTP loopback |
| [ai_suggester.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_suggester.py) | Unmapped line semantic mapping | `suggest_mapping()`, `store_suggestion()`, `approve_suggestion()` | `main.py`, tests | `database`, `ai_model_manager`, `transformers` |
| [remediation_engine.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/remediation_engine.py) | Jinja2 CLI fixes & conflict checks | `generate_remediation()`, `check_static_conflicts()`, `explain_failure_ai()` | `main.py`, tests | `jinja2`, `ai_model_manager` |
| [audit_log.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/audit_log.py) | Cryptographic hash chaining | `create_audit_entry()`, `append_audit_entry()`, `verify_chain()` | `main.py`, tests | `database`, `hashlib` |
| [report_generator.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/report_generator.py) | PDF generation & QR encoding | `generate_pdf_report()`, `verify_report_hash()` | `main.py`, tests | `reportlab`, `pypdf`, `database` |

---

## 9. Frontend Module Map

### 9.1 Active Frontend: `dashboard/`
- **Framework:** React 18.3.1 + TypeScript 5.5.3 + Tailwind CSS 3.4.4 + Vite 5.3.4.
- **Entry Points:** `dashboard/index.html` -> `src/main.tsx` -> `src/App.tsx`.
- **API Client:** [dashboard/src/api.ts](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/dashboard/src/api.ts). Handles in-memory & `sessionStorage` bearer token persistence, automatic `Authorization` header injection, 401 unauth interceptors, and strict request formatting (e.g. omitting client `reviewer_name` on approvals).
- **Screens:**
  1. [LoginScreen.tsx](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/dashboard/src/components/LoginScreen.tsx): Username/password authentication, role status banner.
  2. [UploadScreen.tsx](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/dashboard/src/components/UploadScreen.tsx): Configuration file drag-and-drop or text input, audit initialization.
  3. [AuditResultsScreen.tsx](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/dashboard/src/components/AuditResultsScreen.tsx): Tabular view of Pass/Fail/Unknown controls, status filters, evidence drawer.
  4. [AiSuggestionReviewScreen.tsx](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/dashboard/src/components/AiSuggestionReviewScreen.tsx): Human reviewer approval/rejection UI with approver privilege enforcement.
  5. [RemediationDetailScreen.tsx](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/dashboard/src/components/RemediationDetailScreen.tsx): Displays Jinja2 CLI snippet, AST conflict warning badges, and AI plain-language explanation.
  6. [AuditLogReportScreen.tsx](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/dashboard/src/components/AuditLogReportScreen.tsx): Chronological hash chain ledger, live tamper verification, PDF report download.
  7. [AiModelManagerScreen.tsx](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/dashboard/src/components/AiModelManagerScreen.tsx): Real-time hardware telemetry (CPU, RAM, GPU), model mode selector (`auto`, `fast`, `quality`, `override`).
  8. [Navbar.tsx](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/dashboard/src/components/Navbar.tsx): Screen routing, role badge, session logout.

### 9.2 Obsolete Prototype Frontend: `arena-frontend/`
- Monolithic single-file UI (`arena-frontend/src/App.tsx`, 25.6 KB).
- Outdated `api.ts` lacking authentication, session ownership, and Model Manager support.
- Not referenced in `docker-compose.yml` or backend build pipelines.
- **Status:** Obsolete prototype.

---

## 10. Database / Persistence Map

SQLite database located at `data/auditor.db` (initialized via `database.initialize_database()` on startup):

| Table Name | Schema & Primary Key | Accessing Modules (Read/Write) | Source of Truth Classification |
|---|---|---|---|
| `users` | `user_id` (PK), `username` (UNIQUE), `password_hash`, `salt`, `role`, `is_authorized_approver`, `is_active`, `created_at` | Write: `database.py`<br>Read: `database.py`, `main.py` (`/api/auth/login`) | **AUTHORITATIVE TRUTH** for User Accounts & Roles |
| `audit_sessions` | `session_id` (PK), `csm`, `evals`, `raw_config_text`, `filename`, `config_file_hash`, `created_at`, `owner_user_id` | Write: `main.py` (`audit_upload`, `ai_approve`), `database.py`<br>Read: `main.py` (`get_audit_results`, `get_remediation`, `finalize_audit`, `evaluate_compliance`) | **AUTHORITATIVE TRUTH** for Active Audit Sessions |
| `trusted_mappings` | `vendor_rule_id` (PK), `common_rule_id`, `internalTitle`, `csmFieldChecked`, `condition`, `configuration_evidence`, `check_focus`, `frameworkMappings`, `version_info` | Write: `ai_suggester.py` (`approve_suggestion`)<br>Read: `main.py` (`load_trusted_rules`) | **AUTHORITATIVE TRUTH** for Approved Custom Rules |
| `pending_suggestions` | `suggestion_id` (PK), `timestamp`, `status`, `suggestion`, `reviewed_by`, `reviewed_at` | Write: `ai_suggester.py` (`store_suggestion`, `approve_suggestion`)<br>Read: `ai_suggester.py` | **AUTHORITATIVE TRUTH** for AI Suggestions Queue |
| `audit_ledger` | `id` (PK AUTO), `entry_id` (UNIQUE), `timestamp`, `device_hostname`, `config_file_hash`, `audit_results`, `remediation_summary`, `prevEntryHash`, `entryHash`, `owner_user_id` | Write: `audit_log.py` (`append_audit_entry`)<br>Read: `audit_log.py` (`verify_chain`, `get_last_entry`), `main.py` (`get_ledger`), `report_generator.py` (`verify_report_hash`) | **AUTHORITATIVE TRUTH** for Tamper-Evident Hash Chain |

> [!IMPORTANT]
> **Persistence Drift Finding:** While historical documentation claimed that `audit_log.jsonl`, `trusted_mappings.json`, and `pending_suggestions.json` were the primary files, `database.py`, `audit_log.py`, and `ai_suggester.py` have completely migrated to SQLite tables in `data/auditor.db`. The JSON files on disk are legacy bootstrap artifacts.

---

## 11. Authentication, RBAC & Ownership Map

### 11.1 Password Hashing & Verification
- **Implementation:** [database.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/database.py) (`hash_password`) and [auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/auth.py) (`verify_password`).
- **Algorithm:** PBKDF2-HMAC-SHA256 with 600,000 iterations using Python standard library `hashlib`.
- **Salt:** 16 cryptographically secure random bytes generated via `secrets.token_bytes(16)`.
- **Timing Attack Mitigation:** Constant-time hash verification via `hmac.compare_digest`. In [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py), if an unknown username is supplied, a dummy PBKDF2 verification against fixed dummy credentials executes to neutralize user enumeration timing side-channels.

### 11.2 JWT Minting & Cryptographic Verification
- **Implementation:** [auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/auth.py) (`create_access_token`, `decode_and_verify_jwt`).
- **Algorithm:** HS256 (HMAC-SHA256) per RFC 7515 & RFC 7519, standard library only.
- **Signing Key:** Provisioned from `JWT_SECRET_KEY` environment variable or dynamically generated 32-byte secret persisted in `data/.jwt_secret` with 0600 permissions.
- **Token Claims:** `sub` (user_id UUID), `username`, `role`, `is_authorized_approver` (boolean), `exp` (8-hour expiration), `iat` (issued-at timestamp).
- **Validation:** Enforces 30-second clock-skew leeway, strictly rejects `none` or unexpected algorithms, rejects malformed Base64URL padding.

### 11.3 RBAC Permissions Matrix
Three canonical roles exist: `viewer`, `uploader`, `reviewer`.

| Operation / Endpoint | Allowed Roles | Approver Requirement | Enforcement Location |
|---|---|---|---|
| `POST /api/auth/login` | Public | None | In-memory abuse rate-limiter |
| `GET /api/auth/me` | All authenticated | None | `get_current_user` |
| `POST /api/audit/upload` | `uploader`, `reviewer` | None | `require_role("uploader", "reviewer")` |
| `GET /api/audit/{session_id}/results` | `viewer`, `uploader`, `reviewer` | None | `require_role(...)` + `check_session_ownership` |
| `POST /api/compliance/evaluate` | `viewer`, `uploader`, `reviewer` | None | `require_role(...)` + `check_session_ownership` |
| `GET /api/compliance/frameworks` | `viewer`, `uploader`, `reviewer` | None | `require_role(...)` |
| `POST /api/ai/suggest` | `uploader`, `reviewer` | None | `require_role("uploader", "reviewer")` |
| `POST /api/ai/approve` | `reviewer` ONLY | **`is_authorized_approver: 1` ONLY** | `require_role("reviewer", require_approver=True)` |
| `GET /api/model/status` | `viewer`, `uploader`, `reviewer` | None | `require_role(...)` |
| `POST /api/model/mode` | `reviewer` ONLY | **`is_authorized_approver: 1` ONLY** | `require_role("reviewer", require_approver=True)` |
| `POST /api/remediation/{rule_id}` | `uploader`, `reviewer` | None | `require_role(...)` + `check_session_ownership` |
| `POST /api/audit/finalize` | `uploader`, `reviewer` | None | `require_role(...)` + `check_session_ownership` |
| `GET /api/ledger` | `viewer`, `uploader`, `reviewer` | None | `require_role(...)` |
| `GET /api/ledger/verify` | `viewer`, `uploader`, `reviewer` | None | `require_role(...)` |
| `GET /api/report/{entry_id}/download` | `viewer`, `uploader`, `reviewer` | None | `require_role(...)` |
| `GET /api/report/{entry_id}/verify` | `viewer`, `uploader`, `reviewer` | None | `require_role(...)` |

### 11.4 Reviewer Accountability & Ownership
- **Reviewer Identity Spoof Prevention:** In [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py) (`ai_approve`), the approving reviewer identity is pulled directly from `current_user["sub"]`. Any client-supplied `reviewer_name` in the wire payload is discarded for accountability.
- **Resource Ownership & Anti-Enumeration:** In [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py) (`check_session_ownership`), uploaders can only access sessions where `session['owner_user_id'] == current_user['sub']`. If an uploader requests another user's session, the system returns **HTTP 404 Not Found** (not HTTP 403) to prevent resource ID enumeration.

---

## 12. Compliance Architecture Reality Audit

The compliance subsystem consists of two operational paths:
1. **Legacy Cisco MVP Evaluator:** [cisco_auditor.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cisco_auditor.py). Parses raw configuration strings into CSM and evaluates 10 hardcoded rules loaded from `vendor_rule_mapping.json`.
2. **Multi-Framework Architecture (Phases 3A.1 – 3A.5):** Fully decoupled framework abstraction:
   - [compliance_framework.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_framework.py): Implements domain models (`Framework`, `Control`, `Evidence`, `EvaluationResult`), status enum (`ComplianceStatus.PASS`, `FAIL`, `UNKNOWN`), and `FrameworkRegistry`.
   - [cis_benchmark_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cis_benchmark_cisco_iosxe.py): Implements `CisCiscoIosXeEvaluator` evaluating 7 CIS benchmark controls directly against normalized CSM.
   - [disa_stig_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/disa_stig_cisco_iosxe.py): Implements `StigCiscoIosXeEvaluator` evaluating 10 DISA-STIG controls directly against normalized CSM.
   - [compliance_aggregator.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_aggregator.py): Implements `MultiFrameworkAggregator` which deduplicates results, detects conflicting evaluations, calculates pass rates (`Pass / (Pass + Fail) * 100`), unknown rates, and sorts evidence deterministically.

### Verification of Invariants:
- `PASS / FAIL / UNKNOWN`: UNKNOWN is strictly preserved and never coerced into Fail or Pass.
- Pass Rate Denominator: UNKNOWN results are strictly excluded from the pass rate denominator:
  $$\text{Pass Rate} = \frac{\text{Pass}}{\text{Pass} + \text{Fail}} \times 100$$
- Evaluators consume **only** normalized CSM; they never parse raw vendor strings.
- Evaluators contain **zero** AI/LLM dependencies and **zero** network access capabilities.

---

## 13. AI Architecture Reality Audit

The AI subsystem operates on an **out-of-band advisory model** with absolute zero authority over compliance decisions:

```
Configured Model ≠ Executed Model
DistilBERT Similarity ≠ LLM Rationale ≠ Compliance Result
AI Suggestion ≠ Trusted Mapping ≠ Compliance Result
```

1. **AI Model Manager:** [ai_model_manager.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_model_manager.py).
   - Centralized singleton (`get_model_manager()`).
   - Hardware detection (`probe_system_hardware()`): reads total/available RAM and CPU cores via `ctypes` on Windows and `/sys` on Linux.
   - Operating Modes: `fast` (`llama3.2:1b`), `quality` (`qwen2.5:7b-instruct-q4_K_M`), `auto` (routes based on RAM threshold: >= 16GB RAM routes to quality, otherwise fast), `override` (allows reviewer approver to force an allowlisted model).
   - Strict Model Allowlist: untrusted strings cannot be passed to Ollama.
   - Loopback Isolation: connects exclusively to `127.0.0.1:11434` (or configured host) with 2-second to 15-second bounded timeouts.
   - Refusal Handling: detects LLM refusals (`REFUSAL_MARKERS`) and falls back immediately to deterministic text.
2. **Semantic Similarity Suggester:** [ai_suggester.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_suggester.py).
   - Runs `distilbert-base-uncased` (66M parameters) on local PyTorch CPU.
   - Computes cosine similarity between unmapped lines and baseline rule descriptions.
   - If similarity >= 0.82 or matches known patterns, queries `AIModelManager` for plain-language rationale.
   - Result is logged to SQLite `pending_suggestions` with status `pending`.
3. **Plain-Language Remediation Explainer:** [remediation_engine.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/remediation_engine.py) (`explain_failure_ai`).
   - Requests plain-language explanations of control failures from `AIModelManager`.
   - If Ollama is offline or in deterministic mode, falls back cleanly to deterministic explanation templates.

---

## 14. Remediation Architecture

The remediation subsystem ([remediation_engine.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/remediation_engine.py)) is engineered with strict execution-safety properties:
- **Jinja2 Rendering:** CLI fixes are rendered from templates in `templates/remediation/` (currently `CISCO-NTP-001.j2`). Context variables are strictly scoped to parsed CSM data.
- **AST Static Conflict Analysis:** Scans configuration dependencies that a proposed CLI fix would break. For `CISCO-NTP-001`, flags `NTP_AUTH_KEY_MISSING` if `ntp authenticate` is enabled without authentication keys, and `NTP_VRF_SOURCE_CHECK` if Management VRF is active.
- **Execution Safety Invariant (AST Verified):**
  - Contains `verify_safety_no_execution()` which uses Python's `ast` module to verify that no execution or socket libraries (`subprocess`, `os.system`, `paramiko`, `netmiko`, `pexpect`, `telnetlib`, `socket`) are imported.
  - [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py) runs an identical AST self-test at import time (`verify_api_safety_no_execution()`).
  - **Remediation is 100% DISPLAY-ONLY.** Zero network egress or command execution pathways exist.

---

## 15. REST API Architecture

The FastAPI application ([main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py)) exposes 16 business endpoints:

| Endpoint | Method | Auth | Role | Ownership | Dependencies | Route Thickness |
|---|---|---|---|---|---|---|
| `/api/auth/login` | POST | None | Public | N/A | `database`, `auth`, `LOGIN_ATTEMPTS` | Moderate (timing mitigation, rate limit) |
| `/api/auth/me` | GET | Bearer | Any | N/A | JWT claims | Thin |
| `/api/audit/upload` | POST | Bearer | `uploader`, `reviewer` | Assigned to `sub` | `cisco_auditor`, `database` | Business-Logic Heavy (parses, evals, saves session) |
| `/api/audit/{session_id}/results` | GET | Bearer | Any | Uploader isolated | `database` | Thin |
| `/api/ai/suggest` | POST | Bearer | `uploader`, `reviewer` | N/A | `ai_suggester`, `database` | Moderate (DistilBERT inference, SQLite insert) |
| `/api/ai/approve` | POST | Bearer | `reviewer` (Approver: 1) | N/A | `ai_suggester`, `cisco_auditor`, `database` | Business-Logic Heavy (reviewer gate, SQLite update, re-evaluation) |
| `/api/model/status` | GET | Bearer | Any | N/A | `ai_model_manager` | Thin |
| `/api/model/mode` | POST | Bearer | `reviewer` (Approver: 1) | N/A | `ai_model_manager` | Moderate |
| `/api/remediation/{rule_id}` | POST | Bearer | `uploader`, `reviewer` | Uploader isolated | `remediation_engine`, `database` | Moderate (Jinja2 render, conflict analysis, AI explain) |
| `/api/audit/finalize` | POST | Bearer | `uploader`, `reviewer` | Uploader isolated | `audit_log`, `report_generator`, `database` | Business-Logic Heavy (hash chaining, PDF render) |
| `/api/ledger` | GET | Bearer | Any | N/A | `database` (`audit_ledger`) | Thin |
| `/api/ledger/verify` | GET | Bearer | Any | N/A | `audit_log`, `database` | Moderate (recomputes full hash chain) |
| `/api/report/{entry_id}/download`| GET | Bearer | Any | N/A | File system (`cisco_compliance_report.pdf`)| Thin |
| `/api/report/{entry_id}/verify` | GET | Bearer | Any | N/A | `report_generator`, `database` | Moderate (extracts PDF metadata, validates hash) |
| `/api/compliance/frameworks` | GET | Bearer | Any | N/A | `compliance_framework.get_default_registry()` | Thin |
| `/api/compliance/evaluate` | POST | Bearer | Any | Uploader isolated (if session_id) | `compliance_framework`, evaluators, `compliance_aggregator`, `database` | Business-Logic Heavy (multi-evaluator dispatch, aggregation, deduplication) |

---

## 16. Graphify Baseline

Knowledge graph extraction was executed via `graphify update .`.

### 16.1 Graph Metrics & Statistics
- **Total Nodes:** 3,661
- **Total Edges / Links:** 4,880
- **Identified Communities:** 177 communities (149 major displayed, 28 thin omitted)
- **Extraction Fidelity:** 96% EXTRACTED, 4% INFERRED (217 edges, avg confidence 0.95), 0% AMBIGUOUS
- **Token Cost:** 0 input / 0 output (Pure AST extraction, 12 workers)
- **Import Cycles Detected:** **0 cycles** (Clean DAG topology)

### 16.2 God Nodes (Core Architectural Hubs)
1. `EvaluationResult` — 52 edges (central compliance outcome model)
2. `Evidence` — 49 edges (deterministic audit justification model)
3. `Control` — 45 edges (security control specification model)
4. `FrameworkRegistry` — 40 edges (evaluator discovery & dependency injection hub)
5. `create_access_token()` — 36 edges (cryptographic authorization hub)
6. `get_connection()` — 35 edges (database access gateway)
7. `StigCiscoIosXeEvaluator` — 35 edges (DISA-STIG evaluator)
8. `TestDisaStigControlEvaluatorUnit` — 35 edges (DISA-STIG unit test suite)
9. `CisCiscoIosXeEvaluator` — 34 edges (CIS Benchmark evaluator)
10. `ComplianceStatus` — 33 edges (verdict state contract)

---

## 17. Source-of-Truth Matrix

| Concern | Authoritative Source of Truth | Secondary / Legacy Implementations | Confidence |
|---|---|---|---|
| User Authentication | [auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/auth.py) (`decode_and_verify_jwt`) | None | HIGH |
| Password Hashing | [database.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/database.py) (`hash_password`) | [auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/auth.py) reuses `database.hash_password` | HIGH |
| JWT Signing & Claims | [auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/auth.py) (`create_access_token`) | None | HIGH |
| Role-Based Access Control | [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py) (`require_role`) | Role definitions in [auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/auth.py) | HIGH |
| Resource Ownership | [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py) (`check_session_ownership`) | None | HIGH |
| Configuration Normalization | [cisco_auditor.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cisco_auditor.py) (`parse_cisco`) | None | HIGH |
| Framework Registry | [compliance_framework.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_framework.py) (`FrameworkRegistry`) | None | HIGH |
| CIS Benchmark Evaluation | [cis_benchmark_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cis_benchmark_cisco_iosxe.py) | Legacy rules in [cisco_auditor.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cisco_auditor.py) | HIGH |
| DISA-STIG Evaluation | [disa_stig_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/disa_stig_cisco_iosxe.py) | None | HIGH |
| Compliance Verdict Contract | [compliance_framework.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_framework.py) (`ComplianceStatus`) | Legacy string literals (`"Pass"`, `"Fail"`, `"Unknown"`) in `cisco_auditor.py` | HIGH |
| Multi-Framework Aggregation | [compliance_aggregator.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_aggregator.py) | Summary counts in `main.py` (`audit_upload`) | HIGH |
| AI Model Selection & Mode | [ai_model_manager.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_model_manager.py) (`AIModelManager`) | None | HIGH |
| Local AI Suggestion | [ai_suggester.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_suggester.py) (`suggest_mapping`) | None | HIGH |
| Trusted Mappings Store | SQLite `trusted_mappings` table | [trusted_mappings.json](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/trusted_mappings.json) (legacy bootstrap) | HIGH |
| Remediation Generation | [remediation_engine.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/remediation_engine.py) (`generate_remediation`) | None | HIGH |
| Conflict Analysis | [remediation_engine.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/remediation_engine.py) (`check_static_conflicts`) | None | HIGH |
| Audit Ledger Persistence | SQLite `audit_ledger` table | [audit_log.jsonl](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/audit_log.jsonl) (non-existent on disk; documented legacy) | HIGH |
| PDF Audit Certificate | [report_generator.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/report_generator.py) (`generate_pdf_report`) | None | HIGH |
| REST API Endpoints | [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py) | None | HIGH |
| Frontend Application | `dashboard/` | `arena-frontend/` (obsolete prototype) | HIGH |

---

## 18. Redundancy Findings

1. **Quadruplicate Skill Directories (SEMANTIC & FILE DUPLICATE):**
   - **Locations:** `.agents/skills`, `.claude/skills`, `agent/skills`, `data/skills`.
   - **Finding:** All four directories contain the exact same 25 skills.
   - **Impact:** Clutters repository, causes confusion during skill updates, wastes storage.
2. **Parallel Evaluation Pipelines in API (COMPATIBILITY LAYER / DUPLICATE PATH):**
   - **Path A:** `POST /api/audit/upload` evaluates configuration via legacy `cisco_auditor.evaluate_rules()`.
   - **Path B:** `POST /api/compliance/evaluate` evaluates configuration via `FrameworkRegistry` (`CisCiscoIosXeEvaluator` + `StigCiscoIosXeEvaluator`) and `compliance_aggregator`.
   - **Finding:** Both endpoints parse configs and compute compliance, but Path B is the multi-framework architecture while Path A is the legacy single-vendor MVP path retained for backward compatibility with the dashboard upload screen.
3. **AST Safety Check Duplication (SPECIALIZED IMPLEMENTATION):**
   - **Locations:** `remediation_engine.py` (`verify_safety_no_execution`), `main.py` (`verify_api_safety_no_execution`), `test_compliance_framework.py`, `test_disa_stig.py`, `test_multi_framework_aggregation.py`.
   - **Finding:** Similar AST traversal loops checking forbidden module names (`subprocess`, `paramiko`, etc.).
   - **Classification:** Intentional security self-test; safe to consolidate into a shared utility in a later phase.
4. **Duplicate Frontend Applications (EXACT & EVOLVED DUPLICATE):**
   - **Locations:** `arena-frontend/` vs `dashboard/`.
   - **Finding:** `arena-frontend/` is an earlier unauthenticated prototype that was copied into `dashboard/` and abandoned. `dashboard/` has evolved to include auth, model management, and tests.

---

## 19. Dead-Code Candidates

| Candidate | Location | Evidence / Consumers | Classification | Recommended Future Action |
|---|---|---|---|---|
| Entire `arena-frontend` directory | `arena-frontend/` | Zero backend references, not in Docker, not tested | **CONFIRMED DEAD** | Safe to remove in 3R refactor |
| Vestigial `audit_log.jsonl` references | `main.py`, `audit_log.py`, `report_generator.py` | `audit_log.jsonl` does not exist on disk; all ops use SQLite `audit_ledger` | **CONFIRMED DEAD** (as file), **COMPATIBILITY ARGUMENT** in signatures | Clean up default parameters and docstrings |
| Uncalled migration functions | `database.py` (`migrate_ledger`, `migrate_trusted_mappings`, `migrate_pending_suggestions`) | Only run if tables are empty and legacy files exist; files do not exist or are static | **PROBABLE DEAD** | Deprecate or guard behind migration CLI |
| Pytest fixture mismatch | `test_ollama_integration.py` (`test_offline_capability`) | Takes parameters `(model, prompt)`; breaks pytest collection with Error 1 | **DEFECTIVE TEST SIGNATURE** | Rename to helper function or wrap in fixture |
| Non-discovered full loop tests | `test_api_full_loop.py` (`run_test`), `test_step5_full_loop.py` (`main`) | Named without `test_` prefix; ignored by pytest default collection | **ACTIVE STANDALONE SCRIPT** | Wrap in proper `test_*` functions for pytest discovery |
| Quadruplicate skills copies | `.claude/skills`, `agent/skills`, `data/skills` | Duplicate copies of `.agents/skills` | **CONFIRMED REDUNDANT** | Consolidate to `.agents/skills` |
| Presentation binaries in repo root | `SIH2026-*.pptx`, `SIH2026-*.pdf` (4 files, ~60MB) | Top-level repo presentation slides | **NON-CODE ARTIFACT** | Move to docs/archive directory |

---

## 20. Legacy / Experimental Components

1. **Pre-Model-Manager Direct Ollama Calls:**
   - In `remediation_engine.py` and `ai_suggester.py`, previous direct `urllib.request` loops to Ollama were refactored into `ai_model_manager.generate()`. Small fallback comments and legacy error handling remains.
2. **`vendor_rule_mapping.json` Hardcoded Path:**
   - `cisco_auditor.py` and `main.py` resolve rules via `07_Compliance_Scanners/Rule_Library/extracted/Rule_Library/vendor_rule_mapping.json`.
   - This directory path contains duplicate nested `Rule_Library` folders from an earlier extraction.
3. **Hardcoded Rule Template Scarcity:**
   - Only `CISCO-NTP-001.j2` exists in `templates/remediation/`. All other rule remediations will raise `FileNotFoundError` if requested.

---

## 21. Dependency Findings

### Python (`requirements.txt`):
All 11 listed dependencies are directly utilized:
- `fastapi`, `uvicorn`: [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py) web server.
- `pydantic`: Request/response schemas in [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py).
- `jinja2`: CLI fix rendering in [remediation_engine.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/remediation_engine.py).
- `reportlab`, `pypdf`: Cryptographic PDF certificate generation & extraction in [report_generator.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/report_generator.py).
- `python-multipart`: File upload handling in [main.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py).
- `torch`, `transformers`: Local DistilBERT 66M embeddings in [ai_suggester.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_suggester.py).
- `pytest`, `httpx`: Automated testing harnesses.

**Finding:** No unused direct dependencies. No heavy third-party auth dependencies (e.g. `passlib`, `pyjwt`, `python-jose`) exist—auth is implemented purely with standard library.

### Node.js (`dashboard/package.json`):
- Dependencies: `lucide-react`, `react`, `react-dom`.
- DevDependencies: `@types/react`, `@types/react-dom`, `@vitejs/plugin-react`, `autoprefixer`, `postcss`, `tailwindcss`, `typescript`, `vite`.
- **Finding:** Minimal, lean frontend footprint. No extraneous libraries.

---

## 22. Documentation Drift

| Claim in Documentation | Document Source | Actual Source Code Implementation | Status |
|---|---|---|---|
| "No database: audit_log.jsonl and JSON files remain single source of truth" | `main.py` docstring (lines 14–17) | Full SQLite database in `database.py` stores sessions, users, mappings, and ledger. `audit_log.jsonl` does not exist. | **STALE / MISMATCH** |
| "Authentication/user management is deferred to Phase 2" | `main.py` docstring (line 17) | Fully implemented pure-Python HS256 JWT auth, PBKDF2 hashing, seed users, and RBAC active in `auth.py` and `main.py`. | **STALE / MISMATCH** |
| "In-memory session store keyed by session_id (UUID)" | `main.py` docstring (line 15) | Sessions are persisted in SQLite `audit_sessions` table via `database.save_session()`. | **STALE / MISMATCH** |
| Frontend located in `arena-frontend` | `arena-frontend/README.md` | Active frontend is `dashboard/`, running in Docker and covered by unit tests. `arena-frontend` is abandoned. | **STALE / MISMATCH** |
| Reviewer identifies by `reviewer_name` in request | Early PRD docs | Reviewer identity is pulled strictly from JWT claim `current_user['sub']`. Wire parameter is ignored. | **MATCH (UPDATED IN CODE)** |
| 10 CIS benchmark controls implemented | PRD notes | CIS Benchmark evaluator implements 7 controls; DISA-STIG implements 10 controls. | **MISMATCH (CIS=7, STIG=10)** |
| Models: llama3.2:1b and qwen2.5:7b-instruct-q4_K_M | PRD v5 & Benchmark Audit | Exact match in `ai_model_manager.py` allowlist and Docker compose. | **MATCH** |
| DistilBERT 66M for unmapped lines | PRD Addendum §4 Step 3 | Exact match in `ai_suggester.py` (`distilbert-base-uncased` on CPU). | **MATCH** |

---

## 23. Test Architecture

### Well-Tested Domains:
- **Compliance Abstraction & Registry:** 46 unit & invariant tests ([test_compliance_framework.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_compliance_framework.py)).
- **DISA-STIG Cisco IOS-XE Evaluator:** 39 tests covering all 10 controls with pass, fail, unknown cases ([test_disa_stig.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_disa_stig.py)).
- **CIS Cisco IOS-XE Evaluator:** 32 tests covering all 7 controls ([test_cis_benchmark.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_cis_benchmark.py)).
- **AI Model Manager Core & API:** 48 tests across unit and API boundary ([test_ai_model_manager.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_ai_model_manager.py), [test_api_model_manager.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_api_model_manager.py)).
- **Authentication & RBAC:** 57 tests across unit, API auth, RBAC, and ownership ([test_auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_auth.py), [test_api_auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_api_auth.py), [test_api_rbac.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_api_rbac.py), [test_api_ownership.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/test_api_ownership.py)).
- **Frontend Authentication & Model Manager:** 36 tests via Node.js test runner.

### Gaps & Friction Points:
1. `test_docker_offline_auth.py` assumes a live containerized environment on ports 8000 and 3000; when run under local pytest, it fails 12/12 due to connection refusal.
2. `test_ollama_integration.py` contains a parameterized function starting with `test_`, causing an error under pytest collection.
3. `test_api_full_loop.py` and `test_step5_full_loop.py` require manual execution because their entry points are named `run_test()` and `main()` instead of `test_*`.

---

## 24. Security Boundary Analysis

1. **Authentication Boundary:**
   - Stateless JWT validation via HS256. Secret is dynamically generated and protected.
   - Fails closed on missing or tampered tokens with HTTP 401.
   - Timing defenses are active during login.
2. **RBAC & Approver Boundary:**
   - Gating on both role (`reviewer`) and approver clearance (`is_authorized_approver: 1`) strictly enforced on rule approvals and model overrides.
3. **Session Ownership & Anti-Enumeration:**
   - Uploaders are confined to their own sessions. Probing for external session IDs returns HTTP 404.
4. **Execution Safety Fence:**
   - Evaluated by AST analysis. No socket or execution packages imported in API or remediation layers.

---

## 25. AI Safety Boundary Analysis

- **Advisory Role Only:** AI output is strictly isolated from compliance evaluation logic. Evaluators do not import or invoke AI models.
- **Refusal Defenses:** If an LLM refuses or fails to generate rationale, the system falls back to deterministic rule descriptions without blocking the audit.
- **Reviewer Gated Custom Rules:** AI-generated suggestions are stored in `pending_suggestions` and **never** written to `trusted_mappings` without manual approval by an authorized reviewer.
- **Loopback Isolation:** AI model communication is confined to local loopback (`127.0.0.1:11434`), preventing prompt or telemetry exfiltration.

---

## 26. Compliance Boundary Analysis

- **Immutability of Verdicts:** The aggregator strictly preserves `UNKNOWN` states and raises exceptions on conflicting evaluation results.
- **Zero AI Influence:** Compliance pass/fail scoring is determined entirely by deterministic AST and regex logic.
- **Provenance Preservation:** Every evaluation result records the evaluator ID, control ID, framework ID, and structured evidence.

---

## 27. Architectural Risk Register

| ID | Area | Finding | Evidence | Risk | Severity | Action | Refactor Priority |
|---|---|---|---|---|---|---|---|
| **R1** | Frontend Duplication | `arena-frontend` is an abandoned duplicate of `dashboard` | `arena-frontend/` unreferenced; `dashboard/` active in Docker & tests | Code bloat, dev confusion, misleading search results | Low | Safe to delete | Refactor Later (3R.1) |
| **R2** | Skills Duplication | `.agents/skills`, `.claude/skills`, `agent/skills`, `data/skills` are identical | 25 identical skill folders repeated 4 times | Clutters repo, risks out-of-sync edits | Low | Consolidate to single canonical directory | Refactor Later (3R.1) |
| **R3** | Documentation Drift | `main.py` docstring claims "No database" & "No auth" | Lines 14–17 in `main.py` contradict active `database.py` and `auth.py` | Engineers misled on architecture | Medium | Update docstrings to match reality | Refactor Later (3R.7) |
| **R4** | Vestigial Arguments | `logfile: pathlib.Path = DEFAULT_LOG_FILE` in `audit_log.py` | Functions query SQLite `audit_ledger` ignoring the file argument | Confusion over active persistence store | Low | Clean up function signatures | Refactor Later (3R.3) |
| **R5** | Pytest Collection Error | `test_ollama_integration.py::test_offline_capability` | Has parameters `(model, prompt)` causing pytest Error 1 | Breaks clean pytest run across whole repo | Medium | Rename function or add pytest fixture | Refactor Later (3R.1) |
| **R6** | Disconnected Full Loop Tests | `test_step5_full_loop.py` & `test_api_full_loop.py` | Entry points are `main()` and `run_test()` | Pytest does not run full-loop regression automatically | Medium | Wrap in `def test_*()` pytest functions | Refactor Later (3R.1) |
| **R7** | Docker Test Local Failure | `test_docker_offline_auth.py` assumes live Docker containers | Fails 12/12 under local pytest if Docker is stopped | False alarm in local test runs | Low | Add `@pytest.mark.docker` or connection skip guard | Refactor Later (3R.1) |
| **R8** | Dual Upload Paths | `/api/audit/upload` vs `/api/compliance/evaluate` | Upload uses legacy evaluator; evaluate uses multi-framework aggregator | Architectural coupling & dual maintenance | Medium | Harmonize upload to multi-framework in later phase | Needs Careful Refactor (3R.4) |
| **R9** | Remediation Template Scarcity | Only `CISCO-NTP-001.j2` exists in templates | Other rule IDs raise `FileNotFoundError` | Limited remediation coverage | Low | Expand templates as vendor rules expand | Refactor Later (Phase 3B) |
| **R10** | Binary Decks in Root | 4 PPTX/PDF presentation decks in repo root (~60MB) | Top level root directory | Bloats git clones and repo size | Low | Move to `docs/presentations/` | Refactor Later (3R.1) |

---

## 28. Refactor Candidate Matrix

| Component / Finding | Classification | Rationale |
|---|---|---|
| `arena-frontend/` | **SAFE TO REMOVE** | Completely superseded by `dashboard/`; not built or deployed. |
| Duplicate skills in `.claude`, `agent`, `data` | **SAFE TO CONSOLIDATE** | Exact duplicates of `.agents/skills`. |
| Top-level PPTX/PDF decks | **SAFE TO SIMPLIFY** | Can be moved to `docs/archive/` or `.gitignore`. |
| `test_ollama_integration.py` collection error | **SAFE TO SIMPLIFY** | Rename `test_offline_capability` to `verify_offline_capability`. |
| `test_step5_full_loop` & `test_api_full_loop` entry points | **SAFE TO SIMPLIFY** | Add `test_*` wrapper functions so pytest collects them. |
| `test_docker_offline_auth.py` connection skip | **SAFE TO SIMPLIFY** | Skip cleanly if Docker port 8000/3000 is not reachable. |
| `main.py` docstring drift | **SAFE TO SIMPLIFY** | Align docstring with active SQLite & Auth reality. |
| `audit_log.py` dummy `logfile` parameter | **SAFE TO CONSOLIDATE** | Remove dummy parameter while keeping SQLite ledger intact. |
| AST safety assertion helpers | **SAFE TO CONSOLIDATE** | Extract shared `verify_ast_no_execution(filepath)` into a utility module. |
| `/api/audit/upload` legacy path vs `/api/compliance/evaluate` | **NEEDS CAREFUL REFACTOR** | Dashboard `UploadScreen` currently expects the response structure of `/api/audit/upload`. Refactoring requires updating both frontend client and backend in lockstep. |
| [auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/auth.py) JWT & timing attack defense | **SECURITY-SENSITIVE** | **DO NOT TOUCH.** Verified, zero-dependency, passing 57 security tests. |
| [database.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/database.py) PBKDF2 hashing & user schema | **SECURITY-SENSITIVE** | **DO NOT TOUCH.** Critical user security and credential storage. |
| [cis_benchmark_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cis_benchmark_cisco_iosxe.py) | **COMPLIANCE-SENSITIVE** | **DO NOT TOUCH.** Verified deterministic evaluation of 7 CIS controls. |
| [disa_stig_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/disa_stig_cisco_iosxe.py) | **COMPLIANCE-SENSITIVE** | **DO NOT TOUCH.** Verified deterministic evaluation of 10 DISA-STIG controls. |
| [compliance_aggregator.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_aggregator.py) | **COMPLIANCE-SENSITIVE** | **DO NOT TOUCH.** Authoritative pass-rate and conflict-detection logic. |
| [ai_model_manager.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_model_manager.py) allowlist & loopback | **SECURITY-SENSITIVE** | **DO NOT TOUCH.** Protects against unauthorized model execution and external leaks. |
| [cisco_auditor.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cisco_auditor.py) `parse_cisco` | **KEEP AS-IS** | Authoritative parser for Cisco IOS-XE configuration to CSM. |
| `00_Project_Documentation` through `10_Additional_References` | **KEEP AS-IS** | Reference standards, datasets, and extracted rule libraries. |

---

## 29. Recommended 3R Refactoring Plan

Based on the empirical evidence gathered during this audit, the recommended refactoring roadmap is divided into structured, risk-minimized phases:

### Phase 3R.1 — Test Suite Sanitization & Dead Code Cleanup (Low Risk)
1. **Sanitize Test Discovery:** Rename `test_offline_capability` in `test_ollama_integration.py` to avoid pytest collection failure; add `test_*` entry points in `test_api_full_loop.py` and `test_step5_full_loop.py`; add Docker connectivity guard to `test_docker_offline_auth.py`.
2. **Remove Dead Prototype:** Delete `arena-frontend/` directory after verifying `dashboard/` covers all required features.
3. **Consolidate Skills:** Remove triplicate copies of `.agents/skills` from `.claude/skills`, `agent/skills`, and `data/skills`.
4. **Relocate Presentation Decks:** Move root PPTX/PDF slide files to `docs/presentations/`.

### Phase 3R.2 — Documentation & Parameter Synchronization (Low Risk)
1. **Update Docstrings:** Correct stale docstrings in `main.py`, `audit_log.py`, and `report_generator.py` to reflect the SQLite `auditor.db` reality.
2. **Clean Function Signatures:** Remove vestigial `logfile: pathlib.Path = DEFAULT_LOG_FILE` arguments where the implementation exclusively uses SQLite.

### Phase 3R.3 — Shared Utility Consolidation (Low Risk)
1. **Consolidate AST Safety Checks:** Create a single canonical `security_utils.py` with `assert_no_execution_libraries(filepath)` to eliminate the 5 duplicate AST analysis implementations.

### Phase 3R.4 — API & Dashboard Pipeline Harmonization (Medium Risk)
1. **Harmonize Upload Endpoint:** Update `POST /api/audit/upload` to leverage `compliance_framework` and `compliance_aggregator` under the hood, or migrate `dashboard/src/components/UploadScreen.tsx` to directly call `POST /api/compliance/evaluate`.
2. **Verify Frontend Compatibility:** Ensure all 36 frontend tests and Vite production builds remain 100% green after harmonization.

### Phase 3R.5 — Final Graphify & Security Verification
1. Run `graphify update .` to capture the post-refactor graph and verify reduction in redundant nodes and communities.
2. Execute the complete 329-test backend suite and 36-test frontend suite to ensure zero regressions.

---

## 30. Items Explicitly NOT Recommended for Refactoring

The following components are battle-tested, verified by automated tests, and **MUST NOT BE TOUCHED**:

1. **Deterministic Evaluators:**
   - [cis_benchmark_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cis_benchmark_cisco_iosxe.py)
   - [disa_stig_cisco_iosxe.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/disa_stig_cisco_iosxe.py)
   - Reason: Precision logic mapping verified against Cisco ground-truth test configurations.
2. **Multi-Framework Aggregation Core:**
   - [compliance_aggregator.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_aggregator.py)
   - Reason: Hard-won invariants for deduplication, conflict raising, and excluding `UNKNOWN` from pass-rate denominators.
3. **Cryptographic Authentication Subsystem:**
   - [auth.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/auth.py)
   - Reason: Zero-dependency, pure standard library RFC 7515/7519 implementation. Stable and secure.
4. **Password Hashing & PBKDF2 Iterations:**
   - [database.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/database.py) (`hash_password`)
   - Reason: 600,000 PBKDF2-HMAC-SHA256 iterations; altering iteration count or salt handling will invalidate existing user hashes.
5. **AI Model Manager Allowlist & Timeout Bounds:**
   - [ai_model_manager.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/ai_model_manager.py)
   - Reason: Critical security gate preventing prompt injection attacks and arbitrary model execution.
6. **Cisco IOS-XE Configuration Parser:**
   - [cisco_auditor.py](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cisco_auditor.py) (`parse_cisco`)
   - Reason: Foundational normalizer producing the CSM consumed by all downstream evaluators.

---

## 31. Open Questions & Uncertainty

1. **Dashboard Upload Integration:** Should the dashboard's `UploadScreen` continue calling `/api/audit/upload` (legacy response shape) or be refactored to consume `/api/compliance/evaluate` with multi-framework selection badges?
2. **Remediation Template Scope:** Should additional Jinja2 remediation templates for the remaining CIS and DISA-STIG failed controls be implemented as part of Phase 3R refactoring, or deferred to Phase 3B?
3. **Database Migration Policy:** Do we need a formal migration tool (e.g. Alembic or a custom lightweight runner) when schema changes occur in future phases, or does the current idempotent `ALTER TABLE` pattern in `database.py` suffice?

---

## 32. Final Assessment

The codebase exhibits exceptional architectural rigor in its newly implemented subsystems (Phases 3A.1 – 3A.5, AI Model Manager, Auth, Database). The boundaries between deterministic compliance and advisory AI are strictly enforced. However, historical remnants from the early MVP phase (prototype `arena-frontend`, vestigial `audit_log.jsonl` references, stale docstrings in `main.py`, and duplicate skill directories) create documentation drift and unnecessary complexity.

A targeted, staged Phase 3R refactor following the recommended roadmap will safely eliminate this debt without disturbing any security or compliance invariants.

---

## CODEBASE REALITY — SUMMARY

- **Current State:** 3A.1 – 3A.5 Complete; 3R.0 Audit Complete; Baseline Frozen.
- **Main Architectural Strengths:**
  - Strict separation of deterministic compliance evaluation from advisory local AI.
  - Zero-dependency, pure Python HS256 JWT auth and PBKDF2 password hashing.
  - Robust multi-framework abstraction supporting CIS and DISA-STIG concurrently.
  - Clean DAG architecture with zero import cycles confirmed by Graphify.
- **Main Redundancy Candidates:**
  - Prototype `arena-frontend/` (duplicate of `dashboard/`).
  - Quadruplicate skill folders in `.claude/skills`, `agent/skills`, `data/skills`.
  - Parallel evaluation paths in `main.py` (`/api/audit/upload` vs `/api/compliance/evaluate`).
  - 5 duplicate implementations of AST execution safety checks.
- **Main Dead-Code Candidates:**
  - `arena-frontend/` directory.
  - Vestigial `audit_log.jsonl` file references.
  - Parameterized function `test_offline_capability` in `test_ollama_integration.py`.
- **Main Architectural Risks:**
  - Stale docstrings in `main.py` claiming no database and no authentication exist.
  - Dashboard upload screen tied to legacy evaluation response shape.
- **Security-Sensitive Areas:**
  - `auth.py` (JWT decoding, token generation, secret handling).
  - `database.py` (PBKDF2 hashing, user password hashes, salts).
  - `main.py` (timing attack mitigations, login abuse rate-limiting, approver gates, session ownership).
- **Compliance-Sensitive Areas:**
  - `compliance_framework.py` (`ComplianceStatus`, `EvaluationResult`, `Evidence`).
  - `cis_benchmark_cisco_iosxe.py` (7 CIS controls).
  - `disa_stig_cisco_iosxe.py` (10 DISA-STIG controls).
  - `compliance_aggregator.py` (pass-rate calculation, UNKNOWN exclusion, deduplication, conflict detection).
- **AI-Sensitive Areas:**
  - `ai_model_manager.py` (model allowlist, timeout bounds, loopback isolation, refusal markers).
  - `ai_suggester.py` (human reviewer gate before rule trust).
- **Graphify Findings:**
  - 3,661 nodes, 4,880 edges, 177 communities.
  - Core God Nodes: `EvaluationResult` (52 edges), `Evidence` (49 edges), `Control` (45 edges), `FrameworkRegistry` (40 edges).
  - Zero import cycles detected.
- **Refactoring Priorities:**
  1. Test suite discovery fix & dead prototype / duplicate skills removal (3R.1).
  2. Docstring & vestigial argument cleanup (3R.2).
  3. Shared AST safety utility consolidation (3R.3).
  4. API & dashboard upload harmonization (3R.4).
- **Items That Should NOT Be Touched:**
  - CIS and DISA-STIG evaluator logic.
  - Aggregator scoring and deduplication formulas.
  - Pure Python HS256 JWT auth and PBKDF2 password hashing.
  - Model manager allowlist and loopback enforcement.
  - Cisco configuration parser (`parse_cisco`).
- **Unknowns Requiring Investigation:**
  - Preferred UX for multi-framework selection in dashboard upload flow.
  - Scope and scheduling of additional Jinja2 remediation templates.
- **Baseline Tests:**
  - Backend Unit/Integration: **316 / 316 PASS** (100%).
  - Standalone Full Loops: `test_step5_full_loop.py` (**17/17 stages PASS**), `test_api_full_loop.py` (**11/11 stages PASS**).
  - Frontend: **36 / 36 PASS** (100%).
  - Frontend Build: `tsc && vite build` built cleanly in 24.04s.
- **Git State:** On branch `main`, ahead of `origin/main` by 1 commit (`911e3fb`).
- **Production Modifications:** **NONE** (Strict read-only compliance preserved).
- **3B started:** **NO**
- **Vendor #2 started:** **NO**
- **Upskill started:** **NO**
