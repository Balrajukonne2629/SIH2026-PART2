# Graph Report - PART-2  (2026-09-20)

## Corpus Check
- 151 files · ~3,192,965 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 35 file(s) not represented in the graph (top: .xml 8, .zip 8, .xsl 6)

## Summary
- 2497 nodes · 3921 edges · 127 communities (111 shown, 16 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 390 edges (avg confidence: 0.95)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- package.json
- 2. Known Implementation Limitations
- create_access_token
- App.tsx
- properties
- EvaluationResult
- test_api_ownership.py
- main.py
- ai_model_manager.py
- Security and Hardening
- verify_api_safety_no_execution
- AI-Driven Multi-Vendor Network Security Compliance Auditor
- fixture
- compliance_aggregator.py
- Code Review and Quality
- Test-Driven Development
- Focused Precedence Tests (`test_api_model_manager.py` — 31/31 PASSED)
- arena_frontend_src_styles
- test_multi_framework_aggregation.py
- NTRO PS26155 — Phase 3R.2 Documentation & Parameter Synchronization Report
- Context Engineering
- type
- database.py
- Git Workflow and Versioning
- NTRO PS26155 — Phase 3R.4 API & Dashboard Pipeline Harmonization Report
- get_connection
- Shipping and Launch
- 28. Refactor Candidate Matrix
- test_docker_offline_auth.py
- TestDisaStigEvaluationParity
- AIModelManager
- Any
- .get_status
- API and Interface Design
- Browser Testing with DevTools
- Performance Optimization
- test_ai_model_manager.py
- api.ts
- UploadScreen.tsx
- 12. Final Gate Verification (Chunk 2C.1)
- check_session_ownership
- test_frontend_model_manager.mjs
- types.ts
- CI/CD and Automation
- Constraint-Driven Development
- Deprecation and Migration
- Frontend UI Engineering
- UserIdentity
- auth.py
- get_jwt_secret
- access_control
- inbound_acl_count
- Incremental Implementation
- vendor
- properties
- TestDisaStigControlEvaluatorUnit
- Code Simplification
- Debugging and Error Recovery
- Documentation and ADRs
- properties
- properties
- Planning and Task Breakdown
- properties
- properties
- test_api_reviewer_identity.py
- ReOrder: Keep Your Regulars Ordering Direct
- Interview Me
- compilerOptions
- properties
- NTRO PS26155 — AI Hardware & Local Model Benchmark Audit
- DASHBOARD TRUTH, TELEMETRY & AI RUNTIME CONSISTENCY AUDIT REPORT
- properties
- Doubt-Driven Development
- Process
- MultiFrameworkAggregator
- Idea Refine
- Using Agent Skills
- Spec-Driven Development
- 2. Detailed Per-Rule Evidence and Rationale
- properties
- properties
- enabled
- properties
- Source-Driven Development
- properties
- Refinement & Evaluation Criteria
- test_api_model_manager.py
- Ideation Frameworks Reference
- test_api_auth.py
- compliance_check_result_schema.json
- ModelMode
- Addendum to v4.0 — Refinements for MVP Build
- Collection Status
- properties
- NTRO PS26155 — AI Model Manager: Chunk 1 Backend Core Implementation Report
- items
- 00_Project_Documentation/README.md
- RESOURCE_INVENTORY.md
- rules/graphify.md
- workflows/graphify.md
- idea-refine.sh
- index.html (Dashboard Entrypoint)
- src_index
- test_api_rbac.py
- properties
- TestOllamaInvocationAndFallbacks
- properties
- FrameworkRegistry
- remediation
- checked_at
- NTRO PS26155 — AI Model Manager: Configuration Precedence & Consistency Audit
- NTRO PS26155 — AI Model Manager: Chunk 2A.1 Implementation Report
- test_api_compliance.py
- NTRO PS26155 — Multi-Framework Compliance Architecture (Phase 3A.1 – 3A.4)
- NTRO PS26155 — AI Model Manager: Chunk 2A.1 Implementation Report
- get_user_by_username
- NTRO PS26155 — Codebase Reality Audit
- TestCisControlEvaluatorUnit
- Control
- ComplianceStatus
- FrameworkEvaluator
- hash_password
- 8. Backend Module Map
- TestCisBenchmarkCatalog
- TestDisaStigCatalog

## God Nodes (most connected - your core abstractions)
1. `EvaluationResult` - 57 edges
2. `Evidence` - 54 edges
3. `Control` - 50 edges
4. `FrameworkRegistry` - 47 edges
5. `8. Backend Module Map` - 45 edges
6. `create_access_token()` - 41 edges
7. `StigCiscoIosXeEvaluator` - 39 edges
8. `CisCiscoIosXeEvaluator` - 38 edges
9. `ComplianceStatus` - 37 edges
10. `get_connection()` - 37 edges

## Surprising Connections (you probably didn't know these)
- `9. Recommendations (For Future Implementation / Chunk 2B)` --references--> `AIModelManager`  [INFERRED]
  AI_MODEL_MANAGER_CONFIG_PRECEDENCE_AUDIT.md → ai_model_manager.py
- `5. Security & Invariant Verification` --references--> `assert_no_execution_imports()`  [INFERRED]
  3R4_API_DASHBOARD_PIPELINE_HARMONIZATION_REPORT.md → ast_safety.py
- `10.4 Deterministic Evidence Consolidation` --references--> `ConsolidatedEvidence`  [INFERRED]
  MULTI_FRAMEWORK_COMPLIANCE_ARCHITECTURE.md → compliance_aggregator.py
- `3.4 Deterministic Evidence Model (`Evidence`)` --references--> `Evidence`  [INFERRED]
  MULTI_FRAMEWORK_COMPLIANCE_ARCHITECTURE.md → compliance_framework.py
- `3.2 Control Domain Contract (`Control`)` --references--> `Control`  [INFERRED]
  MULTI_FRAMEWORK_COMPLIANCE_ARCHITECTURE.md → compliance_framework.py

## Import Cycles
- None detected.

## Communities (127 total, 16 thin omitted)

### Community 0 - "package.json"
Cohesion: 0.06
Nodes (32): dependencies, lucide-react, react, react-dom, devDependencies, autoprefixer, postcss, tailwindcss (+24 more)

### Community 1 - "2. Known Implementation Limitations"
Cohesion: 0.22
Nodes (8): 2. Known Implementation Limitations, 3. Phase 2 Vendor Extension Architecture, Extension Contract & Current State: How New Vendors Plug In, Limitation 1: Rule `CISCO-INT-001` Description String Matching Fragility, Limitation 2: Rule `CISCO-ROUTING-001` BGP-Only Protocol Scope, Limitation 3: Template-Engineered vs. Open-Ended Generative AI Explanations, Literal Current State in `vendor_rule_mapping.json`:, NTRO PS26155 MVP: Architecture Notes & Codebase Reference

### Community 2 - "create_access_token"
Cohesion: 0.15
Nodes (31): base64url_decode(), base64url_encode(), create_access_token(), decode_and_verify_jwt(), InvalidTokenError, Any, Encodes bytes to unpadded Base64URL string (RFC 7515)., Decodes unpadded Base64URL string to bytes strictly (RFC 7515). Rejects… (+23 more)

### Community 3 - "App.tsx"
Cohesion: 0.20
Nodes (15): clearAccessToken(), getAccessToken(), getCurrentUser(), getModelStatus(), onUnauthorized(), setModelMode(), App(), AiModelManagerScreen() (+7 more)

### Community 4 - "properties"
Cohesion: 0.09
Nodes (23): type, type, type, type, type, type, properties, type (+15 more)

### Community 5 - "EvaluationResult"
Cohesion: 0.09
Nodes (25): 1. File Inventory & Pipeline Mapping, EvaluationResult, Evidence, Framework-neutral compliance evaluation verdict for a single control against…, Deterministic evidence explaining the factual basis for an evaluation verdict.…, Any, Evaluates normalized CSM data against DISA STIG requirements for Cisco IOS XE.…, Evaluates normalized CSM against DISA-STIG controls. Args: csm: Normalized… (+17 more)

### Community 6 - "test_api_ownership.py"
Cohesion: 0.05
Nodes (51): 4.3 Direct Unit Testing, create_session_for_uploader(), fixture, NTRO PS26155 Auditor — Resource Ownership & Session Isolation Tests (Chunk 5)…, Scenario 1: Audit upload assigns owner_user_id strictly from JWT sub claim., Scenario 2: Client cannot override owner_user_id via JSON body payload., Scenario 3: Client cannot override owner_user_id via query parameters., Scenario 4: Client cannot override owner_user_id via custom headers. (+43 more)

### Community 8 - "main.py"
Cohesion: 0.11
Nodes (31): BaseModel, fastapi_middleware_cors, fastapi_responses, ApproveRequest, check_login_rate_limit(), _clean_expired_login_attempts(), ComplianceEvaluateRequest, FinalizeRequest (+23 more)

### Community 9 - "ai_model_manager.py"
Cohesion: 0.08
Nodes (36): _MEMORYSTATUSEX, probe_system_hardware(), AI Model Manager Subsystem (PRD Addendum §2, Benchmark Audit Architecture).…, Probes system memory, CPU cores, and GPU capabilities using stdlib where…, 12.1 Actual Runtime Hardware Probe Execution, _get_embedding(), get_model(), Local AI Unmapped Line Suggester & Reviewer Approval Workflow (PRD Addendum… (+28 more)

### Community 10 - "Security and Hardening"
Cohesion: 0.06
Nodes (31): Always Do (No Exceptions), Ask First (Requires Human Approval), Broken Access Control, Broken Authentication, Common Rationalizations, Cross-Site Scripting (XSS), Data Privacy & Compliance, Destructive Operations on Derived Paths (+23 more)

### Community 11 - "verify_api_safety_no_execution"
Cohesion: 0.07
Nodes (34): 10. Final Status, 1. Executive Summary, 2.1 Target Investigated, 2.2 Empirical Comparison & Evidence, 2.3 Responsibility Confirmation, 2. Duplication Investigated & Evidence, 3. Shared Utility Created, 4.1 In [`remediation_engine.py`](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/remediation_engine.py): (+26 more)

### Community 12 - "AI-Driven Multi-Vendor Network Security Compliance Auditor"
Cohesion: 0.06
Nodes (31): 10. Data Model (Core Objects), 11. Technology Stack, 12. Risks & Mitigations, 13. Roadmap (Post-Hackathon), 14. Build Order — Single-File, Single-Path First, 15. MVP Acceptance Criteria, 16. What We Are Not Claiming, 17. Shared Internal-Rule / Multi-Framework Model (+23 more)

### Community 13 - "fixture"
Cohesion: 0.29
Nodes (7): fixture, Ensures test isolation by resetting model manager mode between tests., reset_model_manager_state(), reviewer_non_approver_token(), reviewer_token(), uploader_token(), viewer_token()

### Community 14 - "compliance_aggregator.py"
Cohesion: 0.09
Nodes (22): AggregationError, ConflictingControlEvaluationError, ConsolidatedEvidence, FrameworkSummary, InvalidEvaluationResultError, MultiFrameworkAuditResult, OverallMetrics, Any (+14 more)

### Community 15 - "Code Review and Quality"
Cohesion: 0.07
Nodes (29): 1. Correctness, 2. Readability & Simplicity, 3. Architecture, 4. Security, 5. Performance, Change Descriptions, Change Sizing, Code Review and Quality (+21 more)

### Community 16 - "Test-Driven Development"
Cohesion: 0.07
Nodes (29): Browser Testing with DevTools, Common Rationalizations, DAMP Over DRY in Tests, Decision Guide, Discover the Stack First, Name Tests Descriptively, One Assertion Per Concept, Overview (+21 more)

### Community 17 - "Focused Precedence Tests (`test_api_model_manager.py` — 31/31 PASSED)"
Cohesion: 0.12
Nodes (22): 4. Test Evidence & Regression Parity, Focused Precedence Tests (`test_api_model_manager.py` — 31/31 PASSED), Full Regression Suite Results (100% PARITY), 4. Test Evidence & Regression Parity, Focused Precedence Tests (`test_api_model_manager.py` — 31/31 PASSED), Full Regression Suite Results (100% PARITY), Case A: API sets FAST while OLLAMA_MODEL=qwen. Actual inference must use…, Case B: API sets QUALITY while OLLAMA_MODEL=llama. Actual inference must use… (+14 more)

### Community 19 - "test_multi_framework_aggregation.py"
Cohesion: 0.07
Nodes (31): ast, NTRO PS26155 — AST Safety Verification Utility (Phase 3R.3). Provides…, NTRO PS26155 — CIS Benchmark Cisco IOS-XE Deterministic Control Catalog (Phase…, Registers the CIS Cisco IOS-XE Benchmark v2.2.1 framework and evaluator into…, register_cis_cisco_iosxe(), get_default_registry(), NTRO PS26155 — Framework Abstraction & Domain Data Model (Phase 3A.1).…, Returns the shared process-level FrameworkRegistry instance. (+23 more)

### Community 20 - "NTRO PS26155 — Phase 3R.2 Documentation & Parameter Synchronization Report"
Cohesion: 0.18
Nodes (10): 10. Final Status, 1. Executive Summary, 4. Files Changed, 6. Verification Results, 7. Graphify & Ponytail Results, 8. Confirmation of Zero Runtime Behavior Change, 9. Remaining Documentation Debt (Deferred to 3R.3 / 3R.4), Graphify Knowledge Graph Post-Sync: (+2 more)

### Community 21 - "Context Engineering"
Cohesion: 0.07
Nodes (28): Anti-Patterns, Common Rationalizations, Compress before dropping, Confusion Management, Context Budget Management, Context Engineering, Context Packing Strategies, Level 1: Rules Files (+20 more)

### Community 22 - "type"
Cohesion: 0.12
Nodes (16): items, type, items, type, type, items, type, allowed_vlans (+8 more)

### Community 23 - "database.py"
Cohesion: 0.14
Nodes (20): 19. Dead-Code Candidates, Connection, initialize_database(), migrate_ledger(), migrate_pending_suggestions(), migrate_schema_add_ownership(), migrate_trusted_mappings(), Idempotently and non-destructively adds nullable owner_user_id to audit tables. (+12 more)

### Community 24 - "Git Workflow and Versioning"
Cohesion: 0.07
Nodes (26): 1. Commit Early, Commit Often, 2. Atomic Commits, 3. Descriptive Messages, 4. Keep Concerns Separate, 5. Size Your Changes, Branch Naming, Branching Strategy, Change Summaries (+18 more)

### Community 25 - "NTRO PS26155 — Phase 3R.4 API & Dashboard Pipeline Harmonization Report"
Cohesion: 0.11
Nodes (19): 1. Executive Summary, 2.2 Callers & Consumers, 2. Pipeline Trace & Empirical Comparison, 3. Why Pipelines Remain Intentionally Separate (Doubt-Driven Analysis), 4.1 Backend Session Ownership Resolution Consolidation, 4.2 Frontend Client Parity Harmonization, 4. Harmonization Implemented, 5. Security & Invariant Verification (+11 more)

### Community 26 - "get_connection"
Cohesion: 0.13
Nodes (23): 5. References Intentionally Left Unchanged & Why, append_audit_entry(), compute_entry_hash(), create_audit_entry(), get_last_entry(), Path, Re-walks entire log table, recalculates all hashes, and verifies prevEntryHash…, Computes SHA256 over canonical JSON of all entry fields excluding entryHash. (+15 more)

### Community 27 - "Shipping and Launch"
Cohesion: 0.08
Nodes (25): Accessibility, Code Quality, Common Rationalizations, Documentation, Error Budget Release Gate, Error Reporting, Feature Flag Strategy, Infrastructure (+17 more)

### Community 28 - "28. Refactor Candidate Matrix"
Cohesion: 0.40
Nodes (5): 28. Refactor Candidate Matrix, Pytest-discoverable entrypoint for FastAPI full-loop integration test., test_api_full_loop(), Pytest-discoverable entrypoint for PRD Step 5 full loop integration test., test_step5_full_loop()

### Community 29 - "test_docker_offline_auth.py"
Cohesion: 0.05
Nodes (53): 1. Executive Summary, 2. Before vs After Metrics, 3.1 Item 1: Pytest Collection Fix in `test_ollama_integration.py`, 3.2 Item 2: Pytest Integration for Full-Loop Tests, 3.3 Item 3: Docker-Availability Skip Guard in `test_docker_offline_auth.py`, 3.4 Item 4: Dead Prototype Frontend Removal (`arena-frontend/`), 3.5 Item 5: Skills Directory Analysis & Consolidation, 3. Detailed Scope Execution (+45 more)

### Community 30 - "TestDisaStigEvaluationParity"
Cohesion: 0.33
Nodes (3): fixture, Tests 1:1 evaluation parity against cisco_auditor.py on labeled_test_config.txt., TestDisaStigEvaluationParity

### Community 31 - "AIModelManager"
Cohesion: 0.16
Nodes (8): AIModelManager, 1. Summary of Changes & Files Modified, 1. Summary of Changes & Files Modified, Coordinates local model selection, invocation, and fail-safe degradation., Seeds initial manager state from environment variables at startup. Preserves…, Enforces loopback-only binding to prevent Server-Side Request Forgery (SSRF)., Resets active mode to AUTO and clears overrides (or re-bootstraps from…, TestModelSelection

### Community 32 - "Any"
Cohesion: 0.08
Nodes (43): Module Responsibilities [OBSERVED FACT], get_model_manager(), approve_suggestion(), Path, store_suggestion(), 10. Database / Persistence Map, 13. AI Architecture Reality Audit, get_session() (+35 more)

### Community 33 - ".get_status"
Cohesion: 0.14
Nodes (11): 4. Model-Selection Logic `[IMPLEMENTED & TESTED]`, 3. Configuration Precedence Trace (Check 1), 7. Conceptual Architecture Evaluation (Check 5), Actual Precedence Order, Architectural Deviation Identified, Observed Precedence in Calling Subsystems, Observed Precedence in REST API Status, Any (+3 more)

### Community 34 - "API and Interface Design"
Cohesion: 0.08
Nodes (24): 1. Contract First, 2. Consistent Error Semantics, 3. Validate at Boundaries, 4. Prefer Addition Over Modification, 5. Predictable Naming, 6. Honouring an Idempotency Key, API and Interface Design, Common Rationalizations (+16 more)

### Community 35 - "Browser Testing with DevTools"
Cohesion: 0.08
Nodes (24): Accessibility Verification with DevTools, Available Tools, Browser Testing with DevTools, Clean Console Standard, Common Rationalizations, Console Analysis Patterns, Content Boundary Markers, For Network Issues (+16 more)

### Community 36 - "Performance Optimization"
Cohesion: 0.08
Nodes (24): Common Rationalizations, Connection Pool Exhaustion, Core Web Vitals Targets, Large Bundle Size, Log every attempt, including the reverted ones, Missing Caching (Backend), Missing Image Optimization (Frontend), N+1 Queries (Backend) (+16 more)

### Community 37 - "test_ai_model_manager.py"
Cohesion: 0.23
Nodes (7): HardwareProfile, inspect, io, Comprehensive Test Suite for AI Model Manager (Chunk 1 Backend Core). Verifies:…, TestHardwareAwareAutoSelection, unittest, unittest_mock

### Community 38 - "api.ts"
Cohesion: 0.23
Nodes (13): API_BASE, ApiError, approveSuggestion(), finalizeAudit(), getRemediation(), notifyUnauthorized(), request(), suggestMapping() (+5 more)

### Community 39 - "UploadScreen.tsx"
Cohesion: 0.24
Nodes (12): 31. Open Questions & Uncertainty, getAuditResults(), getLedger(), getReportDownloadUrl(), uploadAuditConfig(), verifyLedger(), verifyReport(), AuditLogReportScreen() (+4 more)

### Community 40 - "12. Final Gate Verification (Chunk 2C.1)"
Cohesion: 0.12
Nodes (13): 12.2 Hardware / UI / Documentation Consistency, 12.3 Complete Regression Test Counts, 12.4 DistilBERT Architectural Boundary Confirmation, 12.5 Air-Gap Claim Precision & Classification, 12.6 Source-of-Truth Invariants Confirmed, 12.7 Remaining Known Limitations, 12. Final Gate Verification (Chunk 2C.1), 2. Complete Dashboard Telemetry Truth Table (+5 more)

### Community 41 - "check_session_ownership"
Cohesion: 0.25
Nodes (9): 11.3 RBAC Permissions Matrix, 11.4 Reviewer Accountability & Ownership, 11. Authentication, RBAC & Ownership Map, check_session_ownership(), get_current_user(), FastAPI authentication dependency. Extracts Bearer token from Authorization…, Enforces audit session resource isolation and anti-enumeration. Reviewers may…, 2. `POST /api/compliance/evaluate` (+1 more)

### Community 42 - "test_frontend_model_manager.mjs"
Cohesion: 0.15
Nodes (12): localStorageStore, mockLocalStorage, mockSessionStorage, sessionStorageStore, localStorageStore, mockLocalStorage, mockSessionStorage, SAMPLE_STATUS_OFFLINE (+4 more)

### Community 43 - "types.ts"
Cohesion: 0.17
Nodes (11): AuditLogEntry, AuditStatus, ConflictItem, FrameworkMapping, HardwareProfile, LoginResponse, ModelModeUpdateRequest, RecentAudit (+3 more)

### Community 44 - "CI/CD and Automation"
Cohesion: 0.08
Nodes (23): Automation Beyond CI, Basic CI Pipeline, Build Cop Role, CI/CD and Automation, CI Optimization, Common Rationalizations, Dependabot / Renovate, Deployment Strategies (+15 more)

### Community 45 - "Constraint-Driven Development"
Cohesion: 0.08
Nodes (22): Adapting it, Contract, Floor guard: reference implementation, Reference (Node, ~stack-agnostic patterns), Common Rationalizations, Constraint-Driven Development, Escalation Path, Loading Constraints (+14 more)

### Community 46 - "Deprecation and Migration"
Cohesion: 0.08
Nodes (23): Adapter Pattern, Code Is a Liability, Common Rationalizations, Compulsory vs Advisory Deprecation, Core Principles, Database Schema Migrations (Expand/Contract), Deprecation and Migration, Deprecation Planning Starts at Design Time (+15 more)

### Community 47 - "Frontend UI Engineering"
Cohesion: 0.08
Nodes (23): Accessibility (WCAG 2.1 AA), ARIA Labels, Avoid the AI Aesthetic, Color, Common Rationalizations, Component Architecture, Component Patterns, Design System Adherence (+15 more)

### Community 48 - "UserIdentity"
Cohesion: 0.24
Nodes (9): login(), setAccessToken(), AiModelManagerScreenProps, AiSuggestionReviewScreenProps, LoginScreen(), LoginScreenProps, RemediationDetailScreenProps, UploadScreenProps (+1 more)

### Community 49 - "auth.py"
Cohesion: 0.25
Nodes (7): AuthError, Exception, NTRO PS26155 Auditor — Zero-Dependency Authentication Subsystem Pure Python…, Base exception for authentication and token validation errors., base64, hmac, secrets

### Community 50 - "get_jwt_secret"
Cohesion: 0.33
Nodes (6): get_jwt_secret(), Path, Retrieves or provisions the 256-bit secret key used for HS256 JWT signing.…, test_response_does_not_contain_jwt_secret(), test_environment_secret_override_behavior(), test_secret_generation_and_persistence()

### Community 51 - "access_control"
Cohesion: 0.67
Nodes (3): additionalProperties, type, access_control

### Community 52 - "inbound_acl_count"
Cohesion: 0.67
Nodes (3): minimum, type, inbound_acl_count

### Community 53 - "Incremental Implementation"
Cohesion: 0.09
Nodes (22): Common Rationalizations, Contract-First Slicing, Implementation Rules, Increment Checklist, Incremental Implementation, Overview, Red Flags, Risk-First Slicing (+14 more)

### Community 54 - "vendor"
Cohesion: 0.67
Nodes (3): vendor, enum, type

### Community 55 - "properties"
Cohesion: 0.09
Nodes (22): type, maximum, minimum, type, type, type, properties, type (+14 more)

### Community 60 - "Code Simplification"
Cohesion: 0.10
Nodes (20): 1. Preserve Behavior Exactly, 2. Follow Project Conventions, 3. Prefer Clarity Over Cleverness, 4. Maintain Balance, 5. Scope to What Changed, Code Simplification, Common Rationalizations, Language-Specific Guidance (+12 more)

### Community 61 - "Debugging and Error Recovery"
Cohesion: 0.09
Nodes (21): Build Failure Triage, Common Rationalizations, Debugging and Error Recovery, Error-Specific Patterns, Instrumentation Guidelines, Overview, Red Flags, Runtime Error Triage (+13 more)

### Community 62 - "Documentation and ADRs"
Cohesion: 0.09
Nodes (21): ADR Lifecycle, ADR Template, API Documentation, Architecture Decision Records (ADRs), Changelog Maintenance, Common Rationalizations, Document Known Gotchas, Documentation and ADRs (+13 more)

### Community 67 - "properties"
Cohesion: 0.13
Nodes (15): additionalProperties, properties, required, type, type, type, type, type (+7 more)

### Community 68 - "properties"
Cohesion: 0.11
Nodes (19): additionalProperties, properties, type, type, type, type, minimum, type (+11 more)

### Community 70 - "Planning and Task Breakdown"
Cohesion: 0.11
Nodes (18): Common Rationalizations, Output Files, Overview, Parallelization Opportunities, Plan Document Template, Planning and Task Breakdown, Red Flags, See Also (+10 more)

### Community 72 - "properties"
Cohesion: 0.17
Nodes (12): properties, type, type, type, type, minimum, type, acls_present (+4 more)

### Community 73 - "properties"
Cohesion: 0.11
Nodes (18): type, type, type, type, bgp_enabled, eigrp_enabled, isis_enabled, ospf_enabled (+10 more)

### Community 74 - "test_api_reviewer_identity.py"
Cohesion: 0.06
Nodes (49): authorized_approver_token(), non_approver_reviewer_token(), fixture, NTRO PS26155 Auditor — Reviewer Identity & Approval Accountability Binding…, Scenario 1: Authorized reviewer can approve compliance rules., Scenario 2: Reviewer identity recorded in DB equals authenticated JWT 'sub'., Scenario 3: Client-supplied reviewer_name is ignored; JWT sub is authoritative., Scenario 4: Client-supplied reviewer_id in payload is ignored. (+41 more)

### Community 78 - "ReOrder: Keep Your Regulars Ordering Direct"
Cohesion: 0.11
Nodes (17): Example 1: Vague Early-Stage Concept (Full 3-Phase Session), Example 2: Feature Idea Within an Existing Product (Codebase-Aware), Example 3: Process/Workflow Idea (Non-Product), Ideation Session Examples, Key Assumptions to Validate, MVP Scope, Not Doing (and Why), Open Questions (+9 more)

### Community 79 - "Interview Me"
Cohesion: 0.11
Nodes (17): Common Rationalizations, Example, Interaction with Other Skills, Interview Me, Loading Constraints, Output, Overview, Red Flags (+9 more)

### Community 80 - "compilerOptions"
Cohesion: 0.11
Nodes (17): compilerOptions, allowImportingTsExtensions, isolatedModules, jsx, lib, module, moduleResolution, noEmit (+9 more)

### Community 83 - "properties"
Cohesion: 0.12
Nodes (17): type, type, additionalProperties, properties, type, buffered_logging_enabled, console_logging_enabled, logging (+9 more)

### Community 84 - "NTRO PS26155 — AI Hardware & Local Model Benchmark Audit"
Cohesion: 0.05
Nodes (37): 10. Fast vs Quality Analysis, 11. Proposed Auto-Selection Signals [ENGINEERING RECOMMENDATION], 12. Fallback Strategy [ENGINEERING RECOMMENDATION], 13. Security Findings [SECURITY REVIEW], 14. Recommended AI Model Manager Architecture, 16. Required Future Tests [ENGINEERING RECOMMENDATION], 17. Limitations of This Audit [UNVERIFIED / NOT TESTED], 18. Exact Commands & Evidence Used (+29 more)

### Community 85 - "DASHBOARD TRUTH, TELEMETRY & AI RUNTIME CONSISTENCY AUDIT REPORT"
Cohesion: 0.11
Nodes (18): 10.1 Frontend Test Suite (Node.js Test Runner), 10.2 Frontend TypeScript & Production Build, 10.3 Backend Test Suite (Pytest), 10. Automated Test Verification Results, 11. Recommendations for Chunk 3 & Multi-Framework Readiness, 1. Executive Summary, 3.1 Architectural Truth, 3. DistilBERT Reality Audit (+10 more)

### Community 86 - "properties"
Cohesion: 0.12
Nodes (16): type, type, communities_present, community_strings_encrypted, read_only, snmp, snmpv3_users_present, trap_enabled (+8 more)

### Community 89 - "Doubt-Driven Development"
Cohesion: 0.12
Nodes (15): Common Rationalizations, Cross-model escalation, Doubt-Driven Development, Interaction with Other Skills, Loading Constraints, Overview, Red Flags, Step 1: CLAIM — Surface what stands (+7 more)

### Community 90 - "Process"
Cohesion: 0.12
Nodes (15): 1. Define "working" before instrumenting, 2. Pick the right signal for each question, 3. Structured logging, 4. Metrics, 5. Distributed tracing, 6. Alerting, 7. Verify the telemetry itself, Common Rationalizations (+7 more)

### Community 93 - "MultiFrameworkAggregator"
Cohesion: 0.08
Nodes (17): 2.1 Side-by-Side Architectural Trace, MultiFrameworkAggregator, Deterministic aggregation engine for multi-framework compliance evaluation…, Initializes aggregator with an optional registry for framework metadata…, 11.1 Architectural Role & Boundaries, make_res(), Any, Tests cross-framework macro metrics and transparency. (+9 more)

### Community 96 - "Idea Refine"
Cohesion: 0.13
Nodes (14): Anti-patterns to Avoid, Detailed Instructions, How It Works, Idea Refine, Output, Phase 1: Understand & Expand (Divergent), Phase 2: Evaluate & Converge, Phase 3: Sharpen & Ship (+6 more)

### Community 97 - "Using Agent Skills"
Cohesion: 0.13
Nodes (14): 1. Surface Assumptions, 2. Manage Confusion Actively, 3. Push Back When Warranted, 4. Enforce Simplicity, 5. Maintain Scope Discipline, 6. Verify, Don't Assume, Core Operating Behaviors, Failure Modes to Avoid (+6 more)

### Community 101 - "Spec-Driven Development"
Cohesion: 0.14
Nodes (13): Common Rationalizations, Keeping the Spec Alive, Overview, Phase 0: Scope Check, Phase 1: Specify, Phase 2: Plan, Phase 3: Tasks, Phase 4: Implement (+5 more)

### Community 103 - "2. Detailed Per-Rule Evidence and Rationale"
Cohesion: 0.14
Nodes (13): 10. COMMON-MGMT-001 (`CISCO-MGMT-001`), 1. COMMON-SSH-001 (`CISCO-SSH-001`), 1. Summary of Mappings, 2. COMMON-AAA-001 (`CISCO-AAA-001`), 2. Detailed Per-Rule Evidence and Rationale, 3. COMMON-NTP-001 (`CISCO-NTP-001`), 4. COMMON-LOG-001 (`CISCO-LOG-001`), 5. COMMON-SNMP-001 (`CISCO-SNMP-001`) (+5 more)

### Community 104 - "properties"
Cohesion: 0.12
Nodes (16): format, type, type, type, completed_at, configuration_hash, framework, scan (+8 more)

### Community 105 - "properties"
Cohesion: 0.09
Nodes (23): maximum, minimum, type, minimum, type, minimum, type, minimum (+15 more)

### Community 106 - "enabled"
Cohesion: 0.15
Nodes (13): type, type, additionalProperties, properties, type, authentication_enabled, enabled, ntp (+5 more)

### Community 107 - "properties"
Cohesion: 0.10
Nodes (20): additionalProperties, description, $id, items, type, additionalProperties, required, properties (+12 more)

### Community 109 - "Source-Driven Development"
Cohesion: 0.15
Nodes (12): Common Rationalizations, Overview, Red Flags, Retrieval Safety: Treat Fetched Content as Data, Source-Driven Development, Step 1: Detect Stack and Versions, Step 2: Fetch Official Documentation, Step 3: Implement Following Documented Patterns (+4 more)

### Community 111 - "properties"
Cohesion: 0.17
Nodes (12): properties, required, type, type, type, type, device, hostname (+4 more)

### Community 113 - "Refinement & Evaluation Criteria"
Cohesion: 0.17
Nodes (11): 1. User Value, 2. Feasibility, 3. Differentiation, Assumption Audit, Core Evaluation Dimensions, Decision Framework, Might Be True (Nice to Have), Must Be True (Dealbreakers) (+3 more)

### Community 115 - "test_api_model_manager.py"
Cohesion: 0.07
Nodes (7): API Integration Tests for AI Model Manager (Chunk 2A: REST API). Verifies: 1.…, Verifies that shorthand 'qwen2.5:7b' is rejected with explicit guidance., When Ollama is offline, GET /api/model/status reports fallback state without…, Asserts that changing AI model mode does not modify reviewer permissions or…, test_model_mode_change_does_not_affect_auth_or_trusted_mappings(), test_ollama_offline_status_resilience(), test_override_with_shorthand_qwen_rejected()

### Community 117 - "Ideation Frameworks Reference"
Cohesion: 0.22
Nodes (8): Analogous Inspiration, Constraint-Based Ideation, First Principles Thinking, How Might We (HMW), Ideation Frameworks Reference, Jobs to Be Done (JTBD), Pre-mortem, SCAMPER

### Community 120 - "compliance_check_result_schema.json"
Cohesion: 0.12
Nodes (15): additionalProperties, description, type, $id, properties, findings, result_id, summary (+7 more)

### Community 121 - "ModelMode"
Cohesion: 0.17
Nodes (14): 1. Implementation Summary `[IMPLEMENTED]`, Key Milestones Delivered:, 2. Files Inspected & Code Evidence, 3. Can an invalid environment model bypass the strict model allowlist?, ModelMode, ModelResponse, Enum, str (+6 more)

### Community 123 - "Addendum to v4.0 — Refinements for MVP Build"
Cohesion: 0.25
Nodes (7): 1. Shared internal-rule / multi-framework model (revises §10 Data Model), 2. Split performance requirement (revises §7), 3. Simplified approval — one authorized reviewer for MVP (revises FR-3.4), 4. Build order — single-file, single-path first, Addendum to v4.0 — Refinements for MVP Build, Final Architecture Statement (supersedes §1 positioning language, rest of §1 stands), MVP Acceptance Criteria

### Community 125 - "Collection Status"
Cohesion: 0.50
Nodes (3): Collection Status, Included and recovered, Not yet validated

### Community 126 - "properties"
Cohesion: 0.10
Nodes (20): type, type, type, type, type, cdp_or_lldp, finger, ftp (+12 more)

### Community 128 - "NTRO PS26155 — AI Model Manager: Chunk 1 Backend Core Implementation Report"
Cohesion: 0.11
Nodes (18): 15. Files / Modules Likely Affected in Future Implementation, 10. Regression Results `[OBSERVED & TESTED]`, 11. Git Diff & Change-Safety Verification `[OBSERVED]`, 12. Known Limitations `[OBSERVED]`, 13. Recommended Next Chunk `[FUTURE]`, 2. Architecture `[IMPLEMENTED]`, 3. Files Changed `[IMPLEMENTED & TESTED]`, 5. Hardware-Selection Logic `[IMPLEMENTED & TESTED]` (+10 more)

### Community 129 - "items"
Cohesion: 0.17
Nodes (13): items, type, items, type, items, additionalProperties, required, type (+5 more)

### Community 142 - "test_api_rbac.py"
Cohesion: 0.10
Nodes (11): anyio, fastapi, fastapi_testclient, fixture, NTRO PS26155 Auditor — Role-Based Access Control (RBAC) API Integration Tests…, reviewer_non_approver_token(), reviewer_token(), setup_db() (+3 more)

### Community 143 - "properties"
Cohesion: 0.11
Nodes (18): type, type, additionalProperties, properties, type, type, type, type (+10 more)

### Community 145 - "properties"
Cohesion: 0.12
Nodes (17): type, format, type, type, type, file_name, parsed_at, parser (+9 more)

### Community 146 - "FrameworkRegistry"
Cohesion: 0.07
Nodes (24): 2.1 Pydantic Request & Response Models, 2.2 `GET /api/compliance/frameworks`, 2.3 `POST /api/compliance/evaluate`, 2. API Endpoints Architecture & Implementation, Step 2: Identify Simplification Opportunities, 12. Compliance Architecture Reality Audit, Verification of Invariants:, Framework (+16 more)

### Community 147 - "remediation"
Cohesion: 0.29
Nodes (7): description, remediation, risk_warning, vendor_commands, properties, required, type

### Community 149 - "checked_at"
Cohesion: 0.67
Nodes (3): format, type, checked_at

### Community 150 - "NTRO PS26155 — AI Model Manager: Configuration Precedence & Consistency Audit"
Cohesion: 0.11
Nodes (17): 10. Audit Sign-off, 1. Can a reviewer select QUALITY while actual inference uses FAST via OLLAMA_MODEL?, 1. Executive Summary, 2. Can a reviewer select FAST while actual inference uses QUALITY via OLLAMA_MODEL?, 4. API Status Consistency Matrix (Check 2), 4. Can OVERRIDE bypass allowlisting?, 5. Can any of these paths bypass deterministic fallback?, 5. Environment Variable Interaction Scenarios (Check 3) (+9 more)

### Community 151 - "NTRO PS26155 — AI Model Manager: Chunk 2A.1 Implementation Report"
Cohesion: 0.17
Nodes (11): 2. Configuration Lifecycle & Exact Precedence After Fix, 3. OVERRIDE Mode Behavior Verification, 5. Security & AST Audit Results, 6. Scope Boundaries & Constraints Verification, 7. Known Ceilings & Remaining Limitations, Centralize Runtime Configuration Precedence & Synchronization Fix, Exact Precedence Order, Lifecycle Architecture (+3 more)

### Community 152 - "test_api_compliance.py"
Cohesion: 0.06
Nodes (30): 1. Executive Summary, 4.1 Dedicated Test Suite: `test_api_compliance.py` (22 tests), 4.2 Full Regression Verification Matrix, 4. Test Suite Summary, 5. Next Steps & Boundary Enforcement, Key Metrics:, Multi-Framework Compliance REST API Layer, NTRO PS26155 — Phase 3A.5 REST API Integration Report (+22 more)

### Community 153 - "NTRO PS26155 — Multi-Framework Compliance Architecture (Phase 3A.1 – 3A.4)"
Cohesion: 0.09
Nodes (21): 10.1 Architectural Guarantees & Role, 10.2 Pass-Rate Mathematical Semantics, 10.4 Deterministic Evidence Consolidation, 10. Multi-Framework Scoring, Aggregation & Evidence Consolidation (Phase 3A.4), 11.2 Endpoint Specifications, 11. Phase 3A.5 — Multi-Framework REST API Layer, 12. What is Deliberately Deferred, 1. `GET /api/compliance/frameworks` (+13 more)

### Community 154 - "NTRO PS26155 — AI Model Manager: Chunk 2A.1 Implementation Report"
Cohesion: 0.17
Nodes (11): 2. Configuration Lifecycle & Exact Precedence After Fix, 3. OVERRIDE Mode Behavior Verification, 5. Security & AST Audit Results, 6. Scope Boundaries & Constraints Verification, 7. Known Ceilings & Remaining Limitations, Centralize Runtime Configuration Precedence & Synchronization Fix, Exact Precedence Order, Lifecycle Architecture (+3 more)

### Community 156 - "get_user_by_username"
Cohesion: 0.10
Nodes (24): create_user(), get_user_by_id(), get_user_by_username(), list_users(), Any, Creates a user record. Passwords are safe-hashed using PBKDF2-HMAC-SHA256., Retrieves a user by username using case-insensitive match (COLLATE NOCASE)., Retrieves a user by user_id UUID. (+16 more)

### Community 160 - "NTRO PS26155 — Codebase Reality Audit"
Cohesion: 0.05
Nodes (39): 15. REST API Architecture, 16.1 Graph Metrics & Statistics, 16. Graphify Baseline, 1. Audit Objective, 20. Legacy / Experimental Components, 21. Dependency Findings, 22. Documentation Drift, 23. Test Architecture (+31 more)

### Community 163 - "Control"
Cohesion: 0.07
Nodes (28): CisCiscoIosXeEvaluator, Any, Evaluates normalized CSM data against the CIS Cisco IOS-XE Benchmark v2.2.1.…, Evaluates normalized CSM against CIS Cisco IOS-XE controls. Args: csm:…, CIS §2.1.1.2: Set version 2 for 'ip ssh version'., CIS §1.1.1: Enable 'aaa new-model'., CIS §2.3.1.1: Set 'ntp authenticate'., CIS §2.2.4: Set IP address for 'logging host'. (+20 more)

### Community 164 - "ComplianceStatus"
Cohesion: 0.09
Nodes (15): 16.2 God Nodes (Core Architectural Hubs), CODEBASE REALITY — SUMMARY, ComplianceStatus, Enum, str, Authoritative, deterministic compliance evaluation verdict. Strictly restricted…, Converts string representations safely to ComplianceStatus., 3.1 Framework Metadata Contract (`Framework`) (+7 more)

### Community 166 - "FrameworkEvaluator"
Cohesion: 0.10
Nodes (12): 3. Security & Clean Architecture Invariants, ABC, CiscoCsmFrameworkAdapter, FrameworkEvaluator, Any, Abstract interface defining the contract for deterministic compliance…, Returns the unique identifier of the framework this evaluator implements., Evaluates normalized CSM data against applicable framework controls. Args: csm:… (+4 more)

### Community 170 - "hash_password"
Cohesion: 0.31
Nodes (10): 3. Evidence Used to Verify Each Mismatch, Verifies a plaintext password against a stored PBKDF2-HMAC-SHA256 hash and…, verify_password(), 11.1 Password Hashing & Verification, 30. Items Explicitly NOT Recommended for Refactoring, hash_password(), Derives PBKDF2-HMAC-SHA256 key with 600,000 iterations using Python standard…, test_incorrect_password_rejection() (+2 more)

### Community 172 - "8. Backend Module Map"
Cohesion: 0.11
Nodes (32): 2. Documentation Mismatches Found & Resolved, suggest_mapping(), Phase 2 Plug-in Architecture:, audit_pipeline(), eval_condition(), evaluate_rules(), main(), parse_cisco() (+24 more)

## Knowledge Gaps
- **927 isolated node(s):** `idea-refine.sh script`, `idea-refine.sh script`, `$schema`, `$id`, `title` (+922 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 1436 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **16 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `8. Backend Module Map` connect `8. Backend Module Map` to `Any`, `NTRO PS26155 — Codebase Reality Audit`, `create_access_token`, `Control`, `ComplianceStatus`, `EvaluationResult`, `ai_model_manager.py`, `hash_password`, `check_session_ownership`, `compliance_aggregator.py`, `get_jwt_secret`, `test_multi_framework_aggregation.py`, `FrameworkRegistry`, `database.py`, `get_connection`, `get_user_by_username`, `MultiFrameworkAggregator`, `AIModelManager`?**
  _High betweenness centrality (0.089) - this node is a cross-community bridge._
- **Why does `AIModelManager` connect `AIModelManager` to `NTRO PS26155 — AI Model Manager: Chunk 1 Backend Core Implementation Report`, `.get_status`, `Any`, `test_ai_model_manager.py`, `12. Final Gate Verification (Chunk 2C.1)`, `ai_model_manager.py`, `8. Backend Module Map`, `TestOllamaInvocationAndFallbacks`, `Focused Precedence Tests (`test_api_model_manager.py` — 31/31 PASSED)`, `NTRO PS26155 — AI Model Manager: Configuration Precedence & Consistency Audit`, `ModelMode`?**
  _High betweenness centrality (0.066) - this node is a cross-community bridge._
- **Why does `NTRO PS26155 — Codebase Reality Audit` connect `NTRO PS26155 — Codebase Reality Audit` to `Any`, `Control`, `ComplianceStatus`, `UploadScreen.tsx`, `check_session_ownership`, `hash_password`, `verify_api_safety_no_execution`, `8. Backend Module Map`, `FrameworkRegistry`, `database.py`, `28. Refactor Candidate Matrix`?**
  _High betweenness centrality (0.045) - this node is a cross-community bridge._
- **Are the 16 inferred relationships involving `EvaluationResult` (e.g. with `1. File Inventory & Pipeline Mapping` and `CisCiscoIosXeEvaluator`) actually correct?**
  _`EvaluationResult` has 16 INFERRED edges - model-reasoned connections that need verification._
- **Are the 14 inferred relationships involving `Evidence` (e.g. with `1. File Inventory & Pipeline Mapping` and `CisCiscoIosXeEvaluator`) actually correct?**
  _`Evidence` has 14 INFERRED edges - model-reasoned connections that need verification._
- **Are the 10 inferred relationships involving `Control` (e.g. with `1. File Inventory & Pipeline Mapping` and `CisCiscoIosXeEvaluator`) actually correct?**
  _`Control` has 10 INFERRED edges - model-reasoned connections that need verification._
- **Are the 18 inferred relationships involving `FrameworkRegistry` (e.g. with `2.3 `POST /api/compliance/evaluate`` and `2.1 Side-by-Side Architectural Trace`) actually correct?**
  _`FrameworkRegistry` has 18 INFERRED edges - model-reasoned connections that need verification._