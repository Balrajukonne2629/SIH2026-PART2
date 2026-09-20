# Graph Report - PART-2  (2026-09-17)

## Corpus Check
- 195 files · ~3,320,179 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 38 file(s) not represented in the graph (top: .xml 8, .zip 8, .xsl 6)

## Summary
- 2914 nodes · 3436 edges · 146 communities (132 shown, 14 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 19 edges (avg confidence: 0.92)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- dashboard/package.json
- arena-frontend/src/App.tsx
- test_auth.py
- dashboard/src/api.ts
- properties
- database.py
- test_api_ownership.py
- main.py
- Security and Hardening
- Security and Hardening
- Security and Hardening
- AI-Driven Multi-Vendor Network Security Compliance Auditor
- Code Review and Quality
- Test-Driven Development
- Code Review and Quality
- Test-Driven Development
- Code Review and Quality
- Test-Driven Development
- Context Engineering
- ai_suggester.py
- Context Engineering
- Context Engineering
- Git Workflow and Versioning
- Git Workflow and Versioning
- Git Workflow and Versioning
- Shipping and Launch
- Shipping and Launch
- Shipping and Launch
- test_ollama_integration.py
- API and Interface Design
- Browser Testing with DevTools
- Performance Optimization
- arena-frontend/package.json
- API and Interface Design
- Browser Testing with DevTools
- Performance Optimization
- API and Interface Design
- Browser Testing with DevTools
- Performance Optimization
- CI/CD and Automation
- Constraint-Driven Development
- Deprecation and Migration
- Frontend UI Engineering
- CI/CD and Automation
- Constraint-Driven Development
- Deprecation and Migration
- Frontend UI Engineering
- CI/CD and Automation
- Constraint-Driven Development
- Deprecation and Migration
- Frontend UI Engineering
- Incremental Implementation
- Incremental Implementation
- Incremental Implementation
- properties
- Code Simplification
- Debugging and Error Recovery
- Documentation and ADRs
- get_connection
- Code Simplification
- Debugging and Error Recovery
- Documentation and ADRs
- Code Simplification
- Debugging and Error Recovery
- Documentation and ADRs
- main
- properties
- properties
- Planning and Task Breakdown
- Planning and Task Breakdown
- Planning and Task Breakdown
- properties
- properties
- test_api_reviewer_identity.py
- ReOrder: Keep Your Regulars Ordering Direct
- Interview Me
- compilerOptions
- ReOrder: Keep Your Regulars Ordering Direct
- Interview Me
- compilerOptions
- ReOrder: Keep Your Regulars Ordering Direct
- Interview Me
- properties
- test_api_auth.py
- type
- properties
- Doubt-Driven Development
- Process
- Doubt-Driven Development
- Process
- Doubt-Driven Development
- Process
- report_generator.py
- Idea Refine
- Using Agent Skills
- Idea Refine
- Using Agent Skills
- Idea Refine
- Using Agent Skills
- Spec-Driven Development
- Spec-Driven Development
- Spec-Driven Development
- 2. Detailed Per-Rule Evidence and Rationale
- properties
- properties
- enabled
- properties
- Source-Driven Development
- Source-Driven Development
- Source-Driven Development
- properties
- Refinement & Evaluation Criteria
- Refinement & Evaluation Criteria
- Refinement & Evaluation Criteria
- properties
- Ideation Frameworks Reference
- Ideation Frameworks Reference
- properties
- Ideation Frameworks Reference
- compliance_check_result_schema.json
- items
- compilerOptions
- Addendum to v4.0 — Refinements for MVP Build
- Network Compliance Auditor Frontend
- Collection Status
- compliance_percentage
- arena-frontend/vite.config.ts
- risk_score
- unknown
- data/skills/idea-refine/scripts/idea-refine.sh
- arena-frontend/tsconfig.json
- 00_Project_Documentation/README.md
- RESOURCE_INVENTORY.md
- agent/skills/idea-refine/scripts/idea-refine.sh
- rules/graphify.md
- workflows/graphify.md
- vite-env.d.ts
- .claude/skills/idea-refine/scripts/idea-refine.sh
- index.html (Dashboard Entrypoint)
- src_index
- test_api_rbac.py
- properties
- device
- properties

## God Nodes (most connected - your core abstractions)
1. `get_connection()` - 34 edges
2. `create_access_token()` - 28 edges
3. `AI-Driven Multi-Vendor Network Security Compliance Auditor` - 25 edges
4. `decode_and_verify_jwt()` - 23 edges
5. `seed_pending_suggestion()` - 19 edges
6. `Code Review and Quality` - 19 edges
7. `Code Review and Quality` - 19 edges
8. `Code Review and Quality` - 19 edges
9. `create_session_for_uploader()` - 18 edges
10. `main()` - 18 edges

## Surprising Connections (you probably didn't know these)
- `1. File Inventory & Pipeline Mapping` --references--> `json()`  [INFERRED]
  ARCHITECTURE_NOTES.md → arena-frontend/src/api.ts
- `Phase 2 Plug-in Architecture:` --references--> `resolve_csm_path()`  [INFERRED]
  ARCHITECTURE_NOTES.md → cisco_auditor.py
- `Phase 2 Plug-in Architecture:` --references--> `eval_condition()`  [INFERRED]
  ARCHITECTURE_NOTES.md → cisco_auditor.py
- `test_unsupported_jwt_algorithm()` --calls--> `base64url_encode()`  [EXTRACTED]
  test_api_auth.py → auth.py
- `test_expired_jwt()` --calls--> `create_access_token()`  [EXTRACTED]
  test_api_auth.py → auth.py

## Import Cycles
- None detected.

## Communities (146 total, 14 thin omitted)

### Community 0 - "dashboard/package.json"
Cohesion: 0.06
Nodes (33): dependencies, lucide-react, react, react-dom, devDependencies, autoprefixer, postcss, tailwindcss (+25 more)

### Community 1 - "arena-frontend/src/App.tsx"
Cohesion: 0.05
Nodes (53): 1. File Inventory & Pipeline Mapping, 2. Known Implementation Limitations, 3. Phase 2 Vendor Extension Architecture, Extension Contract & Current State: How New Vendors Plug In, Limitation 1: Rule `CISCO-INT-001` Description String Matching Fragility, Limitation 2: Rule `CISCO-ROUTING-001` BGP-Only Protocol Scope, Limitation 3: Template-Engineered vs. Open-Ended Generative AI Explanations, Literal Current State in `vendor_rule_mapping.json`: (+45 more)

### Community 2 - "test_auth.py"
Cohesion: 0.09
Nodes (48): AuthError, base64url_decode(), base64url_encode(), create_access_token(), decode_and_verify_jwt(), get_jwt_secret(), InvalidTokenError, Any (+40 more)

### Community 3 - "dashboard/src/api.ts"
Cohesion: 0.07
Nodes (54): API_BASE, ApiError, approveSuggestion(), clearAccessToken(), finalizeAudit(), getAccessToken(), getAuditResults(), getCurrentUser() (+46 more)

### Community 4 - "properties"
Cohesion: 0.05
Nodes (48): type, type, format, type, type, type, items, type (+40 more)

### Community 5 - "database.py"
Cohesion: 0.08
Nodes (37): Connection, create_user(), get_user_by_id(), get_user_by_username(), initialize_database(), list_users(), migrate_ledger(), migrate_pending_suggestions() (+29 more)

### Community 6 - "test_api_ownership.py"
Cohesion: 0.06
Nodes (48): create_session_for_uploader(), fixture, NTRO PS26155 Auditor — Resource Ownership & Session Isolation Tests (Chunk 5)…, Scenario 1: Audit upload assigns owner_user_id strictly from JWT sub claim., Scenario 2: Client cannot override owner_user_id via JSON body payload., Scenario 3: Client cannot override owner_user_id via query parameters., Scenario 4: Client cannot override owner_user_id via custom headers., Scenario 5: Uploader can access their own session results. (+40 more)

### Community 8 - "main.py"
Cohesion: 0.05
Nodes (66): ast, BaseModel, fastapi_middleware_cors, fastapi_responses, fastapi_testclient, get, ai_approve(), ai_suggest() (+58 more)

### Community 9 - "Security and Hardening"
Cohesion: 0.06
Nodes (31): Always Do (No Exceptions), Ask First (Requires Human Approval), Broken Access Control, Broken Authentication, Common Rationalizations, Cross-Site Scripting (XSS), Data Privacy & Compliance, Destructive Operations on Derived Paths (+23 more)

### Community 10 - "Security and Hardening"
Cohesion: 0.06
Nodes (31): Always Do (No Exceptions), Ask First (Requires Human Approval), Broken Access Control, Broken Authentication, Common Rationalizations, Cross-Site Scripting (XSS), Data Privacy & Compliance, Destructive Operations on Derived Paths (+23 more)

### Community 11 - "Security and Hardening"
Cohesion: 0.06
Nodes (31): Always Do (No Exceptions), Ask First (Requires Human Approval), Broken Access Control, Broken Authentication, Common Rationalizations, Cross-Site Scripting (XSS), Data Privacy & Compliance, Destructive Operations on Derived Paths (+23 more)

### Community 12 - "AI-Driven Multi-Vendor Network Security Compliance Auditor"
Cohesion: 0.06
Nodes (31): 10. Data Model (Core Objects), 11. Technology Stack, 12. Risks & Mitigations, 13. Roadmap (Post-Hackathon), 14. Build Order — Single-File, Single-Path First, 15. MVP Acceptance Criteria, 16. What We Are Not Claiming, 17. Shared Internal-Rule / Multi-Framework Model (+23 more)

### Community 13 - "Code Review and Quality"
Cohesion: 0.07
Nodes (29): 1. Correctness, 2. Readability & Simplicity, 3. Architecture, 4. Security, 5. Performance, Change Descriptions, Change Sizing, Code Review and Quality (+21 more)

### Community 14 - "Test-Driven Development"
Cohesion: 0.07
Nodes (29): Browser Testing with DevTools, Common Rationalizations, DAMP Over DRY in Tests, Decision Guide, Discover the Stack First, Name Tests Descriptively, One Assertion Per Concept, Overview (+21 more)

### Community 15 - "Code Review and Quality"
Cohesion: 0.07
Nodes (29): 1. Correctness, 2. Readability & Simplicity, 3. Architecture, 4. Security, 5. Performance, Change Descriptions, Change Sizing, Code Review and Quality (+21 more)

### Community 16 - "Test-Driven Development"
Cohesion: 0.07
Nodes (29): Browser Testing with DevTools, Common Rationalizations, DAMP Over DRY in Tests, Decision Guide, Discover the Stack First, Name Tests Descriptively, One Assertion Per Concept, Overview (+21 more)

### Community 17 - "Code Review and Quality"
Cohesion: 0.07
Nodes (29): 1. Correctness, 2. Readability & Simplicity, 3. Architecture, 4. Security, 5. Performance, Change Descriptions, Change Sizing, Code Review and Quality (+21 more)

### Community 18 - "Test-Driven Development"
Cohesion: 0.07
Nodes (29): Browser Testing with DevTools, Common Rationalizations, DAMP Over DRY in Tests, Decision Guide, Discover the Stack First, Name Tests Descriptively, One Assertion Per Concept, Overview (+21 more)

### Community 19 - "Context Engineering"
Cohesion: 0.07
Nodes (28): Anti-Patterns, Common Rationalizations, Compress before dropping, Confusion Management, Context Budget Management, Context Engineering, Context Packing Strategies, Level 1: Rules Files (+20 more)

### Community 20 - "ai_suggester.py"
Cohesion: 0.10
Nodes (28): _generate_rationale_ai(), _get_embedding(), get_model(), Local AI Unmapped Line Suggester & Reviewer Approval Workflow (PRD Addendum…, suggest_mapping(), jinja2, json, pathlib (+20 more)

### Community 21 - "Context Engineering"
Cohesion: 0.07
Nodes (28): Anti-Patterns, Common Rationalizations, Compress before dropping, Confusion Management, Context Budget Management, Context Engineering, Context Packing Strategies, Level 1: Rules Files (+20 more)

### Community 22 - "Context Engineering"
Cohesion: 0.07
Nodes (28): Anti-Patterns, Common Rationalizations, Compress before dropping, Confusion Management, Context Budget Management, Context Engineering, Context Packing Strategies, Level 1: Rules Files (+20 more)

### Community 23 - "Git Workflow and Versioning"
Cohesion: 0.07
Nodes (26): 1. Commit Early, Commit Often, 2. Atomic Commits, 3. Descriptive Messages, 4. Keep Concerns Separate, 5. Size Your Changes, Branch Naming, Branching Strategy, Change Summaries (+18 more)

### Community 24 - "Git Workflow and Versioning"
Cohesion: 0.07
Nodes (26): 1. Commit Early, Commit Often, 2. Atomic Commits, 3. Descriptive Messages, 4. Keep Concerns Separate, 5. Size Your Changes, Branch Naming, Branching Strategy, Change Summaries (+18 more)

### Community 25 - "Git Workflow and Versioning"
Cohesion: 0.07
Nodes (26): 1. Commit Early, Commit Often, 2. Atomic Commits, 3. Descriptive Messages, 4. Keep Concerns Separate, 5. Size Your Changes, Branch Naming, Branching Strategy, Change Summaries (+18 more)

### Community 26 - "Shipping and Launch"
Cohesion: 0.08
Nodes (25): Accessibility, Code Quality, Common Rationalizations, Documentation, Error Budget Release Gate, Error Reporting, Feature Flag Strategy, Infrastructure (+17 more)

### Community 27 - "Shipping and Launch"
Cohesion: 0.08
Nodes (25): Accessibility, Code Quality, Common Rationalizations, Documentation, Error Budget Release Gate, Error Reporting, Feature Flag Strategy, Infrastructure (+17 more)

### Community 28 - "Shipping and Launch"
Cohesion: 0.08
Nodes (25): Accessibility, Code Quality, Common Rationalizations, Documentation, Error Budget Release Gate, Error Reporting, Feature Flag Strategy, Infrastructure (+17 more)

### Community 29 - "test_ollama_integration.py"
Cohesion: 0.12
Nodes (23): shutil, socket, subprocess, check_ollama_alive(), ensure_model_available(), format_side_by_side(), generate_completion(), main() (+15 more)

### Community 30 - "API and Interface Design"
Cohesion: 0.08
Nodes (24): 1. Contract First, 2. Consistent Error Semantics, 3. Validate at Boundaries, 4. Prefer Addition Over Modification, 5. Predictable Naming, 6. Honouring an Idempotency Key, API and Interface Design, Common Rationalizations (+16 more)

### Community 31 - "Browser Testing with DevTools"
Cohesion: 0.08
Nodes (24): Accessibility Verification with DevTools, Available Tools, Browser Testing with DevTools, Clean Console Standard, Common Rationalizations, Console Analysis Patterns, Content Boundary Markers, For Network Issues (+16 more)

### Community 32 - "Performance Optimization"
Cohesion: 0.08
Nodes (24): Common Rationalizations, Connection Pool Exhaustion, Core Web Vitals Targets, Large Bundle Size, Log every attempt, including the reverted ones, Missing Caching (Backend), Missing Image Optimization (Frontend), N+1 Queries (Backend) (+16 more)

### Community 33 - "arena-frontend/package.json"
Cohesion: 0.08
Nodes (24): dependencies, react, react-dom, devDependencies, @types/react, @types/react-dom, typescript, vite (+16 more)

### Community 34 - "API and Interface Design"
Cohesion: 0.08
Nodes (24): 1. Contract First, 2. Consistent Error Semantics, 3. Validate at Boundaries, 4. Prefer Addition Over Modification, 5. Predictable Naming, 6. Honouring an Idempotency Key, API and Interface Design, Common Rationalizations (+16 more)

### Community 35 - "Browser Testing with DevTools"
Cohesion: 0.08
Nodes (24): Accessibility Verification with DevTools, Available Tools, Browser Testing with DevTools, Clean Console Standard, Common Rationalizations, Console Analysis Patterns, Content Boundary Markers, For Network Issues (+16 more)

### Community 36 - "Performance Optimization"
Cohesion: 0.08
Nodes (24): Common Rationalizations, Connection Pool Exhaustion, Core Web Vitals Targets, Large Bundle Size, Log every attempt, including the reverted ones, Missing Caching (Backend), Missing Image Optimization (Frontend), N+1 Queries (Backend) (+16 more)

### Community 37 - "API and Interface Design"
Cohesion: 0.08
Nodes (24): 1. Contract First, 2. Consistent Error Semantics, 3. Validate at Boundaries, 4. Prefer Addition Over Modification, 5. Predictable Naming, 6. Honouring an Idempotency Key, API and Interface Design, Common Rationalizations (+16 more)

### Community 38 - "Browser Testing with DevTools"
Cohesion: 0.08
Nodes (24): Accessibility Verification with DevTools, Available Tools, Browser Testing with DevTools, Clean Console Standard, Common Rationalizations, Console Analysis Patterns, Content Boundary Markers, For Network Issues (+16 more)

### Community 39 - "Performance Optimization"
Cohesion: 0.08
Nodes (24): Common Rationalizations, Connection Pool Exhaustion, Core Web Vitals Targets, Large Bundle Size, Log every attempt, including the reverted ones, Missing Caching (Backend), Missing Image Optimization (Frontend), N+1 Queries (Backend) (+16 more)

### Community 40 - "CI/CD and Automation"
Cohesion: 0.08
Nodes (23): Automation Beyond CI, Basic CI Pipeline, Build Cop Role, CI/CD and Automation, CI Optimization, Common Rationalizations, Dependabot / Renovate, Deployment Strategies (+15 more)

### Community 41 - "Constraint-Driven Development"
Cohesion: 0.08
Nodes (22): Adapting it, Contract, Floor guard: reference implementation, Reference (Node, ~stack-agnostic patterns), Common Rationalizations, Constraint-Driven Development, Escalation Path, Loading Constraints (+14 more)

### Community 42 - "Deprecation and Migration"
Cohesion: 0.08
Nodes (23): Adapter Pattern, Code Is a Liability, Common Rationalizations, Compulsory vs Advisory Deprecation, Core Principles, Database Schema Migrations (Expand/Contract), Deprecation and Migration, Deprecation Planning Starts at Design Time (+15 more)

### Community 43 - "Frontend UI Engineering"
Cohesion: 0.08
Nodes (23): Accessibility (WCAG 2.1 AA), ARIA Labels, Avoid the AI Aesthetic, Color, Common Rationalizations, Component Architecture, Component Patterns, Design System Adherence (+15 more)

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

### Community 48 - "CI/CD and Automation"
Cohesion: 0.08
Nodes (23): Automation Beyond CI, Basic CI Pipeline, Build Cop Role, CI/CD and Automation, CI Optimization, Common Rationalizations, Dependabot / Renovate, Deployment Strategies (+15 more)

### Community 49 - "Constraint-Driven Development"
Cohesion: 0.08
Nodes (22): Adapting it, Contract, Floor guard: reference implementation, Reference (Node, ~stack-agnostic patterns), Common Rationalizations, Constraint-Driven Development, Escalation Path, Loading Constraints (+14 more)

### Community 50 - "Deprecation and Migration"
Cohesion: 0.08
Nodes (23): Adapter Pattern, Code Is a Liability, Common Rationalizations, Compulsory vs Advisory Deprecation, Core Principles, Database Schema Migrations (Expand/Contract), Deprecation and Migration, Deprecation Planning Starts at Design Time (+15 more)

### Community 51 - "Frontend UI Engineering"
Cohesion: 0.08
Nodes (23): Accessibility (WCAG 2.1 AA), ARIA Labels, Avoid the AI Aesthetic, Color, Common Rationalizations, Component Architecture, Component Patterns, Design System Adherence (+15 more)

### Community 52 - "Incremental Implementation"
Cohesion: 0.09
Nodes (22): Common Rationalizations, Contract-First Slicing, Implementation Rules, Increment Checklist, Incremental Implementation, Overview, Red Flags, Risk-First Slicing (+14 more)

### Community 53 - "Incremental Implementation"
Cohesion: 0.09
Nodes (22): Common Rationalizations, Contract-First Slicing, Implementation Rules, Increment Checklist, Incremental Implementation, Overview, Red Flags, Risk-First Slicing (+14 more)

### Community 54 - "Incremental Implementation"
Cohesion: 0.09
Nodes (22): Common Rationalizations, Contract-First Slicing, Implementation Rules, Increment Checklist, Incremental Implementation, Overview, Red Flags, Risk-First Slicing (+14 more)

### Community 55 - "properties"
Cohesion: 0.09
Nodes (22): type, maximum, minimum, type, type, type, properties, type (+14 more)

### Community 56 - "Code Simplification"
Cohesion: 0.09
Nodes (21): 1. Preserve Behavior Exactly, 2. Follow Project Conventions, 3. Prefer Clarity Over Cleverness, 4. Maintain Balance, 5. Scope to What Changed, Code Simplification, Common Rationalizations, Language-Specific Guidance (+13 more)

### Community 57 - "Debugging and Error Recovery"
Cohesion: 0.09
Nodes (21): Build Failure Triage, Common Rationalizations, Debugging and Error Recovery, Error-Specific Patterns, Instrumentation Guidelines, Overview, Red Flags, Runtime Error Triage (+13 more)

### Community 58 - "Documentation and ADRs"
Cohesion: 0.09
Nodes (21): ADR Lifecycle, ADR Template, API Documentation, Architecture Decision Records (ADRs), Changelog Maintenance, Common Rationalizations, Document Known Gotchas, Documentation and ADRs (+13 more)

### Community 59 - "get_connection"
Cohesion: 0.09
Nodes (34): append_audit_entry(), compute_entry_hash(), create_audit_entry(), get_last_entry(), Path, Append-Only Hash-Chained Audit Logger (PRD Addendum Section 4 Step 5). Records…, Re-walks entire log table, recalculates all hashes, and verifies prevEntryHash…, Computes SHA256 over canonical JSON of all entry fields excluding entryHash. (+26 more)

### Community 60 - "Code Simplification"
Cohesion: 0.09
Nodes (21): 1. Preserve Behavior Exactly, 2. Follow Project Conventions, 3. Prefer Clarity Over Cleverness, 4. Maintain Balance, 5. Scope to What Changed, Code Simplification, Common Rationalizations, Language-Specific Guidance (+13 more)

### Community 61 - "Debugging and Error Recovery"
Cohesion: 0.09
Nodes (21): Build Failure Triage, Common Rationalizations, Debugging and Error Recovery, Error-Specific Patterns, Instrumentation Guidelines, Overview, Red Flags, Runtime Error Triage (+13 more)

### Community 62 - "Documentation and ADRs"
Cohesion: 0.09
Nodes (21): ADR Lifecycle, ADR Template, API Documentation, Architecture Decision Records (ADRs), Changelog Maintenance, Common Rationalizations, Document Known Gotchas, Documentation and ADRs (+13 more)

### Community 63 - "Code Simplification"
Cohesion: 0.09
Nodes (21): 1. Preserve Behavior Exactly, 2. Follow Project Conventions, 3. Prefer Clarity Over Cleverness, 4. Maintain Balance, 5. Scope to What Changed, Code Simplification, Common Rationalizations, Language-Specific Guidance (+13 more)

### Community 64 - "Debugging and Error Recovery"
Cohesion: 0.09
Nodes (21): Build Failure Triage, Common Rationalizations, Debugging and Error Recovery, Error-Specific Patterns, Instrumentation Guidelines, Overview, Red Flags, Runtime Error Triage (+13 more)

### Community 65 - "Documentation and ADRs"
Cohesion: 0.09
Nodes (21): ADR Lifecycle, ADR Template, API Documentation, Architecture Decision Records (ADRs), Changelog Maintenance, Common Rationalizations, Document Known Gotchas, Documentation and ADRs (+13 more)

### Community 66 - "main"
Cohesion: 0.12
Nodes (23): approve_suggestion(), Path, store_suggestion(), Phase 2 Plug-in Architecture:, audit_pipeline(), eval_condition(), evaluate_rules(), main() (+15 more)

### Community 67 - "properties"
Cohesion: 0.14
Nodes (14): properties, type, type, type, type, hostname, management_ip, os_version (+6 more)

### Community 68 - "properties"
Cohesion: 0.11
Nodes (19): additionalProperties, properties, type, type, type, type, minimum, type (+11 more)

### Community 69 - "Planning and Task Breakdown"
Cohesion: 0.11
Nodes (18): Common Rationalizations, Output Files, Overview, Parallelization Opportunities, Plan Document Template, Planning and Task Breakdown, Red Flags, See Also (+10 more)

### Community 70 - "Planning and Task Breakdown"
Cohesion: 0.11
Nodes (18): Common Rationalizations, Output Files, Overview, Parallelization Opportunities, Plan Document Template, Planning and Task Breakdown, Red Flags, See Also (+10 more)

### Community 71 - "Planning and Task Breakdown"
Cohesion: 0.11
Nodes (18): Common Rationalizations, Output Files, Overview, Parallelization Opportunities, Plan Document Template, Planning and Task Breakdown, Red Flags, See Also (+10 more)

### Community 72 - "properties"
Cohesion: 0.11
Nodes (18): additionalProperties, properties, type, type, type, type, minimum, type (+10 more)

### Community 73 - "properties"
Cohesion: 0.11
Nodes (18): type, type, type, type, bgp_enabled, eigrp_enabled, isis_enabled, ospf_enabled (+10 more)

### Community 74 - "test_api_reviewer_identity.py"
Cohesion: 0.06
Nodes (49): authorized_approver_token(), non_approver_reviewer_token(), fixture, NTRO PS26155 Auditor — Reviewer Identity & Approval Accountability Binding…, Scenario 1: Authorized reviewer can approve compliance rules., Scenario 2: Reviewer identity recorded in DB equals authenticated JWT 'sub'., Scenario 3: Client-supplied reviewer_name is ignored; JWT sub is authoritative., Scenario 4: Client-supplied reviewer_id in payload is ignored. (+41 more)

### Community 75 - "ReOrder: Keep Your Regulars Ordering Direct"
Cohesion: 0.11
Nodes (17): Example 1: Vague Early-Stage Concept (Full 3-Phase Session), Example 2: Feature Idea Within an Existing Product (Codebase-Aware), Example 3: Process/Workflow Idea (Non-Product), Ideation Session Examples, Key Assumptions to Validate, MVP Scope, Not Doing (and Why), Open Questions (+9 more)

### Community 76 - "Interview Me"
Cohesion: 0.11
Nodes (17): Common Rationalizations, Example, Interaction with Other Skills, Interview Me, Loading Constraints, Output, Overview, Red Flags (+9 more)

### Community 77 - "compilerOptions"
Cohesion: 0.11
Nodes (17): compilerOptions, allowJs, allowSyntheticDefaultImports, esModuleInterop, forceConsistentCasingInFileNames, isolatedModules, jsx, lib (+9 more)

### Community 78 - "ReOrder: Keep Your Regulars Ordering Direct"
Cohesion: 0.11
Nodes (17): Example 1: Vague Early-Stage Concept (Full 3-Phase Session), Example 2: Feature Idea Within an Existing Product (Codebase-Aware), Example 3: Process/Workflow Idea (Non-Product), Ideation Session Examples, Key Assumptions to Validate, MVP Scope, Not Doing (and Why), Open Questions (+9 more)

### Community 79 - "Interview Me"
Cohesion: 0.11
Nodes (17): Common Rationalizations, Example, Interaction with Other Skills, Interview Me, Loading Constraints, Output, Overview, Red Flags (+9 more)

### Community 80 - "compilerOptions"
Cohesion: 0.11
Nodes (17): compilerOptions, allowImportingTsExtensions, isolatedModules, jsx, lib, module, moduleResolution, noEmit (+9 more)

### Community 81 - "ReOrder: Keep Your Regulars Ordering Direct"
Cohesion: 0.11
Nodes (17): Example 1: Vague Early-Stage Concept (Full 3-Phase Session), Example 2: Feature Idea Within an Existing Product (Codebase-Aware), Example 3: Process/Workflow Idea (Non-Product), Ideation Session Examples, Key Assumptions to Validate, MVP Scope, Not Doing (and Why), Open Questions (+9 more)

### Community 82 - "Interview Me"
Cohesion: 0.11
Nodes (17): Common Rationalizations, Example, Interaction with Other Skills, Interview Me, Loading Constraints, Output, Overview, Red Flags (+9 more)

### Community 83 - "properties"
Cohesion: 0.12
Nodes (17): type, type, additionalProperties, properties, type, buffered_logging_enabled, console_logging_enabled, logging (+9 more)

### Community 84 - "test_api_auth.py"
Cohesion: 0.08
Nodes (4): NTRO PS26155 Auditor — API Authentication Integration Tests Tests for Chunk 3:…, test_expired_jwt(), test_successful_response_contains_jwt(), test_unsupported_jwt_algorithm()

### Community 85 - "type"
Cohesion: 0.12
Nodes (16): items, type, items, type, type, items, type, allowed_vlans (+8 more)

### Community 86 - "properties"
Cohesion: 0.12
Nodes (16): type, type, communities_present, community_strings_encrypted, read_only, snmp, snmpv3_users_present, trap_enabled (+8 more)

### Community 87 - "Doubt-Driven Development"
Cohesion: 0.12
Nodes (15): Common Rationalizations, Cross-model escalation, Doubt-Driven Development, Interaction with Other Skills, Loading Constraints, Overview, Red Flags, Step 1: CLAIM — Surface what stands (+7 more)

### Community 88 - "Process"
Cohesion: 0.12
Nodes (15): 1. Define "working" before instrumenting, 2. Pick the right signal for each question, 3. Structured logging, 4. Metrics, 5. Distributed tracing, 6. Alerting, 7. Verify the telemetry itself, Common Rationalizations (+7 more)

### Community 89 - "Doubt-Driven Development"
Cohesion: 0.12
Nodes (15): Common Rationalizations, Cross-model escalation, Doubt-Driven Development, Interaction with Other Skills, Loading Constraints, Overview, Red Flags, Step 1: CLAIM — Surface what stands (+7 more)

### Community 90 - "Process"
Cohesion: 0.12
Nodes (15): 1. Define "working" before instrumenting, 2. Pick the right signal for each question, 3. Structured logging, 4. Metrics, 5. Distributed tracing, 6. Alerting, 7. Verify the telemetry itself, Common Rationalizations (+7 more)

### Community 91 - "Doubt-Driven Development"
Cohesion: 0.12
Nodes (15): Common Rationalizations, Cross-model escalation, Doubt-Driven Development, Interaction with Other Skills, Loading Constraints, Overview, Red Flags, Step 1: CLAIM — Surface what stands (+7 more)

### Community 92 - "Process"
Cohesion: 0.12
Nodes (15): 1. Define "working" before instrumenting, 2. Pick the right signal for each question, 3. Structured logging, 4. Metrics, 5. Distributed tracing, 6. Alerting, 7. Verify the telemetry itself, Common Rationalizations (+7 more)

### Community 93 - "report_generator.py"
Cohesion: 0.14
Nodes (14): pypdf, re, generate_pdf_report(), Path, Tamper-Evident PDF Report Generator with QR Code & Embedded Audit Hash (PRD…, Reads embedded hash from PDF document and validates against audit_log.jsonl., Renders comprehensive PDF report with embedded hash and QR verification code., verify_report_hash() (+6 more)

### Community 94 - "Idea Refine"
Cohesion: 0.13
Nodes (14): Anti-patterns to Avoid, Detailed Instructions, How It Works, Idea Refine, Output, Phase 1: Understand & Expand (Divergent), Phase 2: Evaluate & Converge, Phase 3: Sharpen & Ship (+6 more)

### Community 95 - "Using Agent Skills"
Cohesion: 0.13
Nodes (14): 1. Surface Assumptions, 2. Manage Confusion Actively, 3. Push Back When Warranted, 4. Enforce Simplicity, 5. Maintain Scope Discipline, 6. Verify, Don't Assume, Core Operating Behaviors, Failure Modes to Avoid (+6 more)

### Community 96 - "Idea Refine"
Cohesion: 0.13
Nodes (14): Anti-patterns to Avoid, Detailed Instructions, How It Works, Idea Refine, Output, Phase 1: Understand & Expand (Divergent), Phase 2: Evaluate & Converge, Phase 3: Sharpen & Ship (+6 more)

### Community 97 - "Using Agent Skills"
Cohesion: 0.13
Nodes (14): 1. Surface Assumptions, 2. Manage Confusion Actively, 3. Push Back When Warranted, 4. Enforce Simplicity, 5. Maintain Scope Discipline, 6. Verify, Don't Assume, Core Operating Behaviors, Failure Modes to Avoid (+6 more)

### Community 98 - "Idea Refine"
Cohesion: 0.13
Nodes (14): Anti-patterns to Avoid, Detailed Instructions, How It Works, Idea Refine, Output, Phase 1: Understand & Expand (Divergent), Phase 2: Evaluate & Converge, Phase 3: Sharpen & Ship (+6 more)

### Community 99 - "Using Agent Skills"
Cohesion: 0.13
Nodes (14): 1. Surface Assumptions, 2. Manage Confusion Actively, 3. Push Back When Warranted, 4. Enforce Simplicity, 5. Maintain Scope Discipline, 6. Verify, Don't Assume, Core Operating Behaviors, Failure Modes to Avoid (+6 more)

### Community 100 - "Spec-Driven Development"
Cohesion: 0.14
Nodes (13): Common Rationalizations, Keeping the Spec Alive, Overview, Phase 0: Scope Check, Phase 1: Specify, Phase 2: Plan, Phase 3: Tasks, Phase 4: Implement (+5 more)

### Community 101 - "Spec-Driven Development"
Cohesion: 0.14
Nodes (13): Common Rationalizations, Keeping the Spec Alive, Overview, Phase 0: Scope Check, Phase 1: Specify, Phase 2: Plan, Phase 3: Tasks, Phase 4: Implement (+5 more)

### Community 102 - "Spec-Driven Development"
Cohesion: 0.14
Nodes (13): Common Rationalizations, Keeping the Spec Alive, Overview, Phase 0: Scope Check, Phase 1: Specify, Phase 2: Plan, Phase 3: Tasks, Phase 4: Implement (+5 more)

### Community 103 - "2. Detailed Per-Rule Evidence and Rationale"
Cohesion: 0.14
Nodes (13): 10. COMMON-MGMT-001 (`CISCO-MGMT-001`), 1. COMMON-SSH-001 (`CISCO-SSH-001`), 1. Summary of Mappings, 2. COMMON-AAA-001 (`CISCO-AAA-001`), 2. Detailed Per-Rule Evidence and Rationale, 3. COMMON-NTP-001 (`CISCO-NTP-001`), 4. COMMON-LOG-001 (`CISCO-LOG-001`), 5. COMMON-SNMP-001 (`CISCO-SNMP-001`) (+5 more)

### Community 104 - "properties"
Cohesion: 0.15
Nodes (13): format, type, type, type, completed_at, configuration_hash, framework, scanner_version (+5 more)

### Community 105 - "properties"
Cohesion: 0.15
Nodes (13): minimum, type, minimum, type, minimum, type, failed, not_applicable (+5 more)

### Community 106 - "enabled"
Cohesion: 0.15
Nodes (13): type, type, additionalProperties, properties, type, authentication_enabled, enabled, ntp (+5 more)

### Community 107 - "properties"
Cohesion: 0.12
Nodes (16): additionalProperties, description, $id, type, properties, interfaces, schema_version, services (+8 more)

### Community 108 - "Source-Driven Development"
Cohesion: 0.15
Nodes (12): Common Rationalizations, Overview, Red Flags, Retrieval Safety: Treat Fetched Content as Data, Source-Driven Development, Step 1: Detect Stack and Versions, Step 2: Fetch Official Documentation, Step 3: Implement Following Documented Patterns (+4 more)

### Community 109 - "Source-Driven Development"
Cohesion: 0.15
Nodes (12): Common Rationalizations, Overview, Red Flags, Retrieval Safety: Treat Fetched Content as Data, Source-Driven Development, Step 1: Detect Stack and Versions, Step 2: Fetch Official Documentation, Step 3: Implement Following Documented Patterns (+4 more)

### Community 110 - "Source-Driven Development"
Cohesion: 0.15
Nodes (12): Common Rationalizations, Overview, Red Flags, Retrieval Safety: Treat Fetched Content as Data, Source-Driven Development, Step 1: Detect Stack and Versions, Step 2: Fetch Official Documentation, Step 3: Implement Following Documented Patterns (+4 more)

### Community 111 - "properties"
Cohesion: 0.17
Nodes (12): properties, required, type, type, type, type, device, hostname (+4 more)

### Community 112 - "Refinement & Evaluation Criteria"
Cohesion: 0.17
Nodes (11): 1. User Value, 2. Feasibility, 3. Differentiation, Assumption Audit, Core Evaluation Dimensions, Decision Framework, Might Be True (Nice to Have), Must Be True (Dealbreakers) (+3 more)

### Community 113 - "Refinement & Evaluation Criteria"
Cohesion: 0.17
Nodes (11): 1. User Value, 2. Feasibility, 3. Differentiation, Assumption Audit, Core Evaluation Dimensions, Decision Framework, Might Be True (Nice to Have), Must Be True (Dealbreakers) (+3 more)

### Community 114 - "Refinement & Evaluation Criteria"
Cohesion: 0.17
Nodes (11): 1. User Value, 2. Feasibility, 3. Differentiation, Assumption Audit, Core Evaluation Dimensions, Decision Framework, Might Be True (Nice to Have), Must Be True (Dealbreakers) (+3 more)

### Community 115 - "properties"
Cohesion: 0.22
Nodes (9): properties, result_id, scan, summary, type, required, type, required (+1 more)

### Community 116 - "Ideation Frameworks Reference"
Cohesion: 0.22
Nodes (8): Analogous Inspiration, Constraint-Based Ideation, First Principles Thinking, How Might We (HMW), Ideation Frameworks Reference, Jobs to Be Done (JTBD), Pre-mortem, SCAMPER

### Community 117 - "Ideation Frameworks Reference"
Cohesion: 0.22
Nodes (8): Analogous Inspiration, Constraint-Based Ideation, First Principles Thinking, How Might We (HMW), Ideation Frameworks Reference, Jobs to Be Done (JTBD), Pre-mortem, SCAMPER

### Community 118 - "properties"
Cohesion: 0.11
Nodes (18): type, type, additionalProperties, properties, type, type, type, type (+10 more)

### Community 119 - "Ideation Frameworks Reference"
Cohesion: 0.22
Nodes (8): Analogous Inspiration, Constraint-Based Ideation, First Principles Thinking, How Might We (HMW), Ideation Frameworks Reference, Jobs to Be Done (JTBD), Pre-mortem, SCAMPER

### Community 120 - "compliance_check_result_schema.json"
Cohesion: 0.25
Nodes (7): additionalProperties, description, $id, required, $schema, title, type

### Community 121 - "items"
Cohesion: 0.33
Nodes (7): items, additionalProperties, required, raw_evidence, description, items, type

### Community 122 - "compilerOptions"
Cohesion: 0.25
Nodes (7): compilerOptions, composite, module, moduleResolution, noEmit, skipLibCheck, include

### Community 123 - "Addendum to v4.0 — Refinements for MVP Build"
Cohesion: 0.25
Nodes (7): 1. Shared internal-rule / multi-framework model (revises §10 Data Model), 2. Split performance requirement (revises §7), 3. Simplified approval — one authorized reviewer for MVP (revises FR-3.4), 4. Build order — single-file, single-path first, Addendum to v4.0 — Refinements for MVP Build, Final Architecture Statement (supersedes §1 positioning language, rest of §1 stands), MVP Acceptance Criteria

### Community 124 - "Network Compliance Auditor Frontend"
Cohesion: 0.40
Nodes (4): Build, Integration, Network Compliance Auditor Frontend, Run

### Community 125 - "Collection Status"
Cohesion: 0.50
Nodes (3): Collection Status, Included and recovered, Not yet validated

### Community 126 - "compliance_percentage"
Cohesion: 0.50
Nodes (4): maximum, minimum, type, compliance_percentage

### Community 128 - "risk_score"
Cohesion: 0.67
Nodes (3): risk_score, minimum, type

### Community 129 - "unknown"
Cohesion: 0.67
Nodes (3): unknown, minimum, type

### Community 142 - "test_api_rbac.py"
Cohesion: 0.09
Nodes (12): anyio, fastapi, FastAPI dependency factory enforcing Role-Based Access Control (RBAC). Consumes…, require_role(), fixture, NTRO PS26155 Auditor — Role-Based Access Control (RBAC) API Integration Tests…, reviewer_non_approver_token(), reviewer_token() (+4 more)

### Community 143 - "properties"
Cohesion: 0.12
Nodes (17): type, type, type, type, type, cdp_or_lldp, finger, ftp (+9 more)

### Community 144 - "device"
Cohesion: 0.50
Nodes (4): additionalProperties, required, type, device

### Community 145 - "properties"
Cohesion: 0.12
Nodes (17): type, format, type, type, type, file_name, parsed_at, parser (+9 more)

## Knowledge Gaps
- **1775 isolated node(s):** `idea-refine.sh script`, `idea-refine.sh script`, `$schema`, `$id`, `title` (+1770 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 2074 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **14 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Phase 2 Plug-in Architecture:` connect `main` to `arena-frontend/src/App.tsx`?**
  _High betweenness centrality (0.018) - this node is a cross-community bridge._
- **Why does `Extension Contract & Current State: How New Vendors Plug In` connect `arena-frontend/src/App.tsx` to `main`?**
  _High betweenness centrality (0.018) - this node is a cross-community bridge._
- **What connects `idea-refine.sh script`, `idea-refine.sh script`, `$schema` to the rest of the system?**
  _1775 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `dashboard/package.json` be split into smaller, more focused modules?**
  _Cohesion score 0.058823529411764705 - nodes in this community are weakly interconnected._
- **Should `arena-frontend/src/App.tsx` be split into smaller, more focused modules?**
  _Cohesion score 0.052403846153846155 - nodes in this community are weakly interconnected._
- **Should `test_auth.py` be split into smaller, more focused modules?**
  _Cohesion score 0.09387755102040816 - nodes in this community are weakly interconnected._
- **Should `dashboard/src/api.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.07199297629499561 - nodes in this community are weakly interconnected._