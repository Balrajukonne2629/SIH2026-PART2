# NTRO PS26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor

An offline, air-gapped, multi-vendor network security compliance auditing engine featuring deterministic rule evaluation (CIS Benchmarks, DISA STIG, NIST SP 800-53), human-in-the-loop AI assistance, cryptographic SHA-256 audit chaining, non-repudiation verification, and canonical multi-framework reporting.

---

## Canonical Repository Structure

```
.
├── src/                        # Canonical backend application source code
│   ├── __init__.py
│   ├── ai_model_manager.py     # Local LLM hardware detection and routing
│   ├── ai_suggester.py         # DistilBERT unmapped configuration interpreter
│   ├── ast_safety.py           # AST import & execution safety validator
│   ├── audit_log.py            # Tamper-evident SHA-256 hash-chained audit ledger
│   ├── audit_report.py         # Canonical domain model for multi-framework reports
│   ├── auth.py                 # JWT authentication & PBKDF2 credential management
│   ├── cis_benchmark_cisco_iosxe.py # CIS Cisco IOS-XE Benchmark Evaluator
│   ├── cisco_auditor.py        # Cisco IOS-XE parser and deterministic engine
│   ├── compliance_aggregator.py # Multi-framework aggregation and deduplication
│   ├── compliance_framework.py # Abstract framework definitions and registry
│   ├── database.py             # SQLite persistence, migrations, and transactions
│   ├── disa_stig_cisco_iosxe.py# DISA STIG Cisco IOS-XE Evaluator
│   ├── juniper_auditor.py      # Juniper Junos hierarchical parser & evaluator
│   ├── main.py                 # FastAPI REST API endpoints and application
│   ├── remediation_engine.py   # Jinja2 CLI remediation templates & conflict check
│   ├── report_exporter.py      # PDF and DOCX export generation engine
│   ├── report_generator.py     # Legacy PDF certificate generator with QR codes
│   ├── vendor_adapter.py       # Vendor adapter interface (Cisco, Juniper)
│   └── vendor_registry.py      # Dynamic plug-and-play vendor registry
├── frontend/                   # Canonical frontend application (React + Vite + TS)
│   ├── src/                    # Screens, components, contexts, and API client
│   ├── tests/                  # Frontend unit and contract test suites
│   ├── package.json            # Scripts: dev, build, preview, test
│   └── vite.config.ts
├── tests/                      # Automated test suites (27 test files)
│   ├── conftest.py             # Pytest session setup and module identity bridge
│   ├── test_api_compliance.py  # REST API compliance endpoints verification
│   ├── test_api_full_loop.py   # 11-stage API full-loop parity test
│   ├── test_step5_full_loop.py # 17-stage PRD Step 5 deterministic loop verification
│   ├── test_ast_safety.py      # Static AST import security analysis
│   └── ...                     # Vendor, auth, RBAC, lifecycle, export suites
├── tools/                      # Standalone operational tools and benchmarks
│   └── test_ollama_integration.py # Standalone local LLM offline benchmark tool
├── config/                     # Configuration schemas and rule mappings
│   └── Rule_Library/           # Normalized schemas and vendor rule mappings
├── data/                       # Local SQLite DB, exports, and persistent states
│   ├── auditor.db              # SQLite compliance database
│   ├── pending_suggestions.json# Staged AI mapping suggestions queue
│   ├── trusted_mappings.json   # Approved human-in-the-loop rule mappings
│   └── exports/                # Exported report documents (PDF / DOCX)
├── datasets/                   # Sample device configuration datasets
│   ├── Arista/                 # Arista EOS configurations
│   ├── Cisco/                  # Cisco IOS-XE configurations
│   └── Juniper/                # Juniper Junos configurations
├── docs/                       # Project specifications and architectural records
│   ├── NTRO_PS26155_PRD_v4_Addendum.md # Authoritative PRD Addendum
│   ├── MULTI_FRAMEWORK_COMPLIANCE_ARCHITECTURE.md
│   ├── ARCHITECTURE_NOTES.md
│   └── ...
├── references/                 # Upstream compliance standards and research
│   ├── standards/              # CIS, DISA STIG, NIST SP 800-53 catalog
│   ├── parsers/                # Parser reference specifications
│   ├── mappings/               # Framework cross-mappings
│   └── scanners/               # Upstream scanner packages
├── reports/                    # Historical verification and audit milestone reports
├── artifacts/                  # Visual checks and architectural diagrams
├── templates/                  # Jinja2 remediation templates
├── main.py                     # Root entrypoint wrapper (`uvicorn main:app`)
├── pytest.ini                  # Pytest configuration
├── Dockerfile                  # Container definition for backend
├── docker-compose.yml          # Full-stack composition (backend, frontend, ollama)
└── requirements.txt            # Python dependencies
```

---

## Quickstart & Execution

### 1. Backend Service
Run via the canonical entrypoint:
```bash
python -m uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```
Or via the root backward-compatible wrapper:
```bash
uvicorn main:app --reload
```

### 2. Frontend Application
```bash
cd frontend
npm install
npm run dev
```

### 3. Running Automated Tests
Run the entire test suite (515 passed, 12 skipped):
```bash
pytest
```

Run specific core verification loops:
```bash
# PRD Step 5 17-Stage CLI Full-Loop & Tamper Test
python tests/test_step5_full_loop.py

# FastAPI 11-Stage Full-Loop Parity & AST Safety Verification
python tests/test_api_full_loop.py

# Frontend Test Suite (57 passed)
cd frontend && npm test

# Frontend Production Build
cd frontend && npm run build
```
