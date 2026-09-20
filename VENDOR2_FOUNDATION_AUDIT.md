# NTRO PS26155 — Vendor #2 Foundation Audit: Juniper
**Project:** NTRO PS26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor  
**Phase:** Post-3R Cleanup → Vendor #2 Preparation  
**Target Vendor:** Juniper Networks (Junos OS)  
**Date:** September 20, 2026  
**Auditor Mode:** Lazy Senior Developer (Ponytail) / Skeptical Doubt-Driven Audit  
**Authoritative Baseline:** Post-3R.5 Verified State (Commit: `main`, 325 passed, 12 skipped, 0 failed)  
**Status:** Audit & Target Architecture Design Only (Zero Implementation / Zero Modification)

---

## Executive Summary

This foundation audit evaluates the structural readiness of the NTRO PS26155 codebase to onboard **Vendor #2: Juniper Networks (Junos OS)**. Following the completion of the 3R cleanup phase, the core compliance framework (`compliance_framework.py`, `compliance_aggregator.py`) was proven to be genuinely vendor-neutral, fully decoupled from raw CLI syntax, and strictly deterministic.

However, an exhaustive trace of the configuration ingestion, REST API, database schema, AI suggestion, and remediation paths revealed specific points of accidental coupling to Cisco IOS-XE. Adding Juniper support requires zero modifications to the core compliance evaluation or aggregation engines, but requires resolving vendor dispatching in the API ingestion layer and scoping framework evaluations by vendor identity.

**Final Verdict:** **GO WITH REQUIRED PRECONDITIONS**

---

## 1. Baseline Verification

Before conducting architectural analysis, the post-3R repository state was verified directly against runtime systems and source files.

### 1.1 Git Status and Branch Baseline
- **Current Branch:** `main`
- **Upstream Sync:** Ahead of `origin/main` by 1 commit.
- **Working Tree State:** Clean with respect to test execution. Unstaged changes in working tree reflect verified Post-3R consolidation artifacts (`main.py`, `remediation_engine.py`, `report_generator.py`, frontend synchronization, and test scripts).
- **Untracked Architectural Deliverables:** Phase 3A/3R verification reports, `compliance_framework.py`, `compliance_aggregator.py`, `cis_benchmark_cisco_iosxe.py`, `disa_stig_cisco_iosxe.py`, and test suites.

### 1.2 Test Suite Execution Baseline
Full test execution was performed via `pytest` under Python 3.14.0:
- **Total Test Cases Collected:** 337 items
- **Passed:** 325 tests (100% of unit, component, API, security, and integration tests)
- **Skipped:** 12 tests (in `test_docker_offline_auth.py`, awaiting local Docker daemon socket)
- **Failed:** 0 tests
- **Execution Wall-Clock Time:** 83.46 seconds
- **Test Subsystems Verified:**
  - AI Model Manager & Telemetry: 31 tests passed
  - Authentication & Cryptographic Tokens: 44 tests passed
  - RBAC & Authorized Approver Gating: 13 tests passed
  - Session Ownership & Resource Isolation: 21 tests passed
  - Reviewer Identity Server-Binding: 20 tests passed
  - AST Safety & Zero-Execution Asserts: 5 tests passed
  - CIS Cisco IOS-XE Benchmark v2.2.1: 32 tests passed
  - DISA-STIG Cisco IOS-XE V3R7: 39 tests passed
  - Multi-Framework Scoring & Aggregation: 18 tests passed
  - Database Schema & Idempotent Migrations: 14 tests passed
  - Full Compliance End-to-End Pipelines: 3 tests passed

### 1.3 Baseline Framework Registry
At startup, `main.py` explicitly registers two deterministic compliance adapters into `FrameworkRegistry`:
1. `cis-cisco-iosxe`: CIS Cisco IOS XE 17.x Benchmark v2.2.1 (7 verified deterministic controls)
2. `disa-stig-cisco-iosxe`: DISA STIG Cisco IOS XE Benchmark V3R7 (10 verified deterministic controls)

---

## 2. PBKDF2 Ground-Truth Verification

A reported discrepancy in recent project documentation regarding the PBKDF2 iteration count was investigated.

### 2.1 Documentation Discrepancy
- **3R.5 Verification Report Claim:** Claimed `PBKDF2-HMAC-SHA256 = 100,000 iterations`.
- **Earlier Project Specification:** Claimed `PBKDF2-HMAC-SHA256 = 600,000 iterations`.

### 2.2 Ground-Truth Inspection
The runtime source code in `database.py` and `auth.py` was inspected:

```python
# database.py, Lines 29-36
def hash_password(password: str, salt_hex: Optional[str] = None) -> Tuple[str, str]:
    """Derives PBKDF2-HMAC-SHA256 key with 600,000 iterations using Python standard library.
    Returns (password_hash_hex, salt_hex).
    Never stores or logs plaintext passwords.
    """
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    return dk.hex(), salt.hex()
```

```python
# auth.py, Lines 96-103
def verify_password(plain_password: str, password_hash: str, salt: str) -> bool:
    """Verifies a plaintext password against a stored PBKDF2-HMAC-SHA256 hash and salt.
    
    Reuses database.hash_password (600,000 iterations PBKDF2-HMAC-SHA256).
    Uses hmac.compare_digest for constant-time comparison to prevent timing side-channels.
    Safely returns False on malformed inputs, type mismatches, or non-hex salts.
    Never logs plaintext passwords or raises exceptions on invalid data.
    """
```

### 2.3 Verdict & Discrepancy Recording
- **Verified Ground Truth:** Exactly **600,000 iterations** (`hashlib.pbkdf2_hmac("sha256", ..., 600_000)`).
- **Compliance Status:** Fully aligns with OWASP Password Storage Guidelines (recommending 600,000 iterations for PBKDF2-HMAC-SHA256).
- **Discrepancy Cause:** The text in `3R5_FINAL_GRAPHIFY_SECURITY_VERIFICATION_REPORT.md` was an errant copy-paste documentation typo. The underlying implementation was never modified to 100,000 and has always remained 600,000 iterations. Zero code modification is needed.

---

## 3. Current Cisco Data Flow & Architectural Coupling

The complete end-to-end data flow for Cisco configurations was traced through all execution paths:

```
                  Raw Cisco IOS-XE Configuration (.txt / .cfg)
                                      │
                                      ▼
             [POST /api/audit/upload] OR [POST /api/compliance/evaluate]
                                      │
                                      ▼
                 cisco_auditor.parse_cisco(raw_text)
                                      │
                                      ▼
                     Normalized Cisco State Model (CSM)
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
    [Legacy Baseline Evaluation]               [Multi-Framework Registry]
    cisco_auditor.evaluate_rules()             FrameworkRegistry.get_evaluator(fid)
               │                                             │
               │                              ┌──────────────┴──────────────┐
               │                              ▼                             ▼
               │                    CisCiscoIosXeEvaluator       StigCiscoIosXeEvaluator
               │                              │                             │
               │                              └──────────────┬──────────────┘
               │                                             │
               ▼                                             ▼
        evals dictionary                          List[EvaluationResult]
   {"CISCO-SSH-001": {"status": "Pass"}}                     │
               │                                             ▼
               │                              MultiFrameworkAggregator.aggregate()
               │                                             │
               │                                             ▼
               │                                 MultiFrameworkAuditResult
               │                                (Summaries, Metrics, Evidence)
               │                                             │
               └──────────────────────┬──────────────────────┘
                                      │
                                      ▼
                      Session Cache / Database Storage
                      (SQLite: data/auditor.db: audit_sessions)
                                      │
               ┌──────────────────────┼──────────────────────┐
               ▼                      ▼                      ▼
      [Display Remediation]    [Audit Finalization]   [Report Generation]
     remediation_engine.py         audit_log.py       report_generator.py
      - Jinja2 template            - SHA256 Chained   - PDF Compliance Report
      - Static Conflicts             audit_ledger     - QR Code Verification
      - AI Model Manager (Ollama)
```

### Where Vendor-Specific Assumptions Currently Exist in Data Flow
1. **Ingestion Entry Point (`main.py` L497-498):** `audit_upload` unconditionally calls `cisco_auditor.parse_cisco(text)` and `cisco_auditor.evaluate_rules(csm, baseline_rules)`.
2. **API Parsing Fallback (`main.py` L959):** `evaluate_compliance` with `raw_config` unconditionally dispatches to `cisco_auditor.parse_cisco`.
3. **Session Re-Evaluation (`main.py` L634-639):** When an unmapped line suggestion is approved in `ai_approve`, the session is re-evaluated using `cisco_auditor.parse_cisco` and `cisco_auditor.evaluate_rules`.
4. **Baseline Rule Loader (`main.py` L115):** `load_baseline_rules()` hardcodes `data["vendors"]["Cisco IOS-XE"]["rules"]`.
5. **AI Suggestion Baseline Context (`ai_suggester.py` L73):** Falls back to `data["vendors"]["Cisco IOS-XE"]["rules"]`.
6. **Remediation Conflict Engine (`remediation_engine.py` L60, L124):** Only implements static checks for `CISCO-NTP-001`, and the prompt template hardcodes "IOS-XE configuration command".

---

## 4. The Vendor-Neutral Adapter Contract

To onboard Juniper without compromising architectural integrity, the system requires an explicit vendor adapter contract defining parsing, vendor identification, and CSM compatibility.

### 4.1 Parsing Contract
A vendor parser must satisfy the following specification:
- **Input Format:** UTF-8 encoded text configuration string. Supports both:
  - Hierarchical curly-brace syntax (`system { services { ssh { protocol-version v2; } } }`)
  - Flat `set` command syntax (`set system services ssh protocol-version v2`)
- **Parser Entry Point:** `parse_juniper(text: str, filename: str = "config.conf", trusted_rules: list = None) -> dict`
- **Output:** Fully normalized CSM dictionary matching `07_Compliance_Scanners/Rule_Library/extracted/Rule_Library/normalized_config_schema.json`.
- **Parser Error Handling:**
  - Empty string: Return valid empty CSM with `device.hostname = "unknown"`, `device.vendor = "juniper"`, all service booleans `False`, and populated `parser_warnings`.
  - Malformed lines: Append malformed lines to `csm["unmapped_lines"]` and append diagnostic messages to `csm["parser_warnings"]`.
  - Never crash: Must not raise unhandled exceptions on invalid tokens or syntax errors.
- **Dependency Constraint:** **STRICTLY Python Standard Library only** (`re`, `json`, `pathlib`, `hashlib`). The archive `jnprsr-0.1.2.tar.gz` found in `03_Configuration_Parsers/` relies on `antlr4-python3-runtime` and `anytree`; these third-party dependencies must NOT be introduced into production.

### 4.2 Vendor Identification Contract
Currently, vendor detection does not exist in the codebase. The contract requires:
- **Explicit Vendor Selection:** The upload API (`POST /api/audit/upload`) and compliance evaluation API (`POST /api/compliance/evaluate`) must accept an optional `vendor: Optional[str] = Form(None)` / JSON field.
- **Deterministic Auto-Detection:** When `vendor` is `None` or `"auto"`, the system must run a lightweight regex inspection over the raw text:
  - **Cisco Signature:** Lines matching `^version\s+\d+\.\d+`, `^hostname\s+\S+`, `^interface\s+GigabitEthernet`, `^line\s+vty`, `^boot-start-marker`, `!.*IOS-XE`.
  - **Juniper Signature:** Lines matching `^## Last changed:`, `^version\s+[0-9]{2}\.[0-9]`, `^set system `, `^system\s*\{`, `^interfaces\s*\{`, `^protocols\s*\{`, `/\*.*Junos.*?\*/`.
- **Ambiguity Resolution:**
  - If both or neither match with high confidence, fail closed with HTTP 422: `"Unable to determine vendor configuration type. Please specify 'vendor' parameter ('cisco' or 'juniper')."`

### 4.3 CSM Field Compatibility & Classification
Every CSM field defined in `normalized_config_schema.json` and utilized by the Cisco pipeline is classified below:

| CSM Field Path | Type | Current Cisco Usage | Juniper Semantics | Classification |
|---|---|---|---|---|
| `device.hostname` | str | `hostname <name>` | `system { host-name <name>; }` / `set system host-name` | **Vendor-neutral** |
| `device.vendor` | str | `"cisco"` | `"juniper"` | **Vendor-neutral** |
| `device.platform` | str | `"IOS-XE"` | `"Junos"` | **Vendor-neutral** |
| `device.management_ip` | str | Extracted from loopback / mgmt intf | Extracted from `fxp0` / `lo0` address | **Vendor-neutral** |
| `services.ssh` | bool | `transport input ssh` on VTY | `system services ssh` | **Vendor-neutral** |
| `services.ssh_version` | int | `ip ssh version 2` | `system services ssh protocol-version v2` | **Vendor-neutral** |
| `services.telnet` | bool | `transport input telnet` on VTY | `system services telnet` | **Vendor-neutral** |
| `aaa.enabled` | bool | `aaa new-model` | `system authentication-order` / `system login` configured | **Vendor-semantic** |
| `aaa.authentication_method` | str | `aaa authentication login default ...` | Extracted from `authentication-order` list | **Vendor-semantic** |
| `aaa.configured` | bool | AAA commands present | User accounts or auth servers defined | **Vendor-semantic** |
| `logging.enabled` | bool | `logging ...` commands | `system syslog ...` configured | **Vendor-neutral** |
| `logging.remote_logging_enabled` | bool | `logging host <ip>` | `system syslog host <ip>` | **Vendor-neutral** |
| `logging.remote_servers` | list | List of syslog server IPs | List of `syslog host` IPs | **Vendor-neutral** |
| `logging.timestamps_enabled` | bool | `service timestamps log` | `system syslog time-format` (or default Junos ms) | **Vendor-neutral** |
| `ntp.enabled` | bool | `ntp server ...` | `system ntp ...` | **Vendor-neutral** |
| `ntp.servers` | list | List of NTP server IPs | List of `system ntp server <ip>` | **Vendor-neutral** |
| `ntp.authentication_enabled` | bool | `ntp authenticate` | `system ntp authentication-key ...` / `trusted-key` | **Vendor-neutral** |
| `snmp.enabled` | bool | `snmp-server ...` | `snmp { ... }` | **Vendor-neutral** |
| `snmp.community_strings` | list | `snmp-server community <str>` | `snmp community <str>` | **Vendor-neutral** |
| `access_control.management_acl_present` | bool | `access-class` on line vty | `lo0` firewall filter protecting SSH/Telnet | **Vendor-semantic** |
| `access_control.acls_present` | bool | `ip access-list ...` | `firewall family inet filter ...` | **Vendor-semantic** |
| `interfaces[].name` | str | `GigabitEthernet0/0/0` | `ge-0/0/0`, `xe-0/0/0`, `fxp0`, `lo0` | **Vendor-neutral** |
| `interfaces[].shutdown` | bool | `shutdown` | `disable;` statement in interface block | **Vendor-neutral** |
| `interfaces[].enabled` | bool | `no shutdown` | Absence of `disable;` statement | **Vendor-neutral** |
| `interfaces[].description` | str | `description <text>` | `description <text>;` | **Vendor-neutral** |
| `interfaces[].ip_addresses` | list | `ip address <ip> <mask>` | `address <ip>/<cidr>;` under unit family inet | **Vendor-neutral** |
| `routing.routing_protocols` | list | `["bgp", "ospf"]` | `["bgp", "ospf"]` from `protocols { ... }` | **Vendor-neutral** |
| `routing.routing_authentication_enabled`| bool | `neighbor password` in BGP | `authentication-key` under `protocols bgp` | **Vendor-neutral** |
| `management.management_vrf_enabled` | bool | `vrf forwarding Mgmt-intf` | `routing-instances mgmt` / `fxp0` dedicated routing | **Vendor-semantic** |
| `spanning_tree.configured` | bool | `spanning-tree ...` | `protocols rstp` / `protocols mstp` | **Vendor-neutral** |
| `spanning_tree.bpduguard_enabled` | bool | `spanning-tree portfast bpduguard` | `bpdu-block` on edge interface | **Vendor-semantic** |
| `raw_evidence` | list | Source line mappings | Source line mappings | **Vendor-neutral** |
| `unmapped_lines` | list | Unrecognized CLI commands | Unrecognized Junos statements | **Vendor-neutral** |

---

## 5. Cisco Leakage Audit

A comprehensive search across all non-adapter modules was performed to identify accidental Cisco coupling.

### 5.1 Leakage Classification Framework
- **Category A:** Legitimately Cisco-specific (contained within Cisco adapter files or Cisco benchmark specs).
- **Category B:** Accidental coupling (in generic modules; must be abstracted or parametrized).
- **Category C:** Shared abstraction candidate (already neutral or reusable with minimal changes).
- **Category D:** Legacy/dead code (retained only for backwards compatibility).
- **Category E:** Test fixture or benchmark expectation.

### 5.2 Findings and Classification

| File | Location / Symbol | Code / Content | Category | Impact & Assessment |
|---|---|---|:---:|---|
| `main.py` | Line 75 | `PDF_FILE = BASE_DIR / "cisco_compliance_report.pdf"` | **B** | Hardcoded PDF output filename implies Cisco only. Should be dynamically named based on device hostname or audit ID. |
| `main.py` | Line 115 | `data["vendors"]["Cisco IOS-XE"]["rules"]` | **B** | `load_baseline_rules()` only loads Cisco rules. Must accept a `vendor` parameter to load `data["vendors"]["Juniper Junos"]["rules"]`. |
| `main.py` | Lines 497-498 | `cisco_auditor.parse_cisco(...)` in `audit_upload()` | **B** | Direct call to Cisco parser prevents uploading Juniper configurations to `/api/audit/upload`. |
| `main.py` | Line 521, 559 | `"platform": csm.get("device", {}).get("platform", "IOS-XE")` | **B** | Hardcoded default fallback `"IOS-XE"` overrides missing platform metadata with Cisco identity. |
| `main.py` | Lines 634-639 | `cisco_auditor.parse_cisco(...)` in `ai_approve()` | **B** | Re-evaluation of approved unmapped lines forces Cisco parser even if session was Juniper. |
| `main.py` | Line 959 | `cisco_auditor.parse_cisco(...)` in `evaluate_compliance()` | **B** | `raw_config` evaluation route hardcodes Cisco parser. |
| `ai_suggester.py` | Line 73 | `data["vendors"]["Cisco IOS-XE"]["rules"]` | **B** | Suggestions compare unmapped lines strictly against Cisco baseline rules. |
| `ai_suggester.py` | Lines 113-115 | Hints map to `CIS-1.4.1`, `V-215849` (Cisco) | **B** | AI unmapped suggestions emit Cisco-specific framework hints. |
| `remediation_engine.py`| Line 20 | `templates/remediation/CISCO-NTP-001.j2` | **A** | Rule-specific template name is correct, but only Cisco template exists. |
| `remediation_engine.py`| Line 60 | `if rule_id == "CISCO-NTP-001":` in conflict checks | **B** | Static conflict analysis is only implemented for Cisco NTP rule. |
| `remediation_engine.py`| Line 124 | Prompt: `"what IOS-XE configuration command..."` | **B** | LLM prompt explicitly instructs model to explain in terms of IOS-XE commands. |
| `report_generator.py` | Line 23 | `DEFAULT_PDF_FILE = "cisco_compliance_report.pdf"` | **B** | Accidental coupling in default output parameter. |
| `report_generator.py` | Line 113 | `platform = csm.get("device", {}).get("platform", "IOS-XE")` | **B** | Metadata fallback assumes IOS-XE. |
| `database.py` | Line 116 | `trusted_mappings` table lacks `vendor` column | **B** | All approved rules are stored in a single table with no vendor discriminator. |
| `cisco_auditor.py` | Lines 15-38 | `resolve_csm_path()`, `eval_condition()` | **C** | Generic condition evaluator is 100% vendor-neutral; candidate for promotion to shared utility. |
| `cisco_auditor.py` | Lines 40-134 | `parse_cisco()` | **A** | Cisco IOS-XE parser implementation. |
| `cisco_auditor.py` | Lines 136-172 | `evaluate_rules()` | **D** | Legacy baseline evaluation engine. Replaced by `compliance_framework.py` for multi-framework compliance. |
| `dashboard/UploadScreen.tsx` | Line 12-75, 198 | Text: `"Upload raw Cisco IOS-XE configuration"` | **B** | UI exclusively presents Cisco sample configs and Cisco instructions. |
| `dashboard/App.tsx` | Line 28 | `useState('CISCO-NTP-001')` | **B** | UI default state assumes Cisco NTP remediation. |

---

## 6. Framework Abstraction Audit

The core compliance framework was audited to verify whether it can host Cisco and Juniper simultaneously without altering core contracts.

### 6.1 Inspection of Core Contracts (`compliance_framework.py`)
- **`Framework` Data Model:** Fully vendor-neutral. Explicitly contains `vendor_scope: Optional[str]`, allowing `"Cisco IOS-XE"`, `"Juniper Junos"`, or `None` (Universal).
- **`Control` Data Model:** Fully vendor-neutral. Contains `framework_id`, `control_id`, `title`, `expected_state`, `evaluation_metadata`.
- **`ComplianceStatus` Contract:** Case-insensitive enum (`PASS`, `FAIL`, `UNKNOWN`). Preserves `UNKNOWN` boundary without conflating with `FAIL`.
- **`Evidence` Data Model:** Fully vendor-neutral (`observed_value`, `location`, `expected_value`, `rationale`, `confidence`, `source_lines`).
- **`EvaluationResult` Contract:** Links `framework_id`, `control_id`, `status`, and `evidence`. Contains zero vendor attributes.
- **`FrameworkEvaluator` Abstract Interface:** Pure function contract:
  ```python
  @abstractmethod
  def evaluate(self, csm: Dict[str, Any], controls: Optional[Sequence[Control]] = None) -> List[EvaluationResult]:
      pass
  ```
- **`FrameworkRegistry`:** Explicit, dependency-injectable registry. Keyed by unique `framework_id`. Allows registration, retrieval, and replacement.
- **`MultiFrameworkAggregator` (`compliance_aggregator.py`):** Pure aggregation engine. Groups by `framework_id`, resolves duplicate results deterministically, computes pass rates, and compiles evidence. Contains zero vendor logic.

### 6.2 The Core Compliance Architectural Question
> **"Can Juniper be added as another vendor adapter without changing the core compliance engine?"**

**Answer: YES.**

#### Concrete Code Proof:
1. **Zero Core Engine Modification:** Neither `compliance_framework.py` nor `compliance_aggregator.py` needs a single line of code changed.
2. **Evaluator Attachment Point:** A new class `JunosCsmFrameworkAdapter` or `CisJuniperJunosEvaluator` simply inherits from `FrameworkEvaluator` (`compliance_framework.py` L237) and implements `.evaluate(csm)`.
3. **Registration Hook:** The new framework is registered in the existing `FrameworkRegistry` (`compliance_framework.py` L287):
   ```python
   registry.register(
       framework=Framework(
           framework_id="juniper-junos-baseline",
           name="Juniper Junos Baseline Security Policy",
           version="1.0",
           vendor_scope="Juniper Junos",
           control_namespace="JUNOS"
       ),
       evaluator=JunosCsmFrameworkAdapter()
   )
   ```
4. **Aggregation Compatibility:** `MultiFrameworkAggregator.aggregate()` consumes the resulting `EvaluationResult` objects without concern for which vendor adapter produced them.

#### Architectural Caveats Outside the Engine:
While the *engine* is 100% ready, the *API evaluation dispatcher* (`main.py` L986-990) requires attention:
When a client evaluates compliance without passing `framework_ids`, `main.py` executes ALL enabled evaluators. If a Cisco CSM is evaluated against a Juniper evaluator, the Juniper evaluator must safely return `UNKNOWN` for all controls (or `main.py` must filter evaluators by `framework.vendor_scope == csm["device"]["vendor"]`).

---

## 7. Target Design: Juniper Adapter Boundary

Based exclusively on existing patterns in `cisco_auditor.py`, `cis_benchmark_cisco_iosxe.py`, and `compliance_framework.py`, the target Juniper adapter boundary is designed as follows.

```
       Juniper Junos Configuration File (.conf or .set)
                              │
                              ▼
           juniper_auditor.parse_juniper(text, filename)
           - Pure Python stdlib (re, json)
           - Strips comments (/* ... */, #, !!)
           - Handles hierarchical blocks: system { ... }
           - Handles flat set commands: set system ...
           - Populates raw_evidence source line provenance
                              │
                              ▼
             Normalized Configuration State Model (CSM)
             - device.vendor = "juniper"
             - device.platform = "Junos"
             - Standard schema: services, aaa, ntp, logging, snmp, etc.
                              │
                              ▼
           JunosCsmFrameworkAdapter.evaluate(csm)
           (Implements compliance_framework.FrameworkEvaluator)
                              │
                              ▼
                   List[EvaluationResult]
                              │
                              ▼
          Existing MultiFrameworkAggregator.aggregate()
```

### 7.1 Module Structure
- **Target Parser Module:** `juniper_auditor.py` (matching `cisco_auditor.py` pattern).
- **Target Framework Adapter:** `juniper_baseline_adapter.py` (or integrated into `juniper_auditor.py` via `FrameworkEvaluator`).
- **Dependencies:** `pathlib`, `re`, `json`, `datetime`, `hashlib`. **Zero external packages.**

### 7.2 Parser Architecture & Syntax Handling
Junos configurations present two syntaxes, both of which must be handled:
1. **Hierarchical Bracket Syntax (`.conf`):**
   - Lexical scanner maintains a context stack of parent blocks: `['system', 'services', 'ssh']`.
   - Leaves ending in `;` set scalar or list values: `protocol-version v2;` -> `{"ssh_version": 2}`.
2. **Flat Set Command Syntax (`.set`):**
   - Lines starting with `set ` are split into tokens: `set system services ssh protocol-version v2`.
   - Token hierarchy maps directly to CSM attributes.

### 7.3 Evidence Provenance Contract
Every normalized field must record its provenance in `csm["raw_evidence"]`:
```json
{
  "field": "services.ssh_version",
  "value": 2,
  "source_lines": ["protocol-version v2;"],
  "confidence": 1.0
}
```

### 7.4 UNKNOWN and Error Behavior
- **Missing Sections:** If `ntp` or `snmp` is omitted from the Junos configuration, the corresponding CSM section remains empty/unconfigured. When evaluated, the control returns `ComplianceStatus.UNKNOWN`, never `FAIL`.
- **Unsupported Syntax:** Unknown statements are appended to `csm["unmapped_lines"]` for potential AI-assisted suggestion routing.

---

## 8. Control Mapping Strategy

Mapping existing controls to Juniper was analyzed using repository primary materials:
1. `07_Compliance_Scanners/Rule_Library/extracted/Rule_Library/vendor_rule_mapping.json` (which contains 10 prototype Junos rule stubs: `JUNOS-SSH-001` through `JUNOS-MGMT-001`)
2. `07_Compliance_Scanners/Rule_Library/extracted/Rule_Library/juniper_ssh_rule.json`
3. `05_Configuration_Datasets/Juniper/Juniper_Junos_Samples.zip` (synthetic Junos sample configuration)

### 8.1 Category Definitions
- **DIRECTLY PORTABLE:** Semantic requirement and normalized CSM fields are identical across Cisco and Juniper.
- **VENDOR-SEMANTIC:** Security requirement exists across both vendors, but requires Junos-specific parsing logic to populate the normalized field.
- **NOT YET MAPPABLE:** Insufficient verified primary documentation in the repository to define an authoritative compliance mapping.

### 8.2 Control Classification Table

| Common Rule ID | Vendor Rule ID | Title / Focus | Classification | Grounded Repository Evidence |
|---|---|---|:---:|---|
| `COMMON-SSH-001` | `JUNOS-SSH-001` | SSH Protocol Version 2 | **DIRECTLY PORTABLE** | `juniper_ssh_rule.json`: `protocol-version v2`. `sample_juniper_junos_configuration.conf` L12: `services { ssh { protocol-version v2; } }`. Maps directly to `services.ssh_version == 2`. |
| `COMMON-NTP-001` | `JUNOS-NTP-001` | NTP Authentication | **DIRECTLY PORTABLE** | `vendor_rule_mapping.json` L381-395: `set system ntp authentication-key`, `trusted-key`. Sample config L30: `system { ntp { server ... } }`. Maps to `ntp.authentication_enabled`. |
| `COMMON-LOG-001` | `JUNOS-LOG-001` | Remote Syslog & Timestamps | **DIRECTLY PORTABLE** | `vendor_rule_mapping.json` L397-412: `set system syslog host`, `time-format`. Maps to `logging.remote_logging_enabled`, `logging.timestamps_enabled`. |
| `COMMON-SNMP-001` | `JUNOS-SNMP-001` | Insecure SNMP Communities | **DIRECTLY PORTABLE** | `sample_juniper_junos_configuration.conf` L86: `snmp { community public { authorization read-only; } }`. Maps to `snmp.community_strings` with weak community check. |
| `COMMON-AAA-001` | `JUNOS-AAA-001` | AAA & Authentication Order | **VENDOR-SEMANTIC** | `vendor_rule_mapping.json` L364-379: `set system authentication-order`. Junos has no `aaa new-model`. Normalizer must synthesize `aaa.enabled` from presence of `authentication-order` / `login`. |
| `COMMON-ACL-001` | `JUNOS-ACL-001` | Management Access Filter | **VENDOR-SEMANTIC** | `vendor_rule_mapping.json` L431-445: Junos secures management via `firewall family inet filter protect-control-plane` on `lo0`, not Cisco VTY `access-class`. Normalizer must inspect control-plane firewall filters. |
| `COMMON-INT-001` | `JUNOS-INT-001` | Unused Interface Shutdown | **VENDOR-SEMANTIC** | `vendor_rule_mapping.json` L447-461: Junos disables interfaces via `disable;` statement under `interfaces <name>`. Normalizer must translate `disable;` to `shutdown = True`. |
| `COMMON-ROUTING-001`| `JUNOS-ROUTING-001` | Routing Peer Authentication| **VENDOR-SEMANTIC** | `vendor_rule_mapping.json` L463-477: `set protocols bgp ... authentication-key`. Maps to `routing.routing_authentication_enabled`. |
| `COMMON-STP-001` | `JUNOS-STP-001` | STP BPDU Protection | **VENDOR-SEMANTIC** | `vendor_rule_mapping.json` L479-493: `set protocols rstp ... bpdu-block`. Translates to `spanning_tree.bpduguard_enabled`. |
| `COMMON-MGMT-001` | `JUNOS-MGMT-001` | Management VRF Isolation | **VENDOR-SEMANTIC** | `vendor_rule_mapping.json` L495-509: Junos isolates via `routing-instances` virtual-router or dedicated `fxp0` management interface. |
| *Official CIS Junos*| *N/A* | CIS Juniper Junos Benchmark | **NOT YET MAPPABLE** | No CIS Juniper Benchmark PDF exists in `01_Compliance_Standards/CIS/`. |
| *Official DISA Junos*| *N/A* | DISA STIG Juniper Junos | **NOT YET MAPPABLE** | No DISA STIG Juniper XCCDF XML exists in `01_Compliance_Standards/DISA_STIG/`. |

---

## 9. Test Contract for Juniper Integration

Before any Juniper code is implemented, the verification test suite must be specified across all security and quality dimensions.

### 9.1 Parser Tests (`test_juniper_parser.py`)
- **Valid Hierarchical Config:** Parse `sample_juniper_junos_configuration.conf`. Verify 100% field extraction for device, interfaces, services, ntp, snmp, routing, firewall.
- **Valid Flat Set Config:** Parse `.set` syntax equivalent. Verify resulting CSM dictionary is identical to hierarchical parse.
- **Malformed Input:** Inject unmatched braces (`{` without `}`), garbage lines, binary noise. Must not raise unhandled exceptions; must append unmapped tokens to `csm["unmapped_lines"]`.
- **Empty / Comment-Only Config:** Parse empty string or comment blocks. Verify valid empty CSM with zero crash.
- **Determinism:** Execute parser 5 consecutive times on identical input; assert SHA-256 hash of serialized CSM is bitwise identical across all 5 runs.

### 9.2 CSM Compatibility Tests
- **Schema Validation:** Validate generated Juniper CSM against `07_Compliance_Scanners/Rule_Library/extracted/Rule_Library/normalized_config_schema.json`. Assert zero schema violations.
- **No Cisco Leakage:** Assert `device.vendor == "juniper"`, `device.platform == "Junos"`. Assert no Cisco-specific keys (`access-class`, `vty`) exist at root level.
- **Evidence Provenance:** Assert all normalized fields have corresponding `raw_evidence` entries with valid `source_lines`.

### 9.3 Compliance & Framework Tests
- **Deterministic Verdicts:** Unit test each Junos control evaluator against positive (Pass), negative (Fail), and missing (Unknown) CSM fixtures.
- **Registry Integration:** Verify registration of `juniper-junos-baseline` into `FrameworkRegistry`. Verify `.list()`, `.get()`, and `.get_evaluator()`.
- **Framework Isolation:** Verify evaluating a Cisco CSM against `juniper-junos-baseline` returns `UNKNOWN` (or is gracefully bypassed) without throwing exceptions.
- **Multi-Framework Aggregator Integration:** Verify `MultiFrameworkAggregator` aggregates Cisco and Juniper evaluation streams without conflict.

### 9.4 Security & Boundary Tests
- **AST Safety Assertions:** Run `ast_safety.assert_no_execution_imports()` against `juniper_auditor.py`. Must confirm zero `subprocess`, `os.system`, `socket`, `pty`, `paramiko`, `netmiko`.
- **AI Decision Authority Preservation:** Verify pass/fail compliance decisions for Juniper are 100% deterministic with zero LLM/AI dependency.
- **RBAC & Ownership:** Ingest Juniper configs as `uploader` and verify session ownership isolation and reviewer-gated approval workflows remain strictly enforced.

### 9.5 Regression Invariant
- **Zero Cisco Regressions:** All 325 existing tests must continue to pass with 0 failures and 0 regressions.

---

## 10. Architectural Risk Register

| Risk ID | Risk Description | Concrete Repository Evidence | Severity | Proposed Mitigation | Must Fix Before Juniper? |
|---|---|---|:---:|---|:---:|
| **RSK-01** | Ingestion upload path hardcodes Cisco parser | `main.py` L497: `csm = cisco_auditor.parse_cisco(text)` | **HIGH** | Add vendor parameter and auto-detection dispatcher to `POST /api/audit/upload`. | **YES** |
| **RSK-02** | Multi-framework evaluation overscoping | `main.py` L986-990: Runs all registered frameworks if `framework_ids` is None | **HIGH** | Scope evaluator execution: match `framework.vendor_scope` against `csm["device"]["vendor"]`. | **YES** |
| **RSK-03** | Third-party dependency trap for Juniper parsing | `03_Configuration_Parsers/Juniper/jnprsr-0.1.2.tar.gz` uses ANTLR4 & anytree | **HIGH** | Reject `jnprsr`. Write clean, stdlib-only recursive bracket & set tokenizer matching `cisco_auditor.py`. | **YES** |
| **RSK-04** | Missing authoritative Juniper CIS / STIG primary standards | `01_Compliance_Standards/` contains only Cisco PDFs and XMLs | **HIGH** | Restrict Juniper compliance scope to `vendor_rule_mapping.json` 10 Common Rules; do not claim official CIS/STIG numbers. | **YES** |
| **RSK-05** | Global trusted mappings lack vendor scoping | `database.py` L116: `trusted_mappings` schema has no `vendor` column | **MEDIUM** | Non-destructively migrate `trusted_mappings` to include nullable `vendor` column. | **YES** |
| **RSK-06** | AI suggester hardcodes Cisco baseline context | `ai_suggester.py` L73: `data["vendors"]["Cisco IOS-XE"]["rules"]` | **MEDIUM** | Parametrize `suggest_mapping()` to accept vendor identity and load matching vendor rules. | **NO** (Post-V2) |
| **RSK-07** | Remediation engine conflict analysis Cisco-specific | `remediation_engine.py` L60, L124: Hardcodes `CISCO-NTP-001` and "IOS-XE" | **LOW** | Remediation is display-only and keyed by `rule_id`. Junos templates will only be queried for Junos rules. | **NO** (Post-V2) |
| **RSK-08** | Hardcoded Cisco PDF filename and platform fallback | `report_generator.py` L23, L113: `"cisco_compliance_report.pdf"`, fallback `"IOS-XE"` | **LOW** | Parameterize PDF filename and dynamically format platform from `csm["device"]["platform"]`. | **NO** (Post-V2) |

---

## 11. Graphify Findings

Graphify was executed against the post-3R codebase (`graphify-out/graph.json`, 2497 nodes, 3921 edges).

```
                            [FrameworkRegistry] (Degree: 47)
                                    ▲
                                    │ (registers)
                         [FrameworkEvaluator] (Degree: 16)
                                    ▲
         ┌──────────────────────────┼──────────────────────────┐
         │ (inherits)               │ (inherits)               │ (inherits - TARGET)
[CisCiscoIosXeEvaluator]  [StigCiscoIosXeEvaluator]  [JunosBaselineEvaluator]
         │                          │                          │
         └──────────────────────────┼──────────────────────────┘
                                    │ (evaluates)
                                    ▼
                         [Normalized CSM Dict]
                                    ▲
                   ┌────────────────┴────────────────┐
                   │ (produces)                      │ (produces - TARGET)
         [cisco_auditor.py]                [juniper_auditor.py]
```

### Graph Analysis Insights:
1. **Central Hub Nodes for Vendor Onboarding:**
   - `FrameworkRegistry` (Degree 47): The primary registration clearinghouse.
   - `FrameworkEvaluator` (Degree 16): The abstract contract defining evaluation behavior.
   - `EvaluationResult`: The domain outcome currency consumed by the aggregator.
   - `MultiFrameworkAggregator`: The topological sink for evaluation streams.
2. **Modules with Strongest Cisco Coupling:**
   - `cisco_auditor.py`: Completely coupled to Cisco syntax. Must remain untouched as the isolated Cisco adapter.
   - `main.py`: Has direct inbound dependencies on `cisco_auditor` at L66, L497, L634, L959.
3. **Attachment Point for Juniper:**
   - **Parser Level:** Parallel sibling module `juniper_auditor.py` producing normalized CSM.
   - **Framework Level:** New `JunosBaselineEvaluator` inheriting from `FrameworkEvaluator` and registered in `FrameworkRegistry`.
   - **Zero graph cycles:** Adding these leaf nodes introduces no new cyclic dependencies into the graph.
4. **Components That Must Remain Untouched:**
   - `compliance_framework.py` (Core domain contracts and registry)
   - `compliance_aggregator.py` (Deterministic scoring and evidence aggregator)
   - `ast_safety.py` (Security AST import guard)
   - `auth.py` (Cryptographic JWT and password verification)
   - `cisco_auditor.py` (Cisco IOS-XE parser baseline)
   - `cis_benchmark_cisco_iosxe.py` & `disa_stig_cisco_iosxe.py` (Cisco benchmark evaluators)

---

## 12. Juniper Implementation Readiness

### READINESS VERDICT:
## **GO WITH REQUIRED PRECONDITIONS**

### Required Prerequisites Before Implementation Begins:
1. **Precondition 1 (Ingestion Dispatcher):** Refactor `POST /api/audit/upload` and `POST /api/compliance/evaluate` in `main.py` to route configuration text through a vendor dispatcher (`vendor_detector.py` or `get_parser(vendor)`), instead of directly calling `cisco_auditor.parse_cisco`.
2. **Precondition 2 (Framework Scope Guard):** In `main.py` (`POST /api/compliance/evaluate`), ensure that if `framework_ids` is not provided, the engine only selects frameworks whose `vendor_scope` matches the device vendor identified in the normalized CSM (`csm["device"]["vendor"]`).
3. **Precondition 3 (Stdlib Parser Mandate):** Implement `juniper_auditor.py` using **strictly Python standard library** (`re`, `json`). Do NOT attempt to install or extract `jnprsr-0.1.2.tar.gz` with external ANTLR4 dependencies.
4. **Precondition 4 (Grounded Rule Catalog):** Restrict initial Juniper compliance evaluation to the 10 verified prototype rules in `vendor_rule_mapping.json` (`JUNOS-SSH-001` through `JUNOS-MGMT-001`). Do NOT claim or fabricate official CIS or DISA-STIG catalog IDs for Juniper until authoritative primary source files are provided in `01_Compliance_Standards/`.
5. **Precondition 5 (Database Migration):** Add a nullable `vendor` column to `trusted_mappings` table in `database.py` to prevent cross-vendor leakage of custom reviewer-approved rules.

---

## 13. Recommended Next Implementation Sequence

When authorized to proceed with implementation in a subsequent task, execute the work in the following disciplined, atomic stages:

1. **Step 1: Ingestion & Dispatcher Layer Preparation**
   - Create lightweight, deterministic vendor detector (`detect_vendor(text: str) -> str`).
   - Wire dispatcher into `main.py` upload and evaluate routes.
   - Run existing test suite to verify 100% Cisco regression-free parity.
2. **Step 2: Database Schema Non-Destructive Migration**
   - Add nullable `vendor` column to `trusted_mappings` table.
3. **Step 3: Juniper Parser Development (`juniper_auditor.py`)**
   - Implement stdlib-only bracket and set tokenizer.
   - Populate normalized CSM matching `normalized_config_schema.json`.
   - Write unit tests in `test_juniper_parser.py` testing `sample_juniper_junos_configuration.conf`.
4. **Step 4: Juniper Baseline Framework Evaluator**
   - Implement `JunosBaselineEvaluator` inheriting from `FrameworkEvaluator`.
   - Implement deterministic evaluation for the 10 verified rules (`JUNOS-SSH-001`..`JUNOS-MGMT-001`).
   - Register framework `juniper-junos-baseline` into `FrameworkRegistry`.
5. **Step 5: End-to-End Multi-Vendor Pipeline Verification**
   - Write integration tests uploading both Cisco and Juniper configs in `test_api_multi_vendor.py`.
   - Verify multi-framework aggregation produces isolated, deterministic metrics for both vendors.
   - Verify all 325 baseline tests remain completely green.
