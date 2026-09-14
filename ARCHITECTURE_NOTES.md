# NTRO PS26155 MVP: Architecture Notes & Codebase Reference

**Project**: Network Device Configuration Compliance Auditor (NTRO Problem Statement 26155)  
**Implementation Scope**: PRD Addendum v4 §4 Steps 1 through 5  
**Version**: 1.0 (MVP Complete)  
**Date**: September 2026  

---

## 1. File Inventory & Pipeline Mapping

| File | PRD Step | Lines | External Dependencies | Primary Purpose / Role |
| :--- | :---: | :---: | :--- | :--- |
| `cisco_auditor.py` | Step 1 & 2 | 221 | None (stdlib only: `re`, `json`, `hashlib`, `pathlib`, `sys`) | Cisco IOS-XE parser, CSM normalizer, generic condition evaluator, and answer key checker. |
| `05_Configuration_Datasets/Cisco/labeled_test_config.txt` | Step 1 | 73 | None (raw CLI) | Canonical Cisco IOS-XE test config covering 10 baseline rules + 1 unmapped line (`service call-home`). |
| `05_Configuration_Datasets/Cisco/labeled_test_config_answers.json` | Step 1 | 12 | None (JSON) | Ground-truth answer key verifying baseline rule evaluation verdicts. |
| `ai_suggester.py` | Step 3 | 203 | `torch`, `transformers` (DistilBERT 66M) | Unmapped CLI line semantic interpreter, suggestion queue manager, and reviewer approval workflow. |
| `pending_suggestions.json` | Step 3 | 58 | None (JSON) | Append-only store for AI-generated rule suggestions awaiting human review. |
| `trusted_mappings.json` | Step 3 | 31 | None (JSON) | Approved custom rule mappings with mandatory version block (`version`, `approved_by`, `approved_at`, `source: "ai_suggested"`). |
| `remediation_engine.py` | Step 4 | 160 | `jinja2`, `torch`, `transformers` | Parameterized Jinja2 remediation CLI generator, static conflict analyzer, AST safety auditor, and plain-language explainer. |
| `templates/remediation/CISCO-NTP-001.j2` | Step 4 | 8 | Jinja2 syntax | Parameterized CLI remediation template enforcing NTP authentication on target peers. |
| `audit_log.py` | Step 5 | 118 | None (stdlib only: `hashlib`, `json`, `datetime`, `pathlib`) | Append-only cryptographic ledger (`audit_log.jsonl`) with canonical SHA-256 hash chaining, collision-free monotonic IDs, and tamper verification. |
| `audit_log.jsonl` | Step 5 | 2 | None (JSON Lines) | Cryptographically linked audit ledger entries recording configuration state, evaluation verdicts, and remediation actions. |
| `report_generator.py` | Step 5 | 332 | `reportlab`, `pypdf` | Enterprise compliance PDF certificate generator embedding visual status badges, vector QR code, and SHA-256 integrity hash. |
| `cisco_compliance_report.pdf` | Step 5 | Binary | PDF | Generated, tamper-verifiable compliance certificate for `EDGE-RTR-01`. |
| `test_step5_full_loop.py` | Steps 1–5 | 260 | All dependencies | Consolidated canonical test suite verifying all 17 integration stages, SNMP/NTP edge-cases, AST safety audit, reviewer correction/rejection workflows, and performance benchmarks. |

---

## 2. Known Implementation Limitations

The following three design limitations were identified during the MVP development. These represent intentional scoping decisions under the lazy senior developer (`ponytail`) discipline and PRD MVP boundaries, with clear upgrade paths for Phase 2:

### Limitation 1: Rule `CISCO-INT-001` Description String Matching Fragility
- **Current Logic**: `cisco_auditor.py` checks whether an interface is administratively shutdown (`shutdown`) or if its description contains the literal substring `"unused"` (case-insensitive).
- **Fragility**: Real-world enterprise configurations employ diverse naming conventions for unused interfaces, such as `"SHUT"`, `"FREE"`, `"AVAILABLE"`, `"PARKED"`, `"SPARE"`, `"DECOMMISSIONED"`, or leave the description completely empty while setting `shutdown`.
- **Impact**: Unused ports without the specific token `"unused"` rely solely on their admin status. Active ports accidentally containing `"unused"` in a description tag could be misclassified.
- **Phase 2 Upgrade Path**: Migrate from substring heuristics to a formal interface state tuple:
  `{admin_status: bool, operational_status: Optional[bool], vlan_assigned: Optional[int], description_tags: list[str]}`. Interface compliance should evaluate against a user-configurable regex list or an explicit IP/VLAN reservation manifest.

### Limitation 2: Rule `CISCO-ROUTING-001` BGP-Only Protocol Scope
- **Current Logic**: `cisco_auditor.py` inspects `csm["routing"]["bgp"]["neighbors"]` to verify that all active BGP peers enforce authentication via `neighbor <ip> password <secret>`.
- **Limitation**: The rule does not inspect Interior Gateway Protocols (IGP) such as OSPF (`ip ospf message-digest-key`, `ip ospf authentication`), EIGRP (`ip authentication mode eigrp`), or IS-IS (`isis password`).
- **Impact**: Routing protocol authentication is only partially evaluated if the target device operates multi-protocol routing or runs OSPF/EIGRP without BGP.
- **Phase 2 Upgrade Path**: Expand `csm["routing"]` into discrete protocol blocks (`ospf`, `eigrp`, `isis`, `bgp`). Introduce sibling rule IDs: `CISCO-OSPF-001` (OSPF MD5/HMAC authentication) and `CISCO-EIGRP-001` (EIGRP keychain authentication), reusing the generic condition evaluator.

### Limitation 3: Template-Engineered vs. Open-Ended Generative AI Explanations
- **Current Logic**: `remediation_engine.py` generates failure explanations and remediation rationales using deterministic, domain-grounded explanation templates combined with local transformer feature extraction (`distilbert-base-uncased`) and contextual parameter injection, rather than unconstrained generative language model token decoding.
- **Rationale & Benefits**:
  1. **Strict Determinism**: Guarantees that running the explainer multiple times on the same audit result yields consistent, reproducible security findings (meeting PRD Acceptance Criterion #1).
  2. **Hallucination Elimination**: Avoids fabricating phantom CLI syntax, nonexistent CVE IDs, or false security advice.
  3. **Zero Runtime Drift**: Ensures offline execution on CPU without requiring 8GB+ GPU VRAM or cloud API egress (PRD Addendum §2 & §3).
  4. **Safety Enforcement**: Remediation remains strictly display-only; no generative model can emit hallucinated shell commands that trigger device side-effects.
- **Limitation**: Output text follows structured technical patterns rather than free-form conversational interaction. If an operator asks arbitrary conversational questions, the engine does not provide multi-turn dialogue.
- **Phase 2 Upgrade Path**: For multi-turn conversational operator assistance, mount a quantized local small language model (e.g., Llama-3-8B-Instruct via `llama.cpp` / ONNX Runtime) restricted to a read-only RAG pipeline indexing `01_Compliance_Standards/` and `06_Framework_Mappings/`.

---

## 3. Phase 2 Vendor Extension Architecture

The PS26155 platform is engineered to support multi-vendor network compliance without refactoring the core evaluation engine, audit ledger, or reporting subsystem.

```
+-----------------------------------------------------------------------------------+
|                                VENDOR PARSERS                                     |
|                                                                                   |
|   +---------------------+   +---------------------+   +-----------------------+   |
|   |   Cisco IOS-XE      |   |   Juniper JunOS     |   |      Arista EOS       |   |
|   |  cisco_auditor.py   |   |  juniper_auditor.py |   |   arista_auditor.py   |   |
|   +----------+----------+   +----------+----------+   +-----------+-----------+   |
+--------------|-------------------------|--------------------------|---------------+
               |                         |                          |
               +-------------------> +---v----+ <-------------------+
                                     |  CSM   |
                                     +---+----+
                                         |
+----------------------------------------v------------------------------------------+
|                     SHARED CORE COMPLIANCE PLATFORM (UNCHANGED)                   |
|                                                                                   |
|  1. Common Schema Model (CSM JSON matching normalized_config_schema.json)        |
|  2. vendor_rule_mapping.json (Rules keyed by vendor, sharing common_rule_id)     |
|  3. Generic Condition Evaluator (resolve_csm_path() + eval_condition())          |
|  4. AI Interpretation & Reviewer Approval (ai_suggester.py -> trusted_mappings)   |
|  5. Cryptographic Hash-Chained Audit Ledger (audit_log.py -> audit_log.jsonl)    |
|  6. Tamper-Verifiable PDF Report Generator (report_generator.py)                 |
+-----------------------------------------------------------------------------------+
```

### Extension Contract & Current State: How New Vendors Plug In

#### Literal Current State in `vendor_rule_mapping.json`:
- **Current Entries**: The schema file defines top-level keys for `"Cisco IOS-XE"`, `"Juniper Junos"`, and `"Arista EOS"`. Under `"Juniper Junos"` and `"Arista EOS"`, 10 rule stubs are listed (`JUNOS-SSH-001`..`JUNOS-MGMT-001` and `ARISTA-SSH-001`..`ARISTA-MGMT-001`) with prototype metadata (`common_rule_id`, `vendor_rule_id`, `configuration_evidence`, `check_focus`, and `status: "prototype"`).
- **Not Yet Populated / Deferred**: Neither vendor entry has `frameworkMappings`, nor do they contain runtime condition fields (`csmFieldChecked`, `condition`). Furthermore, no vendor parsers (`juniper_auditor.py`, `arista_auditor.py`) or test datasets exist in the current codebase. As explicitly mandated by PRD Addendum §4, multi-vendor support is deferred to Phase 2; the MVP focuses exclusively on proving the full compliance pipeline on Cisco IOS-XE.

#### Phase 2 Plug-in Architecture:
Adding a new vendor (e.g., **Juniper Junos** or **Arista EOS**) requires adding the parser and populating condition rules without modifying the core compliance engine:

1. **Write the Vendor Parser (`<vendor>_auditor.py`)**:
   - Ingests vendor-specific CLI configuration text (e.g., hierarchical curly-brace syntax for JunOS, EOS CLI for Arista).
   - Normalizes extracted state into standard **CSM JSON** defined in:
     `07_Compliance_Scanners/Rule_Library/extracted/Rule_Library/normalized_config_schema.json`.
   - Emits `{csm: dict, unmapped_lines: list[str], raw_evidence: dict}`.

2. **Populate Vendor Rules in `vendor_rule_mapping.json`**:
   - Upgrade the prototype stubs under `"Juniper Junos"` and `"Arista EOS"` to include `csmFieldChecked`, `condition`, and `frameworkMappings`.
   - Each vendor rule maps to the same internal `common_rule_id` (e.g., `COMMON-SSH-001`, `COMMON-NTP-001`).

3. **Generic Evaluator Reusability**:
   - The generic condition evaluator functions in `cisco_auditor.py`:
     `resolve_csm_path(csm: dict, path: str)` and `eval_condition(val: any, cond: str) -> str`
     are completely vendor-agnostic. They evaluate dot-paths against CSM JSON directly.
   - For Phase 2, `resolve_csm_path` and `eval_condition` extract cleanly into a shared `evaluator_core.py` reused across all vendor pipelines.

4. **Audit Ledger & PDF Immutability**:
   - `audit_log.py` takes `{device_hostname, config_file_hash, audit_results, remediation_summary}`. It does not inspect vendor specifics.
   - `report_generator.py` formats the evaluated results table dynamically based on the rule list, rendering identical cryptographic certificates regardless of underlying hardware.

