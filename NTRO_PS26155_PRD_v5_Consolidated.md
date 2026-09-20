# AI-Driven Multi-Vendor Network Security Compliance Auditor
### Product Requirements Document — v5.0 (Consolidated: Hybrid Architecture + Gap Closures)
**Problem Statement ID:** NTRO PS 26155
**Category:** Software / Cybersecurity
**Sponsoring Org:** National Technical Research Organisation (NTRO)
**Prepared by:** Balraju Konne & Team | SIH 2026

**This document supersedes v4 and its addendum by merging them and adding solutions to ten previously identified gaps (§18–§23). No prior content has been removed; gaps are closed with new or expanded sections.**

---

## 1. Positioning

This is a **hybrid, offline-first compliance auditor**: a local AI model handles semantic interpretation of unfamiliar CLI syntax and plain-language explanation of findings, while a separate, deterministic rule engine handles all security verification and pass/fail decisions.

> **Final architecture statement:** Local AI handles unfamiliar configuration interpretation and explanations. Human approval converts suggestions into trusted mappings. A deterministic CSM-based rule engine performs compliance evaluation. Approved Jinja2 templates generate remediation. Static analysis flags known conflicts. No AI output directly decides compliance or executes commands.

The division of labor is deliberate and non-negotiable:
- **AI interprets. Rules decide.** The AI model never determines compliance status and never marks anything pass/fail.
- **AI suggests. A human approves.** Any new CLI-to-security-field mapping sits pending until an authorized reviewer confirms it (see §19 for the role model).
- **AI explains. Nothing auto-executes.** No AI-generated or AI-modified command is ever applied to a device automatically.

---

## 2. Problem Statement

- **Syntactic diversity** — one security policy needs different CLI syntax per vendor, and no static template library can anticipate every variant.
- **Manual, error-prone audits** — human review of CLI dumps misses drift and vulnerabilities.
- **Fragile parsers** — static regex/TextFSM templates break on unfamiliar syntax with no recovery path except a developer patch.
- **No trust story** — cloud-LLM tools are a non-starter for sensitive network infrastructure; this design keeps AI local and clearly bounded.

---

## 3. Goals & Non-Goals

**Goals**
- Vendor-agnostic auditing across a defined initial vendor set (Cisco, Juniper, Fortinet), architecture built to extend — not claimed as universal.
- Cut manual audit time substantially.
- AI-assisted interpretation of unmapped CLI syntax, always human-gated before being trusted.
- Vendor-exact remediation with plain-language AI explanation, passed through a deterministic conflict check.
- A fully offline core pipeline, deployed on-premises (see §18).

**Non-Goals (MVP)**
- Auto-applying any remediation, AI-generated or otherwise.
- Claiming complete vendor agnosticism or full framework coverage.
- Claiming the conflict checker guarantees remediation safety.
- Multi-tenant SaaS delivery.

---

## 4. Personas & Core Use Cases

| Persona | Role | Primary Goal |
|---|---|---|
| Network Security Admin | Operates multi-vendor firewalls/routers | Bulk audits, drift detection, remediation with rationale |
| Compliance Officer | Verifies regulatory alignment | Tamper-evident PDF reports with CIS/NIST/STIG scores |
| Network Architect | Onboards new hardware | Teaches system new syntax via AI-assisted mapping, human-reviewed |
| Authorized Reviewer *(new — see §19)* | Sole approver of pending AI mapping suggestions in MVP | Keeps the mapping library trustworthy without adding process overhead |

---

## 5. Scope

### In-Scope (MVP)
- Bulk file upload (.cfg/.txt/.conf).
- TextFSM/TTP parsing (`ntc-templates`) into a Common Security Model (CSM).
- Local AI model (Qwen2.5-7B or Llama-3.1-8B GGUF, via Ollama/llama.cpp) for semantic interpretation of unmapped lines and plain-language explanations.
- Interactive training loop: AI suggests → one authorized reviewer approves → mapping trusted platform-wide (§19).
- Deterministic rule engine, shared internal-rule/multi-framework model (§17).
- Explicit three-state result model: **Pass / Fail / Unknown**.
- Vendor-exact Jinja2 remediation + AI explanation + deterministic conflict check with a defined pattern scope (§21).
- Config snapshot before/after for rollback reference.
- Hash-chained, tamper-evident audit log + PDF report with embedded verification hash.
- Fail-closed logic throughout.
- On-premises deployment via Docker (§18).

### Out-of-Scope (Roadmap)
- Auto-push of remediation to live devices.
- Live SSH pull during hackathon demo.
- Full network-reachability simulation (Batfish-class tooling).
- Multi-tenant / MSSP mode.
- Two-reviewer approval workflow (deferred to production-hardening, see §19).

---

## 6. Functional Requirements

**Module 1 — Ingestion**
- FR-1.1: Drag-and-drop bulk upload of raw CLI config files.
- FR-1.2: Vendor auto-detection based on syntax signatures.
- FR-1.3: Per-file ingestion status tracking.
- FR-1.4: File-level validation and sanitization before parsing (§20).

**Module 2 — Normalization**
- FR-2.1: TextFSM/TTP templates convert raw CLI to structured JSON.
- FR-2.2: CSM mapping to a defined internal schema.
- FR-2.3: Unparseable lines retained verbatim, flagged, routed to AI interpretation — never dropped.

**Module 3 — AI-Assisted Semantic Mapping & Training Loop**
- FR-3.1: Unmapped CLI lines sent to the local AI model for semantic interpretation.
- FR-3.2: AI proposes a candidate CSM field with a stated confidence score and short rationale.
- FR-3.3: Authorized reviewer accepts, corrects, or rejects the suggestion via GUI.
- FR-3.4: Accepted mappings are approved by the one designated authorized reviewer for MVP (§19); versioned with author + timestamp.
- FR-3.5: Approved mappings enter the deterministic template library — future matches skip the AI call entirely.
- FR-3.6: Every mapping suggestion and approval records the AI model name, version, and checksum active at suggestion time (§22).
- FR-3.7: A newly proposed mapping that conflicts with an existing approved mapping is flagged for reviewer re-approval, never silently overwritten (§23).

**Module 4 — Compliance Audit Engine (fully deterministic)**
- FR-4.1: Evaluate CSM data against internal rules, each mapped to one or more framework control IDs (§17).
- FR-4.2: Explicit Pass / Fail / Unknown matrix — Unknown is first-class, never silently defaulted.
- FR-4.3: Each result links to the exact config line(s) used as evidence.
- FR-4.4: No AI model participates in this module.

**Module 5 — Remediation & Reporting**
- FR-5.1: Vendor-exact CLI remediation via Jinja2 templates.
- FR-5.2: Each remediation passes through the deterministic conflict checker with a defined pattern scope (§21).
- FR-5.3: AI-generated plain-language explanation accompanies each remediation.
- FR-5.4: Config snapshot stored automatically before manual apply.
- FR-5.5: Executive PDF report with embedded hash/QR, re-verifiable against the audit log.
- FR-5.6: No remediation command is ever executed automatically.

**Module 6 — Access & Data Governance *(new)***
- FR-6.1: Role-based access control (§19).
- FR-6.2: Configurable data retention and deletion policy (§20 note: ingestion validation; retention itself at §20b).
- FR-6.3: Audit log backup and recovery procedure (§24 numbering absorbed into §23 as final gap item — see below).

---

## 7. Non-Functional Requirements

| Category | Requirement |
|---|---|
| Security | No configuration data leaves the deployment boundary at any stage; AI runs entirely on-device. |
| Boundary of AI influence | AI may propose mappings and generate explanations; it may never determine pass/fail/unknown and never generates an auto-executed command. Enforced architecturally, not by convention. |
| Deterministic performance | Parse + rule-evaluate a 2,000-line config in under 5 seconds on a defined reference machine (4-core / 8GB RAM, no GPU). |
| AI-assisted performance | No hard latency claim; report a measured range (e.g. "X–Y seconds per unmapped line") from actual testing on reference hardware — not asserted. |
| Auditability | Hash-chained audit log; independently verifiable via a standalone script; backup procedure defined (§23). |
| Accuracy | Mapping-suggestion and audit-control accuracy measured against a labeled test set, reported as tested numbers. |
| Fail-safety | No control auto-marked compliant on incomplete input; no remediation auto-applied regardless of AI confidence. |

---

## 8. Deterministic Conflict Checker

Before any remediation is generated, the system builds a lightweight in-memory model of the device's existing rules from parsed CSM data and checks the proposed change against a **defined set of conflict pattern categories** (§21). Results are labeled **"Review Required — Potential Conflict Detected"** or **"No Conflicts Detected"** (never "Safe to Apply," since absence of a checked pattern isn't proof of absence of all issues). Full network-reachability simulation is a stated Roadmap item, not silently substituted.

---

## 9. Tamper-Evident Audit Trail

Each audit run produces `{timestamp, deviceId, configHash, resultHash, prevEntryHash}`, chained via SHA-256. The PDF report embeds a QR/hash independently re-verifiable against the log. This module involves no AI. Backup/recovery procedure defined in §23.

---

## 10. Data Model (Core Objects)

```json
// Device Inventory
{
  "deviceId": "UUID",
  "vendor": "cisco | juniper | fortinet",
  "hostname": "String",
  "lastAuditId": "UUID"
}

// Internal Rule — shared across frameworks (see §17)
{
  "ruleId": "INTERNAL-SSH-001",
  "internalTitle": "SSH protocol version must be 2",
  "csmFieldChecked": "csm.ssh.version",
  "condition": "equals 2",
  "implementationLogic": "String | function ref",
  "frameworkMappings": [
    { "framework": "CIS", "controlId": "CIS-5.2.1", "sourceRef": "URL" },
    { "framework": "NIST-800-53", "controlId": "AC-17", "sourceRef": "URL" },
    { "framework": "DISA-STIG", "controlId": "V-220xxx", "sourceRef": "URL" }
  ]
}

// Audit Record
{
  "auditId": "UUID",
  "deviceId": "UUID",
  "timestamp": "ISO-8601",
  "results": [
    { "ruleId": "INTERNAL-SSH-001", "status": "pass | fail | unknown", "evidenceRef": "String" }
  ],
  "complianceScore": "Integer",
  "logHash": "SHA-256",
  "prevLogHash": "SHA-256"
}

// Remediation Suggestion
{
  "ruleId": "INTERNAL-SSH-001",
  "vendorCommand": "String",
  "aiExplanation": "String",
  "aiModelVersion": "String",
  "conflictCheckResult": "no_conflicts_detected | conflict_detected",
  "conflictPatternMatched": "String | null",
  "autoApplied": false
}

// AI Mapping Suggestion (pending review)
{
  "suggestionId": "UUID",
  "rawConfigLine": "String",
  "suggestedCsmField": "String",
  "aiConfidence": 0.0,
  "aiRationale": "String",
  "aiModelName": "String",
  "aiModelVersion": "String",
  "aiModelChecksum": "String",
  "status": "pending | approved | rejected | superseded",
  "reviewedBy": "String | null",
  "conflictsWithMappingId": "UUID | null"
}

// User / Role (new — see §19)
{
  "userId": "UUID",
  "role": "uploader | reviewer | viewer",
  "isAuthorizedApprover": "Boolean"
}
```

---

## 11. Technology Stack

| Layer | Choice | Notes |
|---|---|---|
| Frontend | React (Vite) | |
| Backend API | Python FastAPI | |
| Parsing | TextFSM, TTP, `ntc-templates` | |
| Local AI model | Qwen2.5-7B-Instruct or Llama-3.1-8B-Instruct (GGUF), via Ollama/llama.cpp | Licensing addressed in §22 |
| Audit rule engine | Custom Python, shared internal-rule model (§17) | Fully deterministic |
| Conflict checker | Custom rule-comparison logic, defined pattern scope (§21) | |
| Database | PostgreSQL (or SQLite for demo) | |
| Remediation templating | Jinja2 | |
| PDF reports | ReportLab or WeasyPrint | |
| Hashing / audit chain | Python `hashlib` (SHA-256) | |
| Auth | JWT-based, with role claims (§19) | |
| Deployment | Docker / Docker Compose, on-premises (§18) | |

---

## 12. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Local AI model slow/inconsistent on demo hardware | Medium | AI invoked only for unmapped lines; pre-warm model; measured range not a hard claim (§7) |
| AI suggests an incorrect mapping | Low-Medium (by design) | Human approval required before trust (FR-3.3/3.4) |
| Conflict checker misses a pattern outside its defined scope | Medium | Scope explicitly enumerated and disclosed (§21); full simulation on Roadmap |
| Curated control subset looks incomplete | Low | Framed as deliberate, disclosed MVP scope; shared-rule architecture is directly extensible |
| CIS Benchmark licensing | Medium | Reference by control ID only; schema has no field for benchmark text (§10, §17) |
| Learned mapping poisoning | Medium | Review/approve gate, versioning, conflict flagging on new mappings (FR-3.7) |
| False pass/fail from parser/mapping gaps | High | Explicit fail-closed "Unknown" state |
| Malformed/oversized upload | Medium | Ingestion validation and limits (§20) |
| Audit log loss/corruption | Medium | Backup and recovery procedure (§23) |
| AI model license non-compliance | Low | License terms confirmed and stated (§22) |

---

## 13. Roadmap (Post-Hackathon)

- Full network-reachability simulation, upgrading the scoped conflict checker.
- Live SSH pull (Netmiko/Paramiko) with encrypted credential vault.
- Two-reviewer / cool-down approval workflow for production hardening.
- Expanded vendor and control-framework coverage.
- Multi-tenant mode with per-tenant data isolation.
- Optional, explicitly-gated auto-remediation push — still never AI-triggered.
- Continuous drift monitoring.
- Offline installer media (USB-based) for classified/air-gapped environments (§18).

---

## 14. Build Order — Single-File, Single-Path First

1. Upload one Cisco config → parse → normalize to CSM.
2. Evaluate against ~10–15 internal rules → explicit Pass/Fail/Unknown output.
3. One deliberately-unmapped line → AI suggests mapping + rationale → authorized reviewer approves → re-audits correctly.
4. One failed control → Jinja2 remediation + AI explanation + conflict check result.
5. Audit log entry (hash-chained) + PDF report with embedded verification hash.

Test this full loop repeatedly before adding a second vendor, second config file, or additional controls.

---

## 15. MVP Acceptance Criteria

- [ ] Same config file produces identical parse/audit output across 5+ consecutive runs.
- [ ] At least one control resolves to each of Pass, Fail, and Unknown in the demo dataset.
- [ ] One intentionally-unmapped line is correctly routed to AI interpretation and only applied after authorized-reviewer approval.
- [ ] Rejecting/correcting an AI suggestion works without corrupting the audit result.
- [ ] At least one failed control produces remediation + AI explanation + conflict-check result.
- [ ] No remediation command executes automatically anywhere — confirmed by code review.
- [ ] Audit log entry is hash-chained correctly and independently verifiable via a standalone script.
- [ ] PDF report's embedded hash re-verifies against the stored log entry.
- [ ] Full loop completes in one uninterrupted run.
- [ ] Deterministic-path performance number and AI-assisted-path range are both measured and recorded.
- [ ] Full workflow completes with Wi-Fi disabled on the demo machine (§18 offline proof).
- [ ] Ingestion rejects an oversized/malformed file gracefully without crashing (§20).
- [ ] Audit log backup/restore procedure has been run at least once successfully (§23).

---

## 16. What We Are Not Claiming

- Not complete vendor agnosticism — a defined, disclosed initial vendor set.
- Not full compliance-framework coverage — a defined, disclosed control subset per framework.
- Not a guarantee of remediation safety — a defined-scope conflict checker that reduces risk and surfaces known conflict patterns.
- Not fully deterministic end-to-end — the AI interpretation layer is probabilistic by nature; every one of its outputs is human-gated before it can affect a trusted result, which is how the system remains reliable despite this.
- Not a substitute for full network-reachability simulation — that remains a stated Roadmap upgrade.
- Not multi-tenant, not auto-remediating, not live-SSH-connected in this MVP.

---

## 17. Shared Internal-Rule / Multi-Framework Model

One technical check often satisfies requirements across multiple frameworks simultaneously (e.g., "SSH must use protocol version 2" maps to a CIS control, a NIST 800-53 control, and a DISA STIG item at once). Rather than duplicating logic per framework:

- Each **internal rule** is built and tested once, with `implementationLogic` as the single source of truth.
- Each rule carries a `frameworkMappings` array listing every framework control ID it satisfies, with a source link.
- **No benchmark text is ever stored** — only control ID, a short internal title written by the team, the source reference link, and the team's own implementation logic. This makes CIS-licensing safety a structural property of the schema (§10), not a policy reminder that could be forgotten.
- This reduces build and test surface roughly threefold versus maintaining separate CIS/NIST/STIG rule sets, and gives a stronger architecture answer if a judge asks how framework overlap is handled.

---

## 18. Deployment Model

**The system is deployed on-premises, inside the customer's own network boundary — never as a service the team hosts or operates.**

- **Packaging:** the full stack (FastAPI backend, React frontend, local AI model, database) ships as a Docker Compose bundle. One command (`docker-compose up`) brings up the entire application on the customer's own machine or local server.
- **Access:** users reach the application via `localhost` or an internal LAN address (e.g., `192.168.x.x:3000`) — never a public URL. No internet hop is involved in normal use, which is what makes the offline claim true at the point of access, not just at the point of processing.
- **Setup vs. runtime:** initial setup (pulling the Docker image, downloading AI model weights) requires internet once. After that, the system runs and is used indefinitely with no network connection required — this distinction is stated explicitly to avoid ambiguity in Q&A.
- **Classified/air-gapped environments (Roadmap):** for environments where even the one-time internet setup is unacceptable, an offline installer on physical media (USB) is a stated future option, carrying the full Docker image and model weights pre-downloaded.
- **Demo proof:** the full end-to-end workflow (§14) is run once with Wi-Fi enabled for setup, then re-run with Wi-Fi disabled to demonstrate the offline claim directly rather than asserting it.

---

## 19. Access Control / Role Model

Three roles, enforced via JWT claims:

| Role | Permissions |
|---|---|
| **Uploader** | Upload configs, view own audit results and reports |
| **Authorized Reviewer** | All Uploader permissions + approve/reject/correct pending AI mapping suggestions (FR-3.3/3.4) |
| **Viewer** | Read-only access to reports and audit history, no upload or approval rights |

**MVP simplification:** exactly **one designated Authorized Reviewer** account approves all pending mappings — no two-reviewer or cool-down workflow in MVP (that returns as a Roadmap item for production hardening). This removes process complexity without weakening the safety principle: every AI suggestion still requires a real human decision before it's trusted, it's just made by one accountable, named role instead of a multi-party process the hackathon timeline can't support.

---

## 20. Ingestion Security & Validation

- **File type allow-list:** only `.cfg`, `.txt`, `.conf` accepted; anything else rejected with a clear error, never silently processed.
- **Size limit:** a defined maximum file size (e.g., 10MB) rejected gracefully above that threshold, preventing resource exhaustion on ingestion.
- **Content sanitization:** uploaded files are treated strictly as text data for parsing — never executed, evaluated, or interpreted as code at any stage.
- **Malformed input handling:** a corrupted or unparseable file produces a clear per-file error status, not a pipeline crash — consistent with the fail-closed principle applied elsewhere (FR-4.2).
- **Timeout protection:** ingestion/parsing of any single file is bounded by a timeout, so one pathological file can't stall the whole queue.

### 20b. Data Retention & Deletion Policy

- **Raw uploaded configs and snapshots:** retained for a configurable period (default: 90 days), after which they are automatically purged unless explicitly flagged for retention by a Viewer/Reviewer.
- **Audit records and hash-chain entries:** retained indefinitely by default, since their value is historical/tamper-evidence — but exportable and prunable under an explicit admin action for storage management.
- **Manual deletion:** an authorized reviewer can request deletion of a specific device's data; the action itself is logged (who, when) so deletion doesn't create a silent gap in the audit trail.
- **Demo data statement:** all configs used in demonstration and testing are synthetic or anonymized, containing no real customer or production network data (§20c below expands this).

### 20c. Demo Data Sourcing

All sample configuration files used for development, testing, and the hackathon demo are either hand-authored synthetic configs or drawn from publicly available vendor documentation examples — never real production or customer network data. This is stated explicitly in the PPT/demo script, both as good practice and as a pre-emptive answer to an obvious judge question for a security-themed product.

---

## 21. Conflict Checker — Defined Pattern Scope

The deterministic conflict checker evaluates a proposed remediation against the existing rule model for these specific, enumerated pattern categories (MVP scope — extensible on Roadmap):

1. **Direct contradiction** — new rule and an existing rule apply the opposite action (`allow` vs `deny`) to the same source/destination/service tuple.
2. **Shadowing** — new rule would never take effect because a broader existing rule earlier in evaluation order already matches the same traffic.
3. **Overlap without full contradiction** — new rule's address/port range partially overlaps an existing rule in a way that changes effective access, even if not a direct contradiction.
4. **Redundancy** — new rule duplicates an existing rule with no net effect (flagged as informational, not a safety conflict).

Anything outside these four categories is **not guaranteed to be caught** — this limitation is stated plainly in §16 and §8, not left implicit. Full reachability simulation (Roadmap) is what closes this gap completely.

---

## 22. AI Model Licensing

- **Qwen2.5-7B-Instruct** (Apache 2.0 license) and **Llama-3.1-8B-Instruct** (Meta's Llama 3.1 Community License) are the two candidate local models; both permit local inference and internal deployment use, which is exactly this product's use case.
- **No model weights are redistributed** as part of the product — each deployment downloads its own copy directly from the official source (Ollama library / Hugging Face) during one-time setup, keeping the team clear of any redistribution-specific license terms.
- **License terms are re-verified before final submission**, since terms can be updated by the model provider; the chosen model's current license text is checked against actual usage (local inference, no redistribution, internal tool) rather than assumed.
- This mirrors the same discipline already applied to CIS benchmark licensing (§17) — the team treats third-party content/model terms as a first-class check, not an afterthought.

---

## 23. Mapping Conflict Resolution & Audit Log Backup/Recovery

### Mapping Conflict Resolution
When a newly proposed AI mapping suggestion would conflict with an already-approved mapping (e.g., two different interpretations of a similar syntax pattern over time):
- The new suggestion is marked with `conflictsWithMappingId` pointing to the existing approved mapping.
- It is **not** auto-resolved in either direction — it's routed to the Authorized Reviewer as a flagged decision, showing both the existing and proposed mapping side by side.
- If the reviewer approves the new one, the old mapping's status becomes `superseded` (not deleted — preserved for audit history) and is timestamped.
- This prevents silent mapping drift, which was the original gap — every change in interpretation is a visible, attributed decision.

### Audit Log Backup & Recovery
- The hash-chained audit log is periodically backed up to a secondary local location (e.g., a separate disk or directory on the same on-prem deployment) — since the system is offline by design, backup is local/on-prem as well, not cloud-based.
- Because each entry embeds the hash of the previous entry, a restored backup can be **integrity-verified** independently — if the chain is intact, the backup is provably untampered.
- Recovery procedure: restore the backup file, re-run the standalone chain-verification script, confirm the last entry's hash matches the most recent PDF report's embedded hash before resuming normal operation.
- This closes the gap of "what happens if the log store is lost" with a concrete, testable procedure rather than leaving it unaddressed.

---

*This v5 PRD consolidates the hybrid AI/deterministic architecture (v4), the MVP refinements (addendum), and closes ten structural gaps: deployment model, access control, data retention, AI model versioning, ingestion security, mapping conflict resolution, conflict-checker pattern scope, demo data sourcing, audit log backup/recovery, and AI model licensing. Every claim in this document is scoped, disclosed, and — where possible — demo-provable rather than merely asserted.*
