# Addendum to v4.0 — Refinements for MVP Build
**Applies to:** NTRO_PS26155_PRD_v4_Hybrid.md
**Status:** v4 remains the product vision and full architecture. This addendum adjusts five specific points and adds MVP acceptance criteria. It does not replace v4.

---

## Final Architecture Statement (supersedes §1 positioning language, rest of §1 stands)

> Local AI handles unfamiliar configuration interpretation and explanations. Human approval converts suggestions into trusted mappings. A deterministic CSM-based rule engine performs compliance evaluation. Approved Jinja2 templates generate remediation. Static analysis flags known conflicts. No AI output directly decides compliance or executes commands.

This is the most balanced reading of the problem statement — AI is not removed, but it is structurally prevented from becoming an unsafe or unreliable security authority. Every change below serves this statement.

---

## 1. Shared internal-rule / multi-framework model (revises §10 Data Model)

Replace per-framework duplicate rule definitions with one internal rule mapped to multiple framework references. Build and test the rule once; it reports against CIS/NIST/STIG simultaneously.

```json
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
```

Never store benchmark text itself — only control ID, your own short internal title, source link, and your own implementation logic. This makes the copyright-safety requirement structural rather than a policy note.

## 2. Split performance requirement (revises §7)

Deterministic path and AI-assisted path get separate, honestly-scoped numbers — do not bundle them:

| Path | Requirement |
|---|---|
| Deterministic (parse + rule-evaluate, Modules 2 & 4) | Evaluate a 2,000-line config in under 5 seconds on a defined reference machine (state exact spec, e.g. 4-core / 8GB RAM, no GPU) |
| AI-assisted (unmapped-line interpretation, Module 3) | No hard latency claim — report actual measured range from testing (e.g. "X–Y seconds per unmapped line on reference hardware"), since local-model latency is hardware-dependent |

State methodology: number of test runs, config sizes used, hardware used. A measured range beats an unverified target.

## 3. Simplified approval — one authorized reviewer for MVP (revises FR-3.4)

Drop the two-reviewer / cool-down design for MVP. One designated authorized reviewer approves a pending AI mapping suggestion before it's trusted platform-wide. Still versioned with author + timestamp. Two-reviewer workflow moves to Roadmap as a production-hardening item — it adds process complexity without adding build value for a single-admin hackathon demo.

## 4. Build order — single-file, single-path first

Do not build multi-vendor or multi-control breadth before this path is solid:

1. Upload one Cisco config → parse → normalize to CSM.
2. Evaluate against ~10–15 internal rules → explicit Pass/Fail/Unknown output.
3. One deliberately-unmapped line → AI suggests mapping + rationale → reviewer approves → re-audits correctly.
4. One failed control → Jinja2 remediation + AI plain-language explanation + static conflict check result.
5. Audit log entry (hash-chained) + PDF report with embedded verification hash.

Test this full loop repeatedly — same input, same output, every run — before adding a second vendor, a second config file, or additional controls. Breadth is the last thing added, not the first.

---

## MVP Acceptance Criteria

The MVP is demo-ready when all of the following are true, tested on the single-file path above:

- [ ] Same config file produces identical parse/audit output across 5+ consecutive runs (determinism check on Modules 2 & 4).
- [ ] At least one control resolves to each of Pass, Fail, and Unknown in the demo dataset — all three states visibly distinct in UI and PDF.
- [ ] One intentionally-unmapped CLI line is correctly routed to AI interpretation, produces a mapping suggestion with confidence + rationale, and is only applied after explicit reviewer approval.
- [ ] Rejecting or correcting an AI suggestion works and does not corrupt the audit result.
- [ ] At least one failed control produces a remediation command, a plain-language AI explanation, and a conflict-check result (either "No Conflicts Detected" or a shown conflict).
- [ ] No remediation command is executed automatically anywhere in the flow — confirmed by code review, not just by not clicking a button.
- [ ] Audit log entry is hash-chained correctly (prevEntryHash matches prior entry's hash) and independently verifiable via a standalone script.
- [ ] PDF report generates with embedded hash/QR, and that hash re-verifies against the stored log entry.
- [ ] Full loop (upload → audit → AI mapping moment → remediation moment → report) completes in one uninterrupted run without manual intervention beyond the intended review/approve clicks.
- [ ] Deterministic-path performance number and AI-assisted-path range are both measured and recorded, not asserted.

Only after every box above is checked should vendor #2, additional controls, or additional demo polish be added.
