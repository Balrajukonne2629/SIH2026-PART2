# NTRO PS26155 — Multi-Framework Compliance Architecture (Phase 3A.1 – 3A.4)
## Framework Abstraction, Control Catalogs & Scoring Aggregator

**Product:** NTRO PS26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor  
**Team:** NextGen  
**Phase:** 3A.1, 3A.2, 3A.3 & 3A.4 (Framework Abstraction, Catalogs & Aggregator)  
**Status:** COMPLETE & VERIFIED  

---

## 1. Why the Framework Abstraction Exists

The Cisco MVP established a high-performance, deterministic compliance auditing engine that evaluates normalized Cisco Security Model (CSM) representations in under 10 milliseconds. However, in an enterprise and national security context, compliance is rarely single-framework:
- Security Operations Centers must audit device configurations against the **CIS Benchmark** (e.g. Cisco IOS-XE 17.x Benchmark v2.2.1).
- Military and federal environments require **DISA-STIG** (e.g. Cisco IOS-XE Router NDM STIG V3R7).
- Regulatory bodies demand alignment with **NIST SP 800-53 rev5** controls (via DoD CCIs).

Without a unified framework abstraction layer, supporting multiple frameworks would lead to:
1. Fragmented, duplicated parser/scanner implementations per standard.
2. Vendor-specific rule logic coupling to compliance standards.
3. Inconsistent scoring rules and evidence formats across frameworks.

The Phase 3A.1 abstraction establishes a **framework-neutral domain model and evaluator contract**. It decouples:
- **Vendor Configuration Ingestion & Normalization** (Vendor CLI $\rightarrow$ Normalized CSM)
- from **Compliance Evaluation** (Normalized CSM $\rightarrow$ Framework-Neutral Results).

---

## 2. Locked Architectural Pipeline

```
          Vendor Configuration (CLI Text)
                        │
                        ▼
          Vendor Parser / Normalization
        (cisco_auditor.parse_cisco, etc.)
                        │
                        ▼
          Vendor-Neutral Normalized CSM
   (interfaces, services, aaa, logging, ntp, etc.)
                        │
                        ▼
          Framework Evaluation Engine
       ┌─────────────────────────────────┐
       │ FrameworkRegistry               │
       │  ├── CIS Evaluator              │
       │  ├── DISA-STIG Evaluator        │
       │  └── Future Framework N         │
       └─────────────────────────────────┘
                        │
                        ▼
          Deterministic Evaluation
        (Rule / Condition Matching on CSM)
                        │
                        ▼
            PASS / FAIL / UNKNOWN
                        │
                        ▼
          Structured Deterministic Evidence
      (observed_value, location, expected_value)
```

### Architectural Guarantees:
- **Normalized Ingestion Only:** Framework evaluators MUST consume normalized vendor-neutral CSM data. Evaluators never parse raw CLI text directly.
- **Deterministic Authority:** Framework evaluation is 100% deterministic. No external services, no random numbers, no heuristics.
- **Zero AI in Decision Path:** Framework evaluators MUST NOT call Ollama, MUST NOT depend on LLMs, and MUST NOT use AI-generated PASS/FAIL decisions.

> **Core Invariant:** Framework adapters are deterministic and do not use AI to make authoritative compliance decisions.

---

## 3. The Framework-Neutral Domain Data Model

Implemented in [`compliance_framework.py`](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_framework.py):

### 3.1 Framework Metadata Contract (`Framework`)
Represents an authoritative compliance benchmark or standard.
```python
@dataclass(frozen=True)
class Framework:
    framework_id: str          # Stable, lowercase identifier (e.g. "cis", "disa-stig", "nist-800-53")
    name: str                  # Formal human-readable name
    version: str               # Version string (e.g. "2.2.1", "V3R7", "rev5")
    description: str = ""      # Scope and summary
    vendor_scope: Optional[str] = None  # e.g. "Cisco IOS-XE" or None (Universal)
    control_namespace: str = "" # Prefix/namespace (e.g. "CIS", "V-", "NIST")
    enabled: bool = True
```

### 3.2 Control Domain Contract (`Control`)
Represents a single verifiable requirement within a framework.
```python
@dataclass(frozen=True)
class Control:
    framework_id: str          # Associated framework identifier
    control_id: str            # Stable control ID (e.g. "2.1.1.2", "V-215845", "MA-4 (6)")
    title: str                 # Title of the security control
    description: str           # Detailed security requirement explanation
    severity: str = "medium"   # Normalized severity: "low", "medium", "high", "critical"
    expected_state: str = ""   # Expected configuration state description
    evaluation_metadata: Dict[str, Any] = field(default_factory=dict)
    evidence_requirements: Sequence[str] = field(default_factory=tuple)
    remediation_metadata: Dict[str, Any] = field(default_factory=dict)
```

### 3.3 Compliance Status Contract (`ComplianceStatus`)
Strictly restricted to three statuses:
- **`PASS`** (`"Pass"`): Evaluated configuration fully satisfies the control criteria.
- **`FAIL`** (`"Fail"`): Evaluated configuration actively violates or lacks the required security setting.
- **`UNKNOWN`** (`"Unknown"`): Configuration cannot be verified deterministically from the parsed CSM (e.g., unmapped syntax, missing telemetry, or prerequisite module unconfigured).

**Preservation Rule:** `UNKNOWN` is semantically distinct from `FAIL`. It must NEVER be silently converted into `FAIL`. `UNKNOWN` marks the exact boundary where the system may stage an unmapped line for human-gated AI assistance.

### 3.4 Deterministic Evidence Model (`Evidence`)
Explains the factual basis of the evaluation without narrative fluff:
```python
@dataclass(frozen=True)
class Evidence:
    observed_value: Any        # Exactly WHAT was found in CSM
    location: str              # WHERE in CSM or config it was observed (e.g. "csm.services.ssh_version")
    expected_value: Any        # WHAT was required by the benchmark
    rationale: str             # WHY the deterministic evaluator reached this verdict
    confidence: float = 1.0    # 1.0 for deterministic rule matches
    source_lines: Sequence[str] = field(default_factory=tuple)
```

### 3.5 Evaluation Result Contract (`EvaluationResult`)
The framework-neutral output produced for every evaluated control:
```python
@dataclass(frozen=True)
class EvaluationResult:
    framework_id: str
    control_id: str
    status: ComplianceStatus
    evidence: Optional[Evidence] = None
    reason: str = ""
    observed_value: Any = None
    expected_value: Any = None
    evaluator_id: str = "deterministic"
    timestamp: Optional[str] = None
```

---

## 4. Evaluator Contract (`FrameworkEvaluator`)

Abstract base contract for all framework evaluators:
```python
class FrameworkEvaluator(ABC):
    @property
    @abstractmethod
    def framework_id(self) -> str:
        """Returns the unique identifier of the framework handled."""
        pass

    @abstractmethod
    def evaluate(
        self,
        csm: Dict[str, Any],
        controls: Optional[Sequence[Control]] = None
    ) -> List[EvaluationResult]:
        """Deterministically evaluates controls against normalized CSM."""
        pass
```

---

## 5. Framework Registry (`FrameworkRegistry`)

An explicit, dependency-injectable registry managing registered frameworks and their corresponding evaluators:
- `register(framework, evaluator=None, allow_replace=False)`: Registers a framework; guards against accidental duplicate registration.
- `get(framework_id)`: Fetches metadata; raises `FrameworkNotFoundError` on unknown IDs.
- `get_evaluator(framework_id)`: Fetches the registered evaluator engine.
- `list(enabled_only=False)`: Returns registered frameworks sorted alphabetically by ID.
- `exists(framework_id)`: Quick boolean existence check.
- `unregister(framework_id)`: Removes framework from registry.

---

## 6. Relationship to the Existing Cisco MVP

**Zero-Regression Design Principle:**
The existing Cisco auditor (`cisco_auditor.py`) is verified and remains 100% untouched.

To bridge the existing Cisco implementation to the new framework contract without risky refactoring, Phase 3A.1 introduces [`CiscoCsmFrameworkAdapter`](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_framework.py):
1. Takes the normalized CSM produced by `cisco_auditor.parse_cisco()`.
2. Delegates deterministic rule evaluation to `cisco_auditor.evaluate_rules()`.
3. Transforms raw rule outputs into standard `EvaluationResult` instances with structured `Evidence`.
4. Guarantees 1:1 parity with the verified Cisco baseline.

---

## 7. AI Boundary & Security Controls

```
                        AI Model Manager / DistilBERT
                        (Unmapped Line Suggestion & Rationale)
                                    │
                                    │ (Advisory Only)
                                    ▼
                         Human Reviewer Gate
                         (SecOps Approver Signature)
                                    │
                                    │ (Appended to Trusted Rules)
                                    ▼
                       Deterministic Rule Evaluator
                         (Authoritative Pass/Fail)
```

1. **AI Isolation:** Neither `compliance_framework.py` nor its evaluators import `ai_model_manager`, `ollama`, or machine learning dependencies.
2. **Execution Safety:** Zero imports of `subprocess`, `os.system`, `eval`, or `exec`.
3. **Network Boundary:** Zero socket, HTTP, or remote client imports.
4. **Static AST Enforcement:** Tested automatically in `test_compliance_framework.py::TestSecurityAndSafetyInvariants::test_ast_safety_audit_compliance_framework`.

---

## 8. CIS Benchmark Cisco IOS-XE Control Catalog (Phase 3A.2)

**Implementation Status:** COMPLETE & VERIFIED  
**Module:** [`cis_benchmark_cisco_iosxe.py`](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/cis_benchmark_cisco_iosxe.py)  
**Authoritative Benchmark Source:** `CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf` (Benchmark v2.2.1)

### 8.1 Catalog Overview & Provenanced Controls

The CIS Cisco IOS-XE Benchmark defines strict deterministic controls for router and switch baseline security. Phase 3A.2 implements the 7 verified controls mapped in `vendor_rule_mapping.json` and `mapping_log.md`:

| CIS Control ID | CIS Section Title | Internal Rule ID | Severity | Normalized CSM Location & Condition |
| :--- | :--- | :--- | :--- | :--- |
| **`2.1.1.2`** | Set version 2 for 'ip ssh version' | `CISCO-SSH-001` | High | `csm.services`: `ssh_version == 2` & `ssh == True` & `telnet == False` |
| **`1.1.1`** | Enable 'aaa new-model' | `CISCO-AAA-001` | High | `csm.aaa`: `enabled == True` & `authentication_method is not None` |
| **`2.3.1.1`** | Set 'ntp authenticate' | `CISCO-NTP-001` | Medium | `csm.ntp`: `servers` non-empty & `authentication_enabled == True` |
| **`2.2.4`** | Set IP address for 'logging host' | `CISCO-LOG-001` | Medium | `csm.logging`: `remote_logging_enabled == True` & `timestamps_enabled == True` |
| **`1.5.7`** | Set 'snmp-server host' when using SNMP | `CISCO-SNMP-001` | Medium | `csm.snmp`: `enabled == True` & zero weak communities (`public`, `private`, etc.) |
| **`1.2.5`** | Set 'access-class' for 'line vty' | `CISCO-ACL-001` / `MGMT-001` | High | `csm.access_control`: `management_acl_present == True` |
| **`3.3.3.1`** | Set 'neighbor password' | `CISCO-ROUTING-001` | High | `csm.routing`: `routing_protocols` non-empty & `routing_authentication_enabled == True` |

### 8.2 Evaluator Implementation (`CisCiscoIosXeEvaluator`)

1. **Deterministic Execution:** Consumes normalized CSM dictionaries directly.
2. **UNKNOWN Preservation:** Follows the semantic rule that unconfigured features return `ComplianceStatus.UNKNOWN` rather than being conflated with `ComplianceStatus.FAIL`.
3. **Evidence Attachment:** Every `EvaluationResult` carries a fully populated `Evidence` record detailing `observed_value`, `location`, `expected_value`, `rationale`, and `confidence: 1.0`.
4. **Zero-AI & Zero-Exec Invariant:** Contains zero external dependencies, network sockets, or subprocess execution calls.

---

## 9. DISA-STIG Cisco IOS-XE Control Catalog (Phase 3A.3)

**Implementation Status:** COMPLETE & VERIFIED  
**Module:** [`disa_stig_cisco_iosxe.py`](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/disa_stig_cisco_iosxe.py)  
**Authoritative Benchmark Sources:**
- Cisco IOS XE Router NDM STIG V3R7 (`U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml`)
- Cisco IOS XE Router RTR STIG V3R5 (`U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml`)
- Cisco IOS XE Switch L2S STIG V3R2 (`U_Cisco_IOS-XE_Switch_L2S_STIG_V3R2_Manual-xccdf.xml`)

### 9.1 Catalog Overview & Provenanced Controls

The DISA-STIG standard provides DoD cybersecurity requirements for network infrastructure. Phase 3A.3 implements all 10 verified controls mapped in `vendor_rule_mapping.json`, `mapping_log.md`, and the primary XCCDF XMLs:

| STIG Vuln ID | Severity | STIG Title / Focus | Internal Rule | CCIs | Normalized CSM Criteria |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`V-215845`** | High (CAT I) | Cryptographic protection for remote maintenance (SSH v2) | `CISCO-SSH-001` | `CCI-003123` | `csm.services`: `ssh_version == 2` & `ssh == True` & `telnet == False` |
| **`V-215854`** | High (CAT I) | Centralized authentication servers (AAA new-model) | `CISCO-AAA-001` | `CCI-000370` | `csm.aaa`: `enabled == True` & `authentication_method is not None` |
| **`V-215843`** | Medium (CAT II) | Cryptographic NTP authentication | `CISCO-NTP-001` | `CCI-001967` | `csm.ntp`: `servers` non-empty & `authentication_enabled == True` |
| **`V-220139`** | High (CAT I) | Redundant syslog logging with timestamps | `CISCO-LOG-001` | `CCI-001851` | `csm.logging`: `remote_logging_enabled == True` & `timestamps_enabled == True` |
| **`V-215841`** | Medium (CAT II) | Secure SNMP without default/weak communities | `CISCO-SNMP-001` | `CCI-001967` | `csm.snmp`: `enabled == True` & zero weak communities (`public`, `private`, etc.) |
| **`V-215812`** | Medium (CAT II) | Management access flow control (line vty access-class) | `CISCO-ACL-001` | `CCI-001368` | `csm.access_control`: `management_acl_present == True` |
| **`V-216646`** | Low (CAT III) | Inactive interfaces administratively disabled | `CISCO-INT-001` | `CCI-001414` | `csm.interfaces`: all interfaces marked 'unused' have `shutdown == True` |
| **`V-216645`** | Medium (CAT II) | Routing protocol neighbor authentication | `CISCO-ROUTING-001` | `CCI-000803` | `csm.routing`: `routing_protocols` non-empty & `routing_authentication_enabled == True` |
| **`V-220656`** | Medium (CAT II) | Spanning-Tree BPDU Guard on switch access ports | `CISCO-STP-001` | `CCI-002385` | `csm.spanning_tree`: `configured == True` & `bpduguard_enabled == True` |
| **`V-216680`** | Medium (CAT II) | Out-of-band management VRF isolation | `CISCO-MGMT-001` | `CCI-001414` | `csm.management`: `management_vrf_enabled == True` |

### 9.2 Evaluator Implementation (`StigCiscoIosXeEvaluator`)

1. **Deterministic Execution:** Consumes normalized CSM dictionaries directly.
2. **UNKNOWN Semantics:** Explicitly preserved when prerequisites are absent (e.g. no unused interfaces $\rightarrow$ UNKNOWN; STP not configured $\rightarrow$ UNKNOWN; no routing protocols $\rightarrow$ UNKNOWN; SNMP disabled $\rightarrow$ UNKNOWN). UNKNOWN is never conflated with FAIL.
3. **Evidence Attachment:** Every `EvaluationResult` carries a fully populated `Evidence` record detailing `observed_value`, `location`, `expected_value`, `rationale`, and `confidence: 1.0`.
4. **Coexistence with CIS:** CIS (`cis-cisco-iosxe`) and DISA-STIG (`disa-stig-cisco-iosxe`) coexist within the same `FrameworkRegistry` with zero identity or namespace collisions.

> **Deterministic Guarantee:** DISA-STIG evaluation is 100% deterministic and does not use AI to make authoritative compliance decisions.

---

## 10. Multi-Framework Scoring, Aggregation & Evidence Consolidation (Phase 3A.4)

**Implementation Status:** COMPLETE & VERIFIED  
**Module:** [`compliance_aggregator.py`](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/compliance_aggregator.py)

### 10.1 Architectural Guarantees & Role

The aggregation layer sits immediately above the deterministic framework evaluators. It acts as a pure consolidating function:

```
    CIS Evaluator                 DISA-STIG Evaluator
 (CisCiscoIosXeEvaluator)       (StigCiscoIosXeEvaluator)
          │                                 │
          ▼                                 ▼
   EvaluationResult[]                EvaluationResult[]
          └────────────────┬────────────────┘
                           ▼
             MultiFrameworkAggregator
         (Validation, Dedup, Sort, Math)
                           │
                           ▼
               MultiFrameworkAuditResult
    ┌──────────────────────┼──────────────────────┐
    ▼                      ▼                      ▼
FrameworkSummaries   OverallMetrics     ConsolidatedEvidence
(CIS, DISA-STIG)   (Totals, PassRate)   (Stable Order, Provenance)
```

**Hard Invariants:**
1. **Result Immutability:** Does not re-evaluate controls, parse raw configs, or alter evaluation statuses.
2. **UNKNOWN Preservation:** `UNKNOWN` is never converted to `FAIL` or `PASS`.
3. **No Arbitrary Weighting:** Evaluated frameworks are presented with transparent counts. No subjective weights (e.g. 40%/60%) are applied.
4. **No Policy Decisions:** Produces empirical measurements and counts; does not manufacture overall "compliant" badges.

### 10.2 Pass-Rate Mathematical Semantics

The deterministic pass rate is strictly defined as:

$$\text{pass\_rate} = \frac{\text{PASS}}{\text{PASS} + \text{FAIL}} \times 100\%$$

- **UNKNOWN Exclusion:** `UNKNOWN` controls represent incomplete configuration evidence and are excluded from the pass-rate denominator.
- **Zero-Evaluated Boundary Condition:** If $\text{PASS} + \text{FAIL} == 0$, `pass_rate` evaluates to `None` (not $100\%$ or $0\%$).
- **Unknown Rate Metric:** Exposes $\text{unknown\_rate} = \frac{\text{UNKNOWN}}{\text{TOTAL}} \times 100\%$ to clearly show the proportion of indeterminate controls.

### 10.3 Duplicate Resolution & Conflict Handling

- **Identical Duplicate:** Same `(framework_id, control_id)` with identical status is de-duplicated and counted exactly once.
- **Conflicting Duplicate:** Same `(framework_id, control_id)` with contradictory statuses (e.g. `PASS` and `FAIL`) raises a fatal `ConflictingControlEvaluationError`.
- **Cross-Framework Same Control ID:** Evaluated independently without collision because `(framework_id, control_id)` form a composite key.

### 10.4 Deterministic Evidence Consolidation

Evidence records are unified into `ConsolidatedEvidence` objects and sorted by `(framework_id, control_id)` ascending. Output is 100% byte-for-byte identical regardless of input result sequence permutations.

---

---

## 11. Phase 3A.5 — Multi-Framework REST API Layer

Implemented in [`main.py`](file:///c:/Users/konne%20balraju/OneDrive%20-%20Chaitanya%20Bharathi%20Institute%20of%20Technology/HACKATHONS/PART-2/main.py):

### 11.1 Architectural Role & Boundaries
The API layer acts as a thin, secure orchestration facade. It contains:
- **Zero compliance logic:** Delegated entirely to `FrameworkRegistry`, evaluators, and `MultiFrameworkAggregator`.
- **Zero AI / LLM invocations:** Deterministic execution only.
- **Zero subprocess / socket execution:** Clean AST verified at load time.

### 11.2 Endpoint Specifications

#### 1. `GET /api/compliance/frameworks`
- **Purpose:** Discovery of registered deterministic compliance frameworks, metadata, and control counts.
- **Authorization:** `require_role("viewer", "uploader", "reviewer")`
- **Response Schema:**
  ```json
  {
    "frameworks": [
      {
        "framework_id": "cis-cisco-iosxe",
        "name": "CIS Cisco IOS XE 17.x Benchmark",
        "version": "v2.2.1",
        "description": "...",
        "vendor_scope": "Cisco IOS-XE",
        "control_namespace": "CIS",
        "control_count": 7,
        "severity_distribution": {"high": 4, "medium": 3},
        "enabled": true
      },
      {
        "framework_id": "disa-stig-cisco-iosxe",
        "name": "DISA STIG Cisco IOS XE Benchmark",
        "version": "V3R7",
        "description": "...",
        "vendor_scope": "Cisco IOS-XE",
        "control_namespace": "DISA-STIG",
        "control_count": 10,
        "severity_distribution": {"high": 6, "medium": 4},
        "enabled": true
      }
    ],
    "total_count": 2
  }
  ```

#### 2. `POST /api/compliance/evaluate`
- **Purpose:** Executes multi-framework compliance evaluation against CSM, raw config, or session.
- **Authorization:** `require_role("viewer", "uploader", "reviewer")`
- **Request Payloads Supported:**
  - `session_id`: Evaluates cached session. Enforces strict `check_session_ownership`:
    - Uploader A cannot access Uploader B's session (anti-enumeration returns 404).
    - Reviewers retain global access.
  - `csm`: Direct pre-parsed normalized configuration model dictionary.
  - `raw_config`: Raw configuration text (automatically parsed to CSM via `cisco_auditor.parse_cisco`).
  - `framework_ids`: Optional list of framework IDs to evaluate (e.g. `["cis-cisco-iosxe"]`).
- **Response Schema:** Returns `MultiFrameworkAuditResult.to_dict()` containing `framework_summaries`, `overall_metrics`, and deterministically sorted `consolidated_evidence`.

---

## 12. What is Deliberately Deferred

In accordance with the locked roadmap, Phase 3A.5 strictly completes the REST API Integration. The following items remain deferred:
- **Phase 3B:** Frontend Multi-Framework Compliance Dashboard & Jury Visualization.
- **Vendor #2 Support:** Juniper / Fortinet normalization parsers.
- **Upskill Integration:** Continuous learning pipelines.




