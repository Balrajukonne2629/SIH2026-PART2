"""NTRO PS26155 — Framework Abstraction & Domain Data Model (Phase 3A.1).

Establishes the framework-neutral abstraction layer and domain contracts for
deterministic multi-framework compliance evaluation (CIS, DISA-STIG, NIST, etc.):

1. Framework: Metadata, identity, scope, and namespace for a compliance framework.
2. Control: Individual compliance requirement specification and metadata.
3. ComplianceStatus: Strictly Pass, Fail, Unknown (with case-insensitive parsing).
4. Evidence: Deterministic, structured record of observed vs expected CSM state.
5. EvaluationResult: Framework-neutral outcome of control evaluation against normalized CSM.
6. FrameworkEvaluator: Abstract base interface for deterministic evaluation engines.
7. FrameworkRegistry: Explicit, dependency-injectable registry for frameworks and evaluators.
8. CiscoCsmFrameworkAdapter: Non-invasive adapter mapping existing Cisco MVP rules to the framework abstraction.

Architectural Invariants & Safety Guarantees:
- Strictly deterministic: Given identical normalized CSM and controls, evaluation output is 100% reproducible.
- Zero AI dependency: Contains no imports or calls to Ollama, AIModelManager, or remote LLM services.
- Zero execution paths: Contains no subprocess, shell, socket, or network egress capabilities.
- Vendor-neutral: Consumes normalized CSM dictionaries; never parses raw vendor CLI configuration directly.
- UNKNOWN preservation: UNKNOWN is never silently converted to FAIL or PASS.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union
import datetime
import re


# --- 1. Compliance Status Contract ---

class ComplianceStatus(str, Enum):
    """Authoritative, deterministic compliance evaluation verdict.
    
    Strictly restricted to PASS, FAIL, and UNKNOWN.
    UNKNOWN is semantically vital as it represents the boundary where
    configuration cannot be verified deterministically and may later be routed
    for human-gated AI assistance. It must NEVER be conflated with FAIL.
    """
    PASS = "Pass"
    FAIL = "Fail"
    UNKNOWN = "Unknown"

    @classmethod
    def from_str(cls, value: Union[str, "ComplianceStatus"]) -> "ComplianceStatus":
        """Converts string representations safely to ComplianceStatus."""
        if isinstance(value, ComplianceStatus):
            return value
        if not isinstance(value, str):
            raise TypeError(f"Status must be string or ComplianceStatus, got {type(value).__name__}")
        
        normalized = value.strip().lower()
        if normalized in ("pass", "passed", "compliant"):
            return cls.PASS
        if normalized in ("fail", "failed", "non_compliant", "non-compliant"):
            return cls.FAIL
        if normalized in ("unknown", "unmapped", "indeterminate", "pending"):
            return cls.UNKNOWN
        
        raise ValueError(
            f"Invalid compliance status '{value}'. Must be one of: PASS, FAIL, UNKNOWN."
        )

    def is_pass(self) -> bool:
        return self == ComplianceStatus.PASS

    def is_fail(self) -> bool:
        return self == ComplianceStatus.FAIL

    def is_unknown(self) -> bool:
        return self == ComplianceStatus.UNKNOWN


# --- 2. Deterministic Evidence Model ---

@dataclass(frozen=True)
class Evidence:
    """Deterministic evidence explaining the factual basis for an evaluation verdict.
    
    Answers:
      WHAT was observed (observed_value)
      WHERE it was observed (location in normalized CSM or source configuration)
      WHAT was expected (expected_value)
      WHY the deterministic evaluator reached its verdict (rationale)
    """
    observed_value: Any
    location: str
    expected_value: Any
    rationale: str
    confidence: float = 1.0
    source_lines: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self):
        if not self.location or not str(self.location).strip():
            raise ValueError("Evidence location must not be empty.")
        if not self.rationale or not str(self.rationale).strip():
            raise ValueError("Evidence rationale must not be empty.")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Evidence confidence must be between 0.0 and 1.0.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observed_value": self.observed_value,
            "location": self.location,
            "expected_value": self.expected_value,
            "rationale": self.rationale,
            "confidence": self.confidence,
            "source_lines": list(self.source_lines)
        }


# --- 3. Control Domain Model ---

@dataclass(frozen=True)
class Control:
    """Individual security control / benchmark requirement in a compliance framework."""
    framework_id: str
    control_id: str
    title: str
    description: str
    severity: str = "medium"  # low, medium, high, critical
    expected_state: str = ""
    evaluation_metadata: Dict[str, Any] = field(default_factory=dict)
    evidence_requirements: Sequence[str] = field(default_factory=tuple)
    remediation_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.framework_id or not str(self.framework_id).strip():
            raise ValueError("Control framework_id must not be empty.")
        if not self.control_id or not str(self.control_id).strip():
            raise ValueError("Control control_id must not be empty.")
        if not self.title or not str(self.title).strip():
            raise ValueError("Control title must not be empty.")

        # Normalize framework_id to lowercase
        object.__setattr__(self, "framework_id", self.framework_id.strip().lower())
        object.__setattr__(self, "control_id", self.control_id.strip())
        object.__setattr__(self, "severity", self.severity.strip().lower())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework_id": self.framework_id,
            "control_id": self.control_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "expected_state": self.expected_state,
            "evaluation_metadata": dict(self.evaluation_metadata),
            "evidence_requirements": list(self.evidence_requirements),
            "remediation_metadata": dict(self.remediation_metadata)
        }


# --- 4. Framework Domain Model ---

@dataclass(frozen=True)
class Framework:
    """Metadata and identity contract representing an authoritative compliance framework."""
    framework_id: str
    name: str
    version: str
    description: str = ""
    vendor_scope: Optional[str] = None  # e.g. "Cisco IOS-XE" or None (Universal/Vendor-Neutral)
    control_namespace: str = ""         # e.g. "CIS", "V-", "NIST"
    enabled: bool = True

    def __post_init__(self):
        if not self.framework_id or not str(self.framework_id).strip():
            raise ValueError("Framework framework_id must not be empty.")
        if not self.name or not str(self.name).strip():
            raise ValueError("Framework name must not be empty.")
        if not self.version or not str(self.version).strip():
            raise ValueError("Framework version must not be empty.")

        cleaned_id = self.framework_id.strip().lower()
        if not cleaned_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError(
                f"Framework ID '{self.framework_id}' contains invalid characters. "
                "Only alphanumeric, hyphens, and underscores are allowed."
            )
        object.__setattr__(self, "framework_id", cleaned_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework_id": self.framework_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "vendor_scope": self.vendor_scope,
            "control_namespace": self.control_namespace,
            "enabled": self.enabled
        }


# --- 5. Evaluation Result Model ---

@dataclass(frozen=True)
class EvaluationResult:
    """Framework-neutral compliance evaluation verdict for a single control against normalized CSM."""
    framework_id: str
    control_id: str
    status: ComplianceStatus
    evidence: Optional[Evidence] = None
    reason: str = ""
    observed_value: Any = None
    expected_value: Any = None
    evaluator_id: str = "deterministic"
    timestamp: Optional[str] = None

    def __post_init__(self):
        if not self.framework_id or not str(self.framework_id).strip():
            raise ValueError("EvaluationResult framework_id must not be empty.")
        if not self.control_id or not str(self.control_id).strip():
            raise ValueError("EvaluationResult control_id must not be empty.")
        if not isinstance(self.status, ComplianceStatus):
            object.__setattr__(self, "status", ComplianceStatus.from_str(self.status))
        
        object.__setattr__(self, "framework_id", self.framework_id.strip().lower())
        object.__setattr__(self, "control_id", self.control_id.strip())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework_id": self.framework_id,
            "control_id": self.control_id,
            "status": self.status.value,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "reason": self.reason,
            "observed_value": self.observed_value,
            "expected_value": self.expected_value,
            "evaluator_id": self.evaluator_id,
            "timestamp": self.timestamp
        }


# --- 6. Framework Evaluator Contract (Interface) ---

class FrameworkEvaluator(ABC):
    """Abstract interface defining the contract for deterministic compliance evaluators.
    
    An evaluator consumes vendor-neutral normalized CSM and applicable framework controls,
    returning structured EvaluationResult instances.
    
    Hard Invariants:
    - Pure function / deterministic: Repeated evaluations of identical inputs produce identical outputs.
    - Zero AI calls: Evaluators MUST NOT invoke LLMs, Ollama, or external models.
    - Zero raw parsing: Evaluators MUST consume normalized CSM; they must never parse raw CLI text.
    """

    @property
    @abstractmethod
    def framework_id(self) -> str:
        """Returns the unique identifier of the framework this evaluator implements."""
        pass

    @abstractmethod
    def evaluate(
        self,
        csm: Dict[str, Any],
        controls: Optional[Sequence[Control]] = None
    ) -> List[EvaluationResult]:
        """Evaluates normalized CSM data against applicable framework controls.
        
        Args:
            csm: Normalized vendor-neutral configuration model dictionary.
            controls: Optional subset of controls to evaluate. If None, evaluates all available controls.
            
        Returns:
            List of EvaluationResult instances (one per evaluated control).
        """
        pass


# --- 7. Framework Registry ---

class FrameworkNotFoundError(KeyError):
    """Raised when an unregistered framework ID is requested."""
    pass


class FrameworkRegistry:
    """Explicit, dependency-injectable registry for compliance frameworks and their evaluators."""

    def __init__(self):
        self._frameworks: Dict[str, Framework] = {}
        self._evaluators: Dict[str, FrameworkEvaluator] = {}

    def register(
        self,
        framework: Framework,
        evaluator: Optional[FrameworkEvaluator] = None,
        allow_replace: bool = False
    ) -> None:
        """Registers a framework and its optional evaluator.
        
        Args:
            framework: Framework metadata instance.
            evaluator: Optional FrameworkEvaluator implementation.
            allow_replace: If False, raises ValueError on duplicate framework_id.
        """
        if not isinstance(framework, Framework):
            raise TypeError(f"Expected Framework instance, got {type(framework).__name__}")
        
        fid = framework.framework_id
        if fid in self._frameworks and not allow_replace:
            raise ValueError(f"Framework '{fid}' is already registered. Set allow_replace=True to override.")
        
        if evaluator is not None:
            if not isinstance(evaluator, FrameworkEvaluator):
                raise TypeError(f"Expected FrameworkEvaluator instance, got {type(evaluator).__name__}")
            if evaluator.framework_id.lower() != fid:
                raise ValueError(
                    f"Evaluator framework_id '{evaluator.framework_id}' does not match "
                    f"framework '{fid}'."
                )
            self._evaluators[fid] = evaluator
        elif fid in self._evaluators and allow_replace:
            del self._evaluators[fid]

        self._frameworks[fid] = framework

    def get(self, framework_id: str) -> Framework:
        """Retrieves a registered framework by ID."""
        cleaned_id = str(framework_id).strip().lower()
        if cleaned_id not in self._frameworks:
            raise FrameworkNotFoundError(f"Framework '{cleaned_id}' is not registered.")
        return self._frameworks[cleaned_id]

    def get_evaluator(self, framework_id: str) -> Optional[FrameworkEvaluator]:
        """Retrieves the evaluator registered for a framework, if any."""
        cleaned_id = str(framework_id).strip().lower()
        if cleaned_id not in self._frameworks:
            raise FrameworkNotFoundError(f"Framework '{cleaned_id}' is not registered.")
        return self._evaluators.get(cleaned_id)

    def exists(self, framework_id: str) -> bool:
        """Checks if a framework is registered."""
        return str(framework_id).strip().lower() in self._frameworks

    def list(self, enabled_only: bool = False) -> List[Framework]:
        """Lists all registered frameworks sorted by framework_id."""
        frameworks = list(self._frameworks.values())
        if enabled_only:
            frameworks = [f for f in frameworks if f.enabled]
        return sorted(frameworks, key=lambda f: f.framework_id)

    def list_for_vendor(
        self,
        vendor: str,
        enabled_only: bool = True
    ) -> List[Framework]:
        """Lists registered frameworks applicable to the specified vendor or platform.

        Matches vendor case-insensitively against each Framework's vendor_scope.
        Vendor-neutral frameworks (vendor_scope=None) are always included.
        For an unknown vendor, returns only vendor-neutral frameworks (or an empty list).
        Disabled frameworks are excluded when enabled_only=True.

        Args:
            vendor: Vendor identifier or platform string (e.g. 'cisco', 'Cisco IOS-XE').
            enabled_only: If True, filters out disabled frameworks. Defaults to True.

        Returns:
            List of matching Framework instances sorted deterministically by framework_id.
        """
        if not isinstance(vendor, str) or not vendor.strip():
            all_fws = self.list(enabled_only=enabled_only)
            return [f for f in all_fws if f.vendor_scope is None]

        v_norm = vendor.strip().lower()
        v_tokens = set(re.findall(r'[a-z0-9]+', v_norm))
        v_alnum = re.sub(r'[^a-z0-9]', '', v_norm)

        matched: List[Framework] = []
        for fw in self.list(enabled_only=enabled_only):
            if fw.vendor_scope is None:
                matched.append(fw)
                continue

            s_norm = fw.vendor_scope.strip().lower()
            s_tokens = set(re.findall(r'[a-z0-9]+', s_norm))
            s_alnum = re.sub(r'[^a-z0-9]', '', s_norm)

            if not v_tokens or not s_tokens:
                continue

            # Deterministic token & alphanumeric matching
            if (
                v_norm == s_norm
                or v_alnum == s_alnum
                or v_tokens.issubset(s_tokens)
                or s_tokens.issubset(v_tokens)
            ):
                matched.append(fw)

        return sorted(matched, key=lambda f: f.framework_id)

    def unregister(self, framework_id: str) -> bool:
        """Unregisters a framework and its evaluator. Returns True if found and removed."""
        cleaned_id = str(framework_id).strip().lower()
        removed = False
        if cleaned_id in self._frameworks:
            del self._frameworks[cleaned_id]
            removed = True
        if cleaned_id in self._evaluators:
            del self._evaluators[cleaned_id]
        return removed

    def clear(self) -> None:
        """Clears all registered frameworks and evaluators."""
        self._frameworks.clear()
        self._evaluators.clear()


# Default process-level registry
_DEFAULT_REGISTRY = FrameworkRegistry()

def get_default_registry() -> FrameworkRegistry:
    """Returns the shared process-level FrameworkRegistry instance."""
    return _DEFAULT_REGISTRY


# --- 8. Cisco MVP Framework Adapter ---

class CiscoCsmFrameworkAdapter(FrameworkEvaluator):
    """Adapts existing Cisco IOS-XE rule evaluation to the FrameworkEvaluator contract.
    
    Sits above the verified Cisco MVP implementation without modifying cisco_auditor.py.
    Maps Cisco baseline rules and dynamic trusted rules into framework-neutral EvaluationResult objects.
    """

    def __init__(
        self,
        framework_id: str = "cisco-ios-xe-baseline",
        rules_data: Optional[Sequence[Dict[str, Any]]] = None,
        trusted_rules: Optional[Sequence[Dict[str, Any]]] = None
    ):
        self._framework_id = framework_id.strip().lower()
        self._rules_data = list(rules_data) if rules_data is not None else []
        self._trusted_rules = list(trusted_rules) if trusted_rules is not None else []

    @property
    def framework_id(self) -> str:
        return self._framework_id

    def evaluate(
        self,
        csm: Dict[str, Any],
        controls: Optional[Sequence[Control]] = None
    ) -> List[EvaluationResult]:
        """Runs the deterministic Cisco rule evaluation on the provided normalized CSM."""
        import cisco_auditor

        evals = cisco_auditor.evaluate_rules(
            csm=csm,
            rules=self._rules_data,
            trusted_rules=self._trusted_rules
        )

        results: List[EvaluationResult] = []
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Build lookup of rule details
        all_rules = {r.get("vendor_rule_id"): r for r in (self._rules_data + self._trusted_rules)}

        for rule_id, res in evals.items():
            status_str = res.get("status", "Unknown")
            status = ComplianceStatus.from_str(status_str)
            focus = res.get("focus", "Security")
            evidence_found = res.get("evidence_found", [])

            rule_meta = all_rules.get(rule_id, {})
            title = rule_meta.get("internalTitle") or rule_meta.get("title") or rule_id

            evidence = Evidence(
                observed_value=evidence_found,
                location=f"csm.{focus.lower().replace(' ', '_')}",
                expected_value=rule_meta.get("condition") or "Deterministic requirement satisfied",
                rationale=f"Evaluated rule {rule_id} against normalized CSM. Status: {status.value}.",
                confidence=1.0,
                source_lines=tuple(evidence_found)
            )

            results.append(
                EvaluationResult(
                    framework_id=self._framework_id,
                    control_id=rule_id,
                    status=status,
                    evidence=evidence,
                    reason=f"{title}: {status.value}",
                    observed_value=evidence_found,
                    expected_value=rule_meta.get("condition"),
                    evaluator_id="cisco_auditor.evaluate_rules",
                    timestamp=now_iso
                )
            )

        return results
