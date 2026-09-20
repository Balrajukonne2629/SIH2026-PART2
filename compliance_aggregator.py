"""NTRO PS26155 — Multi-Framework Scoring, Aggregation & Evidence Consolidation (Phase 3A.4).

Consumes authoritative, deterministic EvaluationResult streams from framework evaluators
(e.g., CIS, DISA-STIG) and produces consolidated audit-level summaries and evidence.

Implements:
1. FrameworkSummary: Per-framework control counts (PASS, FAIL, UNKNOWN) and deterministic pass rates.
2. OverallMetrics: Cross-framework macro totals and overall pass rates without arbitrary weighting.
3. ConsolidatedEvidence: Deterministically ordered, provenance-preserved evidence records.
4. MultiFrameworkAuditResult: Audit-level aggregate outcome containing summaries, metrics, and evidence.
5. MultiFrameworkAggregator: Deterministic aggregation engine validating inputs, resolving duplicates,
   and synthesizing multi-framework metrics.

Hard Invariants:
- Immutability of verdicts: Never transforms UNKNOWN to FAIL or PASS; preserves raw evaluator results.
- Zero AI / LLM in decision path: Contains no imports or calls to Ollama, AIModelManager, or remote models.
- Zero execution or network capabilities: Contains no subprocess, socket, shell, or URL retrieval logic.
- Pure aggregation: Consumes already-evaluated EvaluationResult objects; never parses raw CLI or re-evaluates rules.
- Deterministic output: Identical input results always yield identical summaries, counts, and ordering.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import datetime

from compliance_framework import (
    ComplianceStatus,
    Control,
    Evidence,
    EvaluationResult,
    Framework,
    FrameworkRegistry,
    get_default_registry,
)


# --- 1. Custom Exceptions ---

class AggregationError(Exception):
    """Base exception for multi-framework aggregation failures."""
    pass


class ConflictingControlEvaluationError(AggregationError):
    """Raised when conflicting evaluation statuses exist for the same control in the same framework."""
    pass


class InvalidEvaluationResultError(AggregationError):
    """Raised when an input result object is malformed or missing required attributes."""
    pass


# --- 2. Domain Models ---

@dataclass(frozen=True)
class FrameworkSummary:
    """Consolidated summary for a single compliance framework within an audit."""
    framework_id: str
    framework_name: Optional[str] = None
    framework_version: Optional[str] = None
    total_controls: int = 0
    pass_count: int = 0
    fail_count: int = 0
    unknown_count: int = 0
    pass_rate: Optional[float] = None       # Percentage (0.0 to 100.0) or None if (pass + fail == 0)
    unknown_rate: Optional[float] = None   # Percentage (0.0 to 100.0) or None if (total_controls == 0)
    results: List[EvaluationResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework_id": self.framework_id,
            "framework_name": self.framework_name,
            "framework_version": self.framework_version,
            "total_controls": self.total_controls,
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "unknown_count": self.unknown_count,
            "pass_rate": self.pass_rate,
            "unknown_rate": self.unknown_rate,
            "results": [r.to_dict() for r in self.results],
        }


@dataclass(frozen=True)
class OverallMetrics:
    """Macro-level aggregated compliance metrics across all evaluated frameworks."""
    total_frameworks: int
    total_controls: int
    total_pass: int
    total_fail: int
    total_unknown: int
    overall_pass_rate: Optional[float] = None     # Percentage (0.0 to 100.0) or None if (total_pass + total_fail == 0)
    overall_unknown_rate: Optional[float] = None # Percentage (0.0 to 100.0) or None if (total_controls == 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_frameworks": self.total_frameworks,
            "total_controls": self.total_controls,
            "total_pass": self.total_pass,
            "total_fail": self.total_fail,
            "total_unknown": self.total_unknown,
            "overall_pass_rate": self.overall_pass_rate,
            "overall_unknown_rate": self.overall_unknown_rate,
        }


@dataclass(frozen=True)
class ConsolidatedEvidence:
    """Deterministic, unified record of observed evidence for a specific evaluated control."""
    framework_id: str
    control_id: str
    status: str
    observed_value: Any
    location: str
    expected_value: Any
    rationale: str
    confidence: float = 1.0
    source_lines: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework_id": self.framework_id,
            "control_id": self.control_id,
            "status": self.status,
            "observed_value": self.observed_value,
            "location": self.location,
            "expected_value": self.expected_value,
            "rationale": self.rationale,
            "confidence": self.confidence,
            "source_lines": list(self.source_lines),
        }


@dataclass(frozen=True)
class MultiFrameworkAuditResult:
    """Authoritative, audit-level result aggregating multi-framework evaluations and evidence."""
    audit_id: Optional[str]
    device_hostname: Optional[str]
    framework_summaries: Dict[str, FrameworkSummary]
    overall_metrics: OverallMetrics
    consolidated_evidence: List[ConsolidatedEvidence]
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "device_hostname": self.device_hostname,
            "framework_summaries": {
                fid: s.to_dict() for fid, s in self.framework_summaries.items()
            },
            "overall_metrics": self.overall_metrics.to_dict(),
            "consolidated_evidence": [e.to_dict() for e in self.consolidated_evidence],
            "timestamp": self.timestamp,
        }


# --- 3. Deterministic Aggregator Engine ---

class MultiFrameworkAggregator:
    """Deterministic aggregation engine for multi-framework compliance evaluation results.
    
    Responsibilities:
    1. Validates incoming EvaluationResult collections for schema and integrity.
    2. Enforces deterministic duplicate resolution (deduplicates identicals; rejects conflicting statuses).
    3. Calculates transparent counts and pass-rates per framework and overall.
    4. Compiles structured, deterministically sorted evidence records.
    """

    def __init__(self, registry: Optional[FrameworkRegistry] = None):
        """Initializes aggregator with an optional registry for framework metadata enrichment."""
        self._registry = registry

    def aggregate(
        self,
        results: Sequence[EvaluationResult],
        audit_id: Optional[str] = None,
        device_hostname: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> MultiFrameworkAuditResult:
        """Aggregates a sequence of EvaluationResult objects into a MultiFrameworkAuditResult.
        
        Args:
            results: Sequence of EvaluationResult instances from one or more framework evaluators.
            audit_id: Optional identifier of the audit session.
            device_hostname: Optional target device hostname.
            timestamp: Optional ISO 8601 timestamp string. If None, current UTC timestamp is used.
            
        Returns:
            MultiFrameworkAuditResult containing framework summaries, overall metrics, and evidence.
            
        Raises:
            InvalidEvaluationResultError: If an element is not a valid EvaluationResult or is malformed.
            ConflictingControlEvaluationError: If the same control within a framework has conflicting statuses.
        """
        if results is None:
            raise InvalidEvaluationResultError("Results sequence cannot be None.")

        # 1. Validation and Deterministic Deduplication
        deduped_results_map: Dict[Tuple[str, str], EvaluationResult] = {}

        for item in results:
            self._validate_result(item)
            key = (item.framework_id.lower(), item.control_id)
            if key in deduped_results_map:
                existing = deduped_results_map[key]
                if existing.status != item.status:
                    raise ConflictingControlEvaluationError(
                        f"Conflicting evaluation statuses detected for control '{item.control_id}' "
                        f"in framework '{item.framework_id}': '{existing.status.value}' vs '{item.status.value}'."
                    )
                # If identical duplicate, preserve existing and continue
                continue
            deduped_results_map[key] = item

        # 2. Group by framework (Framework ID sorting ensures determinism)
        framework_groups: Dict[str, List[EvaluationResult]] = {}
        for (fid, _), res in deduped_results_map.items():
            framework_groups.setdefault(fid, []).append(res)

        # 3. Calculate per-framework summaries
        framework_summaries: Dict[str, FrameworkSummary] = {}
        total_pass = 0
        total_fail = 0
        total_unknown = 0
        total_controls_all = 0

        sorted_fids = sorted(framework_groups.keys())
        for fid in sorted_fids:
            res_list = framework_groups[fid]
            # Deterministic control sort within framework
            sorted_res = sorted(res_list, key=lambda r: r.control_id)

            p_count = sum(1 for r in sorted_res if r.status == ComplianceStatus.PASS)
            f_count = sum(1 for r in sorted_res if r.status == ComplianceStatus.FAIL)
            u_count = sum(1 for r in sorted_res if r.status == ComplianceStatus.UNKNOWN)
            t_count = len(sorted_res)

            # Pass rate: PASS / (PASS + FAIL). UNKNOWN is excluded from denominator.
            evaluated_count = p_count + f_count
            pass_rate = round((p_count / evaluated_count) * 100.0, 2) if evaluated_count > 0 else None
            unknown_rate = round((u_count / t_count) * 100.0, 2) if t_count > 0 else None

            # Framework metadata enrichment (if registry available)
            fw_name, fw_version = self._resolve_framework_meta(fid)

            framework_summaries[fid] = FrameworkSummary(
                framework_id=fid,
                framework_name=fw_name,
                framework_version=fw_version,
                total_controls=t_count,
                pass_count=p_count,
                fail_count=f_count,
                unknown_count=u_count,
                pass_rate=pass_rate,
                unknown_rate=unknown_rate,
                results=sorted_res,
            )

            total_pass += p_count
            total_fail += f_count
            total_unknown += u_count
            total_controls_all += t_count

        # 4. Calculate Overall Metrics
        total_frameworks = len(framework_summaries)
        overall_evaluated = total_pass + total_fail
        overall_pass_rate = (
            round((total_pass / overall_evaluated) * 100.0, 2)
            if overall_evaluated > 0
            else None
        )
        overall_unknown_rate = (
            round((total_unknown / total_controls_all) * 100.0, 2)
            if total_controls_all > 0
            else None
        )

        overall_metrics = OverallMetrics(
            total_frameworks=total_frameworks,
            total_controls=total_controls_all,
            total_pass=total_pass,
            total_fail=total_fail,
            total_unknown=total_unknown,
            overall_pass_rate=overall_pass_rate,
            overall_unknown_rate=overall_unknown_rate,
        )

        # 5. Build Deterministically Consolidated Evidence
        # Order: framework_id ascending, control_id ascending
        sorted_keys = sorted(deduped_results_map.keys())
        consolidated_evidence: List[ConsolidatedEvidence] = []

        for key in sorted_keys:
            res = deduped_results_map[key]
            ev = res.evidence
            if ev is not None:
                obs = ev.observed_value
                loc = ev.location
                exp = ev.expected_value
                rat = ev.rationale
                conf = ev.confidence
                src_lines = ev.source_lines
            else:
                obs = res.observed_value
                loc = "csm"
                exp = res.expected_value
                rat = res.reason or "No deterministic rationale provided."
                conf = 1.0
                src_lines = ()

            consolidated_evidence.append(
                ConsolidatedEvidence(
                    framework_id=res.framework_id,
                    control_id=res.control_id,
                    status=res.status.value,
                    observed_value=obs,
                    location=loc,
                    expected_value=exp,
                    rationale=rat,
                    confidence=conf,
                    source_lines=src_lines,
                )
            )

        now_iso = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()

        return MultiFrameworkAuditResult(
            audit_id=audit_id,
            device_hostname=device_hostname,
            framework_summaries=framework_summaries,
            overall_metrics=overall_metrics,
            consolidated_evidence=consolidated_evidence,
            timestamp=now_iso,
        )

    def _validate_result(self, item: Any) -> None:
        """Validates that the input item adheres to the EvaluationResult contract."""
        if not isinstance(item, EvaluationResult):
            raise InvalidEvaluationResultError(
                f"Expected EvaluationResult instance, got {type(item).__name__}."
            )
        if not item.framework_id or not str(item.framework_id).strip():
            raise InvalidEvaluationResultError("EvaluationResult framework_id must not be empty.")
        if not item.control_id or not str(item.control_id).strip():
            raise InvalidEvaluationResultError("EvaluationResult control_id must not be empty.")
        if not isinstance(item.status, ComplianceStatus):
            raise InvalidEvaluationResultError(
                f"EvaluationResult status must be a ComplianceStatus enum, got {type(item.status).__name__}."
            )

    def _resolve_framework_meta(self, framework_id: str) -> Tuple[Optional[str], Optional[str]]:
        """Attempts to resolve human-readable framework name and version from registry."""
        if self._registry is not None and self._registry.exists(framework_id):
            try:
                fw = self._registry.get(framework_id)
                return fw.name, fw.version
            except Exception:
                pass
        return None, None
