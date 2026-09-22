"""NTRO PS26155 — Unified Canonical Audit Report Domain Model (Phase 3D.2).

Establishes the canonical, persisted representation of ONE editable report belonging to ONE audit record.

Architecture & Invariants:
1. One Audit = One Canonical Report:
   Every audit record in audit_ledger is associated with at most one canonical AuditReport.
   Multiple evaluated frameworks (CIS, DISA STIG, etc.) live inside this single report.
2. System-Generated vs Human-Editable Boundary:
   Authoritative system-generated data (audit ID, session ID, vendor, device/config metadata,
   framework IDs, control evaluations, PASS/FAIL/UNKNOWN verdicts, backend pass rates, evidence,
   deterministic rationale, AI mapping provenance) are IMMUTABLE and cannot be modified via report edits.
3. System Snapshot Immutability:
   system_snapshot is a point-in-time immutable record of system audit state. Report edits update
   only editable_content and increment the report version; they NEVER rewrite system_snapshot or audit_ledger.
4. Manual Edit Provenance & Versioning:
   Every human edit records who, when, which field_path, previous_value, new_value, and the resulting version.
5. Optimistic Concurrency / Stale-Version Protection:
   Edits require expected_version. If expected_version != current_version, edit is rejected.
6. Strict Field-Path Allowlist:
   Only explicitly allowlisted human-editable fields may be updated.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Union
import datetime
import json
import uuid

from src.compliance_framework import ComplianceStatus, EvaluationResult, Evidence
from src.compliance_aggregator import MultiFrameworkAuditResult, FrameworkSummary, ConsolidatedEvidence


# --- 1. Custom Exceptions ---

class ReportError(Exception):
    """Base exception for audit report domain errors."""
    pass


class InvalidFieldPathError(ReportError):
    """Raised when an edit targets a field path that is not in the human-editable allowlist."""
    pass


class SystemFieldImmutableError(ReportError):
    """Raised when an edit attempts to modify immutable, system-generated compliance data."""
    pass


class StaleReportVersionError(ReportError):
    """Raised when an edit is submitted with an expected_version that does not match the current version."""
    pass


class ReportNotFoundError(ReportError):
    """Raised when a requested report ID or audit_entry_id does not exist."""
    pass


class DuplicateReportError(ReportError):
    """Raised when attempting to create a second canonical report for an audit record."""
    pass


# --- 2. Field Allowlist and Validation ---

ALLOWED_TOP_LEVEL_EDITABLE_FIELDS = {
    "executive_summary",
    "auditor_observations",
    "recommendations",
    "additional_findings",
    "final_reviewer_notes",
}

ALLOWED_PREFIX_EDITABLE_FIELDS = (
    "control_notes.",
    "remediation_commentary.",
)

FORBIDDEN_SYSTEM_PATHS = {
    "report_id",
    "audit_entry_id",
    "session_id",
    "vendor",
    "version",
    "created_at",
    "updated_at",
    "created_by",
    "device_metadata",
    "configuration_metadata",
    "frameworks",
    "remediation",
    "conflict_warnings",
    "ai_mapping_provenance",
    "system_snapshot",
    "compliance",
    "status",
    "pass_rate",
    "unknown_rate",
    "pass_count",
    "fail_count",
    "unknown_count",
    "total_controls",
    "evidence",
    "observed_value",
    "expected_value",
    "rationale",
    "entry_id",
    "entryhash",
    "preventryhash",
    "config_file_hash",
}


def validate_editable_field_path(field_path: str) -> None:
    """Validates that field_path is an authorized human-editable field.

    Raises:
        SystemFieldImmutableError: If field_path targets immutable system-generated data.
        InvalidFieldPathError: If field_path is not in the approved allowlist.
    """
    if not isinstance(field_path, str) or not field_path.strip():
        raise InvalidFieldPathError("Field path must be a non-empty string.")

    cleaned = field_path.strip()

    # Reject prototype pollution / dunder attempts
    if "__" in cleaned or "constructor" in cleaned or "prototype" in cleaned:
        raise InvalidFieldPathError(f"Field path '{cleaned}' contains forbidden character sequences.")

    # Check for explicit system field attempts
    root_component = cleaned.split(".")[0].lower()
    if root_component in FORBIDDEN_SYSTEM_PATHS:
        raise SystemFieldImmutableError(
            f"Field path '{cleaned}' targets system-generated data and is strictly immutable."
        )

    # Allow top-level authorized fields
    if cleaned in ALLOWED_TOP_LEVEL_EDITABLE_FIELDS:
        return

    # Allow authorized prefix fields (e.g., control_notes.<id>, remediation_commentary.<id>)
    for prefix in ALLOWED_PREFIX_EDITABLE_FIELDS:
        if cleaned.startswith(prefix):
            sub_key = cleaned[len(prefix):].strip()
            if not sub_key:
                raise InvalidFieldPathError(f"Field path '{cleaned}' is missing a specific identifier suffix.")
            return

    raise InvalidFieldPathError(
        f"Field path '{cleaned}' is not an authorized human-editable field. "
        f"Allowed top-level fields: {sorted(ALLOWED_TOP_LEVEL_EDITABLE_FIELDS)}. "
        f"Allowed prefixed fields: 'control_notes.<control_id>', 'remediation_commentary.<rule_id>'."
    )


# --- 3. Domain Models ---

@dataclass(frozen=True)
class ReportEdit:
    """Immutable audit record representing a single human edit to an audit report."""
    edit_id: str
    report_id: str
    version: int
    field_path: str
    previous_value: Any
    new_value: Any
    edited_by: str
    edited_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edit_id": self.edit_id,
            "report_id": self.report_id,
            "version": self.version,
            "field_path": self.field_path,
            "previous_value": self.previous_value,
            "new_value": self.new_value,
            "edited_by": self.edited_by,
            "edited_at": self.edited_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReportEdit":
        return cls(
            edit_id=str(data["edit_id"]),
            report_id=str(data["report_id"]),
            version=int(data["version"]),
            field_path=str(data["field_path"]),
            previous_value=data.get("previous_value"),
            new_value=data.get("new_value"),
            edited_by=str(data["edited_by"]),
            edited_at=str(data["edited_at"]),
        )


@dataclass
class HumanEditableContent:
    """Container for all human-authored content in an audit report."""
    executive_summary: str = ""
    auditor_observations: str = ""
    control_notes: Dict[str, str] = field(default_factory=dict)
    remediation_commentary: Dict[str, str] = field(default_factory=dict)
    recommendations: str = ""
    additional_findings: str = ""
    final_reviewer_notes: str = ""

    def get_field(self, field_path: str) -> Any:
        """Retrieves the current value for an allowlisted field_path."""
        validate_editable_field_path(field_path)
        if field_path in ALLOWED_TOP_LEVEL_EDITABLE_FIELDS:
            return getattr(self, field_path)
        if field_path.startswith("control_notes."):
            key = field_path.split(".", 1)[1]
            return self.control_notes.get(key)
        if field_path.startswith("remediation_commentary."):
            key = field_path.split(".", 1)[1]
            return self.remediation_commentary.get(key)
        return None

    def set_field(self, field_path: str, value: Any) -> None:
        """Sets the value for an allowlisted field_path."""
        validate_editable_field_path(field_path)
        str_val = str(value) if value is not None else ""
        if field_path in ALLOWED_TOP_LEVEL_EDITABLE_FIELDS:
            setattr(self, field_path, str_val)
        elif field_path.startswith("control_notes."):
            key = field_path.split(".", 1)[1]
            self.control_notes[key] = str_val
        elif field_path.startswith("remediation_commentary."):
            key = field_path.split(".", 1)[1]
            self.remediation_commentary[key] = str_val

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executive_summary": self.executive_summary,
            "auditor_observations": self.auditor_observations,
            "control_notes": dict(self.control_notes),
            "remediation_commentary": dict(self.remediation_commentary),
            "recommendations": self.recommendations,
            "additional_findings": self.additional_findings,
            "final_reviewer_notes": self.final_reviewer_notes,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "HumanEditableContent":
        if not data:
            return cls()
        return cls(
            executive_summary=str(data.get("executive_summary") or ""),
            auditor_observations=str(data.get("auditor_observations") or ""),
            control_notes=dict(data.get("control_notes") or {}),
            remediation_commentary=dict(data.get("remediation_commentary") or {}),
            recommendations=str(data.get("recommendations") or ""),
            additional_findings=str(data.get("additional_findings") or ""),
            final_reviewer_notes=str(data.get("final_reviewer_notes") or ""),
        )


@dataclass(frozen=True)
class FrameworkReportItem:
    """Authoritative, multi-framework evaluation item preserved in the canonical report."""
    framework_id: str
    framework_name: Optional[str]
    framework_version: Optional[str]
    vendor_scope: Optional[str]
    description: Optional[str]
    total_controls: int
    passed: int
    failed: int
    unknown: int
    pass_rate: Optional[float]
    unknown_rate: Optional[float]
    control_results: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework_id": self.framework_id,
            "framework_name": self.framework_name,
            "framework_version": self.framework_version,
            "vendor_scope": self.vendor_scope,
            "description": self.description,
            "total_controls": self.total_controls,
            "passed": self.passed,
            "failed": self.failed,
            "unknown": self.unknown,
            "pass_rate": self.pass_rate,
            "unknown_rate": self.unknown_rate,
            "control_results": self.control_results,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FrameworkReportItem":
        return cls(
            framework_id=str(data["framework_id"]),
            framework_name=data.get("framework_name"),
            framework_version=data.get("framework_version"),
            vendor_scope=data.get("vendor_scope"),
            description=data.get("description"),
            total_controls=int(data.get("total_controls", 0)),
            passed=int(data.get("passed", 0)),
            failed=int(data.get("failed", 0)),
            unknown=int(data.get("unknown", 0)),
            pass_rate=data.get("pass_rate"),
            unknown_rate=data.get("unknown_rate"),
            control_results=list(data.get("control_results", [])),
            evidence=list(data.get("evidence", [])),
        )


@dataclass(frozen=True)
class AuditReport:
    """Canonical, editable compliance audit report tied to exactly ONE audit record."""
    report_id: str
    audit_entry_id: str
    session_id: str
    vendor: str
    device_metadata: Dict[str, Any]
    configuration_metadata: Dict[str, Any]
    frameworks: List[FrameworkReportItem]
    remediation: List[Dict[str, Any]]
    conflict_warnings: List[Dict[str, Any]]
    ai_mapping_provenance: List[Dict[str, Any]]
    editable_content: HumanEditableContent
    edit_metadata: List[ReportEdit]
    version: int
    created_at: str
    updated_at: str
    created_by: str

    def to_dict(self) -> Dict[str, Any]:
        """Serializes AuditReport to a clean dictionary representation."""
        return {
            "report_id": self.report_id,
            "audit_entry_id": self.audit_entry_id,
            "session_id": self.session_id,
            "vendor": self.vendor,
            "device_metadata": dict(self.device_metadata),
            "configuration_metadata": dict(self.configuration_metadata),
            "frameworks": [f.to_dict() for f in self.frameworks],
            "remediation": list(self.remediation),
            "conflict_warnings": list(self.conflict_warnings),
            "ai_mapping_provenance": list(self.ai_mapping_provenance),
            "editable_content": self.editable_content.to_dict(),
            "edit_metadata": [e.to_dict() for e in self.edit_metadata],
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "created_by": self.created_by,
        }

    def to_json(self) -> str:
        """Serializes AuditReport to JSON string."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditReport":
        """Deserializes AuditReport from a dictionary."""
        frameworks = [
            FrameworkReportItem.from_dict(f) if isinstance(f, dict) else f
            for f in data.get("frameworks", [])
        ]
        edits = [
            ReportEdit.from_dict(e) if isinstance(e, dict) else e
            for e in data.get("edit_metadata", [])
        ]
        raw_content = data.get("editable_content")
        editable_content = (
            HumanEditableContent.from_dict(raw_content)
            if isinstance(raw_content, dict)
            else (raw_content or HumanEditableContent())
        )

        return cls(
            report_id=str(data["report_id"]),
            audit_entry_id=str(data["audit_entry_id"]),
            session_id=str(data["session_id"]),
            vendor=str(data["vendor"]),
            device_metadata=dict(data.get("device_metadata", {})),
            configuration_metadata=dict(data.get("configuration_metadata", {})),
            frameworks=frameworks,
            remediation=list(data.get("remediation", [])),
            conflict_warnings=list(data.get("conflict_warnings", [])),
            ai_mapping_provenance=list(data.get("ai_mapping_provenance", [])),
            editable_content=editable_content,
            edit_metadata=edits,
            version=int(data.get("version", 1)),
            created_at=str(data["created_at"]),
            updated_at=str(data["updated_at"]),
            created_by=str(data.get("created_by", "system")),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "AuditReport":
        """Deserializes AuditReport from a JSON string."""
        return cls.from_dict(json.loads(json_str))

    def get_system_snapshot(self) -> Dict[str, Any]:
        """Returns the immutable system-generated audit snapshot."""
        return {
            "report_id": self.report_id,
            "audit_entry_id": self.audit_entry_id,
            "session_id": self.session_id,
            "vendor": self.vendor,
            "device_metadata": self.device_metadata,
            "configuration_metadata": self.configuration_metadata,
            "frameworks": [f.to_dict() for f in self.frameworks],
            "remediation": self.remediation,
            "conflict_warnings": self.conflict_warnings,
            "ai_mapping_provenance": self.ai_mapping_provenance,
        }


# --- 4. Canonical Builder ---

def create_report_from_audit_data(
    audit_entry_id: str,
    session_id: str,
    vendor: str,
    device_metadata: Optional[Dict[str, Any]] = None,
    configuration_metadata: Optional[Dict[str, Any]] = None,
    multi_framework_result: Optional[Union[MultiFrameworkAuditResult, Dict[str, Any]]] = None,
    evals: Optional[Dict[str, Any]] = None,
    remediation: Optional[Sequence[Dict[str, Any]]] = None,
    conflict_warnings: Optional[Sequence[Dict[str, Any]]] = None,
    ai_mapping_provenance: Optional[Sequence[Dict[str, Any]]] = None,
    created_by: str = "system",
    report_id: Optional[str] = None,
    initial_editable_content: Optional[Union[HumanEditableContent, Dict[str, Any]]] = None,
) -> AuditReport:
    """Constructs a canonical AuditReport from authoritative system audit data.

    Hard Invariants:
    - Exactly one canonical report per audit record.
    - Preserves MultiFrameworkAuditResult pass rates, control results, and evidence without recomputation.
    - Zero modification of the underlying audit ledger or entry hash.
    """
    if not audit_entry_id or not str(audit_entry_id).strip():
        raise ValueError("audit_entry_id must not be empty.")
    if not session_id or not str(session_id).strip():
        raise ValueError("session_id must not be empty.")
    if not vendor or not str(vendor).strip():
        raise ValueError("vendor must not be empty.")

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    r_id = report_id or f"RPT-{str(uuid.uuid4())[:8]}-{audit_entry_id}"

    # Build FrameworkReportItem list from MultiFrameworkAuditResult or legacy evals
    framework_items: List[FrameworkReportItem] = []

    if multi_framework_result is not None:
        mf_dict = (
            multi_framework_result.to_dict()
            if hasattr(multi_framework_result, "to_dict")
            else multi_framework_result
        )
        summaries = mf_dict.get("framework_summaries", {})
        all_evidence = mf_dict.get("consolidated_evidence", [])

        # Index evidence by framework_id
        ev_by_fw: Dict[str, List[Dict[str, Any]]] = {}
        for ev in all_evidence:
            fid = ev.get("framework_id", "").lower()
            ev_by_fw.setdefault(fid, []).append(ev)

        for fid in sorted(summaries.keys()):
            s = summaries[fid]
            framework_items.append(
                FrameworkReportItem(
                    framework_id=s.get("framework_id", fid),
                    framework_name=s.get("framework_name"),
                    framework_version=s.get("framework_version"),
                    vendor_scope=vendor.strip().lower(),
                    description=s.get("description"),
                    total_controls=s.get("total_controls", 0),
                    passed=s.get("pass_count", 0),
                    failed=s.get("fail_count", 0),
                    unknown=s.get("unknown_count", 0),
                    pass_rate=s.get("pass_rate"),
                    unknown_rate=s.get("unknown_rate"),
                    control_results=s.get("results", []),
                    evidence=ev_by_fw.get(fid.lower(), []),
                )
            )
    elif evals:
        # Legacy single-framework / baseline fallback
        pass_c = sum(1 for v in evals.values() if v.get("status") == "Pass")
        fail_c = sum(1 for v in evals.values() if v.get("status") == "Fail")
        unk_c = sum(1 for v in evals.values() if v.get("status") == "Unknown")
        tot_c = len(evals)
        eval_c = pass_c + fail_c
        pass_rate = round((pass_c / eval_c) * 100.0, 2) if eval_c > 0 else None
        unk_rate = round((unk_c / tot_c) * 100.0, 2) if tot_c > 0 else None

        control_res = [
            {"control_id": rid, **rdata}
            for rid, rdata in sorted(evals.items())
        ]

        framework_items.append(
            FrameworkReportItem(
                framework_id=f"{vendor.strip().lower()}_baseline",
                framework_name=f"{vendor.title()} Security Baseline",
                framework_version="v1.0",
                vendor_scope=vendor.strip().lower(),
                description="Deterministic baseline security compliance",
                total_controls=tot_c,
                passed=pass_c,
                failed=fail_c,
                unknown=unk_c,
                pass_rate=pass_rate,
                unknown_rate=unk_rate,
                control_results=control_res,
                evidence=[],
            )
        )

    # Initial human-editable content
    if isinstance(initial_editable_content, HumanEditableContent):
        content = initial_editable_content
    elif isinstance(initial_editable_content, dict):
        content = HumanEditableContent.from_dict(initial_editable_content)
    else:
        content = HumanEditableContent()

    return AuditReport(
        report_id=r_id,
        audit_entry_id=audit_entry_id,
        session_id=session_id,
        vendor=vendor.strip().lower(),
        device_metadata=dict(device_metadata or {}),
        configuration_metadata=dict(configuration_metadata or {}),
        frameworks=framework_items,
        remediation=list(remediation or []),
        conflict_warnings=list(conflict_warnings or []),
        ai_mapping_provenance=list(ai_mapping_provenance or []),
        editable_content=content,
        edit_metadata=[],
        version=1,
        created_at=now_iso,
        updated_at=now_iso,
        created_by=created_by,
    )


# --- 5. Lifecycle Integration Helpers (Phase 3D.3) ---

def create_or_get_canonical_report(
    audit_entry_id: str,
    session_id: str,
    csm: Optional[Dict[str, Any]] = None,
    evals: Optional[Dict[str, Any]] = None,
    raw_config_text: Optional[str] = None,
    remediation_summary: Optional[Dict[str, Any]] = None,
    multi_framework_result: Optional[Union[MultiFrameworkAuditResult, Dict[str, Any]]] = None,
    ai_mapping_provenance: Optional[Sequence[Dict[str, Any]]] = None,
    conflict_warnings: Optional[Sequence[Dict[str, Any]]] = None,
    created_by: str = "system",
    initial_editable_content: Optional[Union[HumanEditableContent, Dict[str, Any]]] = None,
) -> AuditReport:
    """Retrieves existing canonical AuditReport for audit_entry_id or constructs and persists one.

    Hard Invariants:
    1. One audit -> exactly one canonical AuditReport.
    2. Idempotent: repeated calls for the same audit_entry_id return the existing report.
    3. Existing human edits and report version are preserved across retries.
    4. Zero compliance evaluation or AI inference is executed.
    5. Audit ledger remains authoritative and completely unmodified.
    6. Preserves actual vendor without defaulting to 'cisco' for other vendors.
    """
    import src.database as database
    import hashlib

    # 1. Idempotency Check: Return existing report if already created for this audit
    existing_dict = database.get_audit_report_by_entry_id(audit_entry_id)
    if existing_dict is not None:
        return AuditReport.from_dict(existing_dict)

    # 2. Extract vendor and device metadata safely without arbitrary defaults
    device_info = csm.get("device") if isinstance(csm, dict) and isinstance(csm.get("device"), dict) else {}
    raw_vendor = device_info.get("vendor") or device_info.get("platform") or "unknown"
    vendor = str(raw_vendor).strip().lower()

    device_metadata = {
        "hostname": device_info.get("hostname", "unknown"),
        "vendor": vendor,
        "platform": device_info.get("platform") or vendor,
        "management_ip": device_info.get("management_ip"),
        "interfaces_count": len(csm.get("interfaces", [])) if isinstance(csm, dict) else 0,
    }

    config_hash = (
        hashlib.sha256(raw_config_text.encode("utf-8")).hexdigest()
        if raw_config_text
        else None
    )
    configuration_metadata = {
        "config_file_hash": config_hash,
        "raw_config_length": len(raw_config_text) if raw_config_text else 0,
        "unmapped_lines": csm.get("unmapped_lines", []) if isinstance(csm, dict) else [],
    }

    remediation_items = []
    if isinstance(remediation_summary, dict):
        for rid, rval in remediation_summary.items():
            if isinstance(rval, dict):
                remediation_items.append({"rule_id": rid, **rval})
            else:
                remediation_items.append({"rule_id": rid, "remediation": rval})
    elif isinstance(remediation_summary, list):
        remediation_items = list(remediation_summary)

    # 3. Construct canonical AuditReport domain object
    report = create_report_from_audit_data(
        audit_entry_id=audit_entry_id,
        session_id=session_id,
        vendor=vendor,
        device_metadata=device_metadata,
        configuration_metadata=configuration_metadata,
        multi_framework_result=multi_framework_result,
        evals=evals,
        remediation=remediation_items,
        conflict_warnings=conflict_warnings or [],
        ai_mapping_provenance=ai_mapping_provenance or [],
        created_by=created_by,
        initial_editable_content=initial_editable_content,
    )

    # 4. Atomically persist to database with race-condition safety
    try:
        database.save_audit_report(report)
    except DuplicateReportError:
        # Another process or thread created it concurrently; retrieve and return it
        existing_dict = database.get_audit_report_by_entry_id(audit_entry_id)
        if existing_dict is not None:
            return AuditReport.from_dict(existing_dict)
        raise

    return report


def get_canonical_report(report_id: str) -> Optional[AuditReport]:
    """Retrieves an AuditReport domain object by its report_id."""
    import src.database as database
    r_dict = database.get_audit_report(report_id)
    return AuditReport.from_dict(r_dict) if r_dict is not None else None


def get_canonical_report_by_entry_id(audit_entry_id: str) -> Optional[AuditReport]:
    """Retrieves an AuditReport domain object by its audit_entry_id."""
    import src.database as database
    r_dict = database.get_audit_report_by_entry_id(audit_entry_id)
    return AuditReport.from_dict(r_dict) if r_dict is not None else None
