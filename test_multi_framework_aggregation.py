"""NTRO PS26155 — Multi-Framework Scoring, Aggregation & Evidence Consolidation Test Suite (Phase 3A.4).

Verifies:
1. FrameworkSummary and OverallMetrics calculations under all boundary conditions.
2. Exact pass-rate semantics (PASS / (PASS + FAIL)) with UNKNOWN excluded.
3. Boundary condition: (PASS + FAIL == 0) produces None, never 100%.
4. Deterministic evidence consolidation and stable sorting by (framework_id, control_id).
5. Duplicate handling: identical results deduplicated; conflicting statuses rejected with integrity error.
6. Safe coexistence of identical control IDs across distinct frameworks.
7. Input validation against malformed or missing result objects.
8. Determinism test: random permutation of inputs yields 100% byte-for-byte identical output.
9. Real integration test combining live CisCiscoIosXeEvaluator and StigCiscoIosXeEvaluator outputs.
10. Static AST security invariants (zero AI, zero network, zero execution imports).
"""

import ast
import pathlib
import random
import pytest
from typing import List

from compliance_framework import (
    ComplianceStatus,
    Evidence,
    EvaluationResult,
    FrameworkRegistry,
)
from cis_benchmark_cisco_iosxe import (
    CisCiscoIosXeEvaluator,
    register_cis_cisco_iosxe,
)
from disa_stig_cisco_iosxe import (
    StigCiscoIosXeEvaluator,
    register_disa_stig_cisco_iosxe,
)
from compliance_aggregator import (
    ConflictingControlEvaluationError,
    ConsolidatedEvidence,
    FrameworkSummary,
    InvalidEvaluationResultError,
    MultiFrameworkAggregator,
    MultiFrameworkAuditResult,
    OverallMetrics,
)
import cisco_auditor


# --- Helper to create dummy evaluation results ---

def make_res(framework_id: str, control_id: str, status: ComplianceStatus, obs: Any = "test_val") -> EvaluationResult:
    return EvaluationResult(
        framework_id=framework_id,
        control_id=control_id,
        status=status,
        evidence=Evidence(
            observed_value=obs,
            location=f"csm.{framework_id}.{control_id}",
            expected_value="expected",
            rationale=f"Rationale for {control_id}: {status.value}.",
            confidence=1.0,
        ),
        reason=f"Evaluation {status.value}",
        evaluator_id="test_evaluator",
    )


# --- 1. Pass Rate and Framework Summary Tests ---

class TestPassRateAndFrameworkSummary:
    """Tests count aggregation and pass-rate calculations across all mathematical cases."""

    def setup_method(self):
        self.aggregator = MultiFrameworkAggregator()

    def test_all_pass_100_percent(self):
        results = [make_res("cis", f"ctrl_{i}", ComplianceStatus.PASS) for i in range(5)]
        audit = self.aggregator.aggregate(results)
        summary = audit.framework_summaries["cis"]

        assert summary.total_controls == 5
        assert summary.pass_count == 5
        assert summary.fail_count == 0
        assert summary.unknown_count == 0
        assert summary.pass_rate == 100.0
        assert summary.unknown_rate == 0.0

    def test_all_fail_0_percent(self):
        results = [make_res("cis", f"ctrl_{i}", ComplianceStatus.FAIL) for i in range(5)]
        audit = self.aggregator.aggregate(results)
        summary = audit.framework_summaries["cis"]

        assert summary.total_controls == 5
        assert summary.pass_count == 0
        assert summary.fail_count == 5
        assert summary.unknown_count == 0
        assert summary.pass_rate == 0.0
        assert summary.unknown_rate == 0.0

    def test_mixed_pass_fail_50_percent(self):
        results = [
            make_res("cis", "ctrl_1", ComplianceStatus.PASS),
            make_res("cis", "ctrl_2", ComplianceStatus.FAIL),
        ]
        audit = self.aggregator.aggregate(results)
        summary = audit.framework_summaries["cis"]

        assert summary.total_controls == 2
        assert summary.pass_count == 1
        assert summary.fail_count == 1
        assert summary.pass_rate == 50.0

    def test_unknown_excluded_from_pass_rate_denominator(self):
        # 5 PASS, 0 FAIL, 5 UNKNOWN -> pass_rate must be 100.0%, NOT 50.0%
        results = (
            [make_res("cis", f"p_{i}", ComplianceStatus.PASS) for i in range(5)]
            + [make_res("cis", f"u_{i}", ComplianceStatus.UNKNOWN) for i in range(5)]
        )
        audit = self.aggregator.aggregate(results)
        summary = audit.framework_summaries["cis"]

        assert summary.total_controls == 10
        assert summary.pass_count == 5
        assert summary.fail_count == 0
        assert summary.unknown_count == 5
        assert summary.pass_rate == 100.0
        assert summary.unknown_rate == 50.0

    def test_zero_pass_zero_fail_all_unknown_yields_none_pass_rate(self):
        # 0 PASS, 0 FAIL, 5 UNKNOWN -> denominator is 0 -> pass_rate must be None (NOT 100% or 0%)
        results = [make_res("cis", f"u_{i}", ComplianceStatus.UNKNOWN) for i in range(5)]
        audit = self.aggregator.aggregate(results)
        summary = audit.framework_summaries["cis"]

        assert summary.total_controls == 5
        assert summary.pass_count == 0
        assert summary.fail_count == 0
        assert summary.unknown_count == 5
        assert summary.pass_rate is None
        assert summary.unknown_rate == 100.0

    def test_empty_results_sequence(self):
        audit = self.aggregator.aggregate([])
        assert audit.overall_metrics.total_frameworks == 0
        assert audit.overall_metrics.total_controls == 0
        assert audit.overall_metrics.total_pass == 0
        assert audit.overall_metrics.total_fail == 0
        assert audit.overall_metrics.total_unknown == 0
        assert audit.overall_metrics.overall_pass_rate is None
        assert audit.overall_metrics.overall_unknown_rate is None
        assert len(audit.framework_summaries) == 0
        assert len(audit.consolidated_evidence) == 0


# --- 2. Overall Metrics Tests ---

class TestOverallMetrics:
    """Tests cross-framework macro metrics and transparency."""

    def test_multi_framework_macro_totals(self):
        aggregator = MultiFrameworkAggregator()
        results = [
            # Framework A: 2 Pass, 1 Fail
            make_res("fw_a", "1", ComplianceStatus.PASS),
            make_res("fw_a", "2", ComplianceStatus.PASS),
            make_res("fw_a", "3", ComplianceStatus.FAIL),
            # Framework B: 1 Pass, 1 Fail, 2 Unknown
            make_res("fw_b", "1", ComplianceStatus.PASS),
            make_res("fw_b", "2", ComplianceStatus.FAIL),
            make_res("fw_b", "3", ComplianceStatus.UNKNOWN),
            make_res("fw_b", "4", ComplianceStatus.UNKNOWN),
        ]
        audit = aggregator.aggregate(results)
        om = audit.overall_metrics

        assert om.total_frameworks == 2
        assert om.total_controls == 7
        assert om.total_pass == 3
        assert om.total_fail == 2
        assert om.total_unknown == 2
        # overall_pass_rate = 3 / (3 + 2) = 60.0%
        assert om.overall_pass_rate == 60.0
        # overall_unknown_rate = 2 / 7 = 28.57%
        assert om.overall_unknown_rate == 28.57


# --- 3. Duplicate Handling & Integrity Tests ---

class TestDuplicateHandling:
    """Tests duplicate handling: identical deduplication vs conflicting error."""

    def setup_method(self):
        self.aggregator = MultiFrameworkAggregator()

    def test_identical_duplicates_are_deduplicated_silently(self):
        res1 = make_res("cis", "1.1", ComplianceStatus.PASS)
        res2 = make_res("cis", "1.1", ComplianceStatus.PASS)  # Duplicate
        audit = self.aggregator.aggregate([res1, res2])

        summary = audit.framework_summaries["cis"]
        assert summary.total_controls == 1
        assert summary.pass_count == 1
        assert len(audit.consolidated_evidence) == 1

    def test_conflicting_duplicates_raise_integrity_error(self):
        res1 = make_res("cis", "1.1", ComplianceStatus.PASS)
        res2 = make_res("cis", "1.1", ComplianceStatus.FAIL)  # Conflict!

        with pytest.raises(ConflictingControlEvaluationError) as exc_info:
            self.aggregator.aggregate([res1, res2])
        assert "Conflicting evaluation statuses" in str(exc_info.value)
        assert "1.1" in str(exc_info.value)

    def test_same_control_id_across_different_frameworks_coexists(self):
        res_cis = make_res("cis", "1.2.5", ComplianceStatus.PASS)
        res_stig = make_res("disa-stig", "1.2.5", ComplianceStatus.FAIL)

        audit = self.aggregator.aggregate([res_cis, res_stig])
        assert audit.overall_metrics.total_frameworks == 2
        assert audit.overall_metrics.total_controls == 2
        assert audit.framework_summaries["cis"].pass_count == 1
        assert audit.framework_summaries["disa-stig"].fail_count == 1


# --- 4. Input Validation Tests ---

class TestInputValidation:
    """Tests rejection of malformed or invalid inputs."""

    def setup_method(self):
        self.aggregator = MultiFrameworkAggregator()

    def test_none_input_raises_invalid_result_error(self):
        with pytest.raises(InvalidEvaluationResultError):
            self.aggregator.aggregate(None)  # type: ignore

    def test_non_evaluation_result_object_raises_error(self):
        with pytest.raises(InvalidEvaluationResultError):
            self.aggregator.aggregate(["not_a_result"])  # type: ignore

    def test_empty_framework_id_raises_error(self):
        res = object.__new__(EvaluationResult)
        object.__setattr__(res, "framework_id", "")
        object.__setattr__(res, "control_id", "ctrl_1")
        object.__setattr__(res, "status", ComplianceStatus.PASS)
        with pytest.raises(InvalidEvaluationResultError):
            self.aggregator.aggregate([res])

    def test_empty_control_id_raises_error(self):
        res = object.__new__(EvaluationResult)
        object.__setattr__(res, "framework_id", "cis")
        object.__setattr__(res, "control_id", "")
        object.__setattr__(res, "status", ComplianceStatus.PASS)
        with pytest.raises(InvalidEvaluationResultError):
            self.aggregator.aggregate([res])


# --- 5. Determinism and Ordering Tests ---

class TestDeterminismAndOrdering:
    """Tests that evidence and summaries are deterministically ordered regardless of input order."""

    def test_shuffled_input_produces_identical_serialized_output(self):
        aggregator = MultiFrameworkAggregator()
        base_results = [
            make_res("zeta_fw", "z2", ComplianceStatus.PASS),
            make_res("alpha_fw", "a1", ComplianceStatus.FAIL),
            make_res("zeta_fw", "z1", ComplianceStatus.UNKNOWN),
            make_res("beta_fw", "b2", ComplianceStatus.PASS),
            make_res("alpha_fw", "a2", ComplianceStatus.PASS),
            make_res("beta_fw", "b1", ComplianceStatus.FAIL),
        ]

        # Run 1: original order
        audit1 = aggregator.aggregate(base_results, audit_id="audit_123", timestamp="2026-09-19T00:00:00Z")
        dict1 = audit1.to_dict()

        # Run 2-10: randomly shuffled orders
        for seed in range(10):
            shuffled = list(base_results)
            random.Random(seed).shuffle(shuffled)
            audit_shuffled = aggregator.aggregate(shuffled, audit_id="audit_123", timestamp="2026-09-19T00:00:00Z")
            assert audit_shuffled.to_dict() == dict1, f"Determinism violation with seed {seed}"

    def test_evidence_ordering_is_stable(self):
        aggregator = MultiFrameworkAggregator()
        results = [
            make_res("stig", "V-2", ComplianceStatus.PASS),
            make_res("cis", "2.1", ComplianceStatus.FAIL),
            make_res("stig", "V-1", ComplianceStatus.PASS),
            make_res("cis", "1.1", ComplianceStatus.PASS),
        ]
        audit = aggregator.aggregate(results)
        evidence_keys = [(e.framework_id, e.control_id) for e in audit.consolidated_evidence]

        # Expected: sorted alphabetically by framework_id, then control_id
        assert evidence_keys == [
            ("cis", "1.1"),
            ("cis", "2.1"),
            ("stig", "V-1"),
            ("stig", "V-2"),
        ]


# --- 6. Live Evaluator Integration Test (CIS + DISA-STIG) ---

class TestLiveMultiFrameworkIntegration:
    """End-to-end integration test running live CIS and DISA-STIG evaluators on labeled config."""

    @pytest.fixture
    def parsed_test_csm(self):
        cfg_path = pathlib.Path(__file__).parent / "05_Configuration_Datasets" / "Cisco" / "labeled_test_config.txt"
        assert cfg_path.exists(), f"Missing test config at {cfg_path}"
        text = cfg_path.read_text(encoding="utf-8")
        return cisco_auditor.parse_cisco(text)

    def test_live_cis_and_stig_aggregation(self, parsed_test_csm):
        reg = FrameworkRegistry()
        register_cis_cisco_iosxe(reg)
        register_disa_stig_cisco_iosxe(reg)

        cis_eval = reg.get_evaluator("cis-cisco-iosxe")
        stig_eval = reg.get_evaluator("disa-stig-cisco-iosxe")

        cis_results = cis_eval.evaluate(parsed_test_csm)
        stig_results = stig_eval.evaluate(parsed_test_csm)

        assert len(cis_results) == 7
        assert len(stig_results) == 10

        aggregator = MultiFrameworkAggregator(registry=reg)
        combined = cis_results + stig_results
        audit = aggregator.aggregate(combined, audit_id="TEST-AUDIT-001", device_hostname="EDGE-RTR-01")

        # 1. Overall Metrics
        om = audit.overall_metrics
        assert om.total_frameworks == 2
        assert om.total_controls == 17
        assert om.total_pass == 12   # 5 (CIS) + 7 (STIG)
        assert om.total_fail == 4    # 2 (CIS) + 2 (STIG)
        assert om.total_unknown == 1 # 0 (CIS) + 1 (STIG)
        # Evaluated total: 12 + 4 = 16. Pass rate = 12 / 16 = 75.0%
        assert om.overall_pass_rate == 75.0
        # Unknown rate: 1 / 17 = 5.88%
        assert om.overall_unknown_rate == 5.88

        # 2. CIS Summary
        cis_summary = audit.framework_summaries["cis-cisco-iosxe"]
        assert cis_summary.framework_name == "CIS Cisco IOS XE 17.x Benchmark"
        assert cis_summary.framework_version == "v2.2.1"
        assert cis_summary.total_controls == 7
        assert cis_summary.pass_count == 5
        assert cis_summary.fail_count == 2
        assert cis_summary.unknown_count == 0
        assert cis_summary.pass_rate == 71.43  # 5 / 7 = 71.43%

        # 3. DISA-STIG Summary
        stig_summary = audit.framework_summaries["disa-stig-cisco-iosxe"]
        assert stig_summary.framework_name == "DISA STIG Cisco IOS XE Benchmark"
        assert stig_summary.framework_version == "V3R7"
        assert stig_summary.total_controls == 10
        assert stig_summary.pass_count == 7
        assert stig_summary.fail_count == 2
        assert stig_summary.unknown_count == 1
        assert stig_summary.pass_rate == 77.78  # 7 / 9 = 77.78%
        assert stig_summary.unknown_rate == 10.0 # 1 / 10 = 10.0%

        # 4. Consolidated Evidence
        assert len(audit.consolidated_evidence) == 17
        # Ensure all CIS evidence items precede STIG due to alphabetical sorting ('cis-...' < 'disa-...')
        assert audit.consolidated_evidence[0].framework_id == "cis-cisco-iosxe"
        assert audit.consolidated_evidence[-1].framework_id == "disa-stig-cisco-iosxe"


# --- 7. Security AST Analysis ---

class TestComplianceAggregatorStaticSecurityInvariants:
    """Static AST analysis ensuring compliance_aggregator.py contains zero unsafe imports."""

    PROHIBITED_MODULES = {
        "urllib",
        "requests",
        "socket",
        "http",
        "httpx",
        "subprocess",
        "os.system",
        "eval",
        "exec",
        "ollama",
        "ai_model_manager",
        "ai_suggester",
        "torch",
        "transformers",
    }

    def test_no_prohibited_imports_in_compliance_aggregator(self):
        src_path = pathlib.Path(__file__).parent / "compliance_aggregator.py"
        tree = ast.parse(src_path.read_text(encoding="utf-8"))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    assert root_pkg not in self.PROHIBITED_MODULES, f"Prohibited module imported: {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_pkg = node.module.split(".")[0]
                    assert root_pkg not in self.PROHIBITED_MODULES, f"Prohibited module imported from: {node.module}"
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                    pytest.fail(f"Use of prohibited built-in '{node.func.id}' found at line {node.lineno}")

    def test_no_vendor_specific_branching_in_aggregator(self):
        """Verifies that compliance_aggregator.py contains zero vendor branching or imports."""
        src_path = pathlib.Path(__file__).parent / "compliance_aggregator.py"
        source_text = src_path.read_text(encoding="utf-8")
        tree = ast.parse(source_text, filename="compliance_aggregator.py")

        # 1. AST check: Zero vendor module imports
        vendor_modules = {"cisco_auditor", "juniper_auditor", "vendor_adapter", "vendor_registry"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    assert root_pkg not in vendor_modules, f"Vendor module '{root_pkg}' imported in compliance_aggregator.py"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_pkg = node.module.split(".")[0]
                    assert root_pkg not in vendor_modules, f"Vendor module '{root_pkg}' imported in compliance_aggregator.py"

        # 2. Textual check: Zero vendor branching keywords
        for line_no, line in enumerate(source_text.splitlines(), start=1):
            line_clean = line.strip().lower()
            if line_clean.startswith("#") or line_clean.startswith('"""') or line_clean.startswith('*'):
                continue
            assert 'vendor == "cisco"' not in line_clean, f"Vendor branching found at line {line_no}"
            assert 'vendor == "juniper"' not in line_clean, f"Vendor branching found at line {line_no}"
            assert 'vendor.lower()' not in line_clean, f"Vendor branching found at line {line_no}"
