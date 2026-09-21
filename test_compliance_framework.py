"""Unit, Contract, Parity, and Security AST Tests for Framework Abstraction (Phase 3A.1).

Validates:
1. Framework identity, normalization, validation, and serialization.
2. Control domain model, severity normalization, validation, and serialization.
3. ComplianceStatus strictly PASS, FAIL, UNKNOWN (UNKNOWN distinct from FAIL).
4. Deterministic Evidence construction, immutability, and validation.
5. EvaluationResult model and serialization.
6. FrameworkEvaluator contract and multi-run determinism.
7. FrameworkRegistry registration, deduplication, lookup, filtering, and exceptions.
8. CiscoCsmFrameworkAdapter parity against verified Cisco MVP baseline.
9. Security & Safety AST analysis: zero network, zero execution, zero AI dependencies.
"""

import ast
import json
import pathlib
import pytest

from compliance_framework import (
    ComplianceStatus,
    Evidence,
    Control,
    Framework,
    EvaluationResult,
    FrameworkEvaluator,
    FrameworkRegistry,
    FrameworkNotFoundError,
    CiscoCsmFrameworkAdapter,
    get_default_registry
)


# --- 1. Framework Domain Model Tests ---

class TestFrameworkModel:
    def test_valid_framework_construction(self):
        fw = Framework(
            framework_id="CIS",
            name="Center for Internet Security Benchmark",
            version="2.2.1",
            description="CIS Benchmark for Cisco IOS-XE 17.x",
            vendor_scope="Cisco IOS-XE",
            control_namespace="CIS"
        )
        assert fw.framework_id == "cis"  # Normalized to lowercase
        assert fw.name == "Center for Internet Security Benchmark"
        assert fw.version == "2.2.1"
        assert fw.vendor_scope == "Cisco IOS-XE"
        assert fw.control_namespace == "CIS"
        assert fw.enabled is True

    def test_framework_to_dict(self):
        fw = Framework(
            framework_id="disa-stig",
            name="DISA STIG Cisco IOS-XE",
            version="V3R7",
            description="DoD Security Technical Implementation Guide",
            enabled=False
        )
        data = fw.to_dict()
        assert data["framework_id"] == "disa-stig"
        assert data["version"] == "V3R7"
        assert data["enabled"] is False

    @pytest.mark.parametrize("invalid_id", ["", "   ", "cis benchmark!", "disa@stig", "framework/1"])
    def test_invalid_framework_id_rejected(self, invalid_id):
        with pytest.raises(ValueError):
            Framework(
                framework_id=invalid_id,
                name="Valid Name",
                version="1.0"
            )

    def test_missing_required_fields_rejected(self):
        with pytest.raises(ValueError, match="name must not be empty"):
            Framework(framework_id="cis", name="", version="1.0")
        with pytest.raises(ValueError, match="version must not be empty"):
            Framework(framework_id="cis", name="CIS", version="")


# --- 2. Control Domain Model Tests ---

class TestControlModel:
    def test_valid_control_construction(self):
        ctrl = Control(
            framework_id="CIS",
            control_id="2.1.1.2",
            title="Ensure SSH is Configured with Version 2",
            description="Legacy SSH v1 contains known cryptographic flaws.",
            severity="HIGH",
            expected_state="ip ssh version 2",
            evaluation_metadata={"csm_path": "services.ssh_version"},
            evidence_requirements=["services.ssh_version", "services.telnet"]
        )
        assert ctrl.framework_id == "cis"
        assert ctrl.control_id == "2.1.1.2"
        assert ctrl.severity == "high"  # Normalized to lowercase
        assert ctrl.evaluation_metadata["csm_path"] == "services.ssh_version"

    def test_control_to_dict(self):
        ctrl = Control(
            framework_id="disa-stig",
            control_id="V-215845",
            title="Disable Telnet",
            description="Telnet transmits plaintext credentials.",
            severity="critical"
        )
        d = ctrl.to_dict()
        assert d["framework_id"] == "disa-stig"
        assert d["control_id"] == "V-215845"
        assert d["severity"] == "critical"

    def test_control_validation_errors(self):
        with pytest.raises(ValueError, match="framework_id must not be empty"):
            Control(framework_id="", control_id="1.1", title="Test", description="Desc")
        with pytest.raises(ValueError, match="control_id must not be empty"):
            Control(framework_id="cis", control_id="", title="Test", description="Desc")
        with pytest.raises(ValueError, match="title must not be empty"):
            Control(framework_id="cis", control_id="1.1", title="", description="Desc")


# --- 3. Compliance Status Contract Tests ---

class TestComplianceStatus:
    def test_exact_statuses(self):
        assert ComplianceStatus.PASS == "Pass"
        assert ComplianceStatus.FAIL == "Fail"
        assert ComplianceStatus.UNKNOWN == "Unknown"

    def test_unknown_distinct_from_fail(self):
        status = ComplianceStatus.UNKNOWN
        assert status != ComplianceStatus.FAIL
        assert status.is_unknown() is True
        assert status.is_fail() is False
        assert status.is_pass() is False

    @pytest.mark.parametrize("text,expected", [
        ("Pass", ComplianceStatus.PASS),
        ("PASS", ComplianceStatus.PASS),
        ("passed", ComplianceStatus.PASS),
        ("compliant", ComplianceStatus.PASS),
        ("Fail", ComplianceStatus.FAIL),
        ("FAIL", ComplianceStatus.FAIL),
        ("failed", ComplianceStatus.FAIL),
        ("non-compliant", ComplianceStatus.FAIL),
        ("Unknown", ComplianceStatus.UNKNOWN),
        ("UNKNOWN", ComplianceStatus.UNKNOWN),
        ("unmapped", ComplianceStatus.UNKNOWN),
        ("indeterminate", ComplianceStatus.UNKNOWN),
    ])
    def test_from_str_normalization(self, text, expected):
        assert ComplianceStatus.from_str(text) == expected

    def test_from_str_invalid_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid compliance status"):
            ComplianceStatus.from_str("NA")
        with pytest.raises(ValueError, match="Invalid compliance status"):
            ComplianceStatus.from_str("error")

    def test_from_str_type_error(self):
        with pytest.raises(TypeError):
            ComplianceStatus.from_str(123)  # type: ignore


# --- 4. Evidence Model Tests ---

class TestEvidenceModel:
    def test_valid_evidence(self):
        ev = Evidence(
            observed_value=2,
            location="csm.services.ssh_version",
            expected_value=2,
            rationale="SSH version matches required protocol standard 2.",
            confidence=1.0,
            source_lines=("ip ssh version 2",)
        )
        assert ev.observed_value == 2
        assert ev.location == "csm.services.ssh_version"
        assert ev.rationale.startswith("SSH version")
        assert ev.confidence == 1.0
        assert ev.source_lines == ("ip ssh version 2",)

    def test_evidence_to_dict(self):
        ev = Evidence(
            observed_value=False,
            location="csm.services.telnet",
            expected_value=False,
            rationale="Telnet service is disabled.",
            confidence=1.0
        )
        d = ev.to_dict()
        assert d["observed_value"] is False
        assert d["source_lines"] == []

    def test_evidence_validation_rejects_empty_fields(self):
        with pytest.raises(ValueError, match="location must not be empty"):
            Evidence(observed_value=1, location="", expected_value=1, rationale="ok")
        with pytest.raises(ValueError, match="rationale must not be empty"):
            Evidence(observed_value=1, location="loc", expected_value=1, rationale="")
        with pytest.raises(ValueError, match="confidence must be between"):
            Evidence(observed_value=1, location="loc", expected_value=1, rationale="ok", confidence=1.5)

    def test_evidence_is_immutable(self):
        ev = Evidence(observed_value=1, location="loc", expected_value=1, rationale="ok")
        with pytest.raises(AttributeError):
            ev.location = "new_loc"  # type: ignore


# --- 5. Evaluation Result Model Tests ---

class TestEvaluationResultModel:
    def test_result_pass_with_evidence(self):
        ev = Evidence(observed_value=2, location="csm.services.ssh_version", expected_value=2, rationale="Matches")
        res = EvaluationResult(
            framework_id="cis",
            control_id="2.1.1.2",
            status=ComplianceStatus.PASS,
            evidence=ev,
            reason="SSH version verified",
            observed_value=2,
            expected_value=2
        )
        assert res.status == ComplianceStatus.PASS
        assert res.status.is_pass() is True
        assert res.evidence is not None
        assert res.evidence.observed_value == 2

    def test_result_unknown_preservation(self):
        res = EvaluationResult(
            framework_id="cis",
            control_id="2.1.1.3",
            status=ComplianceStatus.UNKNOWN,
            reason="Control plane protection configuration unmapped in current device config"
        )
        assert res.status == ComplianceStatus.UNKNOWN
        assert res.status.is_unknown() is True
        assert res.status != ComplianceStatus.FAIL

    def test_result_status_string_coercion(self):
        res = EvaluationResult(
            framework_id="disa-stig",
            control_id="V-100",
            status="Fail"  # Coerced to ComplianceStatus.FAIL
        )
        assert res.status == ComplianceStatus.FAIL

    def test_result_to_dict(self):
        res = EvaluationResult(
            framework_id="cis",
            control_id="1.1",
            status=ComplianceStatus.PASS,
            reason="Verified"
        )
        d = res.to_dict()
        assert d["framework_id"] == "cis"
        assert d["status"] == "Pass"
        assert d["evidence"] is None


# --- 6. Framework Evaluator Contract & Determinism Tests ---

class MockDeterministicEvaluator(FrameworkEvaluator):
    """Test implementation of FrameworkEvaluator."""
    @property
    def framework_id(self) -> str:
        return "mock-framework"

    def evaluate(self, csm, controls=None):
        results = []
        for c in (controls or []):
            field_name = c.evaluation_metadata.get("field")
            observed = csm.get(field_name) if field_name else None
            expected = c.evaluation_metadata.get("expected")
            status = ComplianceStatus.PASS if observed == expected else ComplianceStatus.FAIL
            ev = Evidence(
                observed_value=observed,
                location=f"csm.{field_name}",
                expected_value=expected,
                rationale=f"Evaluated {c.control_id}"
            )
            results.append(
                EvaluationResult(
                    framework_id=self.framework_id,
                    control_id=c.control_id,
                    status=status,
                    evidence=ev,
                    observed_value=observed,
                    expected_value=expected
                )
            )
        return results


class TestFrameworkEvaluatorContract:
    def test_evaluator_evaluates_controls(self):
        evaluator = MockDeterministicEvaluator()
        controls = [
            Control(framework_id="mock-framework", control_id="MOCK-01", title="Test 1", description="D", evaluation_metadata={"field": "auth", "expected": True}),
            Control(framework_id="mock-framework", control_id="MOCK-02", title="Test 2", description="D", evaluation_metadata={"field": "telnet", "expected": False}),
        ]
        csm = {"auth": True, "telnet": True}
        results = evaluator.evaluate(csm, controls)
        assert len(results) == 2
        assert results[0].control_id == "MOCK-01"
        assert results[0].status == ComplianceStatus.PASS
        assert results[1].control_id == "MOCK-02"
        assert results[1].status == ComplianceStatus.FAIL

    def test_evaluator_determinism(self):
        evaluator = MockDeterministicEvaluator()
        controls = [
            Control(framework_id="mock-framework", control_id="MOCK-01", title="Test 1", description="D", evaluation_metadata={"field": "auth", "expected": True}),
        ]
        csm = {"auth": True}
        
        # Run 10 times: results must be identical
        runs = [evaluator.evaluate(csm, controls)[0].to_dict() for _ in range(10)]
        for r in runs[1:]:
            assert r["status"] == runs[0]["status"]
            assert r["evidence"] == runs[0]["evidence"]


# --- 7. Framework Registry Tests ---

class TestFrameworkRegistry:
    def test_register_and_get(self):
        reg = FrameworkRegistry()
        fw = Framework(framework_id="cis", name="CIS", version="1.0")
        reg.register(fw)
        assert reg.exists("cis") is True
        assert reg.exists("CIS") is True  # Case insensitive
        retrieved = reg.get("cis")
        assert retrieved.name == "CIS"

    def test_duplicate_registration_rejected(self):
        reg = FrameworkRegistry()
        fw1 = Framework(framework_id="cis", name="CIS 1", version="1.0")
        fw2 = Framework(framework_id="cis", name="CIS 2", version="2.0")
        reg.register(fw1)
        with pytest.raises(ValueError, match="already registered"):
            reg.register(fw2, allow_replace=False)

    def test_duplicate_registration_allowed_with_replace(self):
        reg = FrameworkRegistry()
        fw1 = Framework(framework_id="cis", name="CIS 1", version="1.0")
        fw2 = Framework(framework_id="cis", name="CIS 2", version="2.0")
        reg.register(fw1)
        reg.register(fw2, allow_replace=True)
        assert reg.get("cis").version == "2.0"

    def test_evaluator_registration_and_mismatch_guard(self):
        reg = FrameworkRegistry()
        fw = Framework(framework_id="mock-framework", name="Mock", version="1.0")
        evaluator = MockDeterministicEvaluator()
        reg.register(fw, evaluator=evaluator)
        assert reg.get_evaluator("mock-framework") is evaluator

        # Mismatched evaluator framework_id
        fw_cis = Framework(framework_id="cis", name="CIS", version="1.0")
        with pytest.raises(ValueError, match="does not match framework"):
            reg.register(fw_cis, evaluator=evaluator)

    def test_missing_framework_raises_framework_not_found_error(self):
        reg = FrameworkRegistry()
        with pytest.raises(FrameworkNotFoundError):
            reg.get("nonexistent")
        with pytest.raises(FrameworkNotFoundError):
            reg.get_evaluator("nonexistent")

    def test_list_and_filter(self):
        reg = FrameworkRegistry()
        reg.register(Framework(framework_id="b-fw", name="B", version="1.0", enabled=True))
        reg.register(Framework(framework_id="a-fw", name="A", version="1.0", enabled=False))
        
        all_fw = reg.list()
        assert [f.framework_id for f in all_fw] == ["a-fw", "b-fw"]  # Sorted

        enabled_fw = reg.list(enabled_only=True)
        assert [f.framework_id for f in enabled_fw] == ["b-fw"]

    def test_unregister(self):
        reg = FrameworkRegistry()
        reg.register(Framework(framework_id="cis", name="CIS", version="1.0"))
        assert reg.unregister("cis") is True
        assert reg.exists("cis") is False
        assert reg.unregister("cis") is False

    def test_list_for_vendor_cisco_and_normalization(self):
        """Tests A, B, C: Cisco vendor matching, case-insensitivity, and platform string normalization."""
        reg = FrameworkRegistry()
        reg.register(Framework(framework_id="cis-cisco", name="CIS Cisco", version="1.0", vendor_scope="Cisco IOS-XE"))
        reg.register(Framework(framework_id="stig-cisco", name="STIG Cisco", version="1.0", vendor_scope="Cisco IOS-XE"))
        reg.register(Framework(framework_id="universal-fw", name="Universal", version="1.0", vendor_scope=None))

        # A: vendor="cisco"
        cisco_fws = reg.list_for_vendor("cisco")
        assert [f.framework_id for f in cisco_fws] == ["cis-cisco", "stig-cisco", "universal-fw"]

        # B: Case normalization
        assert [f.framework_id for f in reg.list_for_vendor("CISCO")] == ["cis-cisco", "stig-cisco", "universal-fw"]
        assert [f.framework_id for f in reg.list_for_vendor("Cisco")] == ["cis-cisco", "stig-cisco", "universal-fw"]

        # C: Cisco IOS-XE platform string normalization
        assert [f.framework_id for f in reg.list_for_vendor("Cisco IOS-XE")] == ["cis-cisco", "stig-cisco", "universal-fw"]
        assert [f.framework_id for f in reg.list_for_vendor("cisco ios-xe")] == ["cis-cisco", "stig-cisco", "universal-fw"]
        assert [f.framework_id for f in reg.list_for_vendor("CISCO IOS-XE")] == ["cis-cisco", "stig-cisco", "universal-fw"]

    def test_list_for_vendor_juniper_isolation(self):
        """Test D: Juniper must NOT return Cisco-only frameworks."""
        reg = FrameworkRegistry()
        reg.register(Framework(framework_id="cis-cisco", name="CIS Cisco", version="1.0", vendor_scope="Cisco IOS-XE"))
        reg.register(Framework(framework_id="stig-cisco", name="STIG Cisco", version="1.0", vendor_scope="Cisco IOS-XE"))
        reg.register(Framework(framework_id="universal-fw", name="Universal", version="1.0", vendor_scope=None))

        juniper_fws = reg.list_for_vendor("juniper")
        # Must only return vendor-neutral frameworks, no Cisco frameworks
        assert [f.framework_id for f in juniper_fws] == ["universal-fw"]

        # If no vendor-neutral frameworks exist:
        reg2 = FrameworkRegistry()
        reg2.register(Framework(framework_id="cis-cisco", name="CIS Cisco", version="1.0", vendor_scope="Cisco IOS-XE"))
        assert reg2.list_for_vendor("juniper") == []

    def test_list_for_vendor_unknown_vendor(self):
        """Test E: Unknown vendor returns only vendor-neutral frameworks, or [] if none."""
        reg = FrameworkRegistry()
        reg.register(Framework(framework_id="cis-cisco", name="CIS Cisco", version="1.0", vendor_scope="Cisco IOS-XE"))
        reg.register(Framework(framework_id="universal-fw", name="Universal", version="1.0", vendor_scope=None))

        unknown_fws = reg.list_for_vendor("unknown_vendor_xyz")
        assert [f.framework_id for f in unknown_fws] == ["universal-fw"]

        # Without vendor-neutral
        reg2 = FrameworkRegistry()
        reg2.register(Framework(framework_id="cis-cisco", name="CIS Cisco", version="1.0", vendor_scope="Cisco IOS-XE"))
        assert reg2.list_for_vendor("unknown_vendor_xyz") == []

    def test_list_for_vendor_enabled_filtering(self):
        """Tests F, G: Disabled frameworks excluded when enabled_only=True, included when enabled_only=False."""
        reg = FrameworkRegistry()
        reg.register(Framework(framework_id="active-cis", name="Active CIS", version="1.0", vendor_scope="Cisco IOS-XE", enabled=True))
        reg.register(Framework(framework_id="disabled-stig", name="Disabled STIG", version="1.0", vendor_scope="Cisco IOS-XE", enabled=False))

        # F: enabled_only=True excludes disabled
        enabled_only = reg.list_for_vendor("cisco", enabled_only=True)
        assert [f.framework_id for f in enabled_only] == ["active-cis"]

        # G: enabled_only=False includes disabled if vendor-compatible
        all_vendor = reg.list_for_vendor("cisco", enabled_only=False)
        assert [f.framework_id for f in all_vendor] == ["active-cis", "disabled-stig"]

    def test_list_for_vendor_deterministic_ordering(self):
        """Test H: Repeated calls return identical framework order."""
        reg = FrameworkRegistry()
        reg.register(Framework(framework_id="zeta-fw", name="Zeta", version="1.0", vendor_scope="Cisco IOS-XE"))
        reg.register(Framework(framework_id="alpha-fw", name="Alpha", version="1.0", vendor_scope="Cisco IOS-XE"))
        reg.register(Framework(framework_id="beta-fw", name="Beta", version="1.0", vendor_scope="Cisco IOS-XE"))

        first_call = [f.framework_id for f in reg.list_for_vendor("cisco")]
        assert first_call == ["alpha-fw", "beta-fw", "zeta-fw"]

        for _ in range(5):
            assert [f.framework_id for f in reg.list_for_vendor("cisco")] == first_call

    def test_list_for_vendor_empty_or_whitespace_vendor(self):
        """Tests empty/whitespace vendor string handling."""
        reg = FrameworkRegistry()
        reg.register(Framework(framework_id="cisco-fw", name="Cisco", version="1.0", vendor_scope="Cisco IOS-XE"))
        reg.register(Framework(framework_id="universal-fw", name="Universal", version="1.0", vendor_scope=None))

        assert [f.framework_id for f in reg.list_for_vendor("")] == ["universal-fw"]
        assert [f.framework_id for f in reg.list_for_vendor("   ")] == ["universal-fw"]


# --- 8. Cisco MVP Adapter Parity & Backward Compatibility Tests ---

class TestCiscoCsmAdapterParity:
    def test_adapter_evaluates_cisco_csm_parity(self):
        import cisco_auditor

        base = pathlib.Path(__file__).parent.resolve()
        cfg_file = base / "05_Configuration_Datasets" / "Cisco" / "labeled_test_config.txt"
        rules_file = base / "07_Compliance_Scanners" / "Rule_Library" / "extracted" / "Rule_Library" / "vendor_rule_mapping.json"
        
        rules_data = json.loads(rules_file.read_text(encoding="utf-8-sig"))["vendors"]["Cisco IOS-XE"]["rules"]
        cfg_text = cfg_file.read_text(encoding="utf-8")

        # 1. Direct baseline evaluation from cisco_auditor
        csm = cisco_auditor.parse_cisco(cfg_text)
        direct_evals = cisco_auditor.evaluate_rules(csm, rules_data)

        # 2. Evaluation via framework adapter
        adapter = CiscoCsmFrameworkAdapter(
            framework_id="cisco-ios-xe-baseline",
            rules_data=rules_data
        )
        adapter_results = adapter.evaluate(csm)

        # 3. Assert exact parity
        assert len(adapter_results) == len(direct_evals)
        adapter_map = {r.control_id: r for r in adapter_results}

        for rule_id, d_res in direct_evals.items():
            a_res = adapter_map[rule_id]
            assert a_res.status.value == d_res["status"], f"Status mismatch on {rule_id}"
            assert a_res.framework_id == "cisco-ios-xe-baseline"
            assert a_res.evidence is not None
            assert a_res.evidence.confidence == 1.0


# --- 9. Security & Hardening AST Static Analysis Tests ---

class TestSecurityAndSafetyInvariants:
    def test_ast_safety_audit_compliance_framework(self):
        """Audits compliance_framework.py via AST to ensure zero AI, network, or execution paths."""
        file_path = pathlib.Path(__file__).parent / "compliance_framework.py"
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename="compliance_framework.py")

        forbidden_modules = {
            "urllib", "requests", "httpx", "socket", "http",
            "subprocess", "shutil",
            "ollama", "ai_model_manager", "torch", "transformers"
        }
        forbidden_calls = {"eval", "exec", "__import__", "system", "popen"}

        for node in ast.walk(tree):
            # Check import statements
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    assert root_mod not in forbidden_modules, f"Forbidden import '{alias.name}' detected in compliance_framework.py"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_mod = node.module.split(".")[0]
                    assert root_mod not in forbidden_modules, f"Forbidden from-import '{node.module}' detected in compliance_framework.py"

            # Check function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in forbidden_calls, f"Forbidden call '{node.func.id}' detected in compliance_framework.py"
                elif isinstance(node.func, ast.Attribute):
                    assert node.func.attr not in forbidden_calls, f"Forbidden method call '{node.func.attr}' detected in compliance_framework.py"
