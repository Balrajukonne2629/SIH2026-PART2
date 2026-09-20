"""NTRO PS26155 — DISA-STIG Cisco IOS-XE Test Suite (Phase 3A.3).

Verifies:
1. DISA-STIG Framework metadata and Control catalog integrity (V3R7 provenance).
2. Internal rule mapping completeness and bidirectional consistency.
3. Coexistence of CIS and DISA-STIG frameworks without namespace/identity collision.
4. Strict evaluation logic for each DISA-STIG control (PASS, FAIL, UNKNOWN).
5. UNKNOWN preservation (unconfigured fields never default to FAIL).
6. Exact evaluation parity with cisco_auditor.py on labeled_test_config.txt.
7. Multi-framework independent evaluation on identical CSM.
8. 100% Determinism across consecutive evaluation runs.
9. Static AST security invariants (zero AI, zero network, zero execution imports).
"""

import ast
import json
import pathlib
import pytest
from typing import Any, Dict

from compliance_framework import (
    ComplianceStatus,
    Control,
    Evidence,
    EvaluationResult,
    Framework,
    FrameworkRegistry,
)
from cis_benchmark_cisco_iosxe import (
    CIS_CISCO_IOSXE_FRAMEWORK,
    CisCiscoIosXeEvaluator,
    register_cis_cisco_iosxe,
)
from disa_stig_cisco_iosxe import (
    DISA_STIG_CISCO_IOSXE_FRAMEWORK,
    DISA_STIG_CISCO_IOSXE_FRAMEWORK_ID,
    DISA_STIG_CISCO_IOSXE_CONTROLS,
    CISCO_TO_STIG_MAPPING,
    STIG_TO_CISCO_MAPPING,
    StigCiscoIosXeEvaluator,
    register_disa_stig_cisco_iosxe,
)
import cisco_auditor


# --- 1. Framework Metadata & Catalog Provenance Tests ---

class TestDisaStigCatalog:
    """Tests DISA-STIG framework metadata and control catalog provenance."""

    def test_framework_metadata(self):
        fw = DISA_STIG_CISCO_IOSXE_FRAMEWORK
        assert fw.framework_id == "disa-stig-cisco-iosxe"
        assert fw.name == "DISA STIG Cisco IOS XE Benchmark"
        assert fw.version == "V3R7"
        assert fw.vendor_scope == "Cisco IOS-XE"
        assert fw.control_namespace == "DISA-STIG"
        assert fw.enabled is True

    def test_catalog_controls_provenance(self):
        expected_stig_ids = {
            "V-215845", "V-215854", "V-215843", "V-220139", "V-215841",
            "V-215812", "V-216646", "V-216645", "V-220656", "V-216680"
        }
        assert set(DISA_STIG_CISCO_IOSXE_CONTROLS.keys()) == expected_stig_ids

        for vid, ctrl in DISA_STIG_CISCO_IOSXE_CONTROLS.items():
            assert ctrl.control_id == vid
            assert ctrl.framework_id == "disa-stig-cisco-iosxe"
            assert len(ctrl.title) > 0
            assert len(ctrl.description) > 0
            assert ctrl.severity in ("low", "medium", "high", "critical")
            assert len(ctrl.expected_state) > 0
            assert len(ctrl.evidence_requirements) > 0

            # Verified provenance
            meta = ctrl.evaluation_metadata
            assert "rule_id" in meta and meta["rule_id"].startswith("SV-")
            assert "source_benchmark" in meta
            assert "source_file" in meta and meta["source_file"].endswith(".xml")
            assert "ccis" in meta and len(meta["ccis"]) > 0

    def test_cisco_to_stig_mapping_completeness(self):
        # All 10 Cisco baseline rules map to verified STIG controls
        for i in range(1, 11):
            rule_id = [
                "CISCO-SSH-001", "CISCO-AAA-001", "CISCO-NTP-001", "CISCO-LOG-001",
                "CISCO-SNMP-001", "CISCO-ACL-001", "CISCO-INT-001", "CISCO-ROUTING-001",
                "CISCO-STP-001", "CISCO-MGMT-001"
            ][i - 1]
            assert rule_id in CISCO_TO_STIG_MAPPING
            stig_ids = CISCO_TO_STIG_MAPPING[rule_id]
            for sid in stig_ids:
                assert sid in DISA_STIG_CISCO_IOSXE_CONTROLS


# --- 2. Registry & Framework Coexistence Tests ---

class TestFrameworkCoexistence:
    """Tests registration and side-by-side coexistence of CIS and DISA-STIG."""

    def test_cis_and_stig_coexist_without_collision(self):
        reg = FrameworkRegistry()
        register_cis_cisco_iosxe(reg)
        register_disa_stig_cisco_iosxe(reg)

        assert reg.exists("cis-cisco-iosxe")
        assert reg.exists("disa-stig-cisco-iosxe")

        cis_fw = reg.get("cis-cisco-iosxe")
        stig_fw = reg.get("disa-stig-cisco-iosxe")

        assert cis_fw.version == "v2.2.1"
        assert stig_fw.version == "V3R7"
        assert cis_fw.control_namespace == "CIS"
        assert stig_fw.control_namespace == "DISA-STIG"

        cis_eval = reg.get_evaluator("cis-cisco-iosxe")
        stig_eval = reg.get_evaluator("disa-stig-cisco-iosxe")

        assert isinstance(cis_eval, CisCiscoIosXeEvaluator)
        assert isinstance(stig_eval, StigCiscoIosXeEvaluator)
        assert cis_eval.framework_id == "cis-cisco-iosxe"
        assert stig_eval.framework_id == "disa-stig-cisco-iosxe"


# --- 3. Per-Control Evaluation Unit Tests (PASS, FAIL, UNKNOWN) ---

class TestDisaStigControlEvaluatorUnit:
    """Unit tests for all 10 STIG controls under PASS, FAIL, and UNKNOWN conditions."""

    def setup_method(self):
        self.evaluator = StigCiscoIosXeEvaluator()

    # --- V-215845 (SSH) ---
    def test_eval_v215845_pass(self):
        csm = {"services": {"ssh_version": 2, "ssh": True, "telnet": False}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215845"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS
        assert res.control_id == "V-215845"
        assert res.evidence is not None

    def test_eval_v215845_fail_v1(self):
        csm = {"services": {"ssh_version": 1, "ssh": True, "telnet": False}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215845"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_v215845_unknown_missing(self):
        csm = {}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215845"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- V-215854 (AAA) ---
    def test_eval_v215854_pass(self):
        csm = {"aaa": {"configured": True, "enabled": True, "authentication_method": "group radius local"}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215854"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_v215854_fail_no_method(self):
        csm = {"aaa": {"configured": True, "enabled": True, "authentication_method": None}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215854"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_v215854_unknown_not_configured(self):
        csm = {"aaa": {"configured": False, "enabled": False, "authentication_method": None}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215854"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- V-215843 (NTP) ---
    def test_eval_v215843_pass(self):
        csm = {"ntp": {"enabled": True, "servers": ["10.0.0.1"], "authentication_enabled": True}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215843"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_v215843_fail_unauthenticated(self):
        csm = {"ntp": {"enabled": True, "servers": ["10.0.0.1"], "authentication_enabled": False}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215843"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_v215843_unknown_no_servers(self):
        csm = {"ntp": {"enabled": False, "servers": [], "authentication_enabled": False}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215843"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- V-220139 (Logging) ---
    def test_eval_v220139_pass(self):
        csm = {"logging": {"remote_logging_enabled": True, "timestamps_enabled": True, "enabled": True, "remote_servers": ["10.1.1.1"]}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-220139"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_v220139_fail_no_timestamps(self):
        csm = {"logging": {"remote_logging_enabled": True, "timestamps_enabled": False, "enabled": True, "remote_servers": ["10.1.1.1"]}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-220139"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_v220139_unknown_not_configured(self):
        csm = {"logging": {"remote_logging_enabled": False, "timestamps_enabled": False, "enabled": False}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-220139"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- V-215841 (SNMP) ---
    def test_eval_v215841_pass_clean(self):
        csm = {"snmp": {"enabled": True, "community_strings": ["SecOpsSecureSNMP#99"]}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215841"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_v215841_fail_weak(self):
        csm = {"snmp": {"enabled": True, "community_strings": ["public"]}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215841"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_v215841_unknown_not_enabled(self):
        csm = {"snmp": {"enabled": False, "community_strings": []}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215841"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- V-215812 (Management ACL) ---
    def test_eval_v215812_pass(self):
        csm = {"access_control": {"management_acl_present": True}, "services": {"ssh": True}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215812"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_v215812_fail(self):
        csm = {"access_control": {"management_acl_present": False, "acls_present": False}, "services": {"ssh": True}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215812"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_v215812_unknown(self):
        csm = {"access_control": {"management_acl_present": False, "acls_present": False}, "services": {"ssh": False}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-215812"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- V-216646 (Unused Interfaces) ---
    def test_eval_v216646_pass_all_shutdown(self):
        csm = {
            "interfaces": [
                {"name": "GigabitEthernet2", "description": "Unused interface per security policy", "shutdown": True, "enabled": False},
                {"name": "GigabitEthernet3", "description": "unused port", "shutdown": True, "enabled": False},
            ]
        }
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-216646"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_v216646_fail_unshutdown_unused(self):
        csm = {
            "interfaces": [
                {"name": "GigabitEthernet2", "description": "Unused interface per security policy", "shutdown": False, "enabled": True},
            ]
        }
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-216646"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_v216646_unknown_no_unused(self):
        csm = {
            "interfaces": [
                {"name": "GigabitEthernet1", "description": "Uplink to Core Router", "shutdown": False, "enabled": True},
            ]
        }
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-216646"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- V-216645 (Routing Auth) ---
    def test_eval_v216645_pass(self):
        csm = {"routing": {"routing_protocols": ["bgp"], "routing_authentication_enabled": True}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-216645"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_v216645_fail(self):
        csm = {"routing": {"routing_protocols": ["bgp"], "routing_authentication_enabled": False}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-216645"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_v216645_unknown(self):
        csm = {"routing": {"routing_protocols": [], "routing_authentication_enabled": False}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-216645"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- V-220656 (Switch STP BPDU Guard) ---
    def test_eval_v220656_pass(self):
        csm = {"spanning_tree": {"configured": True, "bpduguard_enabled": True}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-220656"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_v220656_fail(self):
        csm = {"spanning_tree": {"configured": True, "bpduguard_enabled": False}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-220656"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_v220656_unknown(self):
        csm = {"spanning_tree": {"configured": False, "bpduguard_enabled": False}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-220656"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- V-216680 (Management VRF) ---
    def test_eval_v216680_pass(self):
        csm = {"management": {"management_vrf_enabled": True}, "services": {"ssh": True}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-216680"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_v216680_fail(self):
        csm = {"management": {"management_vrf_enabled": False}, "services": {"ssh": True}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-216680"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_v216680_unknown(self):
        csm = {"management": {"management_vrf_enabled": False}, "services": {"ssh": False}}
        ctrl = DISA_STIG_CISCO_IOSXE_CONTROLS["V-216680"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN


# --- 4. Parity with cisco_auditor.py on Labeled Test Config ---

class TestDisaStigEvaluationParity:
    """Tests 1:1 evaluation parity against cisco_auditor.py on labeled_test_config.txt."""

    @pytest.fixture
    def parsed_test_csm(self):
        cfg_path = pathlib.Path(__file__).parent / "05_Configuration_Datasets" / "Cisco" / "labeled_test_config.txt"
        assert cfg_path.exists(), f"Missing test config at {cfg_path}"
        text = cfg_path.read_text(encoding="utf-8")
        return cisco_auditor.parse_cisco(text)

    def test_stig_evaluator_on_labeled_config(self, parsed_test_csm):
        evaluator = StigCiscoIosXeEvaluator()
        results = evaluator.evaluate(parsed_test_csm)
        res_map = {r.control_id: r for r in results}

        assert res_map["V-215845"].status == ComplianceStatus.PASS  # SSH v2
        assert res_map["V-215854"].status == ComplianceStatus.PASS  # AAA new-model
        assert res_map["V-215843"].status == ComplianceStatus.FAIL  # NTP unauthenticated
        assert res_map["V-220139"].status == ComplianceStatus.PASS  # Logging
        assert res_map["V-215841"].status == ComplianceStatus.FAIL  # Weak SNMP string
        assert res_map["V-215812"].status == ComplianceStatus.PASS  # Line vty access-class
        assert res_map["V-216646"].status == ComplianceStatus.PASS  # Unused interface is shutdown
        assert res_map["V-216645"].status == ComplianceStatus.PASS     # Routing auth present
        assert res_map["V-220656"].status == ComplianceStatus.UNKNOWN  # STP not configured in router config
        assert res_map["V-216680"].status == ComplianceStatus.PASS     # Management VRF present

    def test_direct_parity_against_all_cisco_auditor_rules(self, parsed_test_csm):
        rules_path = pathlib.Path(__file__).parent / "07_Compliance_Scanners" / "Rule_Library" / "extracted" / "Rule_Library" / "vendor_rule_mapping.json"
        raw_rules = json.loads(rules_path.read_text(encoding="utf-8-sig"))["vendors"]["Cisco IOS-XE"]["rules"]
        auditor_res = cisco_auditor.evaluate_rules(parsed_test_csm, raw_rules)

        evaluator = StigCiscoIosXeEvaluator()
        stig_results = evaluator.evaluate(parsed_test_csm)
        stig_map = {r.control_id: r.status.value for r in stig_results}

        # Compare all 10 mapped rules
        assert stig_map["V-215845"] == auditor_res["CISCO-SSH-001"]["status"]
        assert stig_map["V-215854"] == auditor_res["CISCO-AAA-001"]["status"]
        assert stig_map["V-215843"] == auditor_res["CISCO-NTP-001"]["status"]
        assert stig_map["V-220139"] == auditor_res["CISCO-LOG-001"]["status"]
        assert stig_map["V-215841"] == auditor_res["CISCO-SNMP-001"]["status"]
        assert stig_map["V-215812"] == auditor_res["CISCO-ACL-001"]["status"]
        assert stig_map["V-216646"] == auditor_res["CISCO-INT-001"]["status"]
        assert stig_map["V-216645"] == auditor_res["CISCO-ROUTING-001"]["status"]
        assert stig_map["V-220656"] == auditor_res["CISCO-STP-001"]["status"]
        assert stig_map["V-216680"] == auditor_res["CISCO-MGMT-001"]["status"]


# --- 5. Multi-Framework Coexistence on Same CSM ---

class TestMultiFrameworkEvaluation:
    """Verifies that CIS and DISA-STIG evaluate the same CSM without cross-contamination."""

    def test_cis_and_stig_evaluate_independently(self):
        cfg_path = pathlib.Path(__file__).parent / "05_Configuration_Datasets" / "Cisco" / "labeled_test_config.txt"
        csm = cisco_auditor.parse_cisco(cfg_path.read_text(encoding="utf-8"))

        cis_eval = CisCiscoIosXeEvaluator()
        stig_eval = StigCiscoIosXeEvaluator()

        cis_res = cis_eval.evaluate(csm)
        stig_res = stig_eval.evaluate(csm)

        assert len(cis_res) == 7
        assert len(stig_res) == 10

        assert all(r.framework_id == "cis-cisco-iosxe" for r in cis_res)
        assert all(r.framework_id == "disa-stig-cisco-iosxe" for r in stig_res)

        cis_ids = {r.control_id for r in cis_res}
        stig_ids = {r.control_id for r in stig_res}

        # Control IDs are disjoint across frameworks
        assert cis_ids.isdisjoint(stig_ids)


# --- 6. Determinism Guarantee ---

class TestDisaStigDeterminism:
    """Verifies that STIG evaluation is 100% deterministic across consecutive runs."""

    def test_five_consecutive_runs(self):
        cfg_path = pathlib.Path(__file__).parent / "05_Configuration_Datasets" / "Cisco" / "labeled_test_config.txt"
        csm = cisco_auditor.parse_cisco(cfg_path.read_text(encoding="utf-8"))
        evaluator = StigCiscoIosXeEvaluator()

        run_dicts = []
        for _ in range(5):
            results = evaluator.evaluate(csm)
            serialized = [r.to_dict() for r in results]
            run_dicts.append(serialized)

        for i in range(1, 5):
            assert run_dicts[i] == run_dicts[0], f"Determinism violation at run {i}"


# --- 7. Security & Hardening AST Analysis ---

class TestDisaStigStaticSecurityInvariants:
    """Static AST analysis ensuring disa_stig_cisco_iosxe.py contains zero unsafe imports."""

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

    def test_no_prohibited_imports_in_disa_stig(self):
        src_path = pathlib.Path(__file__).parent / "disa_stig_cisco_iosxe.py"
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
