"""NTRO PS26155 — CIS Benchmark Cisco IOS-XE Test Suite (Phase 3A.2).

Verifies:
1. CIS Framework metadata and Control catalog integrity (v2.2.1 provenance).
2. Internal rule mapping completeness and bidirectional consistency.
3. Strict evaluation logic for each CIS control (PASS, FAIL, UNKNOWN).
4. UNKNOWN preservation (unconfigured fields never default to FAIL).
5. Exact evaluation parity with cisco_auditor.py on labeled_test_config.txt.
6. 100% Determinism across consecutive evaluation runs.
7. Static AST security invariants (zero AI, zero network, zero execution imports).
"""

import ast
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
    CIS_CISCO_IOSXE_FRAMEWORK_ID,
    CIS_CISCO_IOSXE_CONTROLS,
    CISCO_TO_CIS_MAPPING,
    CIS_TO_CISCO_MAPPING,
    CisCiscoIosXeEvaluator,
    register_cis_cisco_iosxe,
)
import cisco_auditor


# --- 1. Catalog & Metadata Tests ---

class TestCisBenchmarkCatalog:
    """Tests framework metadata and control catalog provenance."""

    def test_framework_metadata(self):
        fw = CIS_CISCO_IOSXE_FRAMEWORK
        assert fw.framework_id == "cis-cisco-iosxe"
        assert fw.name == "CIS Cisco IOS XE 17.x Benchmark"
        assert fw.version == "v2.2.1"
        assert fw.vendor_scope == "Cisco IOS-XE"
        assert fw.control_namespace == "CIS"
        assert fw.enabled is True

    def test_catalog_controls_provenance(self):
        expected_control_ids = {"2.1.1.2", "1.1.1", "2.3.1.1", "2.2.4", "1.5.7", "1.2.5", "3.3.3.1"}
        assert set(CIS_CISCO_IOSXE_CONTROLS.keys()) == expected_control_ids

        for cid, ctrl in CIS_CISCO_IOSXE_CONTROLS.items():
            assert ctrl.control_id == cid
            assert ctrl.framework_id == "cis-cisco-iosxe"
            assert len(ctrl.title) > 0
            assert len(ctrl.description) > 0
            assert ctrl.severity in ("low", "medium", "high", "critical")
            assert len(ctrl.expected_state) > 0
            assert len(ctrl.evidence_requirements) > 0

            # Provenance source check
            source_ref = ctrl.evaluation_metadata.get("source_ref", "")
            assert "CIS_Cisco_IOS_XE_17.x_Benchmark_v2.2.1.pdf" in source_ref
            assert cid in source_ref

    def test_cisco_to_cis_mapping_integrity(self):
        assert "CISCO-SSH-001" in CISCO_TO_CIS_MAPPING
        assert "2.1.1.2" in CISCO_TO_CIS_MAPPING["CISCO-SSH-001"]

        assert "CISCO-AAA-001" in CISCO_TO_CIS_MAPPING
        assert "1.1.1" in CISCO_TO_CIS_MAPPING["CISCO-AAA-001"]

        assert "CISCO-NTP-001" in CISCO_TO_CIS_MAPPING
        assert "2.3.1.1" in CISCO_TO_CIS_MAPPING["CISCO-NTP-001"]

        assert "CISCO-LOG-001" in CISCO_TO_CIS_MAPPING
        assert "2.2.4" in CISCO_TO_CIS_MAPPING["CISCO-LOG-001"]

        assert "CISCO-SNMP-001" in CISCO_TO_CIS_MAPPING
        assert "1.5.7" in CISCO_TO_CIS_MAPPING["CISCO-SNMP-001"]

        assert "CISCO-ACL-001" in CISCO_TO_CIS_MAPPING
        assert "1.2.5" in CISCO_TO_CIS_MAPPING["CISCO-ACL-001"]

        assert "CISCO-ROUTING-001" in CISCO_TO_CIS_MAPPING
        assert "3.3.3.1" in CISCO_TO_CIS_MAPPING["CISCO-ROUTING-001"]

    def test_unmapped_rules_explicitly_excluded_from_cis(self):
        # Per mapping_log.md, CISCO-INT-001 and CISCO-STP-001 are not in CIS Router Benchmark
        assert "CISCO-INT-001" not in CISCO_TO_CIS_MAPPING
        assert "CISCO-STP-001" not in CISCO_TO_CIS_MAPPING


# --- 2. Registry Integration Tests ---

class TestCisRegistryIntegration:
    """Tests registration into FrameworkRegistry."""

    def test_register_into_isolated_registry(self):
        reg = FrameworkRegistry()
        register_cis_cisco_iosxe(reg)
        assert reg.exists("cis-cisco-iosxe")
        fw = reg.get("cis-cisco-iosxe")
        assert fw.version == "v2.2.1"
        evaluator = reg.get_evaluator("cis-cisco-iosxe")
        assert isinstance(evaluator, CisCiscoIosXeEvaluator)

    def test_register_into_default_registry(self):
        reg = register_cis_cisco_iosxe()
        assert reg.exists("cis-cisco-iosxe")
        evaluator = reg.get_evaluator("cis-cisco-iosxe")
        assert evaluator.framework_id == "cis-cisco-iosxe"


# --- 3. Per-Control Evaluation Unit Tests ---

class TestCisControlEvaluatorUnit:
    """Unit tests for each individual CIS control under PASS, FAIL, and UNKNOWN conditions."""

    def setup_method(self):
        self.evaluator = CisCiscoIosXeEvaluator()

    # --- 2.1.1.2 (SSH) ---
    def test_eval_ssh_pass(self):
        csm = {"services": {"ssh_version": 2, "ssh": True, "telnet": False}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["2.1.1.2"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS
        assert res.control_id == "2.1.1.2"
        assert res.evidence is not None
        assert res.evidence.confidence == 1.0

    def test_eval_ssh_fail_version_1(self):
        csm = {"services": {"ssh_version": 1, "ssh": True, "telnet": False}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["2.1.1.2"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_ssh_fail_telnet_enabled(self):
        csm = {"services": {"ssh_version": 2, "ssh": True, "telnet": True}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["2.1.1.2"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_ssh_unknown_missing_section(self):
        csm = {}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["2.1.1.2"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- 1.1.1 (AAA) ---
    def test_eval_aaa_pass(self):
        csm = {"aaa": {"configured": True, "enabled": True, "authentication_method": "group radius local"}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["1.1.1"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_aaa_fail_no_auth_method(self):
        csm = {"aaa": {"configured": True, "enabled": True, "authentication_method": None}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["1.1.1"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_aaa_unknown_not_configured(self):
        csm = {"aaa": {"configured": False, "enabled": False, "authentication_method": None}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["1.1.1"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- 2.3.1.1 (NTP) ---
    def test_eval_ntp_pass(self):
        csm = {"ntp": {"enabled": True, "servers": ["10.0.0.1"], "authentication_enabled": True}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["2.3.1.1"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_ntp_fail_unauthenticated(self):
        csm = {"ntp": {"enabled": True, "servers": ["10.0.0.1"], "authentication_enabled": False}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["2.3.1.1"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_ntp_unknown_no_servers(self):
        csm = {"ntp": {"enabled": False, "servers": [], "authentication_enabled": False}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["2.3.1.1"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- 2.2.4 (Logging) ---
    def test_eval_logging_pass(self):
        csm = {"logging": {"remote_logging_enabled": True, "timestamps_enabled": True, "enabled": True, "remote_servers": ["10.1.1.5"]}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["2.2.4"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_logging_fail_no_timestamps(self):
        csm = {"logging": {"remote_logging_enabled": True, "timestamps_enabled": False, "enabled": True, "remote_servers": ["10.1.1.5"]}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["2.2.4"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_logging_unknown_not_configured(self):
        csm = {"logging": {"remote_logging_enabled": False, "timestamps_enabled": False, "enabled": False}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["2.2.4"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- 1.5.7 (SNMP) ---
    def test_eval_snmp_pass_clean_community(self):
        csm = {"snmp": {"enabled": True, "community_strings": ["SecOpsSecureString99"]}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["1.5.7"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_snmp_fail_weak_community(self):
        csm = {"snmp": {"enabled": True, "community_strings": ["public"]}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["1.5.7"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_snmp_unknown_not_enabled(self):
        csm = {"snmp": {"enabled": False, "community_strings": []}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["1.5.7"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- 1.2.5 (Access Control VTY) ---
    def test_eval_vty_acl_pass(self):
        csm = {"access_control": {"management_acl_present": True}, "services": {"ssh": True}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["1.2.5"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_vty_acl_fail_ssh_without_acl(self):
        csm = {"access_control": {"management_acl_present": False, "acls_present": False}, "services": {"ssh": True}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["1.2.5"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_vty_acl_unknown_no_mgmt(self):
        csm = {"access_control": {"management_acl_present": False, "acls_present": False}, "services": {"ssh": False}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["1.2.5"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN

    # --- 3.3.3.1 (Routing Auth) ---
    def test_eval_routing_pass(self):
        csm = {"routing": {"routing_protocols": ["bgp"], "routing_authentication_enabled": True}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["3.3.3.1"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.PASS

    def test_eval_routing_fail_unauthenticated(self):
        csm = {"routing": {"routing_protocols": ["bgp"], "routing_authentication_enabled": False}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["3.3.3.1"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.FAIL

    def test_eval_routing_unknown_no_protocols(self):
        csm = {"routing": {"routing_protocols": [], "routing_authentication_enabled": False}}
        ctrl = CIS_CISCO_IOSXE_CONTROLS["3.3.3.1"]
        res = self.evaluator.evaluate(csm, [ctrl])[0]
        assert res.status == ComplianceStatus.UNKNOWN


# --- 4. Parity with cisco_auditor.py on Labeled Test Config ---

class TestCisEvaluationParity:
    """Tests parity between CisCiscoIosXeEvaluator and cisco_auditor.py baseline rules."""

    @pytest.fixture
    def parsed_test_csm(self):
        cfg_path = pathlib.Path(__file__).resolve().parent.parent / "datasets" / "Cisco" / "labeled_test_config.txt"
        assert cfg_path.exists(), f"Missing test config at {cfg_path}"
        text = cfg_path.read_text(encoding="utf-8")
        return cisco_auditor.parse_cisco(text)

    def test_cis_evaluator_on_labeled_config(self, parsed_test_csm):
        evaluator = CisCiscoIosXeEvaluator()
        results = evaluator.evaluate(parsed_test_csm)
        res_map = {r.control_id: r for r in results}

        # Verify results match ground truth expectations for labeled_test_config.txt
        assert res_map["2.1.1.2"].status == ComplianceStatus.PASS  # ip ssh version 2, ssh only
        assert res_map["1.1.1"].status == ComplianceStatus.PASS    # aaa new-model enabled with auth
        assert res_map["2.3.1.1"].status == ComplianceStatus.FAIL  # ntp server configured, no auth
        assert res_map["2.2.4"].status == ComplianceStatus.PASS    # remote logging + timestamps
        assert res_map["1.5.7"].status == ComplianceStatus.FAIL    # weak community 'public'
        assert res_map["1.2.5"].status == ComplianceStatus.PASS    # line vty access-class present
        assert res_map["3.3.3.1"].status == ComplianceStatus.PASS  # neighbor password present in bgp

    def test_direct_parity_against_cisco_auditor_rules(self, parsed_test_csm):
        # Run cisco_auditor evaluate_rules
        import json
        rules_path = pathlib.Path(__file__).resolve().parent.parent / "config" / "Rule_Library" / "vendor_rule_mapping.json"
        raw_rules = json.loads(rules_path.read_text(encoding="utf-8-sig"))["vendors"]["Cisco IOS-XE"]["rules"]
        auditor_res = cisco_auditor.evaluate_rules(parsed_test_csm, raw_rules)

        evaluator = CisCiscoIosXeEvaluator()
        cis_results = evaluator.evaluate(parsed_test_csm)
        cis_map = {r.control_id: r.status.value for r in cis_results}

        # Compare mapped rules
        assert cis_map["2.1.1.2"] == auditor_res["CISCO-SSH-001"]["status"]
        assert cis_map["1.1.1"] == auditor_res["CISCO-AAA-001"]["status"]
        assert cis_map["2.3.1.1"] == auditor_res["CISCO-NTP-001"]["status"]
        assert cis_map["2.2.4"] == auditor_res["CISCO-LOG-001"]["status"]
        assert cis_map["1.5.7"] == auditor_res["CISCO-SNMP-001"]["status"]
        assert cis_map["1.2.5"] == auditor_res["CISCO-ACL-001"]["status"]
        assert cis_map["3.3.3.1"] == auditor_res["CISCO-ROUTING-001"]["status"]


# --- 5. Determinism Guarantee ---

class TestCisDeterminism:
    """Verifies that evaluation is 100% deterministic across consecutive runs."""

    def test_five_consecutive_runs(self):
        cfg_path = pathlib.Path(__file__).resolve().parent.parent / "datasets" / "Cisco" / "labeled_test_config.txt"
        csm = cisco_auditor.parse_cisco(cfg_path.read_text(encoding="utf-8"))
        evaluator = CisCiscoIosXeEvaluator()

        run_dicts = []
        for _ in range(5):
            results = evaluator.evaluate(csm)
            # Serialize to dict for byte-for-byte comparison
            serialized = [r.to_dict() for r in results]
            run_dicts.append(serialized)

        for i in range(1, 5):
            assert run_dicts[i] == run_dicts[0], f"Determinism violation at run {i}"


# --- 6. Security & Hardening AST Analysis ---

class TestCisStaticSecurityInvariants:
    """Static AST analysis ensuring cis_benchmark_cisco_iosxe.py contains zero unsafe imports."""

    PROHIBITED_MODULES = {
        "urllib",
        "requests",
        "socket",
        "http",
        "subprocess",
        "os.system",
        "eval",
        "exec",
        "ollama",
        "ai_model_manager",
        "ai_suggester",
    }

    def test_no_prohibited_imports_in_cis_benchmark(self):
        src_path = pathlib.Path(__file__).resolve().parent.parent / "src" / "cis_benchmark_cisco_iosxe.py"
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
