"""Pytest session configuration and module identity bridging.

Ensures that whether code imports `database` or `from src.database import ...`,
both resolve to the identical singleton module in sys.modules, preserving class
identities (e.g. isinstance checks across frameworks) and module-level singletons.
"""
import sys
import pathlib

# Ensure repository root is on sys.path
_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_MODULE_NAMES = [
    "ai_model_manager",
    "ai_suggester",
    "ast_safety",
    "audit_log",
    "audit_report",
    "auth",
    "cis_benchmark_cisco_iosxe",
    "cisco_auditor",
    "compliance_aggregator",
    "compliance_framework",
    "database",
    "disa_stig_cisco_iosxe",
    "juniper_auditor",
    "main",
    "remediation_engine",
    "report_exporter",
    "report_generator",
    "vendor_adapter",
    "vendor_registry",
]

for _name in _MODULE_NAMES:
    _mod = __import__(f"src.{_name}", fromlist=[_name])
    sys.modules[_name] = _mod
