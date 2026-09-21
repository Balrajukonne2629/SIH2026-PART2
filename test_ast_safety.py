"""Unit tests for the consolidated ast_safety utility (Phase 3R.3)."""
import pathlib
import pytest
import ast_safety


def test_clean_files_pass_ast_safety():
    """Asserts that production modules pass AST safety without violation."""
    base_dir = pathlib.Path(__file__).parent
    assert ast_safety.assert_no_execution_imports(base_dir / "ast_safety.py") is True
    assert ast_safety.assert_no_execution_imports(base_dir / "remediation_engine.py") is True
    assert ast_safety.assert_no_execution_imports(base_dir / "main.py") is True
    assert ast_safety.assert_no_execution_imports(base_dir / "vendor_adapter.py") is True
    assert ast_safety.assert_no_execution_imports(base_dir / "vendor_registry.py") is True
    assert ast_safety.assert_no_execution_imports(base_dir / "juniper_auditor.py") is True


def test_forbidden_import_raises_runtime_error(tmp_path):
    """Asserts that importing a forbidden library raises RuntimeError."""
    bad_file = tmp_path / "bad_import.py"
    bad_file.write_text("import subprocess\nprint('hello')\n", encoding="utf-8")
    with pytest.raises(RuntimeError) as exc_info:
        ast_safety.assert_no_execution_imports(bad_file)
    assert "Forbidden library 'subprocess'" in str(exc_info.value)


def test_forbidden_import_from_raises_runtime_error(tmp_path):
    """Asserts that 'from forbidden import ...' raises RuntimeError."""
    bad_file = tmp_path / "bad_import_from.py"
    bad_file.write_text("from socket import socket\n", encoding="utf-8")
    with pytest.raises(RuntimeError) as exc_info:
        ast_safety.assert_no_execution_imports(bad_file)
    assert "Forbidden module 'socket'" in str(exc_info.value)


def test_custom_forbidden_set(tmp_path):
    """Asserts that a custom forbidden set is respected."""
    custom_file = tmp_path / "custom_import.py"
    custom_file.write_text("import json\nimport sys\n", encoding="utf-8")
    assert ast_safety.assert_no_execution_imports(custom_file, forbidden={"urllib"}) is True
    with pytest.raises(RuntimeError):
        ast_safety.assert_no_execution_imports(custom_file, forbidden={"json"})


def test_nonexistent_file_raises_filenotfound():
    """Asserts that nonexistent path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        ast_safety.assert_no_execution_imports("nonexistent_file_xyz_123.py")
