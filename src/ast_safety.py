"""NTRO PS26155 — AST Safety Verification Utility (Phase 3R.3).

Provides centralized, deterministic static AST code analysis asserting that Python source files
contain zero process execution or device communication libraries (strictly enforcing display-only
remediation architecture).
"""
import ast
import pathlib
from typing import Optional, Set, Union

FORBIDDEN_EXECUTION_MODULES: Set[str] = {
    "subprocess",
    "os.system",
    "paramiko",
    "netmiko",
    "pexpect",
    "telnetlib",
    "socket",
}


def assert_no_execution_imports(
    target_path: Union[str, pathlib.Path],
    forbidden: Optional[Set[str]] = None,
) -> bool:
    """Performs static AST analysis asserting that no forbidden execution or

    communication libraries are imported in the specified file.

    Args:
        target_path: Path to the Python source file to inspect.
        forbidden: Optional set of forbidden module names. Defaults to FORBIDDEN_EXECUTION_MODULES.

    Returns:
        True if the file is clean.

    Raises:
        RuntimeError: If a forbidden library or module import is detected.
        FileNotFoundError: If the target file does not exist.
    """
    file_path = pathlib.Path(target_path)
    forbidden_set = forbidden if forbidden is not None else FORBIDDEN_EXECUTION_MODULES
    src = file_path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(file_path))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                if n.name in forbidden_set:
                    raise RuntimeError(
                        f"Safety Violation in {file_path.name}: Forbidden library '{n.name}' imported!"
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module in forbidden_set:
                raise RuntimeError(
                    f"Safety Violation in {file_path.name}: Forbidden module '{node.module}' imported!"
                )

    return True
