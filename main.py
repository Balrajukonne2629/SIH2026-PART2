"""NTRO PS26155 — Root Application Entrypoint Wrapper.

Canonical application entrypoint: src.main:app
This root wrapper provides backward-compatible execution for `uvicorn main:app`.
"""
import sys
import pathlib

# Ensure project root and src are on sys.path
_ROOT = pathlib.Path(__file__).resolve().parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.main import *
import src.main as _src_main

def __getattr__(name):
    return getattr(_src_main, name)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
