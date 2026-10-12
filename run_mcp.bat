@echo off
rem Always run from the repository root, regardless of the caller's cwd.
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m src.mcp_server %*
) else if exist "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" -m src.mcp_server %*
) else (
    python -m src.mcp_server %*
)
