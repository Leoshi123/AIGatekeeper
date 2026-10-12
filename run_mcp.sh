#!/bin/bash
# Always run from the repository root, regardless of the caller's cwd.
cd "$(dirname "$0")" || exit 1

if [ -x ".venv/bin/python" ]; then
    exec .venv/bin/python -m src.mcp_server "$@"
elif [ -x "venv/bin/python" ]; then
    exec venv/bin/python -m src.mcp_server "$@"
else
    exec python -m src.mcp_server "$@"
fi
