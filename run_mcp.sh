#!/bin/bash
source "$(dirname "$0")/.venv/bin/activate"
exec python -m src.mcp_server "$@"
