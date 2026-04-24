# -*- coding: utf-8 -*-
"""
🛡️ AG-Wrapper MCP Server

Model Context Protocol server for AI Agent security tools.

This server is now a thin wrapper around the AGWrapperPlugin.
All tool implementations live in src/mcp_plugin.

Usage:
    python -m src.mcp_server http   # Start HTTP server
    python -m src.mcp_server        # Start stdio server
"""

import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.mcp_plugin import AGWrapperPlugin


# =============================================================================
# SERVER CONFIGURATION
# =============================================================================

mcp = FastMCP(
    name="AG-Wrapper",
    host="127.0.0.1",
    port=8765,
    streamable_http_path="/mcp",
)


# =============================================================================
# PLUGIN REGISTRATION
# =============================================================================

# Register the AG-Wrapper plugin with all its tools
plugin = AGWrapperPlugin(prefix="")  # Empty prefix to keep original tool names
plugin.register(mcp)


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Support both stdio (default) and streamable-http
    transport = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    mcp.run(transport="stdio" if transport != "http" else "streamable-http")
