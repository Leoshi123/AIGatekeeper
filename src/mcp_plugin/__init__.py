# -*- coding: utf-8 -*-
"""
🛡️ AG-Wrapper MCP Plugin

Plugin module for AI Agent security tools.
Can be mounted in any MCP server.

Usage:
    from mcp_plugin import AGWrapperPlugin
    plugin = AGWrapperPlugin()
    plugin.register(mcp)  # where mcp is a FastMCP instance
"""

from .core import AGWrapperPlugin
from .tools import (
    sanitize_code,
    scan_code,
    scan_directory,
    prune_context,
    clean_code,
)

__all__ = [
    "AGWrapperPlugin",
    "sanitize_code",
    "scan_code",
    "scan_directory",
    "prune_context",
    "clean_code",
]
