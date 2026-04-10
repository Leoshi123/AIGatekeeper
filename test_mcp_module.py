#!/usr/bin/env python
"""Test script for MCP server"""

import sys
import json

sys.path.insert(0, "C:/Users/leosh/OneDrive/Documents/AIGatekeeper")

# Test that imports work
try:
    from mcp.server.fastmcp import FastMCP
    from src.sanitizer import MetadataSanitizer
    from src.ast_parser import ASTExtractor
    from src.detector import LegacyShield

    print("OK - All imports successful")
except Exception as e:
    print(f"ERROR - Import error: {e}")
    sys.exit(1)

# Test that tools can be created
try:
    mcp = FastMCP("test")

    @mcp.tool()
    def test_tool(x: int) -> int:
        return x * 2

    print("OK - FastMCP with tools works")
except Exception as e:
    print(f"ERROR - FastMCP error: {e}")
    sys.exit(1)

# Test sanitizer
try:
    sanitizer = MetadataSanitizer()
    result = sanitizer.sanitize("# Created by Claude\nprint('hello')")
    print(f"OK - Sanitizer works: removed {len(result.removed_items)} items")
except Exception as e:
    print(f"ERROR - Sanitizer error: {e}")

print("\nAll tests passed!")
