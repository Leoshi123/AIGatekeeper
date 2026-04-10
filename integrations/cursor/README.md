# =============================================================================
# AIGatekeeper Integration for Cursor IDE
# 
# Cursor uses VSCode's architecture, so similar configurations apply.
# For native AI integration, we use MCP (Model Context Protocol).
# =============================================================================

# METHOD 1: Cursor Settings (cursor.json or settings.json)
# Add to your Cursor user settings:

"""
{
  // Enable AG-Wrapper features
  "cursor.ag.enabled": true,
  "cursor.ag.pythonPath": "python",
  "cursor.ag.blockOnCritical": true,
  
  // Configure AI to use ZTC-Wrapper as middleware
  "cursor.chat.llm": "claude-sonnet-4",
  "cursor.chat.wrappers": [
    {
      "name": "ag-wrapper",
      "command": "python -m src.cli run execute",
      "enabled": true
    }
  ],
  
  // Security: Block AI from generating dangerous code
  "cursor.security.blockCriticalPatterns": true,
  "cursor.security.scanGeneratedCode": true
}
"""

# METHOD 2: Using ZTC-Wrapper as MCP Server
# For Cursor's AI to use ZTC-Wrapper, configure MCP:

"""
{
  "mcpServers": {
    "ag": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "PYTHONPATH": "."
      }
    }
  }
}
"""

# METHOD 3: Cursor Custom Commands
# Add to .cursor/rules/commands.md:

"""
# AIGatekeeper Commands

## Security Scan
Run security scan on current file:
```
python -m src.cli shield scan {file}
```

## Context Pruning  
Extract relevant context for task:
```
python -m src.cli prune extract {file} --task "{task}"
```

## Sanitize Code
Remove AI metadata from code:
```
python -m src.cli sanitize scan {file}
```

## Full Security Check
Run complete security analysis:
```
python -m src.cli run execute --sanitize-input --sanitize-output --block "{prompt}"
```
"""

# METHOD 4: Agent Configuration
# For Cursor's agent mode, add to .cursor/agents.md:

"""
# Agent Configuration

This project uses AIGatekeeper for security. All AI-generated code 
is scanned for:

- Code injection vulnerabilities (eval, exec)
- Hardcoded secrets (API keys, passwords)
- Deserialization vulnerabilities (pickle, yaml)
- Command injection (subprocess, shell=True)
- XSS patterns (innerHTML, dangerouslySetInnerHTML)

The AI should:
1. Use AG-Wrapper CLI for code validation
2. Run security scans before generating code
3. Block critical vulnerabilities
4. Sanitize outputs to remove AI metadata
"""

echo "Cursor integration configured!"
echo "Add the above to your Cursor settings or .cursor folder."