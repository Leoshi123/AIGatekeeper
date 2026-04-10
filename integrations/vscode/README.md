# =============================================================================
# AIGatekeeper Integration for VSCode
# 
# This configures VSCode to use AIGatekeeper for AI code generation.
# Add this to your VSCode settings.json or use the commands below.
# =============================================================================

# METHOD 1: Add to settings.json (User or Workspace)
# Add the following to your VSCode settings:

"""
{
  // ZTC-Wrapper Configuration
  "agWrapper.enabled": true,
  "agWrapper.pythonPath": "python",
  
  // Configure your AI agent to use AG-Wrapper
  // For Claude Code (if using the extension):
  "claudeCode.agEnabled": true,
  "claudeCode.customWrapper": "python -m src.cli run execute",
  
  // For other AI agents, configure their wrapper command:
  "terminal.integrated.defaultProfile.windows": "PowerShell",
}
"""

# METHOD 2: VSCode Tasks (tasks.json)
# Add this to .vscode/tasks.json in your project:

"""
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "AG: Sanitize Code",
      "type": "shell",
      "command": "python -m src.cli sanitize scan ${file}",
      "problemMatcher": [],
      "presentation": {
        "reveal": "always",
        "panel": "new"
      }
    },
    {
      "label": "AG: Prune Context",
      "type": "shell", 
      "command": "python -m src.cli prune extract ${file} --task \"${input:taskDescription}\"",
      "problemMatcher": [],
      "inputs": [
        {
          "id": "taskDescription",
          "type": "promptString",
          "description": "Task description for context pruning"
        }
      ]
    },
    {
      "label": "AG: Security Scan",
      "type": "shell",
      "command": "python -m src.cli shield scan ${file}",
      "problemMatcher": []
    }
  ]
}
"""

# METHOD 3: Keybindings (keybindings.json)
# Add to keybindings.json:

"""
[
  {
    "key": "ctrl+shift+z s",
    "command": "workbench.action.tasks.runTask",
    "args": "AG: Security Scan"
  },
  {
    "key": "ctrl+shift+z p", 
    "command": "workbench.action.tasks.runTask",
    "args": "AG: Prune Context"
  }
]
"""

# METHOD 4: Extension Recommendation
# Install the AG-Wrapper extension when available

echo "To apply these settings:"
echo "1. Open VSCode"
echo "2. Press Ctrl+, to open settings"
echo "3. Add the configuration above"
echo ""
echo "Or copy these files to your project:"
echo "  - .vscode/settings.json"
echo "  - .vscode/tasks.json" 
echo "  - .vscode/keybindings.json"

# Example: Run security scan on current file
# python -m src.cli shield scan $env:VSCODE_OPENED_FILE