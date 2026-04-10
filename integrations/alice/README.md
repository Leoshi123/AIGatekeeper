# =============================================================================
# AIGatekeeper Integration for Alice AI
# 
# Configure Alice to use AIGatekeeper as a security layer.
# =============================================================================

# METHOD 1: Alice Config File
# Create ~/.alice/ag_config.yaml:

"""
ag:
  enabled: true
  python_path: python
  project_root: .
  
  # Security configuration
  security:
    block_on_critical: true
    scan_on_generate: true
    scan_on_edit: true
    allowed_patterns:
      - eval
      - exec  
      - pickle
      - yaml.load
      - subprocess.run
    blocked_severities:
      - CRITICAL
      - HIGH
      
  # Context pruning
  pruning:
    enabled: true
    target_reduction: 70
    include_imports: true
    include_signatures: true
    
  # Sanitization
  sanitize:
    input: true
    output: true
    remove_thinking: true
    remove_absolute_paths: true
    remove_session_tokens: true

# Hook integration
hooks:
  pre_generate:
    enabled: true
    command: "python -m src.cli sanitize clean"
    
  post_generate:
    enabled: true
    command: "python -m src.cli shield scan"
    
  on_save:
    enabled: true
    command: "python -m src.cli shield scan {file}"
"""

# METHOD 2: Alice Environment Setup
# Add to ~/.alice/env:

"""
AG_ENABLED=1
AG_BLOCK_CRITICAL=1
AG_SCAN_ON_GENERATE=1
AG_PRUNE_CONTEXT=1
AG_SANITIZE_OUTPUT=1
"""

# METHOD 3: Python Module for Alice
# File: ~/.alice/plugins/ag_wrapper.py

"""
# AG-Wrapper Plugin for Alice
import subprocess
import os

class AIGatekeeperPlugin:
    '''Security wrapper for Alice AI'''
    
    def __init__(self):
        self.enabled = os.getenv('AG_ENABLED', '1') == '1'
        self.block_critical = os.getenv('AG_BLOCK_CRITICAL', '1') == '1'
    
    def before_generate(self, context):
        '''Sanitize input before generation'''
        if not self.enabled:
            return context
            
        result = subprocess.run(
            ['python', '-m', 'src.cli', 'sanitize', 'clean'],
            input=context,
            capture_output=True,
            text=True
        )
        return result.stdout if result.returncode == 0 else context
    
    def after_generate(self, code):
        '''Validate and sanitize output after generation'''
        if not self.enabled:
            return code
            
        # Security scan
        scan_result = subprocess.run(
            ['python', '-m', 'src.cli', 'shield', 'scan', '-'],
            input=code,
            capture_output=True,
            text=True
        )
        
        if self.block_critical and 'CRITICAL' in scan_result.stdout:
            raise SecurityError('Critical vulnerability detected in generated code')
        
        # Sanitize output
        result = subprocess.run(
            ['python', '-m', 'src.cli', 'sanitize', 'clean'],
            input=code,
            capture_output=True,
            text=True
        )
        
        return result.stdout if result.returncode == 0 else code

# Register
PLUGIN = AIGatekeeperPlugin
"""

echo "Alice integration configured!"
echo "Copy these files to ~/.alice/"