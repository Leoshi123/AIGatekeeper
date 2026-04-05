"""
🛡️ Zero-Trust AI Context Wrapper (ZTC-Wrapper)

Middleware de seguridad para agentes de IA:
- Sanitizador de metadatos
- Extractor AST (poda de contexto)
- Detector de código zombi
- Git hooks
- AI Agent Wrapper
"""

__version__ = "0.1.0"
__author__ = "Leoshi"
__license__ = "MIT"

from .sanitizer import MetadataSanitizer, sanitize_code
from .ast_parser import ASTExtractor, prune_file
from .detector import LegacyShield, scan_directory, Severity
from .wrapper import AIAgentWrapper, WrapperConfig, WrapperResult, run_safe

__all__ = [
    # Sanitizer
    "MetadataSanitizer",
    "sanitize_code",
    # AST Parser
    "ASTExtractor",
    "prune_file",
    # Detector
    "LegacyShield",
    "scan_directory",
    "Severity",
    # Wrapper
    "AIAgentWrapper",
    "WrapperConfig",
    "WrapperResult",
    "run_safe",
]
