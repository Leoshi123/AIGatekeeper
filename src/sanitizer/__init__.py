"""
🛡️ AIGatekeeper — Sanitizer Module

Utiliza el core C++ nativo (pyagcore) si está disponible.
Fallback automático a la implementación Python pura.

v2.1.0: File watcher + YAML config + ag wrap CLI
v1.x: Pure Python implementation
"""

import logging

logger = logging.getLogger("aigatekeeper.sanitizer")

# Intentar importar el core nativo C++
try:
    from pyagcore import MetadataSanitizer as NativeSanitizer
    from pyagcore import sanitize_code as native_sanitize_code
    HAS_NATIVE_CORE = True
    logger.debug("Usando core nativo C++ (pyagcore)")
except ImportError:
    HAS_NATIVE_CORE = False
    logger.debug("Core nativo no disponible, usando Python puro")

# Importar implementación Python pura
from .metadata_cleaner import (
    MetadataSanitizer as PurePythonSanitizer,
    SanitizeResult,
    sanitize_code as py_sanitize_code,
)


class MetadataSanitizer:
    """
    Wrapper que usa core C++ si está disponible, con fallback a Python puro.
    
    Uso idéntico a la versión Python pura.
    """

    def __init__(self):
        if HAS_NATIVE_CORE:
            self._impl = NativeSanitizer()
        else:
            self._impl = PurePythonSanitizer()

    def sanitize(self, code: str) -> SanitizeResult:
        """
        Limpia el código de metadatos generados por IA.
        
        Args:
            code: Código original generado por IA.
            
        Returns:
            SanitizeResult con cleaned_code y removed_items.
        """
        return self._impl.sanitize(code)


def sanitize_code(code: str) -> str:
    """
    Función rápida: sanitiza código y devuelve solo el texto limpio.
    
    Args:
        code: Código a sanitizar.
        
    Returns:
        Código limpio como string.
    """
    if HAS_NATIVE_CORE:
        return native_sanitize_code(code)
    return py_sanitize_code(code)


__all__ = [
    "MetadataSanitizer",
    "SanitizeResult",
    "sanitize_code",
]
