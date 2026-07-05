"""
🛡️ AIGatekeeper — Detector Module

Utiliza el core C++ nativo (pyagcore) si está disponible.
Fallback automático a la implementación Python pura.

v2.1.0: File watcher + YAML config + ag wrap CLI
v1.x: Pure Python implementation
"""

import logging

logger = logging.getLogger("aigatekeeper.detector")

# Intentar importar el core nativo C++
try:
    from pyagcore import LegacyShield as NativeLegacyShield
    from pyagcore import PromptInjectDetector as NativeInjectDetector
    HAS_NATIVE_CORE = True
    logger.debug("Usando core nativo C++ (pyagcore)")
except ImportError:
    HAS_NATIVE_CORE = False
    logger.debug("Core nativo no disponible, usando Python puro")

# ============================================================================
# Tipos base — siempre desde las implementaciones Python puras
# para garantizar compatibilidad total de API (isinstance, .value, etc.)
# ============================================================================
from .zombie_detector import (  # noqa: E402
    LegacyShield as PurePythonLegacyShield,
    ZombiePattern,
    DetectionResult,
    Severity,
    scan_directory as py_scan_directory,
)
from .injection_detector import (  # noqa: E402
    PromptInjectDetector as PurePythonInjectDetector,
    InjectionFinding,
    InjectionCategory,
    InjectionPattern,
)


# ============================================================================
# Conversores nativo → Python (compatibilidad de tipos)
# ============================================================================

def _convert_severity(native_sev):
    """pyagcore.Severity (pybind11 enum) → src.detector.Severity (Python Enum).

    pybind11 enums tienen .name (str) y .value (int).
    Python Severity tiene miembros como Severity.CRITICAL = "CRITICAL".
    Severity[native_sev.name] busca por nombre de miembro, que funciona en ambos.
    """
    return Severity[native_sev.name]


def _convert_zombie_pattern(native_zp):
    """pyagcore.ZombiePattern → ZombiePattern dataclass Python."""
    return ZombiePattern(
        pattern=native_zp.pattern,
        severity=_convert_severity(native_zp.severity),
        description=native_zp.description,
        alternative=native_zp.alternative,
        language=native_zp.language,
        cve_ref=native_zp.cve_ref,
    )


def _convert_detection_result(native_dr):
    """pyagcore.DetectionResult → DetectionResult dataclass Python."""
    return DetectionResult(
        file_path=native_dr.file_path,
        line_number=native_dr.line_number,
        line_content=native_dr.line_content,
        pattern=_convert_zombie_pattern(native_dr.pattern),
        suggestion=native_dr.suggestion,
    )


def _convert_injection_finding(native_f):
    """pyagcore.InjectionFinding → InjectionFinding dataclass Python."""
    return InjectionFinding(
        category=InjectionCategory[native_f.category.name],
        severity=native_f.severity,
        pattern=native_f.pattern,
        matched=native_f.matched,
        description=native_f.description,
        suggestion=native_f.suggestion,
    )


# ============================================================================
# Wrapper LegacyShield — C++ nativo con fallback Python
# ============================================================================

class LegacyShield:
    """
    Detector de código zombi / funciones obsoletas o vulnerables.

    Usa core C++ nativo (re2 + pybind11) si está disponible.
    Fallback automático a Python puro (regex).

    API idéntica en ambos casos.
    """

    def __init__(self, languages=None, project_path=None):
        """
        Args:
            languages: Lista de lenguajes (None = todos).
                       Valores: "python", "javascript", "typescript", "go",
                                "rust", "java", "c", "cpp", "php"
            project_path: Ruta del proyecto (solo Python fallback).
        """
        if HAS_NATIVE_CORE:
            self._impl = NativeLegacyShield(languages)
            self._convert = True
        else:
            # Pure Python acepta languages y project_path
            self._impl = PurePythonLegacyShield(
                languages=languages, project_path=project_path
            )
            self._convert = False

    def pattern_count(self) -> int:
        """Cantidad de patrones cargados."""
        return self._impl.pattern_count()

    def scan_code(self, code: str, file_path: str = "<inline>"):
        """
        Escanea código en busca de patrones zombi.

        Args:
            code: Código fuente a escanear.
            file_path: Ruta del archivo (para reportes).

        Returns:
            List[DetectionResult] con los hallazgos.
        """
        results = self._impl.scan_code(code, file_path)
        if self._convert:
            return [_convert_detection_result(r) for r in results]
        return results

    def scan_file(self, file_path: str):
        """
        Escanea un archivo completo.

        Args:
            file_path: Ruta al archivo.

        Returns:
            List[DetectionResult] con los hallazgos.
        """
        results = self._impl.scan_file(file_path)
        if self._convert:
            return [_convert_detection_result(r) for r in results]
        return results

    @staticmethod
    def block_critical(results) -> bool:
        """True si hay hallazgos CRITICAL que deberían bloquear."""
        return any(r.pattern.severity == Severity.CRITICAL for r in results)

    @staticmethod
    def get_summary(results):
        """Resumen de hallazgos agrupado por severidad y lenguaje."""
        summary = {
            "total": len(results),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "by_language": {},
        }
        for r in results:
            sev = r.pattern.severity
            if sev == Severity.CRITICAL:
                summary["critical"] += 1
            elif sev == Severity.HIGH:
                summary["high"] += 1
            elif sev == Severity.MEDIUM:
                summary["medium"] += 1
            elif sev == Severity.LOW:
                summary["low"] += 1
            else:
                summary["info"] += 1

            lang = r.pattern.language
            summary["by_language"][lang] = summary["by_language"].get(lang, 0) + 1

        return summary

    @staticmethod
    def scan_directory(directory, extensions=None, project_path=None):
        """
        Escanea todos los archivos en un directorio.

        Args:
            directory: Directorio a escanear.
            extensions: Extensiones de archivo a incluir.
            project_path: Ruta al proyecto (para cargar config).

        Returns:
            Dict[str, List[DetectionResult]]: {file_path: [results]}
        """
        return py_scan_directory(directory, extensions, project_path)

    # --- Métodos adicionales de la implementación Python pura ---

    # scan_text y _generate_suggestion existen en la impl Python pura
    # pero no en la nativa. La wrapper los expone para compatibilidad.
    def scan_text(self, text: str) -> dict:
        """Escanea texto y retorna dict JSON-serializable para APIs.

        Args:
            text: Texto a analizar.

        Returns:
            Dict con status, findings y summary.
        """
        results = self.scan_code(text)

        if not results:
            return {
                "status": "clean",
                "message": "No zombie code detected",
                "findings": [],
                "summary": self.get_summary(results),
            }

        return {
            "status": "findings_found",
            "total": len(results),
            "findings": [
                {
                    "file": r.file_path,
                    "line": r.line_number,
                    "content": r.line_content,
                    "severity": r.pattern.severity.value,
                    "pattern": r.pattern.description,
                    "suggestion": r.suggestion,
                }
                for r in results
            ],
            "summary": self.get_summary(results),
        }


# ============================================================================
# Wrapper PromptInjectDetector — C++ nativo con fallback Python
# ============================================================================

class PromptInjectDetector:
    """
    Detector de prompt injection en texto.

    Usa core C++ nativo (re2 + pybind11) si está disponible.
    Fallback automático a Python puro (regex).

    API idéntica en ambos casos.
    """

    def __init__(self, categories=None):
        """
        Args:
            categories: Lista de categorías a detectar (None = todas).
                        Valores: "direct-injection", "indirect-injection",
                                "jailbreak", "role-play"
        """
        if HAS_NATIVE_CORE:
            self._impl = NativeInjectDetector(categories)
            self._convert = True
        else:
            self._impl = PurePythonInjectDetector(categories)
            self._convert = False

    def pattern_count(self) -> int:
        """Cantidad de patrones cargados."""
        return self._impl.pattern_count()

    def scan(self, text: str):
        """
        Escanea texto en busca de patrones de prompt injection.

        Args:
            text: Texto o prompt a analizar.

        Returns:
            List[InjectionFinding] con los hallazgos.
        """
        results = self._impl.scan(text)
        if self._convert:
            return [_convert_injection_finding(r) for r in results]
        return results

    def scan_text(self, text: str) -> dict:
        """
        Escanea texto y retorna dict JSON-serializable para APIs.

        Args:
            text: Texto o prompt a analizar.

        Returns:
            Dict con status, findings y summary.
        """
        results = self.scan(text)

        if not results:
            return {
                "status": "clean",
                "message": "No prompt injection detected",
                "findings": [],
                "summary": {"total": 0, "categories": {}, "severities": {}},
            }

        summary = self.get_summary(results)

        return {
            "status": "findings_found",
            "total": len(results),
            "findings": [
                {
                    "category": f.category.value,
                    "severity": f.severity,
                    "matched": f.matched,
                    "description": f.description,
                    "suggestion": f.suggestion,
                }
                for f in results
            ],
            "summary": summary,
        }

    @staticmethod
    def has_high_severity(findings) -> bool:
        """True si algún hallazgo tiene severidad HIGH."""
        return any(f.severity == "HIGH" for f in findings)

    @staticmethod
    def get_summary(findings) -> dict:
        """Resumen de hallazgos agrupado por severidad y categoría."""
        from collections import defaultdict

        category_counts: dict[InjectionCategory, int] = defaultdict(int)
        severity_counts: dict[str, int] = defaultdict(int)

        for f in findings:
            category_counts[f.category] += 1
            severity_counts[f.severity] += 1

        return {
            "total": len(findings),
            "categories": dict(sorted(category_counts.items(), key=lambda x: x[0].value)),
            "severities": dict(
                sorted(
                    severity_counts.items(),
                    key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(s[0], -1),
                    reverse=True,
                )
            ),
        }


# ============================================================================
# Re-exportar a nivel de módulo
# ============================================================================

# Conveniencia: función scan_directory independiente
def scan_directory(directory, extensions=None, project_path=None):
    """Escanea todos los archivos en un directorio.

    Args:
        directory: Directorio a escanear.
        extensions: Extensiones de archivo a incluir.
        project_path: Ruta al proyecto para cargar configuración.

    Returns:
        Dict {file_path: [results]}
    """
    return py_scan_directory(directory, extensions, project_path)


__all__ = [
    "LegacyShield",
    "ZombiePattern",
    "DetectionResult",
    "Severity",
    "scan_directory",
    "PromptInjectDetector",
    "InjectionFinding",
    "InjectionCategory",
    "InjectionPattern",
]
