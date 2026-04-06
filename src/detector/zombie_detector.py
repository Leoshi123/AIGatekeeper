"""
🛡️ ZTC-Wrapper - Detector Zombi (Legacy-Shield)

Linter de seguridad que detecta funciones obsoletas y vulnerables
usadas por agentes de IA con código antiguo.

Inspirado en OWASP Top 10 y estándares modernos de seguridad.
"""

import re
import os
import fnmatch
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum

# Importar configuración
from src.config import ZTCConfig, get_project_root


class Severity(Enum):
    """Nivel de severidad del problema."""

    CRITICAL = "CRITICAL"  # Peligroso - ejecutar inmediatamente
    HIGH = "HIGH"  # Vulnerabilidad seria
    MEDIUM = "MEDIUM"  # Problema moderado
    LOW = "LOW"  # Advertencia menor
    INFO = "INFO"  # Información


@dataclass
class ZombiePattern:
    """Patrón de código zombi detectado."""

    pattern: str
    severity: Severity
    description: str
    alternative: str
    language: str
    cve_ref: Optional[str] = None


@dataclass
class DetectionResult:
    """Resultado de la detección de código zombi."""

    file_path: str
    line_number: int
    line_content: str
    pattern: ZombiePattern
    suggestion: str


class LegacyShield:
    """
    Detector de código zombi - funciones obsoletas o vulnerables.

    Uso:
        shield = LegacyShield()
        results = shield.scan_file("app.py")
    """

    # Base de datos de patrones zombi
    ZOMBIE_PATTERNS = [
        # ========== PYTHON ==========
        ZombiePattern(
            pattern=r"\beval\s*\(",
            severity=Severity.CRITICAL,
            description="eval() permite ejecución de código arbitrario",
            alternative="ast.literal_eval() para datos seguros, o json.loads()",
            language="python",
            cve_ref="CVE-2021-23336",
        ),
        ZombiePattern(
            pattern=r"\bexec\s*\(",
            severity=Severity.CRITICAL,
            description="exec() permite ejecución de código arbitrario",
            alternative="Usar funciones específicas o bibliotecas de sandbox",
            language="python",
        ),
        ZombiePattern(
            pattern=r"subprocess\.call\s*\([^)]*shell\s*=\s*True",
            severity=Severity.CRITICAL,
            description="subprocess con shell=True es vulnerable a command injection",
            alternative="subprocess.run() sin shell=True, usando lista de argumentos",
            language="python",
            cve_ref="CVE-2021-3737",
        ),
        ZombiePattern(
            pattern=r"subprocess\.Popen\s*\([^)]*shell\s*=\s*True",
            severity=Severity.CRITICAL,
            description="subprocess.Popen con shell=True es vulnerable a injection",
            alternative="subprocess.run() o subprocess.Popen con args como lista",
            language="python",
        ),
        ZombiePattern(
            pattern=r"subprocess\.run\s*\([^)]*shell\s*=\s*True",
            severity=Severity.CRITICAL,
            description="subprocess.run con shell=True es vulnerable a command injection",
            alternative="subprocess.run() sin shell=True, pasando argumentos como lista",
            language="python",
        ),
        ZombiePattern(
            pattern=r"os\.system\s*\(",
            severity=Severity.HIGH,
            description="os.system() es vulnerable a command injection",
            alternative="subprocess.run() con argumentos seguros",
            language="python",
        ),
        ZombiePattern(
            pattern=r"os\.popen\s*\(",
            severity=Severity.HIGH,
            description="os.popen() permite ejecución de comandos",
            alternative="subprocess.run() o pathlib para archivos",
            language="python",
        ),
        ZombiePattern(
            pattern=r"pickle\.loads?\s*\(",
            severity=Severity.HIGH,
            description="pickle puede ejecutar código arbitrario en deserialización",
            alternative="json.loads() para datos, o marshmallow/attrs con validación",
            language="python",
            cve_ref="CVE-2022-42969",
        ),
        ZombiePattern(
            pattern=r"yaml\.load\s*\(",
            severity=Severity.HIGH,
            description="yaml.load() sin Loader es vulnerable a deserialización",
            alternative="yaml.safe_load() o yaml.load(Loader=yaml.CSafeLoader)",
            language="python",
            cve_ref="CVE-2020-14340",
        ),
        ZombiePattern(
            pattern=r"\.format\s*\([^)]*\+",  # String formatting with concatenation
            severity=Severity.MEDIUM,
            description="String formatting con concatenación propensa a errores",
            alternative="f-strings o .format() con placeholders",
            language="python",
        ),
        ZombiePattern(
            pattern=r"MD5\s*\(",
            severity=Severity.MEDIUM,
            description="MD5 es cryptograficamente quebrado",
            alternative="hashlib.sha256() o hashlib.scrypt()",
            language="python",
        ),
        ZombiePattern(
            pattern=r"\bsha1\s*\(",
            severity=Severity.MEDIUM,
            description="SHA-1 tiene vulnerabilidades conocidas",
            alternative="hashlib.sha256() o más reciente",
            language="python",
        ),
        # ========== JAVASCRIPT ==========
        ZombiePattern(
            pattern=r"\beval\s*\(",
            severity=Severity.CRITICAL,
            description="eval() permite ejecución de código arbitrario",
            alternative="JSON.parse() para datos, o Function constructor con validación",
            language="javascript",
        ),
        ZombiePattern(
            pattern=r"document\.write\s*\(",
            severity=Severity.CRITICAL,
            description="document.write() puede ejecutar scripts automáticamente",
            alternative="DOM APIs (document.createElement, appendChild)",
            language="javascript",
            cve_ref="CVE-2020-11022",
        ),
        ZombiePattern(
            pattern=r"innerHTML\s*=",
            severity=Severity.HIGH,
            description="innerHTML sin sanitización es vulnerable a XSS",
            alternative="textContent o usar DOMPurify para sanitizar",
            language="javascript",
            cve_ref="CVE-2020-11022",
        ),
        ZombiePattern(
            pattern=r"\.outerHTML\s*=",
            severity=Severity.HIGH,
            description="outerHTML puede inyectar HTML arbitrario",
            alternative="textContent o methods de templating seguros",
            language="javascript",
        ),
        ZombiePattern(
            pattern=r"new\s+Function\s*\(",
            severity=Severity.HIGH,
            description="Function constructor permite ejecución de código",
            alternative="Funciones inline oarrow functions",
            language="javascript",
        ),
        ZombiePattern(
            pattern=r'window\[\s*["\']location',
            severity=Severity.MEDIUM,
            description="Acceso dinámico a location puede ser peligroso",
            alternative="Usar location.href directamente con validación",
            language="javascript",
        ),
        # ========== GENERAL ==========
        ZombiePattern(
            pattern=r'password\s*=\s*["\'][^"\']+["\']',
            severity=Severity.CRITICAL,
            description="Password hardcodeada en el código",
            alternative="Usar variables de entorno o config seguro",
            language="general",
        ),
        ZombiePattern(
            pattern=r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
            severity=Severity.CRITICAL,
            description="API key hardcodeada",
            alternative="Usar environment variables o secret manager",
            language="general",
        ),
        ZombiePattern(
            pattern=r'secret\s*=\s*["\'][^"\']+["\']',
            severity=Severity.CRITICAL,
            description="Secret hardcodeado",
            alternative="Usar vault o secret manager",
            language="general",
        ),
        # ========== BYPASS DETECTION ==========
        ZombiePattern(
            pattern=r"(?i)(ev|ex)\s*[\+\%]\s*(al|ec)",  # "ev" + "al", "ex" + "ec"
            severity=Severity.CRITICAL,
            description="Concatenación para evadir detección de eval/exec",
            alternative="Usar función explícita si es necesario, con validación",
            language="python",
        ),
        ZombiePattern(
            pattern=r'getattr\s*\(\s*__builtins__\s*,\s*["\'](?:eval|exec|compile)["\']',
            severity=Severity.CRITICAL,
            description="Acceso dinámico a eval/exec vía getattr",
            alternative="Usar funciones explícitas con validación",
            language="python",
        ),
        # ========== GO ==========
        ZombiePattern(
            pattern=r"os\.Exec\s*\(",
            severity=Severity.HIGH,
            description="os.Exec puede ejecutar comandos del sistema",
            alternative="Usar flag o libraries específicas para argumentos",
            language="go",
        ),
        ZombiePattern(
            pattern=r"exec\.Command\s*\([^,]+,\s*[^,]+",
            severity=Severity.MEDIUM,
            description="exec.Command con argumentos dinámicos puede ser peligroso",
            alternative="Usar exec.CommandContext con argumentos validados",
            language="go",
        ),
        ZombiePattern(
            pattern=r"fmt\.Sprintf\s*\([^,]*%s",
            severity=Severity.MEDIUM,
            description="Sprintf con %s puede causar injection",
            alternative="Usar fmt.Sprintf con tipos específicos o json.Marshal",
            language="go",
        ),
        ZombiePattern(
            pattern=r"database\.Sql\s*\([^)]*\+",
            severity=Severity.CRITICAL,
            description="SQL query con concatenación vulnerable a SQL injection",
            alternative="Usar parameterized queries o ORM",
            language="go",
        ),
        ZombiePattern(
            pattern=r"io\.ioutil\.ReadFile\s*\(",
            severity=Severity.LOW,
            description="io.ioutil.ReadFile está deprecated",
            alternative="Usar os.ReadFile o io.ReadAll",
            language="go",
        ),
        # ========== RUST ==========
        ZombiePattern(
            pattern=r"std::process::Command\s*::\s*new\s*\(",
            severity=Severity.HIGH,
            description="Command::new puede ejecutar comandos del sistema",
            alternative="Usar Command::new con argumentos seguros",
            language="rust",
        ),
        ZombiePattern(
            pattern=r"unsafe\s*\{",
            severity=Severity.HIGH,
            description="Bloque unsafe en Rust",
            alternative="Evitar unsafe, usar tipos seguros",
            language="rust",
        ),
        ZombiePattern(
            pattern=r"\.unwrap\s*\(",
            severity=Severity.MEDIUM,
            description="unwrap() puede causar panic",
            alternative="Usar ? operator o manejo de errores con match",
            language="rust",
        ),
        ZombiePattern(
            pattern=r"String::from_utf8_unchecked\s*\(",
            severity=Severity.MEDIUM,
            description="from_utf8_unchecked no valida UTF-8",
            alternative="Usar String::from_utf8 con manejo de errores",
            language="rust",
        ),
        ZombiePattern(
            pattern=r"\.execute\s*\([^)]*\+",
            severity=Severity.CRITICAL,
            description="Raw SQL execution vulnerable a SQL injection",
            alternative="Usar parameterized queries o ORM como diesel",
            language="rust",
        ),
        # ========== JAVA ==========
        ZombiePattern(
            pattern=r"Runtime\.getRuntime\s*\(\)\.exec\s*\(",
            severity=Severity.CRITICAL,
            description="Runtime.exec() permite ejecución de comandos",
            alternative="Usar ProcessBuilder con argumentos separados",
            language="java",
        ),
        ZombiePattern(
            pattern=r"\.executeQuery\s*\([^)]*\+",
            severity=Severity.CRITICAL,
            description="SQL injection vía executeQuery con concatenación",
            alternative="Usar PreparedStatement",
            language="java",
        ),
        ZombiePattern(
            pattern=r"ObjectInputStream\s*\(",
            severity=Severity.HIGH,
            description="ObjectInputStream es vulnerable a deserialización",
            alternative="Usar JSON o serialización segura",
            language="java",
        ),
        ZombiePattern(
            pattern=r"new\s+File\s*\([^)]*\+",
            severity=Severity.MEDIUM,
            description="File con path concatenado puede ser path traversal",
            alternative="Usar Paths.get() con normalización",
            language="java",
        ),
        # ========== C/C++ ==========
        ZombiePattern(
            pattern=r"system\s*\(",
            severity=Severity.CRITICAL,
            description="system() ejecuta comandos del shell",
            alternative="Usar exec家族的函数 con argumentos separados",
            language="c",
        ),
        ZombiePattern(
            pattern=r"strcpy\s*\(",
            severity=Severity.CRITICAL,
            description="strcpy no verifica bounds - buffer overflow",
            alternative="Usar strncpy o strlcpy",
            language="c",
        ),
        ZombiePattern(
            pattern=r"gets\s*\(",
            severity=Severity.CRITICAL,
            description="gets() es deprecated - buffer overflow seguro",
            alternative="Usar fgets() con tamaño específico",
            language="c",
        ),
        ZombiePattern(
            pattern=r"printf\s*\([^)]*%s",
            severity=Severity.HIGH,
            description="printf con %s puede ser format string vulnerability",
            alternative='Usar printf("%s", var) o puts()',
            language="c",
        ),
    ]

    def __init__(self, languages: Optional[List[str]] = None, project_path: str = None):
        """
        Inicializa el detector.

        Args:
            languages: Lista de lenguajes a verificar. Si None, todos.
            project_path: Ruta al proyecto. Si None, auto-detecta.
        """
        # Auto-detectar proyecto si no se especifica
        if project_path is None:
            project_path = get_project_root()

        self.languages = languages or ["python", "javascript", "general"]
        self.project_path = project_path

        # Cargar configuración
        self.config = ZTCConfig.load(project_path)
        self.exclude_patterns = self.config.detector.exclude_patterns

        # Cargar .ztcignore (compatibilidad hacia atrás)
        self.ignore_patterns = self._load_ztcignore()

        self._compile_patterns()

    def _load_ztcignore(self) -> List[str]:
        """Carga patrones del archivo .ztcignore."""
        ztcignore_path = os.path.join(self.project_path, ".ztcignore")
        patterns = []

        if os.path.exists(ztcignore_path):
            try:
                with open(ztcignore_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            patterns.append(line)
            except Exception:
                pass

        return patterns

    def is_ignored(self, file_path: str, line_content: str) -> bool:
        """Determina si un archivo o línea debe ser ignorada."""
        # Check magic comment in line
        if "# ztc: ignore" in line_content or "// ztc: ignore" in line_content:
            return True

        # Check file patterns from .ztcignore
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(file_path, pattern):
                return True

        # Check exclude_patterns from .ztcrc (se aplica al contenido de la línea)
        for pattern in self.exclude_patterns:
            try:
                if re.search(pattern, line_content, re.IGNORECASE):
                    return True
            except re.error:
                # Si el patrón es inválido, usar fnmatch
                if pattern in line_content:
                    return True

        return False

    def _compile_patterns(self):
        """Compila los patrones regex."""
        self.compiled_patterns = []

        for zp in self.ZOMBIE_PATTERNS:
            if zp.language in self.languages:
                try:
                    compiled = re.compile(zp.pattern, re.IGNORECASE)
                    self.compiled_patterns.append((compiled, zp))
                except re.error:
                    # Ignorar patrones inválidos
                    pass

    def scan_file(self, file_path: str) -> List[DetectionResult]:
        """
        Escanea un archivo en busca de patrones zombi.

        Args:
            file_path: Ruta al archivo

        Returns:
            Lista de DetectionResult
        """
        results = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            return results

        for line_num, line in enumerate(lines, 1):
            original_line = line  # Guardar línea original para chequear ignore
            line = line.strip()

            # Skip comments - pero preservar para check de ignore magic
            is_comment = line.startswith("#") or line.startswith("//")

            # Check if this line/file should be ignored
            if self.is_ignored(file_path, original_line):
                continue

            for pattern, zp in self.compiled_patterns:
                if pattern.search(line):
                    results.append(
                        DetectionResult(
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line,
                            pattern=zp,
                            suggestion=self._generate_suggestion(zp, line),
                        )
                    )

        return results

    def scan_code(
        self, code: str, file_path: str = "<inline>"
    ) -> List[DetectionResult]:
        """
        Escanea código en string.

        Args:
            code: Código a analizar
            file_path: Ruta del archivo (para compatibilidad con ignore)

        Returns:
            Lista de resultados
        """
        results = []

        for line_num, line in enumerate(code.split("\n"), 1):
            original_line = line
            line = line.strip()

            # Check if ignored
            if self.is_ignored(file_path, original_line):
                continue

            for pattern, zp in self.compiled_patterns:
                if pattern.search(line):
                    results.append(
                        DetectionResult(
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line,
                            pattern=zp,
                            suggestion=self._generate_suggestion(zp, line),
                        )
                    )

        return results

    def _generate_suggestion(self, zp: ZombiePattern, line: str) -> str:
        """Genera una sugerencia de refactorización."""
        severity = zp.severity.value if zp.severity else "UNKNOWN"
        return f"[{severity}] {zp.description} | Alternativa: {zp.alternative}"

    def get_summary(self, results: List[DetectionResult]) -> Dict:
        """Genera un resumen de los hallazgos."""
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
            severity = r.pattern.severity
            if severity == Severity.CRITICAL:
                summary["critical"] += 1
            elif severity == Severity.HIGH:
                summary["high"] += 1
            elif severity == Severity.MEDIUM:
                summary["medium"] += 1
            elif severity == Severity.LOW:
                summary["low"] += 1
            else:
                summary["info"] += 1

            lang = r.pattern.language
            if lang not in summary["by_language"]:
                summary["by_language"][lang] = 0
            summary["by_language"][lang] += 1

        return summary

    def block_critical(self, results: List[DetectionResult]) -> bool:
        """Determina si hay problemas críticos que deberían bloquear ejecución."""
        return any(r.pattern.severity == Severity.CRITICAL for r in results)


def scan_directory(
    directory: str, extensions: List[str] = None, project_path: str = None
) -> Dict[str, List[DetectionResult]]:
    """
    Escanea todos los archivos en un directorio.

    Args:
        directory: Directorio a escanear
        extensions: Extensiones de archivo a incluir
        project_path: Ruta al proyecto para cargar configuración

    Returns:
        Dict {file_path: [results]}
    """
    import os

    extensions = extensions or [".py", ".js", ".ts", ".jsx", ".tsx"]
    results = {}

    # Usar proyecto proporcionado o auto-detectar
    if project_path is None:
        project_path = get_project_root()

    shield = LegacyShield(project_path=project_path)

    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_path = os.path.join(root, file)
                file_results = shield.scan_file(file_path)
                if file_results:
                    results[file_path] = file_results

    return results


if __name__ == "__main__":
    # Demo
    sample_code = """
import os
import pickle
import yaml

def unsafe_load_config():
    config = yaml.load(user_input)  # Peligroso!
    return config

def execute_user_code():
    result = eval(user_input)  # CRÍTICO!
    return result

def bad_hash():
    return MD5(password)  # Débil cryptograficamente

api_key = "sk-1234567890abcdef"  # expuesta!
"""

    shield = LegacyShield()
    results = shield.scan_code(sample_code)

    print("=== 🔍 Legacy Shield - Scan Results ===\n")

    for r in results:
        print(f"📍 {r.file_path}:{r.line_number}")
        print(f"   {r.line_content}")
        print(f"   {r.suggestion}\n")

    summary = shield.get_summary(results)
    print(f"📊 Resumen: {summary['critical']} críticos, {summary['high']} altos")
