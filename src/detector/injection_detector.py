"""
🛡️ AG-Wrapper - Prompt Injection Detector

Detecta intentos de prompt injection en texto y prompts de usuario:
- Direct injection: override de instrucciones del sistema
- Indirect injection: instrucciones embebidas en datos externos
- Jailbreak: intentos conocidos de bypass de seguridad
- Role-play hijacking: secuestro del rol del sistema
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class InjectionCategory(Enum):
    """Categorías de prompt injection."""

    DIRECT = "direct-injection"
    INDIRECT = "indirect-injection"
    JAILBREAK = "jailbreak"
    ROLE_PLAY = "role-play"


@dataclass
class InjectionFinding:
    """Resultado de detección de prompt injection."""

    category: InjectionCategory
    severity: str
    pattern: str
    matched: str
    description: str
    suggestion: str


@dataclass
class InjectionPattern:
    """Patrón de detección de prompt injection."""

    pattern: str
    category: InjectionCategory
    severity: str
    description: str
    suggestion: str


class PromptInjectDetector:
    """
    Detector de prompt injection en texto y prompts.

    Uso:
        detector = PromptInjectDetector()
        results = detector.scan("Ignore all previous instructions")
    """

    INJECTION_PATTERNS = [
        # ========== DIRECT INJECTION ==========
        InjectionPattern(
            pattern=r"ignore\s+(all\s+)?(previous\s+)?(instructions|rules|commands|prompts)",
            category=InjectionCategory.DIRECT,
            severity="MEDIUM",
            description="Intento de ignorar instrucciones previas del sistema",
            suggestion="No permitir que input externo descarte instrucciones del sistema",
        ),
        InjectionPattern(
            pattern=r"(you\s+(are\s+)?now|from\s+now\s+on).{0,40}(hacker|free|unrestricted|no\s+rules|no\s+limits|evil|malicious)",
            category=InjectionCategory.DIRECT,
            severity="MEDIUM",
            description="Intento de reasignación de rol para eludir restricciones",
            suggestion="Validar que el role del sistema no sea reemplazable por input externo",
        ),
        InjectionPattern(
            pattern=r"forget\s+(your\s+|all\s+)?(.{0,40})?(rules|instructions|guidelines|prompts|constraints)",
            category=InjectionCategory.DIRECT,
            severity="MEDIUM",
            description="Intento de borrar reglas/configuración del sistema",
            suggestion="Las instrucciones del sistema no deben ser modificables por input externo",
        ),
        InjectionPattern(
            pattern=r"disregard\s+(all\s+)?(previous|prior)\s+(instructions|rules)",
            category=InjectionCategory.DIRECT,
            severity="MEDIUM",
            description="Intento de descartar instrucciones previas del sistema",
            suggestion="No permitir que input externo anule instrucciones del sistema",
        ),
        InjectionPattern(
            pattern=r"override\s+(your\s+)?(instructions|rules|prompts|settings|config)",
            category=InjectionCategory.DIRECT,
            severity="HIGH",
            description="Intento explícito de override de configuración del sistema",
            suggestion="Bloquear overrides de configuración del sistema desde input externo",
        ),
        # ========== INDIRECT INJECTION ==========
        InjectionPattern(
            pattern=r"---BEGIN\s+(INSTRUCTIONS|PROMPT|SYSTEM|COMMANDS)---",
            category=InjectionCategory.INDIRECT,
            severity="LOW",
            description="Posible instrucción embebida en delimitador",
            suggestion="Sanitizar contenido externo que contenga delimitadores de instrucciones",
        ),
        InjectionPattern(
            pattern=r"---END\s+OF\s+(INPUT|CONTEXT|MESSAGE|DATA)---",
            category=InjectionCategory.INDIRECT,
            severity="LOW",
            description="Posible separador de contexto con instrucciones posteriores",
            suggestion="Validar contenido después de separadores de contexto",
        ),
        InjectionPattern(
            pattern=r"```system\n|```instructions\n|```prompt\n",
            category=InjectionCategory.INDIRECT,
            severity="LOW",
            description="Bloque de código que puede contener instrucciones embebidas",
            suggestion="Inspeccionar bloques de código que imiten formato de system prompts",
        ),
        # ========== JAILBREAK ==========
        InjectionPattern(
            pattern=r"\bDAN\b|do\s+anything\s+now|jail\s*broken|jailbreak",
            category=InjectionCategory.JAILBREAK,
            severity="HIGH",
            description="Posible intento de jailbreak (DAN u homólogo)",
            suggestion="Bloquear patrones de jailbreak conocidos",
        ),
        InjectionPattern(
            pattern=r"(hypothetical|fictional|imaginary)\s+(scenario|setting|situation).{0,60}(no\s+rules|unrestricted|evil|hack)",
            category=InjectionCategory.JAILBREAK,
            severity="MEDIUM",
            description="Intento de jailbreak via escenario hipotético",
            suggestion="Validar que escenarios hipotéticos no intenten eludir restricciones",
        ),
        InjectionPattern(
            pattern=r"(act\s+)?as\s+if\s+(you\s+)?(have|are)\s+no\s+(rules|limits|restrictions|boundaries)",
            category=InjectionCategory.JAILBREAK,
            severity="HIGH",
            description="Intento de jailbreak explícito declarando ausencia de reglas",
            suggestion="Bloquear declaraciones de ausencia de restricciones",
        ),
        # ========== ROLE-PLAY HIJACKING ==========
        InjectionPattern(
            pattern=r"(this\s+is|here\s+are)\s+(your\s+)?(new\s+)?system\s+prompt",
            category=InjectionCategory.ROLE_PLAY,
            severity="HIGH",
            description="Intento de redefinición del system prompt del agente",
            suggestion="El system prompt no debe ser reemplazable desde input externo",
        ),
        InjectionPattern(
            pattern=r"pretend\s+(you\s+(are|were)|to\s+be).{0,60}(no\s+(rules|limits|restrictions|boundaries|ethical)|unrestricted|without\s+limits|evil|malicious)",
            category=InjectionCategory.ROLE_PLAY,
            severity="MEDIUM",
            description="Intento de role-play para eludir restricciones de seguridad",
            suggestion="Validar que role-play no intente eliminar restricciones del sistema",
        ),
        InjectionPattern(
            pattern=r"(initial|original|default)\s+(instructions|prompt|settings).{0,40}(override|replace|change|new)",
            category=InjectionCategory.ROLE_PLAY,
            severity="HIGH",
            description="Intento de modificar configuración inicial del sistema",
            suggestion="La configuración inicial del sistema es inmutable desde input externo",
        ),
    ]

    SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

    def __init__(self, categories: Optional[list[str]] = None):
        """
        Inicializa el detector.

        Args:
            categories: Lista de categorías a detectar (None = todas).
                        Valores: "direct-injection", "indirect-injection",
                                "jailbreak", "role-play"
        """
        self.categories = categories
        if categories:
            self._patterns = [
                p for p in self.INJECTION_PATTERNS
                if p.category.value in categories
            ]
        else:
            self._patterns = self.INJECTION_PATTERNS

    def scan(self, text: str) -> list[InjectionFinding]:
        """
        Escanea texto en busca de patrones de prompt injection.

        Args:
            text: Texto o prompt a analizar.

        Returns:
            Lista de InjectionFinding con los hallazgos.
        """
        findings = []
        seen_matches = set()

        for pattern in self._patterns:
            for match in re.finditer(pattern.pattern, text, re.IGNORECASE):
                matched_text = match.group(0).strip()

                # Evitar duplicados exactos del mismo patrón
                dedup_key = (pattern.category.value, matched_text.lower())
                if dedup_key in seen_matches:
                    continue
                seen_matches.add(dedup_key)

                findings.append(
                    InjectionFinding(
                        category=pattern.category,
                        severity=pattern.severity,
                        pattern=pattern.pattern,
                        matched=matched_text,
                        description=pattern.description,
                        suggestion=pattern.suggestion,
                    )
                )

        return findings

    def scan_text(self, text: str) -> dict:
        """
        Escanea texto y retorna dict JSON-serializable para APIs.

        Args:
            text: Texto o prompt a analizar.

        Returns:
            Dict con status, findings y summary.
        """
        findings = self.scan(text)

        if not findings:
            return {
                "status": "clean",
                "message": "No prompt injection detected",
                "findings": [],
                "summary": {"total": 0, "categories": {}, "severities": {}},
            }

        summary = self.get_summary(findings)

        return {
            "status": "findings_found",
            "total": len(findings),
            "findings": [
                {
                    "category": f.category.value,
                    "severity": f.severity,
                    "matched": f.matched,
                    "description": f.description,
                    "suggestion": f.suggestion,
                }
                for f in findings
            ],
            "summary": summary,
        }

    def get_summary(self, findings: list[InjectionFinding]) -> dict:
        """
        Genera resumen de hallazgos agrupado por severidad y categoría.

        Args:
            findings: Lista de InjectionFinding.

        Returns:
            Dict con totales agrupados.
        """
        category_counts: dict[InjectionCategory, int] = {}
        severity_counts: dict[str, int] = {}

        for f in findings:
            category_counts[f.category] = category_counts.get(f.category, 0) + 1
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        severity_order = sorted(
            severity_counts.keys(),
            key=lambda s: self.SEVERITY_ORDER.get(s, -1),
            reverse=True,
        )

        return {
            "total": len(findings),
            "categories": dict(sorted(category_counts.items(), key=lambda x: x[0].value)),
            "severities": {s: severity_counts[s] for s in severity_order},
        }
