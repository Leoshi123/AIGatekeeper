"""
🛡️ AG-Wrapper - Configuración del Proyecto

Carga y gestiona la configuración desde .agrc
"""

import os
import yaml
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, field


@dataclass
class DetectorConfig:
    """Configuración del detector."""

    exclude_patterns: List[str] = field(default_factory=list)
    strict_mode: bool = False
    block_on_critical: bool = True


@dataclass
class SanitizerConfig:
    """Configuración del sanitizador."""

    remove_comments: bool = True
    remove_paths: bool = True
    remove_tokens: bool = True


@dataclass
class IgnoreConfig:
    """Configuración de paths ignorados."""

    paths: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)


@dataclass
class AGConfig:
    """Configuración principal de AG-Wrapper."""

    detector: DetectorConfig = field(default_factory=DetectorConfig)
    sanitizer: SanitizerConfig = field(default_factory=SanitizerConfig)
    ignore: IgnoreConfig = field(default_factory=IgnoreConfig)

    @classmethod
    def load(cls, project_path: str = ".") -> "AGConfig":
        """
        Carga configuración desde .agrc en el proyecto.

        Args:
            project_path: Ruta al proyecto (donde está .agrc)

        Returns:
            AGConfig con valores por defecto si no existe archivo
        """
        config_path = os.path.join(project_path, ".agrc")

        if not os.path.exists(config_path):
            return cls()  # Return defaults

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            return cls(
                detector=DetectorConfig(
                    exclude_patterns=data.get("detector", {}).get(
                        "exclude_patterns", []
                    ),
                    strict_mode=data.get("detector", {}).get("strict_mode", False),
                    block_on_critical=data.get("detector", {}).get(
                        "block_on_critical", True
                    ),
                ),
                sanitizer=SanitizerConfig(
                    remove_comments=data.get("sanitizer", {}).get(
                        "remove_comments", True
                    ),
                    remove_paths=data.get("sanitizer", {}).get("remove_paths", True),
                    remove_tokens=data.get("sanitizer", {}).get("remove_tokens", True),
                ),
                ignore=IgnoreConfig(
                    paths=data.get("ignore", {}).get("paths", []),
                    files=data.get("ignore", {}).get("files", []),
                ),
            )
        except Exception as e:
            print(f"Warning: Error loading .agrc: {e}")
            return cls()  # Return defaults


def get_project_root() -> str:
    """Detecta la raíz del proyecto buscando .agrc o .git"""
    # Buscar hacia arriba desde el directorio actual
    current = Path.cwd()

    # Máximo 5 niveles hacia arriba
    for _ in range(5):
        if (current / ".agrc").exists() or (current / ".git").exists():
            return str(current)
        parent = current.parent
        if parent == current:  # Root reached
            break
        current = parent

    return str(Path.cwd())
