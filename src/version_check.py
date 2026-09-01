# -*- coding: utf-8 -*-
"""
🚀 AIGatekeeper - Version Check Module

Detección de versiones para el MCP. El flujo SIEMPRE es:
1. Leer la versión LOCAL (fuente única: src.__version__)
2. Consultar GitHub Releases para obtener la última release
3. Comparar y reportar si el usuario está desactualizado

Resiliencia: si no hay red o la API falla, NUNCA se bloquea —
se retorna la versión local como referencia con error informativo.
"""

import json
import time
import logging
import urllib.request
from typing import Optional

from src import __version__ as LOCAL_VERSION

REPO = "Leoshi123/AIGatekeeper"
GITHUB_API = f"https://api.github.com/repos/{REPO}/releases/latest"
TIMEOUT_SECONDS = 5

logger = logging.getLogger(__name__)


def get_local_version() -> str:
    """Lee la versión local desde la única fuente canónica (src.__version__)."""
    return LOCAL_VERSION


def fetch_latest_release(timeout: int = TIMEOUT_SECONDS) -> Optional[dict]:
    """Consulta GitHub Releases API por la última release. Retorna None si falla la red."""
    try:
        req = urllib.request.Request(
            GITHUB_API,
            headers={
                "User-Agent": "AIGatekeeper-MCP",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        logger.warning(f"update_check: no se pudo consultar GitHub: {e}")
        return None


def normalize_version(version: str) -> str:
    """Normaliza 'v3.0.0' → '3.0.0'. Elimina prefijos 'v'/'V' y espacios."""
    return version.strip().lstrip("vV")


def compare_versions(local: str, latest: str) -> int:
    """
    Compara dos versiones semver (maneja prefijos 'v' y componentes parciales).

    Retorna:
        -1 si local < latest (desactualizado)
         0 si local == latest (al día)
         1 si local > latest (más nuevo que la release pública)
    """
    def parse(v: str):
        parts = []
        for p in normalize_version(v).split("."):
            num = ""
            for ch in p:
                if ch.isdigit():
                    num += ch
                else:
                    break
            parts.append(int(num) if num else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    left, right = parse(local), parse(latest)
    return (left > right) - (left < right)


def check_for_updates(timeout: int = TIMEOUT_SECONDS) -> dict:
    """
    Verifica si la versión local está desactualizada.

    PRIMERO local, LUEGO remoto. Nunca lanza excepción:
    sin red → state "unknown" con versión local como referencia.

    Returns:
        dict con local_version, latest_version (si hay red), outdated, message.
    """
    local = get_local_version()

    base = {
        "local_version": local,
        "check_timestamp": time.time(),
    }

    release = fetch_latest_release(timeout=timeout)
    if release is None:
        base.update({
            "outdated": None,
            "error": (
                "No se pudo consultar GitHub (sin red o API limitada). "
                "La versión local es la referencia."
            ),
        })
        return base

    tag = release.get("tag_name", "")
    latest = normalize_version(tag)
    cmp_result = compare_versions(local, latest)

    base.update({
        "latest_version": latest,
        "latest_tag": tag,
        "release_name": release.get("name", ""),
        "published_at": release.get("published_at", ""),
        "release_url": release.get(
            "html_url", f"https://github.com/{REPO}/releases"
        ),
        "outdated": cmp_result < 0,
        "up_to_date": cmp_result == 0,
        "ahead": cmp_result > 0,
    })

    if cmp_result < 0:
        base["message"] = (
            f"⚠️ Estás usando AIGatekeeper v{local}, pero la última versión es v{latest} "
            f"({release.get('name', '')}). Actualizá para obtener las últimas mejoras "
            f"y parches de seguridad: {base['release_url']}"
        )
    elif cmp_result == 0:
        base["message"] = f"✅ Tenés la última versión de AIGatekeeper (v{local})."
    else:
        base["message"] = (
            f"ℹ️ Tu versión local (v{local}) es más nueva que la última release pública "
            f"(v{latest}). Estás en un desarrollo sin publicar."
        )

    return base


if __name__ == "__main__":
    import pprint

    pprint.pprint(check_for_updates())