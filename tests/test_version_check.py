# -*- coding: utf-8 -*-
"""
Tests para src/version_check.py — actualización del MCP.
Cubre: lectura de versión local, comparación semver, y el flujo completo
(local primero, remoto después) incluso sin red.
"""

import pytest

from src.version_check import (
    get_local_version,
    normalize_version,
    compare_versions,
    check_for_updates,
    fetch_latest_release,
)


class TestNormalizeVersion:
    def test_prefixed_v(self):
        assert normalize_version("v3.0.0") == "3.0.0"

    def test_mayuscula(self):
        assert normalize_version("V2.1.0") == "2.1.0"

    def test_sin_prefijo(self):
        assert normalize_version("1.0.2") == "1.0.2"

    def test_con_espacios(self):
        assert normalize_version("  3.0.0  ") == "3.0.0"


class TestCompareVersions:
    def test_igual(self):
        assert compare_versions("3.0.0", "3.0.0") == 0

    def test_local_menor(self):
        assert compare_versions("1.0.2", "3.0.0") == -1

    def test_local_mayor(self):
        assert compare_versions("3.1.0", "3.0.0") == 1

    def test_patch_menor(self):
        assert compare_versions("3.0.0", "3.0.1") == -1

    def test_con_prefijo_v(self):
        assert compare_versions("v3.0.0", "v3.0.0") == 0

    def test_componente_parcial(self):
        assert compare_versions("3.0", "3.0.0") == 0

    def test_pre_release_no_rompe(self):
        # "3.0.0-beta" se parsea como 3.0.0 → igual (no crashea)
        assert compare_versions("3.0.0-beta", "3.0.0") == 0


class TestCheckForUpdates:
    def test_local_version_es_fuente_canonica(self):
        from src import __version__
        # La versión local SIEMPRE es la fuente canónica (src/__init__.py)
        assert get_local_version() == __version__

    def test_flujo_completo_al_dia(self, monkeypatch):
        from src import __version__ as VERSION

        latest = "v" + VERSION

        def fake_release(timeout=5):
            return {
                "tag_name": latest,
                "name": "Versioning unificado + update_check",
                "published_at": "2026-09-01T00:00:00Z",
                "html_url": f"https://github.com/Leoshi123/AIGatekeeper/releases/tag/{latest}",
            }

        monkeypatch.setattr("src.version_check.fetch_latest_release", fake_release)
        result = check_for_updates()

        assert result["outdated"] is False
        assert result["up_to_date"] is True
        assert result["local_version"] == VERSION
        assert result["latest_version"] == VERSION
        assert "última versión" in result["message"]

    def test_flujo_completo_desactualizado(self, monkeypatch):
        from src import __version__ as VERSION

        def fake_release(timeout=5):
            return {
                "tag_name": "v4.0.0",
                "name": "Future Release",
                "published_at": "2026-09-01T00:00:00Z",
                "html_url": "https://github.com/Leoshi123/AIGatekeeper/releases/tag/v4.0.0",
            }

        monkeypatch.setattr("src.version_check.fetch_latest_release", fake_release)
        result = check_for_updates()

        assert result["outdated"] is True
        assert result["local_version"] == VERSION
        assert result["latest_version"] == "4.0.0"
        assert "actualiz" in result["message"].lower()

    def test_sin_red_no_bloquea(self, monkeypatch):
        from src import __version__ as VERSION

        def fake_release(timeout=5):
            return None

        monkeypatch.setattr("src.version_check.fetch_latest_release", fake_release)
        result = check_for_updates()

        assert result["outdated"] is None
        assert result["local_version"] == VERSION
        assert "error" in result

    def test_fetch_latest_release_con_red(self, monkeypatch):
        # Validamos que la función real existe y es invocable (no crashea al exportar)
        assert callable(fetch_latest_release)