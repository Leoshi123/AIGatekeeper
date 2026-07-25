"""
Tests for src/languages.py — Centralized Language Registry.

Validates:
- Registry integrity (no duplicate extensions across languages)
- All enabled languages have at least one extension
- No two languages own the same extension
- DEFAULT_EXTENSIONS covers all enabled languages
- detect_language() works correctly
- Future (v3.0.0) languages are present but disabled
"""

import pytest

from src.languages import (
    SUPPORTED_LANGUAGES,
    DEFAULT_EXTENSIONS,
    ALL_EXTENSIONS,
    LanguageInfo,
    get_enabled_languages,
    get_all_extensions,
    extensions_for_language,
    detect_language,
)


class TestRegistryIntegrity:
    """Core integrity checks for the language registry."""

    def test_no_duplicate_extensions_across_languages(self):
        """Two different languages must not claim the same file extension."""
        seen: dict[str, str] = {}  # ext -> first language key
        for lang_key, lang_info in SUPPORTED_LANGUAGES.items():
            for ext in lang_info.extensions:
                if ext in seen:
                    pytest.fail(
                        f"Extension {ext!r} is claimed by both "
                        f"{seen[ext]!r} and {lang_key!r}"
                    )
                seen[ext] = lang_key

    def test_all_enabled_languages_have_extensions(self):
        """Every enabled language must have at least one extension."""
        for lang_key, lang_info in SUPPORTED_LANGUAGES.items():
            if lang_info.enabled and lang_info.name not in (
                "General (all languages)",
                "Prompt Injection (text)",
            ):
                assert len(lang_info.extensions) > 0, (
                    f"Language {lang_key!r} is enabled but has no extensions"
                )

    def test_registry_is_frozen_dataclass(self):
        """LanguageInfo instances must be immutable."""
        info = LanguageInfo(name="test", extensions=(".x",))
        with pytest.raises(AttributeError):
            info.name = "mutated"  # type: ignore[misc]

    def test_enabled_languages_count(self):
        """We expect exactly 16 enabled languages (14 file-based + 2 special categories)."""
        enabled = get_enabled_languages()
        assert len(enabled) == 16, f"Expected 16 enabled languages, got {len(enabled)}"

    def test_all_v3_languages_are_enabled(self):
        """v3.0.0 languages must be enabled since v3.0.0 release."""
        v3_langs = ["ruby", "kotlin", "csharp", "swift", "scala"]
        for lang in v3_langs:
            assert lang in SUPPORTED_LANGUAGES, f"v3.0.0 language {lang!r} missing from registry"
            assert SUPPORTED_LANGUAGES[lang].enabled, (
                f"v3.0.0 language {lang!r} should be enabled since v3.0.0"
            )


class TestExtensions:
    """Extension-related helpers."""

    def test_get_all_extensions_deduplicates(self):
        """No extension should appear twice in DEFAULT_EXTENSIONS."""
        assert len(DEFAULT_EXTENSIONS) == len(set(DEFAULT_EXTENSIONS))

    def test_default_extensions_match_enabled_languages(self):
        """DEFAULT_EXTENSIONS must be the union of all enabled language extensions."""
        expected = []
        seen: set[str] = set()
        for lang_info in SUPPORTED_LANGUAGES.values():
            if not lang_info.enabled:
                continue
            for ext in lang_info.extensions:
                if ext not in seen:
                    seen.add(ext)
                    expected.append(ext)
        assert DEFAULT_EXTENSIONS == expected

    def test_all_extensions_includes_disabled(self):
        """ALL_EXTENSIONS includes extensions from disabled languages too.

        When all file-based languages are enabled, ALL_EXTENSIONS == DEFAULT_EXTENSIONS.
        This test should be re-evaluated when new disabled languages are added.
        """
        all_exts = get_all_extensions(enabled_only=False)
        default_exts = get_all_extensions(enabled_only=True)
        # All known extensions are from enabled languages (no disabled ones with extensions)
        assert set(all_exts) == set(default_exts)

    def test_extensions_for_language_valid(self):
        """extensions_for_language returns correct tuple for known language."""
        exts = extensions_for_language("python")
        assert exts == (".py",)

    def test_extensions_for_unknown_language_raises(self):
        """extensions_for_language raises ValueError for unknown key."""
        with pytest.raises(ValueError, match="Unknown language"):
            extensions_for_language("brainfuck")


class TestDetectLanguage:
    """detect_language() file path inference."""

    @pytest.mark.parametrize(
        "path,expected",
        [
            ("main.py", "python"),
            ("app.js", "javascript"),
            ("component.tsx", "typescript"),
            ("handler.ts", "typescript"),
            ("page.jsx", "jsx"),
            ("server.go", "go"),
            ("lib.rs", "rust"),
            ("App.java", "java"),
            ("core.c", "c"),
            ("util.cpp", "c"),
            ("index.php", "php"),
        ],
    )
    def test_detect_known_extensions(self, path, expected):
        assert detect_language(path) == expected

    def test_detect_unknown_extension_returns_none(self):
        assert detect_language("readme.md") is None

    def test_detect_future_language_extension(self):
        """Disabled languages should still be detectable by extension."""
        assert detect_language("model.rb") == "ruby"
        assert detect_language("App.kt") == "kotlin"
        assert detect_language("Program.cs") == "csharp"
        assert detect_language("main.swift") == "swift"
        assert detect_language("Build.scala") == "scala"


class TestCPlusPlusConsistency:
    """Validate C++ default extensions stay in sync with the Python registry.

    The C++ code (scanner.h, pyag.cpp) hardcodes its own default extension
    list because it can't import Python at compile time. This test ensures
    those hardcoded lists match the Python source of truth.
    """

    def test_cpp_extensions_match_python(self):
        """scanner.h default extensions must equal DEFAULT_EXTENSIONS."""
        import re
        from pathlib import Path

        scanner_h = Path(__file__).parent.parent / "core" / "include" / "scanner.h"
        content = scanner_h.read_text()

        # Extract the default extensions from scan_directory declaration
        match = re.search(
            r'scan_directory\(\s*const std::string& directory,'
            r'\s*const std::vector<std::string>& extensions = \{([^}]+)\}',
            content,
        )
        assert match, "Could not find scan_directory default extensions in scanner.h"

        raw = match.group(1)
        cpp_exts = sorted(
            s.strip().strip('"') for s in raw.split(",") if s.strip()
        )
        py_exts = sorted(DEFAULT_EXTENSIONS)

        assert cpp_exts == py_exts, (
            f"C++ extensions in scanner.h don't match Python registry.\n"
            f"  C++ only: {set(cpp_exts) - set(py_exts)}\n"
            f"  Python only: {set(py_exts) - set(cpp_exts)}"
        )

    def test_pyag_bindings_match_python(self):
        """pyag.cpp default extensions must equal DEFAULT_EXTENSIONS."""
        import re
        from pathlib import Path

        pyag_cpp = Path(__file__).parent.parent / "core" / "bindings" / "pyag.cpp"
        content = pyag_cpp.read_text()

        match = re.search(
            r'scan_directory.*?extensions.*?=\s*std::vector<std::string>\{([^}]+)\}',
            content,
            re.DOTALL,
        )
        assert match, "Could not find scan_directory default extensions in pyag.cpp"

        raw = match.group(1)
        cpp_exts = sorted(
            s.strip().strip('"') for s in raw.split(",") if s.strip()
        )
        py_exts = sorted(DEFAULT_EXTENSIONS)

        assert cpp_exts == py_exts, (
            f"C++ extensions in pyag.cpp don't match Python registry.\n"
            f"  C++ only: {set(cpp_exts) - set(py_exts)}\n"
            f"  Python only: {set(py_exts) - set(cpp_exts)}"
        )
