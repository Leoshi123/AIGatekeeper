"""
AG-Wrapper — Centralized Language Registry

Single source of truth for supported programming languages, their file
extensions, and metadata. Every module that needs to know "which languages
and extensions do we support?" imports from here.

Rules:
- Never hardcode extensions or language lists outside this module.
- To add a new language: add an entry to SUPPORTED_LANGUAGES and you're done.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class LanguageInfo:
    """Metadata for a supported programming language."""

    name: str
    extensions: tuple[str, ...]
    pattern_count: int = 0  # Updated by detector modules at import time
    enabled: bool = True


# ── Registry ──────────────────────────────────────────────────────────────────

SUPPORTED_LANGUAGES: Dict[str, LanguageInfo] = {
    "python": LanguageInfo(
        name="Python",
        extensions=(".py",),
    ),
    "javascript": LanguageInfo(
        name="JavaScript / Node.js",
        extensions=(".js",),
    ),
    "typescript": LanguageInfo(
        name="TypeScript",
        extensions=(".ts", ".tsx"),
    ),
    "jsx": LanguageInfo(
        name="React (JSX)",
        extensions=(".jsx",),
    ),
    "go": LanguageInfo(
        name="Go",
        extensions=(".go",),
    ),
    "rust": LanguageInfo(
        name="Rust",
        extensions=(".rs",),
    ),
    "java": LanguageInfo(
        name="Java",
        extensions=(".java",),
    ),
    "c": LanguageInfo(
        name="C / C++",
        extensions=(".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"),
    ),
    "php": LanguageInfo(
        name="PHP",
        extensions=(".php",),
    ),
    # ── v3.0.0 ──
    "ruby": LanguageInfo(
        name="Ruby",
        extensions=(".rb",),
    ),
    "kotlin": LanguageInfo(
        name="Kotlin",
        extensions=(".kt", ".kts"),
    ),
    "csharp": LanguageInfo(
        name="C#",
        extensions=(".cs",),
    ),
    "swift": LanguageInfo(
        name="Swift",
        extensions=(".swift",),
    ),
    "scala": LanguageInfo(
        name="Scala",
        extensions=(".scala",),
    ),
    # ── Special categories (not file-based) ──
    "general": LanguageInfo(
        name="General (all languages)",
        extensions=(),
    ),
    "prompt": LanguageInfo(
        name="Prompt Injection (text)",
        extensions=(),
    ),
}


# ── Derived helpers ───────────────────────────────────────────────────────────

def get_enabled_languages() -> List[str]:
    """Return language keys where enabled=True."""
    return [k for k, v in SUPPORTED_LANGUAGES.items() if v.enabled]


def get_all_extensions(enabled_only: bool = True) -> List[str]:
    """Return a flat, deduplicated list of file extensions.

    Args:
        enabled_only: If True, only include extensions from enabled languages.
    """
    seen: set[str] = set()
    result: list[str] = []

    for lang_info in SUPPORTED_LANGUAGES.values():
        if enabled_only and not lang_info.enabled:
            continue
        for ext in lang_info.extensions:
            if ext not in seen:
                seen.add(ext)
                result.append(ext)

    return result


def extensions_for_language(lang_key: str) -> tuple[str, ...]:
    """Return extensions for a specific language key."""
    info = SUPPORTED_LANGUAGES.get(lang_key)
    if info is None:
        raise ValueError(f"Unknown language: {lang_key!r}")
    return info.extensions


def detect_language(file_path: str) -> Optional[str]:
    """Infer the language key from a file path by extension.

    Returns None if the extension is not in the registry.
    """
    for lang_key, lang_info in SUPPORTED_LANGUAGES.items():
        for ext in lang_info.extensions:
            if file_path.endswith(ext):
                return lang_key
    return None


def get_pattern_count() -> Dict[str, int]:
    """Return pattern count per language (populated by detector modules)."""
    return {k: v.pattern_count for k, v in SUPPORTED_LANGUAGES.items()}


# ── Convenience constants for backward compat ─────────────────────────────────

#: Default extensions for scan_directory / file watchers (enabled languages only)
DEFAULT_EXTENSIONS: List[str] = get_all_extensions(enabled_only=True)

#: All known extensions (including disabled / planned)
ALL_EXTENSIONS: List[str] = get_all_extensions(enabled_only=False)
