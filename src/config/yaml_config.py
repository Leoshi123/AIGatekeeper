"""
AG-Wrapper - YAML Configuration

Loads and merges ``ag.yaml`` configuration for the wrapper, detector,
sanitizer, and file watcher.

The config is searched upward from CWD — first match wins.
CLI flags always override YAML values at runtime.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


# ── defaults ──────────────────────────────────────────────────────────────────

_DEFAULT_EXTENSIONS = [".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs"]
_DEFAULT_EXCLUDE_DIRS = [
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "build",
    "dist",
    ".tox",
]


# ── sub-configs ────────────────────────────────────────────────────────────────


@dataclass
class DetectorConfig:
    severity_threshold: str = "high"
    custom_patterns: list[dict] = field(default_factory=list)


@dataclass
class SanitizerConfig:
    remove_comments: bool = True
    remove_paths: bool = True
    preserve_shebang: bool = True
    preserve_copyright: bool = False


@dataclass
class WatcherConfig:
    extensions: list[str] = field(default_factory=lambda: list(_DEFAULT_EXTENSIONS))
    exclude_dirs: list[str] = field(default_factory=lambda: list(_DEFAULT_EXCLUDE_DIRS))
    block_on_scan: bool = False
    quiet: bool = False


# ── root config ────────────────────────────────────────────────────────────────


@dataclass
class YamlConfig:
    """Full AIGatekeeper configuration loaded from ``ag.yaml``."""

    version: str = "1.0"

    # Wrapper section maps directly to WrapperConfig fields
    wrapper: dict = field(default_factory=dict)

    detector: DetectorConfig = field(default_factory=DetectorConfig)
    sanitizer: SanitizerConfig = field(default_factory=SanitizerConfig)
    watch: WatcherConfig = field(default_factory=WatcherConfig)

    source_path: Optional[Path] = None  # where the YAML was found

    # ── class methods ──────────────────────────────────────────────────────

    @classmethod
    def load(cls, path: str | Path) -> "YamlConfig":
        """Load config from a specific YAML file path."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

        return cls._from_dict(raw, source_path=path)

    @classmethod
    def find_and_load(cls, start_dir: str | Path | None = None) -> "YamlConfig":
        """Walk upward from *start_dir* (or CWD) looking for ``ag.yaml``.

        Returns an empty (defaults-only) config if no file is found — never
        raises.
        """
        start = Path(start_dir or Path.cwd()).resolve()

        for parent in [start] + list(start.parents):
            candidate = parent / "ag.yaml"
            if candidate.is_file():
                raw = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
                return cls._from_dict(raw, source_path=candidate)

        return cls()  # defaults

    @classmethod
    def _from_dict(cls, raw: dict, source_path: Optional[Path] = None) -> "YamlConfig":
        cfg = cls(source_path=source_path)

        cfg.version = raw.get("version", "1.0")

        if "wrapper" in raw and isinstance(raw["wrapper"], dict):
            cfg.wrapper = raw["wrapper"]

        if "detector" in raw and isinstance(raw["detector"], dict):
            d = raw["detector"]
            cfg.detector.severity_threshold = d.get("severity_threshold", "high")
            cfg.detector.custom_patterns = d.get("custom_patterns", [])

        if "sanitizer" in raw and isinstance(raw["sanitizer"], dict):
            s = raw["sanitizer"]
            cfg.sanitizer.remove_comments = s.get("remove_comments", True)
            cfg.sanitizer.remove_paths = s.get("remove_paths", True)
            cfg.sanitizer.preserve_shebang = s.get("preserve_shebang", True)
            cfg.sanitizer.preserve_copyright = s.get("preserve_copyright", False)

        if "watch" in raw and isinstance(raw["watch"], dict):
            w = raw["watch"]
            cfg.watch.extensions = w.get("extensions", _DEFAULT_EXTENSIONS)
            cfg.watch.exclude_dirs = w.get("exclude_dirs", _DEFAULT_EXCLUDE_DIRS)
            cfg.watch.block_on_scan = w.get("block_on_scan", False)
            cfg.watch.quiet = w.get("quiet", False)

        return cfg

    # ── helpers ─────────────────────────────────────────────────────────────

    def build_wrapper_config(self) -> dict:
        """Return a dict suitable for ``WrapperConfig(**cfg)`` overrides."""
        return dict(self.wrapper)

    def to_dict(self) -> dict:
        """Serialize back to a plain dict (useful for ``ag config show``)."""
        return {
            "version": self.version,
            "wrapper": dict(self.wrapper),
            "detector": {
                "severity_threshold": self.detector.severity_threshold,
                "custom_patterns": self.detector.custom_patterns,
            },
            "sanitizer": {
                "remove_comments": self.sanitizer.remove_comments,
                "remove_paths": self.sanitizer.remove_paths,
                "preserve_shebang": self.sanitizer.preserve_shebang,
                "preserve_copyright": self.sanitizer.preserve_copyright,
            },
            "watch": {
                "extensions": self.watch.extensions,
                "exclude_dirs": self.watch.exclude_dirs,
                "block_on_scan": self.watch.block_on_scan,
                "quiet": self.watch.quiet,
            },
        }
