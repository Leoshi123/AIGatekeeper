"""
AG-Wrapper - Config Module

Re-exports from both legacy (``.agrc``) and new (``ag.yaml``) config systems.
"""

# Legacy config (.agrc) — kept for backward compatibility
from .legacy_config import AGConfig as LegacyAGConfig
from .legacy_config import DetectorConfig as LegacyDetectorConfig
from .legacy_config import SanitizerConfig as LegacySanitizerConfig
from .legacy_config import IgnoreConfig, get_project_root

# Keep AGConfig as legacy for backward compat (used by detector, etc.)
AGConfig = LegacyAGConfig

# New YAML config (ag.yaml)
from .yaml_config import YamlConfig, DetectorConfig, SanitizerConfig, WatcherConfig

__all__ = [
    # Legacy
    "LegacyAGConfig",
    "LegacyDetectorConfig",
    "LegacySanitizerConfig",
    "IgnoreConfig",
    "get_project_root",
    # New
    "YamlConfig",
    "DetectorConfig",
    "SanitizerConfig",
    "WatcherConfig",
]
