"""
🛡️ ZTC-Wrapper - Módulo Detector
"""

from .zombie_detector import (
    LegacyShield,
    ZombiePattern,
    DetectionResult,
    Severity,
    scan_directory,
)

__all__ = [
    "LegacyShield",
    "ZombiePattern",
    "DetectionResult",
    "Severity",
    "scan_directory",
]
