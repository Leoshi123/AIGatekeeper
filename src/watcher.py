"""
AG-Wrapper - File Watcher

Watches a directory for file changes and runs security scans in real time
using ``watchdog``.

Usage:
    ag watch [path]          # watch a directory
    ag watch --config ag.yaml  # with YAML config
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Optional

from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from watchdog.observers import Observer

from src.config.yaml_config import YamlConfig
from src.detector import LegacyShield, scan_directory


class AGWatchHandler(FileSystemEventHandler):
    """Reacts to file changes by scanning for security issues."""

    def __init__(
        self,
        config: YamlConfig,
        detector: LegacyShield,
        quiet: bool = False,
    ) -> None:
        super().__init__()
        self.config = config
        self.detector = detector
        self.quiet = quiet
        self._debounce: dict[str, float] = {}

    def on_modified(self, event: FileModifiedEvent) -> None:
        if event.is_directory:
            return

        path = Path(event.src_path)
        if not self._should_scan(path):
            return

        # Debounce: skip if same file was scanned < 1s ago
        now = time.monotonic()
        last = self._debounce.get(event.src_path, 0)
        if now - last < 1.0:
            return
        self._debounce[event.src_path] = now

        self._scan_file(path)

    def _should_scan(self, path: Path) -> bool:
        """Check if the file matches watched extensions and isn't excluded."""
        # Extension check
        if path.suffix not in self.config.watch.extensions:
            return False

        # Exclude dirs check
        for part in path.parts:
            if part in self.config.watch.exclude_dirs:
                return False

        return True

    def _scan_file(self, path: Path) -> None:
        """Run detector on the file and print results."""
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            if not self.quiet:
                print(f"⚠️  Cannot read {path}: {exc}")
            return

        results = self.detector.scan_code(code, file_path=str(path))

        if not results:
            if not self.quiet:
                print(f"✅ {path} — clean")
            return

        summary = self.detector.get_summary(results)
        icon = "🛑" if summary["critical"] > 0 else "⚠️"
        print(f"{icon} {path} — {summary['total']} issue(s) "
              f"(critical={summary['critical']}, high={summary['high']})")

        for r in results[:5]:
            print(f"   [{r.pattern.severity.value}] {r.pattern.description}")
            if self.config.watch.block_on_scan:
                print(f"   💡 {r.pattern.alternative}")

        if self.config.watch.block_on_scan and summary["critical"] > 0:
            print(f"🛑 BLOQUEADO: se detectaron {summary['critical']} problema(s) crítico(s)")


def start_watch(
    path: str | Path = ".",
    config: Optional[YamlConfig] = None,
    quiet: bool = False,
) -> None:
    """Start the file watcher (blocking)."""
    watch_path = Path(path).resolve()
    if not watch_path.is_dir():
        print(f"❌ Not a directory: {watch_path}")
        sys.exit(1)

    if config is None:
        config = YamlConfig.find_and_load()

    detector = LegacyShield(project_path=str(watch_path))

    handler = AGWatchHandler(config, detector, quiet=quiet)
    observer = Observer()

    # Watch recursively
    observer.schedule(handler, str(watch_path), recursive=True)

    print(f"👀 AG-Watch activo en: {watch_path}")
    print(f"   Extensiones: {', '.join(config.watch.extensions)}")
    print(f"   Excluye: {', '.join(config.watch.exclude_dirs)}")
    if config.watch.block_on_scan:
        print("   Modo: bloqueo activo 🛑")
    print("   Ctrl+C para detener")
    print()

    try:
        observer.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n👋 AG-Watch detenido.")
        observer.stop()
    except Exception as exc:
        print(f"❌ Error: {exc}")
        observer.stop()

    observer.join()
