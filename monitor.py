"""
Real-time protection: watches folders and scans new or modified files.
This is a paid feature, so main.py only starts it when the flag is on.
"""
import time
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
from watchdog.observers import Observer

from scanner import Scanner
from quarantine import quarantine_file


class _Handler(FileSystemEventHandler):
    def __init__(self, scanner: Scanner, on_threat: Callable[[str, str], None]):
        self.scanner = scanner
        self.on_threat = on_threat

    def _check(self, path: str):
        p = Path(path)
        if not p.is_file():
            return
        # Small delay so the file finishes writing before we read it
        time.sleep(0.5)
        result = self.scanner.scan_file(p)
        if result.infected:
            quarantine_file(p, result.threat or "Unknown")
            self.on_threat(str(p), result.threat or "Unknown")

    def on_created(self, event):
        if not event.is_directory:
            self._check(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._check(event.src_path)


class RealtimeMonitor:
    def __init__(self, scanner: Scanner, on_threat: Callable[[str, str], None]):
        self.observer = Observer()
        self.handler = _Handler(scanner, on_threat)
        self._running = False

    def watch(self, folder: str):
        self.observer.schedule(self.handler, folder, recursive=True)

    def start(self):
        if not self._running:
            self.observer.start()
            self._running = True

    def stop(self):
        if self._running:
            self.observer.stop()
            self.observer.join()
            self._running = False