"""
Scanning engine. Sends files to the Shield3xxAV server (/scan endpoint).

Requires: the server at config.SERVER_URL is reachable and you are logged in.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Optional

import requests
from config import SERVER_URL


def login(identifier, password):
    response = requests.post(
        f"{SERVER_URL.rstrip('/')}/login",
        json={
            "identifier": identifier.strip(),
            "password": password,
        },
        timeout=30,
    )
    response.raise_for_status()

    data = response.json()
    token = data.get("access_token") or data.get("token")

    if not isinstance(token, str) or not token.strip():
        raise RuntimeError(
            "The server did not return a valid login token."
        )

    return token.strip()


def cloud_scan(path, token):
    with open(path, "rb") as file:
        response = requests.post(
            f"{SERVER_URL.rstrip('/')}/scan",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": (str(path), file)},
            timeout=120,
        )

    response.raise_for_status()
    return response.json()


@dataclass
class ScanResult:
    path: str
    infected: bool
    threat: Optional[str] = None
    error: Optional[str] = None


class Scanner:
    """Scanning interface backed by the server."""

    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.available = True

    def login(self, identifier: str, password: str) -> None:
        self.token = login(identifier, password)

    def is_available(self) -> bool:
        try:
            response = requests.get(
                f"{SERVER_URL.rstrip('/')}/health",
                timeout=10,
            )
            return response.status_code < 500

        except Exception:
            return False

    def scan_file(self, path: Path) -> ScanResult:
        try:
            if not self.token:
                return ScanResult(
                    str(path),
                    infected=False,
                    error="Not logged in to the scan server.",
                )

            data = cloud_scan(path, self.token)

            if not isinstance(data, dict):
                return ScanResult(
                    str(path),
                    infected=False,
                    error="Invalid scan response from server.",
                )

            status = str(data.get("status", "")).strip().lower()

            if status == "infected":
                threat = (
                    data.get("threat")
                    or data.get("virus")
                    or "Unknown"
                )

                return ScanResult(
                    str(path),
                    infected=True,
                    threat=str(threat),
                )

            if status == "clean":
                return ScanResult(
                    str(path),
                    infected=False,
                )

            return ScanResult(
                str(path),
                infected=False,
                error=(
                    "Unrecognized scan status from server: "
                    f"{status or 'missing'}"
                ),
            )

        except Exception as exc:
            return ScanResult(
                str(path),
                infected=False,
                error=str(exc),
            )

    def scan_folder(
        self,
        folder: Path,
        on_progress: Optional[Callable[[ScanResult], None]] = None,
        should_stop: Callable[[], bool] = lambda: False,
    ) -> Iterator[ScanResult]:
        for path in self._iter_files(folder):
            if should_stop():
                return

            result = self.scan_file(path)

            if on_progress:
                on_progress(result)

            yield result

    @staticmethod
    def _iter_files(folder: Path) -> Iterator[Path]:
        for path in Path(folder).rglob("*"):
            if path.is_file() and not path.is_symlink():
                yield path