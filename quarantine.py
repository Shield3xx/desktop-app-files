"""
Moves infected files into the quarantine folder and records them in a log.
Files are renamed with a .quarantined suffix so they can't be run by accident.
Restore and delete actions are available from the GUI.
"""
import json
import shutil
import time
import uuid 
from pathlib import Path
from typing import List, Dict

from config import QUARANTINE_DIR, QUARANTINE_LOG


def _load_log() -> List[Dict]:
    if not QUARANTINE_LOG.exists():
        return []

    try:
        data = json.loads(
            QUARANTINE_LOG.read_text(encoding="utf-8")
        )

        if not isinstance(data, list):
            raise ValueError("Quarantine log must contain a list.")

        if not all(isinstance(entry, dict) for entry in data):
            raise ValueError("Quarantine log contains an invalid entry.")

        return data

    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(
            f"Cannot safely read quarantine log: {exc}"
        ) from exc


def _save_log(entries: List[Dict]) -> None:
    temporary = QUARANTINE_LOG.with_name(
        QUARANTINE_LOG.name + ".tmp"
    )

    try:
        temporary.write_text(
            json.dumps(entries, indent=2),
            encoding="utf-8",
        )
        temporary.replace(QUARANTINE_LOG)

    finally:
        if temporary.exists():
            temporary.unlink()


def quarantine_file(path: Path, threat: str) -> Path:
    path = Path(path)

    if not path.is_file():
        raise FileNotFoundError(
            f"File to quarantine does not exist: {path}"
        )

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    # Read the log before moving the file, so a corrupt log
    # cannot strand the file without a record.
    entries = _load_log()

    stamp = int(time.time())
    dest = QUARANTINE_DIR / (
        f"{stamp}_{uuid.uuid4().hex}_{path.name}.quarantined"
    )

    shutil.move(str(path), str(dest))

    try:
        entries.append({
            "original_path": str(path),
            "quarantined_path": str(dest),
            "threat": threat,
            "time": stamp,
        })

        _save_log(entries)

    except Exception:
        # Attempt to restore the original file if its record
        # could not be saved.
        try:
            if dest.exists() and not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(dest), str(path))
        except Exception as rollback_error:
            raise RuntimeError(
                "Quarantine record saving failed, and automatic "
                f"file recovery also failed. File location: {dest}. "
                f"Recovery error: {rollback_error}"
            ) from rollback_error

        raise

    return dest
    stamp = int(time.time())
    dest = QUARANTINE_DIR / f"{stamp}_{path.name}.quarantined"
    shutil.move(str(path), str(dest))

    entries = _load_log()
    entries.append({
        "original_path": str(path),
        "quarantined_path": str(dest),
        "threat": threat,
        "time": stamp,
    })
    _save_log(entries)
    return dest


def list_quarantined() -> List[Dict]:
    return _load_log()


def restore_file(entry: Dict) -> None:
    src = Path(entry["quarantined_path"])
    dst = Path(entry["original_path"])
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    _save_log([e for e in _load_log() if e != entry])


def delete_quarantined(entry: Dict) -> None:
    Path(entry["quarantined_path"]).unlink(missing_ok=True)
    _save_log([e for e in _load_log() if e != entry])