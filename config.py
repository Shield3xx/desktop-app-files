import os
import platform
from pathlib import Path

import os
import webbrowser

CLAMD_PATH = r"C:\Program Files\ClamAV\clamd.exe"

def ensure_clamav():
    if os.path.exists(CLAMD_PATH):
        return True
    print("ClamAV not found at:", CLAMD_PATH)
    webbrowser.open("https://www.clamav.net/downloads")
    return False

APP_NAME = "Shield3xxAV"

# Quarantine folder lives in the user's data directory
if platform.system() == "Windows":
    DATA_DIR = Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
else:
    DATA_DIR = Path.home() / f".{APP_NAME.replace(' ', '_').lower()}"

QUARANTINE_DIR = DATA_DIR / "quarantine"
QUARANTINE_LOG = DATA_DIR / "quarantine_log.json"

# SQLite database for scan history and quarantine records
DB_PATH = str(DATA_DIR / "safeguard.db")

DATA_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

SERVER_URL = "https://shield3xx.onrender.com"

# Feature flags. Real-time protection is a paid feature; the account
# system (added later) will set these from the server, not from the client.
REALTIME_PROTECTION_ENABLED = False

from pathlib import Path
import json

BASE_DIR = Path(__file__).resolve().parent
QUARANTINE_DIR = BASE_DIR / "quarantine"
QUARANTINE_LOG = BASE_DIR / "quarantine_log.json"

QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

if not QUARANTINE_LOG.exists():
    QUARANTINE_LOG.write_text("[]", encoding="utf-8")