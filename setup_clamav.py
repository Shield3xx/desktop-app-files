import ctypes
import hashlib
import os
import subprocess
import sys
import tempfile
import urllib.request

# ---- Put your ClamAV URL here ----
CLAMAV_URL = "https://www.clamav.net/downloads/production/clamav-1.5.4.win.x64.msi"

# ---- Put the SHA-256 published on clamav.net for this file here ----
CLAMAV_SHA256 = "A025FA23A4B9D64FCE448D5A211AFCF30DC26BA6528186E6223D1B945F9D95D6"

CLAMAV_INSTALL_DIR = r"C:\Program Files\ClamAV"
CLAMD_PATH = os.path.join(CLAMAV_INSTALL_DIR, "clamd.exe")
LOG_PATH = os.path.join(tempfile.gettempdir(), "safeguard_clamav_setup.log")


def log(msg):
    """Print and append to a log file (elevated copies have no visible console)."""
    print(msg)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except OSError:
        pass


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def request_admin():
    """Relaunch this script elevated. Windows shows the UAC popup.
    Returns True if the elevated copy was started, False if the user declined."""
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{os.path.abspath(__file__)}" {params}', None, 1
    )
    # ShellExecuteW returns > 32 on success; <= 32 means declined or failed
    return ret > 32


def sha256_of(path):
    """Return the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_clamav():
    """Download, verify, and silently install ClamAV if it isn't present."""
    if os.path.exists(CLAMD_PATH):
        log("ClamAV is already installed.")
        return True

    installer = os.path.join(tempfile.gettempdir(), os.path.basename(CLAMAV_URL))
    log(f"Downloading ClamAV from {CLAMAV_URL}")
    urllib.request.urlretrieve(CLAMAV_URL, installer)

    actual = sha256_of(installer)
    if actual.lower() != CLAMAV_SHA256.lower():
        os.remove(installer)
        raise RuntimeError(
            f"SHA-256 mismatch: expected {CLAMAV_SHA256}, got {actual}. Installer deleted."
        )

    log("Hash verified. Installing silently...")
    subprocess.run(["msiexec", "/i", installer, "/qn"], check=True)
    return os.path.exists(CLAMD_PATH)


def main():
    if os.path.exists(CLAMD_PATH):
        log("ClamAV is already installed.")
        return 0

    if not is_admin():
        log("Administrator permission is required to install ClamAV. Requesting it...")
        if request_admin():
            # Elevated copy is running in its own process; this one stops here.
            return 0
        log("Administrator permission was declined. ClamAV was NOT installed.")
        log("Run start.bat again and accept the prompt, or install ClamAV manually.")
        return 1

    try:
        if ensure_clamav():
            log("ClamAV is installed.")
            return 0
        log("ClamAV install failed.")
        return 1
    except Exception as e:
        log(f"ClamAV install error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
