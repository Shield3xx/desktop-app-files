import sys
from PySide6.QtWidgets import QApplication
import gui


def run_app():
    app = QApplication.instance() 
    if app is None:
        app = QApplication(sys.argv)
    # Login is optional. If an account already exists, try to sync it
    # (best-effort, never blocks the app). Otherwise start straight away.
    gui.run()


if __name__ == "__main__":
    run_app()
