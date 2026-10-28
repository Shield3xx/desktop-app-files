from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QFrame, QHBoxLayout, QLabel, QListWidget,
    QMainWindow, QMessageBox, QPushButton, QTabWidget, QTextEdit,
    QVBoxLayout, QWidget, QProgressBar, QInputDialog,
)
from pathlib import Path
import time

from login_dialog import LoginDialog
import account
from scanner import Scanner, ScanResult
from quarantine import quarantine_file, list_quarantined, restore_file, delete_quarantined
from monitor import RealtimeMonitor
import config
import database


class ScanWorker(QThread):
    """Runs file and folder scans off the UI thread."""

    progress = Signal(object)  # ScanResult
    finished_scan = Signal(int, int, int, int)
    # scanned, detected, quarantined, quarantine_failed

    def __init__(self, scanner: Scanner, target: Path):
        super().__init__()
        self.scanner = scanner
        self.target = target
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        scanned = 0
        detected = 0
        quarantined = 0
        quarantine_failed = 0
        started = int(time.time())

        try:
            if not self.target.exists():
                raise FileNotFoundError(
                    f"Scan target does not exist: {self.target}"
                )

            if self.target.is_file():
                results = (self.scanner.scan_file(self.target),)
            elif self.target.is_dir():
                results = self.scanner.scan_folder(
                    self.target,
                    should_stop=lambda: self._stop,
                )
            else:
                raise ValueError(
                    f"Unsupported scan target: {self.target}"
                )

            for result in results:
                if self._stop:
                    break

                scanned += 1

                if result.infected and not result.error:
                    detected += 1

                    try:
                        quarantine_file(
                            Path(result.path),
                            result.threat or "Unknown",
                        )
                        quarantined += 1

                    except Exception as exc:
                        quarantine_failed += 1
                        result.error = f"Quarantine failed: {exc}"

                self.progress.emit(result)

        except Exception as exc:
            self.progress.emit(
                ScanResult(
                    path=str(self.target),
                    infected=False,
                    error=f"Scan failed: {exc}",
                )
            )

        finally:
            try:
                database.add_scan_history(
                    str(self.target),
                    scanned,
                    detected,
                    started,
                    int(time.time()),
                )
            except Exception as exc:
                self.progress.emit(
                    ScanResult(
                        path=str(self.target),
                        infected=False,
                        error=f"Could not save scan history: {exc}",
                    )
                )

            self.finished_scan.emit(
                scanned,
                detected,
                quarantined,
                quarantine_failed,
            )


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(config.APP_NAME)
        self.resize(900, 600)

        try:
            self.scanner = Scanner()
        except RuntimeError as e:
            QMessageBox.critical(self, "ClamAV not running", str(e))
            self.scanner = None

        self.worker = None
        self.monitor = None

        root = QWidget(objectName="root")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(24, 20, 24, 20)
        outer.setSpacing(14)

        top = QHBoxLayout()
        self.btn_login = QPushButton("Log in", objectName="ghost")
        self.btn_login.clicked.connect(self._open_login)
        top.addWidget(self.btn_login, 0, Qt.AlignLeft | Qt.AlignTop)
        top.addStretch()
        self.btn_signup = QPushButton("Sign up", objectName="ghost")
        self.btn_signup.clicked.connect(self._open_signup)
        top.addWidget(self.btn_signup, 0, Qt.AlignRight | Qt.AlignTop)
        outer.addLayout(top)

        header = QHBoxLayout()
        titles = QVBoxLayout()
        t = QLabel(config.APP_NAME, objectName="title")
        sub = QLabel("Antivirus protection for your files", objectName="subtitle")
        titles.addWidget(t)
        titles.addWidget(sub)
        header.addLayout(titles)
        header.addStretch()
        self.status_badge = QLabel("● Protected")
        self.status_badge.setStyleSheet(
            "color:#3ddc97; background:#16271f; border-radius:12px; padding:6px 12px;")
        header.addWidget(self.status_badge)
        outer.addLayout(header)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs)
        self.setCentralWidget(root)
        self.tabs.addTab(self._scan_tab(), "Scan")
        self.tabs.addTab(self._quarantine_tab(), "Quarantine")
        self.tabs.addTab(self._realtime_tab(), "Real-time")
        self._refresh_account_buttons()

        self.setStyleSheet("""
            QMainWindow, QWidget#root { background: #14151a; color: #e8eaf0;
                                        font-family: "Segoe UI", sans-serif; font-size: 13px; }
            QLabel#title { font-size: 20px; font-weight: 600; color: #ffffff; }
            QLabel#subtitle { color: #8b90a0; font-size: 12px; }
            QLabel#statValue { font-size: 22px; font-weight: 600; color: #ffffff; }
            QLabel#statLabel { color: #8b90a0; font-size: 11px; text-transform: uppercase; }
            QFrame#card { background: #1d1f26; border: 1px solid #2a2d36; border-radius: 10px; }
            QPushButton { background: #2f6fed; color: white; border: none;
                          padding: 9px 16px; border-radius: 7px; font-weight: 500; }
            QPushButton:hover { background: #4283f5; }
            QPushButton:pressed { background: #2459c4; }
            QPushButton:disabled { background: #2a2d36; color: #6b7080; }
            QPushButton#ghost { background: transparent; color: #c9cdd8;
                                border: 1px solid #353945; }
            QPushButton#ghost:hover { background: #242732; }
            QPushButton#danger { background: #c0392b; }
            QPushButton#danger:hover { background: #d9483b; }
            QTextEdit, QListWidget { background: #101116; border: 1px solid #2a2d36;
                                     border-radius: 8px; padding: 8px;
                                     selection-background-color: #2f6fed; }
            QListWidget::item { padding: 6px; border-radius: 4px; }
            QListWidget::item:selected { background: #2f6fed; }
            QTabWidget::pane { border: none; top: -1px; }
            QTabBar::tab { background: transparent; color: #8b90a0; padding: 10px 18px;
                           margin-right: 4px; border-bottom: 2px solid transparent;
                           font-weight: 500; }
            QTabBar::tab:selected { color: #ffffff; border-bottom: 2px solid #2f6fed; }
            QTabBar::tab:hover:!selected { color: #c9cdd8; }
            QProgressBar { border: none; background: #242732; border-radius: 3px;
                           height: 6px; }
            QProgressBar::chunk { background: #2f6fed; border-radius: 3px; }
            QMessageBox { background: #1d1f26; }
        """)

    def _stat_card(self, label: str, value: str) -> QFrame:
        card = QFrame(objectName="card")
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 12, 16, 12)
        val = QLabel(value, objectName="statValue")
        lab = QLabel(label, objectName="statLabel")
        v.addWidget(val)
        v.addWidget(lab)
        card._value = val
        return card

    # ---- Scan tab ----
    def _scan_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        stats = QHBoxLayout()
        self.stat_scanned = self._stat_card("Files scanned", "0")
        self.stat_threats = self._stat_card("Threats found", "0")
        stats.addWidget(self.stat_scanned)
        stats.addWidget(self.stat_threats)
        layout.addLayout(stats)

        self.scan_log = QTextEdit(readOnly=True)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.hide()

        row = QHBoxLayout()
        self.btn_scan_file = QPushButton("Scan file")
        self.btn_scan_folder = QPushButton("Scan folder")
        self.btn_stop = QPushButton("Stop", objectName="ghost")
        self.btn_stop.setEnabled(False)
        row.addWidget(self.btn_scan_file)
        row.addWidget(self.btn_scan_folder)
        row.addWidget(self.btn_stop)

        self.btn_scan_file.clicked.connect(self._scan_file)
        self.btn_scan_folder.clicked.connect(self._scan_folder)
        self.btn_stop.clicked.connect(self._stop_scan)

        layout.addLayout(row)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.scan_log)
        return w

    def _scan_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose file to scan")
        if path:
            self._start_scan(Path(path))

    def _scan_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose folder to scan")
        if folder:
            self._start_scan(Path(folder))

    def _start_scan(self, target: Path):
        if not self.scanner:
            QMessageBox.warning(
                self,
                "Scanner unavailable",
                "The scanner has not been initialized.",
            )
            return

        if not target.exists():
            QMessageBox.warning(
                self,
                "File or folder not found",
                f"The selected target does not exist:\n{target}",
            )
            return

        self.scan_log.clear()
        self.scan_log.append(f"Scanning {target} ...")

        self.progress_bar.show()
        self.btn_scan_file.setEnabled(False)
        self.btn_scan_folder.setEnabled(False)
        self.btn_stop.setEnabled(True)

        self.worker = ScanWorker(self.scanner, target)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished_scan.connect(self._on_finished)
        self.worker.start()

    def _stop_scan(self):
        if self.worker:
            self.worker.stop()

    def _on_progress(self, result: ScanResult):
        if result.error:
            self.scan_log.append(
                f'<span style="color:#f0b429">Error</span>&nbsp; {result.path}: {result.error}')
        elif result.infected:
            self.scan_log.append(
                f'<span style="color:#ff6b6b;font-weight:600">Threat</span>&nbsp; '
                f'{result.path} &rarr; {result.threat}')
        # clean files are not logged individually to keep the view fast

    def _on_finished(
        self,
        scanned: int,
        detected: int,
        quarantined: int,
        quarantine_failed: int,
    ):
        self.progress_bar.hide()
        self.btn_scan_file.setEnabled(True)
        self.btn_scan_folder.setEnabled(True)
        self.btn_stop.setEnabled(False)

        self.stat_scanned._value.setText(str(scanned))
        self.stat_threats._value.setText(str(detected))

        self.scan_log.append(
            f"Done. Scanned: {scanned}. "
            f"Threats detected: {detected}. "
            f"Quarantined successfully: {quarantined}. "
            f"Quarantine failures: {quarantine_failed}."
        )

    # ---- Quarantine tab ----
    def _quarantine_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        self.q_list = QListWidget()
        row = QHBoxLayout()
        btn_refresh = QPushButton("Refresh", objectName="ghost")
        btn_restore = QPushButton("Restore", objectName="ghost")
        btn_delete = QPushButton("Delete permanently", objectName="danger")
        row.addWidget(btn_refresh)
        row.addWidget(btn_restore)
        row.addWidget(btn_delete)
        btn_refresh.clicked.connect(self._refresh_quarantine)
        btn_restore.clicked.connect(self._restore_selected)
        btn_delete.clicked.connect(self._delete_selected)
        layout.addLayout(row)
        layout.addWidget(self.q_list)
        self._refresh_quarantine()
        return w

    def _refresh_quarantine(self):
        self.q_list.clear()
        self._q_entries = list_quarantined()
        for e in self._q_entries:
            self.q_list.addItem(f"{e['threat']}  |  {e['original_path']}")

    def _selected_entry(self):
        row = self.q_list.currentRow()
        return self._q_entries[row] if 0 <= row < len(self._q_entries) else None

    def _restore_selected(self):
        e = self._selected_entry()
        if e:
            restore_file(e)
            self._refresh_quarantine()

    def _delete_selected(self):
        e = self._selected_entry()
        if e and QMessageBox.question(self, "Delete", "Permanently delete this file?") \
                == QMessageBox.Yes:
            delete_quarantined(e)
            self._refresh_quarantine()

    # ---- Real-time tab (paid feature) ----
    def _realtime_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        self.rt_status = QLabel("Real-time protection: OFF")
        self.btn_rt = QPushButton("Start real-time protection")
        self.btn_rt.clicked.connect(self._toggle_realtime)
        layout.addWidget(self.rt_status)
        layout.addWidget(self.btn_rt)
        layout.addStretch()
        return w

    def _open_login(self):
        dlg = LoginDialog(self, mode="login")

        if dlg.exec() != LoginDialog.Accepted:
            return

        identifier = getattr(dlg, "identifier_value", "")
        if not identifier:
            identifier = getattr(dlg, "email_value", "")
        if not identifier and hasattr(dlg, "email"):
            identifier = dlg.email.text().strip()

        password = dlg.password_value

        if not identifier or not password:
            QMessageBox.warning(
                self,
                "Login details missing",
                "Enter your username or email and password.",
            )
            return

        self.btn_login.setEnabled(False)
        self.btn_login.setText("Connecting...")
        previous_account = account.load_account() or {}

        try:
            # Authenticate with the server only once.
            login_function = getattr(account, "login_account", None)

            if callable(login_function):
                saved = login_function(identifier.strip(), password)
            else:
                # Compatibility with the older email-only account module.
                if not account.validate_email(identifier):
                    raise RuntimeError(
                        "This account.py version supports email login "
                        "only. Username login requires the updated "
                        "account.py login function."
                    )

                saved = account.authenticate(
                    email=identifier,
                    password=password,
                    username=(account.load_account() or {}).get(
                        "username", ""
                    ),
                    signup=False,
                )

            if not isinstance(saved, dict) or not saved.get("token"):
                raise RuntimeError(
                    "The server did not return a usable login token."
                )
                
            username_to_sync = (
                saved.get("username")
                or previous_account.get("username")
                or ""
            ).strip()

            if not username_to_sync:
                username_to_sync, accepted = QInputDialog.getText(
                    self,
                    "Link your username",
                    "Enter the username for your existing account:",
                )
                username_to_sync = (
                    username_to_sync.strip() if accepted else ""
                )

            if username_to_sync:
                try:
                    account.sync_username_to_server(
                        saved["token"],
                        username_to_sync,
                    )

                    email_to_save = (
                        saved.get("email")
                        or previous_account.get("email")
                        or identifier
                    )

                    account.save_account(
                        email_to_save,
                        username_to_sync,
                        saved["token"],
                    )

                    self.scan_log.append("Username synced with server.")

                except Exception as exc:
                    self.scan_log.append(
                        f"Username sync failed: {exc}"
                    )
                    QMessageBox.warning(
                        self,
                        "Username sync failed",
                        "Email login succeeded, but the server could "
                        f"not save your username.\n\n{exc}",
                    )


            if self.scanner:
                self.scanner.token = saved["token"]

            self._refresh_account_buttons()
            self.scan_log.append(
                "Login successful: the server authenticated your account."
            )

            QMessageBox.information(
                self,
                "Login successful",
                "The server accepted your login details, your "
                "account has been verified by the server, "
                "and your connection was successful.",
            )

        except Exception as exc:
            self.scan_log.append(f"Login failed: {exc}")

            QMessageBox.warning(
                self,
                "Login failed",
                "The app could not complete authentication with the "
                f"server.\n\nDetails: {exc}\n\n"
                "Check your internet connection, account details, "
                "and server availability.",
            )

        finally:
            dlg.password_value = ""
            self.btn_login.setEnabled(True)
            self._refresh_account_buttons()

    def _open_signup(self):
        dlg = LoginDialog(self, mode="signup")

        if dlg.exec() != LoginDialog.Accepted:
            return

        if not self.scanner:
            QMessageBox.warning(
                self,
                "Scanner unavailable",
                "The scanner could not be initialized.",
            )
            dlg.password_value = ""
            return

        try:
            # This performs registration once. The backend returns the
            # authentication token, which is saved by account.py.
            saved = account.register_account(
                dlg.email_value,
                dlg.username_value,
                dlg.password_value,
            )

            self.scanner.token = saved["token"]

            QMessageBox.information(
                self,
                "Account",
                "Account created and synchronized successfully. "
                "You are now logged in.",
            )

            self.scan_log.append(
                f"Signed up successfully as {saved['username']}."
            )

        except Exception as exc:
            QMessageBox.warning(
                self,
                "Signup failed",
                f"The account could not be created:\n\n{exc}",
            )

        finally:
            dlg.password_value = ""
            self._refresh_account_buttons()

    def _refresh_account_buttons(self):
        logged_in = bool(
            self.scanner and self.scanner.token
        )

        self.btn_login.setText(
            "Logged in" if logged_in else "Log in"
        )

        self.btn_signup.setVisible(True)

    def _toggle_realtime(self):
        # Real-time protection needs an account. Prompt for login/sign up if none.
        if account.load_account() is None:
            QMessageBox.information(
                self, "Account needed",
                "Real-time protection needs an account. Log in or sign up to continue.")
            self._open_signup()
            return
        # Gate: this will check the account/subscription once the backend exists.
        if not config.REALTIME_PROTECTION_ENABLED:
            QMessageBox.information(
                self, "Paid feature",
                "Real-time protection requires a paid plan."
            )
            return
        if self.monitor is None:
            self.monitor = RealtimeMonitor(self.scanner, self._on_realtime_threat)
            self.monitor.watch(str(Path.home() / "Downloads"))
            self.monitor.start()
            self.rt_status.setText("Real-time protection: ON (watching Downloads)")
            self.btn_rt.setText("Stop real-time protection")
        else:
            self.monitor.stop()
            self.monitor = None
            self.rt_status.setText("Real-time protection: OFF")
            self.btn_rt.setText("Start real-time protection")

    def _on_realtime_threat(self, path: str, threat: str):
        # Called from the watcher thread; hop back to the UI thread
        from PySide6.QtCore import QMetaObject, Q_ARG
        QMetaObject.invokeMethod(
            self.scan_log, "append", Qt.QueuedConnection,
            Q_ARG(str, f"[REAL-TIME] {path} -> {threat} (quarantined)")
        )

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        if self.monitor:
            self.monitor.stop()
        super().closeEvent(event)


def run():
    database.init_db()
    app = QApplication.instance() or QApplication([])
    app.setApplicationName(config.APP_NAME)
    win = MainWindow()
    win.show()
    app.exec()