from PySide6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

import account


class LoginDialog(QDialog):
    def __init__(self, parent=None, mode="signup"):
        super().__init__(parent)

        self.mode = mode
        self.setWindowTitle(
            "Log in" if mode == "login" else "Sign up"
        )
        self.setMinimumWidth(380)

        self.email = QLineEdit()
        self.username = QLineEdit()
        self.password = QLineEdit()

        self.email.setPlaceholderText(
            "Gmail address or username"
            if mode == "login"
            else "you@gmail.com"
        )
        self.username.setPlaceholderText("Username")

        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.Password)

        saved = account.load_account() or {}

        if mode == "login":
            self.email.setText(
                saved.get("username") or saved.get("email", "")
            )
        else:
            self.email.setText(saved.get("email", ""))
            self.username.setText(saved.get("username", ""))

        form = QFormLayout()

        form.addRow(
            "Email or username:" if mode == "login" else "Gmail:",
            self.email,
        )
        form.addRow("Username:", self.username)
        form.addRow("Password:", self.password)

        if mode == "login":
            self.username.hide()
            username_label = form.labelForField(self.username)

            if username_label:
                username_label.hide()

        self.hint = QLabel(
            "An internet connection is required to sign up or log in. "
            "After a successful login, local scanning, quarantine, "
            "and scan history can be used offline."
        )
        self.hint.setWordWrap(True)

        self.btn_continue = QPushButton("Continue")
        self.btn_continue.setDefault(True)
        self.btn_continue.clicked.connect(self._accept)

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.reject)

        buttons = QHBoxLayout()
        buttons.addStretch()
        buttons.addWidget(self.btn_cancel)
        buttons.addWidget(self.btn_continue)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(self.hint)
        layout.addLayout(buttons)

    @property
    def email_value(self):
        return self.email.text().strip().lower()

    @property
    def identifier_value(self):
        return self.email.text().strip()

    @property
    def username_value(self):
        return self.username.text().strip()

    @username_value.setter
    def username_value(self, value):
        self.username.setText(value or "")

    @property
    def password_value(self):
        return self.password.text()

    @password_value.setter
    def password_value(self, value):
        self.password.setText(value or "")

    def _accept(self):
        identifier = self.email.text().strip()
        password = self.password.text()
        username = self.username.text().strip()

        if self.mode == "signup":
            if not account.validate_email(identifier):
                QMessageBox.warning(
                    self,
                    "Invalid email",
                    "Please enter a valid Gmail address ending in "
                    "@gmail.com.",
                )
                return

            if not account.validate_username(username):
                QMessageBox.warning(
                    self,
                    "Invalid username",
                    "Username must be 3–32 characters and contain only "
                    "letters, numbers, periods, underscores, or hyphens.",
                )
                return

            if len(password) < 6:
                QMessageBox.warning(
                    self,
                    "Invalid password",
                    "Your password must contain at least 6 characters.",
                )
                return

        else:
            if not identifier:
                QMessageBox.warning(
                    self,
                    "Missing login",
                    "Enter your Gmail address or username.",
                )
                return

            if not password:
                QMessageBox.warning(
                    self,
                    "Missing password",
                    "Enter your password.",
                )
                return

        # The GUI performs the actual server request after this dialog
        # closes. Do not authenticate from inside the dialog.
        self.accept()