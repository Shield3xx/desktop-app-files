import json
import re
import urllib.error
import urllib.request

import config


SERVER_URL = config.SERVER_URL.rstrip("/")
ACCOUNT_FILE = config.DATA_DIR / "account.json"

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9._%+-]+@gmail\.com$",
    re.IGNORECASE,
)

USERNAME_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]{3,32}$"
)


def _request_json(method, endpoint, payload=None, token=None, timeout=30):
    """Send a JSON request to the Shield3xxAV backend."""
    url = f"{SERVER_URL}{endpoint}"

    headers = {"Accept": "application/json"}
    data = None

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method=method.upper(),
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_text = response.read().decode("utf-8")

        if not response_text.strip():
            return {}

        return json.loads(response_text)

    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")

        try:
            details = json.loads(body)
            if isinstance(details, dict):
                message = details.get("detail", body)
            else:
                message = body
        except (ValueError, TypeError):
            message = body or "The server returned an error."

        raise RuntimeError(
            f"Server error ({exc.code}): {message}"
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(
            "Could not connect to the Shield3xxAV server: "
            f"{exc.reason}"
        ) from exc

    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "The server returned an invalid JSON response."
        ) from exc


def validate_email(email):
    """Accept only Gmail addresses for new registrations."""
    return isinstance(email, str) and bool(
        EMAIL_PATTERN.fullmatch(email.strip())
    )


def validate_username(username):
    """Check the username format used by the backend."""
    return isinstance(username, str) and bool(
        USERNAME_PATTERN.fullmatch(username.strip())
    )


def load_account():
    """Load saved account data without retaining plaintext passwords."""
    try:
        if not ACCOUNT_FILE.exists():
            return None

        with ACCOUNT_FILE.open("r", encoding="utf-8") as file:
            saved = json.load(file)

        if not isinstance(saved, dict):
            return None

        changed = False

        for key in ("password", "synced"):
            if key in saved:
                saved.pop(key, None)
                changed = True

        if changed:
            try:
                with ACCOUNT_FILE.open("w", encoding="utf-8") as file:
                    json.dump(saved, file, indent=4)
            except OSError:
                pass

        return saved

    except (OSError, json.JSONDecodeError):
        return None


def save_account(email, username="", token=None):
    """
    Save account details and the token.
    Never save the plaintext password.
    """
    previous = load_account() or {}

    email = (email or previous.get("email", "")).strip().lower()
    username = (username or "").strip()

    if token is None:
        token = previous.get("token", "")

    saved = {
        "email": email,
        "username": username,
        "token": token or "",
    }
    ACCOUNT_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = ACCOUNT_FILE.with_suffix(".tmp")

    try:
        with temporary_file.open("w", encoding="utf-8") as file:
            json.dump(saved, file, indent=4)

        temporary_file.replace(ACCOUNT_FILE)

    except OSError as exc:
        try:
            temporary_file.unlink(missing_ok=True)
        except OSError:
            pass

        raise RuntimeError(
            f"Could not save the account locally: {exc}"
        ) from exc

    return saved

def sync_username_to_server(token, username):
    """Save an existing account's username to the authenticated server profile."""
    username = (username or "").strip()

    if not token:
        raise ValueError("Please log in before syncing your username.")

    if not username:
        raise ValueError("A username is required to sync your account.")

    result = _request_json(
        "POST",
        "/me/username",
        {"username": username},
        token=token,
    )

    if not isinstance(result, dict):
        raise RuntimeError("The server returned an invalid username response.")

    return result

def _get_token(result):
    token = result.get("access_token") or result.get("token")

    if not isinstance(token, str) or not token.strip():
        raise RuntimeError(
            "The server response did not contain a valid login token."
        )

    return token.strip()


def register_account(email, username, password):
    """Register a new account and save the token returned by the server."""
    email = email.strip().lower()
    username = username.strip()

    if not validate_email(email):
        raise ValueError(
            "Please enter a valid Gmail address ending in @gmail.com."
        )

    if not validate_username(username):
        raise ValueError(
            "Username must be 3–32 characters and contain only "
            "letters, numbers, periods, underscores, or hyphens."
        )

    if len(password) < 6:
        raise ValueError(
            "Password must contain at least 6 characters."
        )

    result = _request_json(
        "POST",
        "/signup",
        {
            "email": email,
            "username": username,
            "password": password,
        },
    )

    token = _get_token(result)

    return save_account(
        result.get("email") or email,
        result.get("username") or username,
        token,
    )


def login_account(identifier, password):
    """Log in using either a Gmail address or a username."""
    identifier = identifier.strip()

    if not identifier:
        raise ValueError("Enter your Gmail address or username.")

    if not password:
        raise ValueError("Enter your password.")

    result = _request_json(
        "POST",
        "/login",
        {
            "identifier": identifier,
            "password": password,
        },
    )

    token = _get_token(result)
    previous = load_account() or {}

    # The updated backend returns the account email and username.
    # The fallback helps with older server responses.
    if "email" in result:
        email = result.get("email") or ""
    elif "@" in identifier:
        email = identifier
    else:
        email = previous.get("email", "")

    if "username" in result:
        username = result.get("username") or ""
    else:
        username = previous.get("username", "")

    return save_account(email, username, token)


def set_username(token, username):
    """Assign a username to an authenticated existing account."""
    if not validate_username(username):
        raise ValueError(
            "Username must be 3–32 characters and contain only "
            "letters, numbers, periods, underscores, or hyphens."
        )

    result = _request_json(
        "POST",
        "/me/username",
        {"username": username.strip()},
        token=token,
    )

    previous = load_account() or {}

    return save_account(
        result.get("email") or previous.get("email", ""),
        result.get("username") or username.strip(),
        token,
    )


def change_password(token, current_password, new_password):
    """Change the server password after verifying the current password."""
    if not current_password:
        raise ValueError("Enter your current password.")

    if len(new_password) < 6:
        raise ValueError(
            "New password must contain at least 6 characters."
        )

    return _request_json(
        "POST",
        "/me/password",
        {
            "current_password": current_password,
            "new_password": new_password,
        },
        token=token,
    )
def sync_username_to_server(token, username):
    """Link an existing account's username to its server profile."""
    username = (username or "").strip()

    if not token:
        raise ValueError("Please log in before syncing your username.")

    if not username:
        raise ValueError("Please enter your username.")

    result = _request_json(
        "POST",
        "/me/username",
        {"username": username},
        token=token,
    )

    if not isinstance(result, dict):
        raise RuntimeError("Invalid response from the server.")

    return result

def authenticate(email, password, username="", signup=False):
    """
    Compatibility wrapper for older code that calls authenticate().
    """
    if signup:
        return register_account(email, username, password)

    return login_account(email, password)


def sync_to_server(email, username, password):
    """
    Compatibility wrapper for older signup code.
    Registration itself writes the account data to Firestore.
    """
    try:
        register_account(email, username, password)
        return True, "Account registered and synchronized successfully."
    except Exception as exc:
        return False, str(exc)


def get_subscription(token):
    """Retrieve the authenticated user's subscription."""
    if not token:
        raise ValueError(
            "No login token is available. Please log in first."
        )

    result = _request_json(
        "GET",
        "/me/subscription",
        token=token,
    )

    if not isinstance(result, dict):
        raise RuntimeError(
            "The server returned invalid subscription data."
        )

    return result


def logout():
    """Remove locally saved account details."""
    try:
        if ACCOUNT_FILE.exists():
            ACCOUNT_FILE.unlink()
        return True

    except OSError as exc:
        raise RuntimeError(
            f"Could not remove the saved account: {exc}"
        ) from exc