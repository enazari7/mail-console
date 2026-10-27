"""Administrator accounts, server-side sessions, CSRF tokens and login throttling."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .db import now_us, tx

# Argon2id, RFC 9106 "second recommended" profile (64 MiB, t=3, p=4).
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024
USERNAME_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@")

# Login throttling windows (failures within the window block further attempts).
WINDOW_US = 15 * 60 * 1_000_000
MAX_FAILURES_PER_IP = 5
MAX_FAILURES_PER_USER = 10
MAX_FAILURES_GLOBAL = 50
# Addresses with a successful login in this window are exempt from the
# per-username and global limits, so an attacker cannot lock the owner out.
TRUSTED_WINDOW_US = 30 * 86400 * 1_000_000

# Each Argon2 operation allocates memory_cost (64 MiB). Bound concurrency so a
# burst of login requests cannot exhaust the web service's memory limit.
_HASH_SLOTS = threading.BoundedSemaphore(2)
HASH_WAIT_SECONDS = 5.0


class AuthError(ValueError):
    pass


class AuthBusy(RuntimeError):
    """Too many concurrent password hash operations; try again shortly."""


def _with_hash_slot(fn, *args):
    if not _HASH_SLOTS.acquire(timeout=HASH_WAIT_SECONDS):
        raise AuthBusy()
    try:
        return fn(*args)
    finally:
        _HASH_SLOTS.release()


def validate_username(username: str) -> str:
    username = username.strip()
    if not 3 <= len(username) <= 64 or not set(username) <= USERNAME_CHARS:
        raise AuthError("username must be 3-64 characters: letters, digits, . _ - @")
    return username


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise AuthError("password is too long")
    if password.strip() == "" or len(set(password)) < 4:
        raise AuthError("password is too simple")


def hash_password(password: str) -> str:
    validate_password(password)
    return _with_hash_slot(_hasher.hash, password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Constant-work verification; a missing account still costs one hash."""
    if len(password) > MAX_PASSWORD_LENGTH:
        password = password[:MAX_PASSWORD_LENGTH]
    try:
        return _with_hash_slot(_hasher.verify, stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def admin_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT count(*) FROM admins").fetchone()[0]


def create_admin(conn: sqlite3.Connection, username: str, password: str) -> int:
    username = validate_username(username)
    password_hash = hash_password(password)
    ts = now_us()
    with tx(conn):
        if conn.execute("SELECT 1 FROM admins WHERE username = ?", (username,)).fetchone():
            raise AuthError(f"administrator {username!r} already exists")
        cur = conn.execute(
            "INSERT INTO admins(username, password_hash, created_ts, password_changed_ts) VALUES (?, ?, ?, ?)",
            (username, password_hash, ts, ts),
        )
    return cur.lastrowid


def set_password(conn: sqlite3.Connection, admin_id: int, password: str, *, keep_session: bytes | None = None) -> None:
    """Change a password and revoke every other session of that admin."""
    password_hash = hash_password(password)
    with tx(conn):
        conn.execute("UPDATE admins SET password_hash = ?, password_changed_ts = ? WHERE id = ?",
                     (password_hash, now_us(), admin_id))
        conn.execute("DELETE FROM sessions WHERE admin_id = ? AND token_hash IS NOT ?", (admin_id, keep_session))


def _token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def _username_key(username: str) -> str:
    # Attempted usernames are stored only as a hash: a password typed into
    # the username field must not end up in the database.
    return hashlib.sha256(username.strip().lower().encode()).hexdigest()[:32]


@dataclass
class Session:
    admin_id: int
    username: str
    csrf_token: str
    token_hash: bytes
    created_ts: int
    expires_ts: int


def login_allowed(conn: sqlite3.Connection, client_ip: str, username: str) -> bool:
    now = now_us()
    since = now - WINDOW_US
    row = conn.execute(
        "SELECT"
        " sum(CASE WHEN client_ip = ? THEN 1 ELSE 0 END),"
        " sum(CASE WHEN username_hash = ? THEN 1 ELSE 0 END),"
        " count(*)"
        " FROM login_attempts WHERE ts >= ? AND success = 0",
        (client_ip, _username_key(username), since),
    ).fetchone()
    by_ip, by_user, overall = (v or 0 for v in row)
    if by_ip >= MAX_FAILURES_PER_IP:
        return False
    trusted = conn.execute("SELECT 1 FROM login_attempts WHERE client_ip = ? AND success = 1 AND ts >= ? LIMIT 1",
                           (client_ip, now - TRUSTED_WINDOW_US)).fetchone()
    return bool(trusted) or (by_user < MAX_FAILURES_PER_USER and overall < MAX_FAILURES_GLOBAL)


def begin_attempt(conn: sqlite3.Connection, client_ip: str, username: str) -> int:
    """Record an attempt as failed *before* hashing, so parallel bursts count."""
    with tx(conn):
        return conn.execute("INSERT INTO login_attempts(ts, client_ip, username_hash, success) VALUES (?, ?, ?, 0)",
                            (now_us(), client_ip, _username_key(username))).lastrowid


def finish_attempt(conn: sqlite3.Connection, attempt_id: int, client_ip: str, success: bool) -> None:
    if not success:
        return
    with tx(conn):
        conn.execute("UPDATE login_attempts SET success = 1 WHERE id = ?", (attempt_id,))
        # A successful login clears this address's failure history.
        conn.execute("DELETE FROM login_attempts WHERE client_ip = ? AND success = 0", (client_ip,))


def record_attempt(conn: sqlite3.Connection, client_ip: str, username: str, success: bool) -> None:
    finish_attempt(conn, begin_attempt(conn, client_ip, username), client_ip, success)


def clear_failures(conn: sqlite3.Connection) -> int:
    with tx(conn):
        return conn.execute("DELETE FROM login_attempts WHERE success = 0").rowcount


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> int | None:
    row = conn.execute("SELECT id, password_hash FROM admins WHERE username = ?", (username.strip(),)).fetchone()
    ok = verify_password(row["password_hash"] if row else None, password)
    if not ok or row is None:
        return None
    if _hasher.check_needs_rehash(row["password_hash"]):
        with tx(conn):
            conn.execute("UPDATE admins SET password_hash = ? WHERE id = ?", (_hasher.hash(password), row["id"]))
    return row["id"]


def create_session(conn: sqlite3.Connection, admin_id: int, *, idle_minutes: int, max_hours: int,
                   client_ip: str | None, user_agent: str | None) -> str:
    token = secrets.token_urlsafe(32)
    ts = now_us()
    with tx(conn):
        conn.execute(
            "INSERT INTO sessions(token_hash, admin_id, csrf_token, created_ts, last_seen_ts, expires_ts, client_ip,"
            " user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (_token_hash(token), admin_id, secrets.token_urlsafe(32), ts, ts,
             min(ts + idle_minutes * 60_000_000, ts + max_hours * 3_600_000_000),
             client_ip, (user_agent or "")[:200]),
        )
        conn.execute("UPDATE admins SET last_login_ts = ? WHERE id = ?", (ts, admin_id))
    return token


def load_session(conn: sqlite3.Connection, token: str | None, *, idle_minutes: int, max_hours: int) -> Session | None:
    """Return the session for a cookie token and slide its idle expiry."""
    if not token or len(token) > 128:
        return None
    token_hash = _token_hash(token)
    row = conn.execute(
        "SELECT s.*, a.username FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token_hash = ?",
        (token_hash,),
    ).fetchone()
    if row is None:
        return None
    ts = now_us()
    if row["expires_ts"] <= ts:
        with tx(conn):
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        return None
    expires = min(ts + idle_minutes * 60_000_000, row["created_ts"] + max_hours * 3_600_000_000)
    if ts - row["last_seen_ts"] > 30_000_000:  # avoid a write on every request
        with tx(conn):
            conn.execute("UPDATE sessions SET last_seen_ts = ?, expires_ts = ? WHERE token_hash = ?",
                         (ts, expires, token_hash))
    return Session(admin_id=row["admin_id"], username=row["username"], csrf_token=row["csrf_token"],
                   token_hash=token_hash, created_ts=row["created_ts"], expires_ts=expires)


def delete_session(conn: sqlite3.Connection, token_hash: bytes) -> None:
    with tx(conn):
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def delete_other_sessions(conn: sqlite3.Connection, admin_id: int, keep: bytes) -> int:
    with tx(conn):
        return conn.execute("DELETE FROM sessions WHERE admin_id = ? AND token_hash != ?", (admin_id, keep)).rowcount


def csrf_matches(expected: str | None, supplied: str | None) -> bool:
    if not expected or not supplied:
        return False
    return hmac.compare_digest(expected.encode(), supplied.encode())


# --- TOTP second factor (RFC 6238: SHA-1, 30 s, 6 digits) ---------------------

import base64 as _base64  # noqa: E402
import struct as _struct  # noqa: E402
import time as _time  # noqa: E402
from urllib.parse import quote as _quote  # noqa: E402

TOTP_STEP = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1            # accept one step of clock drift either side
PENDING_LOGIN_SECONDS = 300
PENDING_LOGIN_ATTEMPTS = 5


def totp_new_secret() -> str:
    return _base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_at(secret: str, counter: int) -> str:
    key = _base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, _struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (_struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** TOTP_DIGITS
    return f"{value:0{TOTP_DIGITS}d}"


def totp_now(secret: str, at: float | None = None) -> str:
    return _totp_at(secret, int((at if at is not None else _time.time()) // TOTP_STEP))


def totp_match(secret: str, code: str, at: float | None = None, after_counter: int | None = None) -> int | None:
    """Return the matching time step for ``code``, or None. Steps <= after_counter are rejected (replay)."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != TOTP_DIGITS:
        return None
    now = int((at if at is not None else _time.time()) // TOTP_STEP)
    for counter in range(now - TOTP_WINDOW, now + TOTP_WINDOW + 1):
        if after_counter is not None and counter <= after_counter:
            continue
        if hmac.compare_digest(_totp_at(secret, counter), code):
            return counter
    return None


def totp_uri(secret: str, username: str) -> str:
    label = _quote(f"BeastPing Mail Console:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={_quote('BeastPing Mail Console')}&digits=6&period=30"


def totp_secret_of(conn: sqlite3.Connection, admin_id: int) -> str | None:
    row = conn.execute("SELECT totp_secret FROM admins WHERE id = ?", (admin_id,)).fetchone()
    return row[0] if row else None


def totp_check(conn: sqlite3.Connection, admin_id: int, code: str) -> bool:
    """Verify a code for an admin and consume its time step (no replay, even under concurrency)."""
    row = conn.execute("SELECT totp_secret, totp_last_counter FROM admins WHERE id = ?", (admin_id,)).fetchone()
    if row is None or not row[0]:
        return False
    counter = totp_match(row[0], code, after_counter=row[1])
    if counter is None:
        return False
    with tx(conn):
        cur = conn.execute("UPDATE admins SET totp_last_counter = ? WHERE id = ?"
                           " AND (totp_last_counter IS NULL OR totp_last_counter < ?)", (counter, admin_id, counter))
    return cur.rowcount == 1


TOTP_MAX_FAILURES = 10          # per administrator per WINDOW_US, regardless of client address


def _totp_key(admin_id: int) -> str:
    return _username_key(f"totp-failure:{admin_id}")


def totp_allowed(conn: sqlite3.Connection, admin_id: int) -> bool:
    count = conn.execute("SELECT count(*) FROM login_attempts WHERE username_hash = ? AND success = 0 AND ts >= ?",
                         (_totp_key(admin_id), now_us() - WINDOW_US)).fetchone()[0]
    return count < TOTP_MAX_FAILURES


def record_totp_failure(conn: sqlite3.Connection, admin_id: int, client_ip: str) -> None:
    """Counted per administrator; a later correct password does not clear it."""
    with tx(conn):
        conn.execute("INSERT INTO login_attempts(ts, client_ip, username_hash, success) VALUES (?, ?, ?, 0)",
                     (now_us(), f"totp:{client_ip}", _totp_key(admin_id)))


def discard_attempt(conn: sqlite3.Connection, attempt_id: int) -> None:
    """The password was right but a second factor is still required: neither a failure nor a success."""
    with tx(conn):
        conn.execute("DELETE FROM login_attempts WHERE id = ?", (attempt_id,))


TOTP_SETUP_SECONDS = 600


def totp_begin_setup(conn: sqlite3.Connection, admin_id: int) -> str:
    """Create a pending secret on the server; only it can be confirmed."""
    from .db import set_setting
    secret = totp_new_secret()
    with tx(conn):
        set_setting(conn, f"totp_pending:{admin_id}", f"{secret}:{now_us() + TOTP_SETUP_SECONDS * 1_000_000}")
    return secret


def totp_confirm_setup(conn: sqlite3.Connection, admin_id: int, code: str) -> bool:
    from .db import get_setting
    value = get_setting(conn, f"totp_pending:{admin_id}")
    if not value:
        return False
    secret, _, expires = value.partition(":")
    if not expires.isdigit() or int(expires) < now_us():
        return False
    if not totp_enable(conn, admin_id, secret, code):
        return False
    with tx(conn):
        conn.execute("DELETE FROM settings WHERE key = ?", (f"totp_pending:{admin_id}",))
    return True


def totp_enable(conn: sqlite3.Connection, admin_id: int, secret: str, code: str) -> bool:
    counter = totp_match(secret, code)
    if counter is None:
        return False
    with tx(conn):
        conn.execute("UPDATE admins SET totp_secret = ?, totp_last_counter = ? WHERE id = ?",
                     (secret, counter, admin_id))
    return True


def totp_disable(conn: sqlite3.Connection, admin_id: int) -> None:
    with tx(conn):
        conn.execute("UPDATE admins SET totp_secret = NULL, totp_last_counter = NULL WHERE id = ?", (admin_id,))


def create_pending_login(conn: sqlite3.Connection, admin_id: int, client_ip: str | None) -> str:
    token = secrets.token_urlsafe(32)
    ts = now_us()
    with tx(conn):
        conn.execute("DELETE FROM pending_logins WHERE expires_ts < ?", (ts,))
        conn.execute("INSERT INTO pending_logins(token_hash, admin_id, created_ts, expires_ts, client_ip)"
                     " VALUES (?, ?, ?, ?, ?)",
                     (_token_hash(token), admin_id, ts, ts + PENDING_LOGIN_SECONDS * 1_000_000, client_ip))
    return token


def take_pending_login(conn: sqlite3.Connection, token: str | None) -> tuple[bytes, int] | None:
    """Return (token hash, admin id) for a live pending login and count the attempt."""
    if not token or len(token) > 128:
        return None
    th = _token_hash(token)
    row = conn.execute("SELECT admin_id, expires_ts, attempts FROM pending_logins WHERE token_hash = ?",
                       (th,)).fetchone()
    if row is None or row["expires_ts"] < now_us() or row["attempts"] >= PENDING_LOGIN_ATTEMPTS:
        return None
    with tx(conn):
        conn.execute("UPDATE pending_logins SET attempts = attempts + 1 WHERE token_hash = ?", (th,))
    return th, row["admin_id"]


def finish_pending_login(conn: sqlite3.Connection, token_hash: bytes) -> None:
    with tx(conn):
        conn.execute("DELETE FROM pending_logins WHERE token_hash = ?", (token_hash,))
