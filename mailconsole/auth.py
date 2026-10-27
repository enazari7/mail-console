"""Administrator accounts, server-side sessions, CSRF tokens and login throttling."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
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


class AuthError(ValueError):
    pass


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
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Constant-work verification; a missing account still costs one hash."""
    if len(password) > MAX_PASSWORD_LENGTH:
        password = password[:MAX_PASSWORD_LENGTH]
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
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
    since = now_us() - WINDOW_US
    row = conn.execute(
        "SELECT"
        " sum(CASE WHEN client_ip = ? THEN 1 ELSE 0 END),"
        " sum(CASE WHEN username_hash = ? THEN 1 ELSE 0 END),"
        " count(*)"
        " FROM login_attempts WHERE ts >= ? AND success = 0",
        (client_ip, _username_key(username), since),
    ).fetchone()
    by_ip, by_user, overall = (v or 0 for v in row)
    return by_ip < MAX_FAILURES_PER_IP and by_user < MAX_FAILURES_PER_USER and overall < MAX_FAILURES_GLOBAL


def record_attempt(conn: sqlite3.Connection, client_ip: str, username: str, success: bool) -> None:
    with tx(conn):
        conn.execute("INSERT INTO login_attempts(ts, client_ip, username_hash, success) VALUES (?, ?, ?, ?)",
                     (now_us(), client_ip, _username_key(username), int(success)))
        if success:
            # A successful login clears this address's failure history.
            conn.execute("DELETE FROM login_attempts WHERE client_ip = ? AND success = 0", (client_ip,))


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
