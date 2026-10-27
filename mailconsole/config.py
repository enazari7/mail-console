"""Runtime configuration, read from environment variables (MC_*).

All values have safe defaults. The systemd units load them from
/etc/mail-console/mail-console.env (see .env.example).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class ConfigError(ValueError):
    pass


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name}: expected a boolean, got {raw!r}")


def _int(name: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name}: expected an integer, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ConfigError(f"{name}: must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{name}: must be <= {maximum}")
    return value


def _float(name: str, default: float, minimum: float = 0.0) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name}: expected a number, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name}: must be >= {minimum}")
    return value


def _list(name: str, default: str) -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _units(name: str, default: str) -> list[tuple[str, str]]:
    """Parse "Label=unit.service,Label2=unit2.service"."""
    units = []
    for item in _list(name, default):
        label, sep, unit = item.partition("=")
        if not sep:
            label, unit = item, item
        units.append((label.strip(), unit.strip()))
    return units


def _zone(name: str, default: str) -> ZoneInfo:
    raw = os.environ.get(name, default).strip() or default
    try:
        return ZoneInfo(raw)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConfigError(f"{name}: unknown time zone {raw!r}") from exc


DEFAULT_UNITS = (
    "Postfix=postfix@-.service,"
    "Mailguard=mailguard.service,"
    "OpenDKIM=opendkim.service,"
    "Dovecot=dovecot.service"
)


@dataclass(frozen=True)
class Config:
    data_dir: Path
    db_path: Path
    bind_host: str
    port: int
    log_source: str
    log_path: Path
    log_timezone: ZoneInfo
    postfix_prefixes: list[str]
    ops_programs: list[str]
    monitor_units: list[tuple[str, str]]
    postqueue_cmd: str
    systemctl_cmd: str
    journalctl_cmd: str
    journal_units: list[str]
    poll_interval: float
    monitor_interval: float
    batch_lines: int
    max_line_bytes: int
    max_events_per_message: int
    queue_reuse_gap_hours: int
    default_retention_days: int
    max_db_mb: int
    session_idle_minutes: int
    session_max_hours: int
    cookie_secure: bool
    trust_proxy: bool
    allowed_hosts: list[str] = field(default_factory=list)
    store_raw_lines: bool = True


def load_config() -> Config:
    data_dir = Path(os.environ.get("MC_DATA_DIR", "/var/lib/mail-console"))
    db_path = Path(os.environ.get("MC_DB_PATH", str(data_dir / "mail-console.sqlite3")))
    log_source = os.environ.get("MC_LOG_SOURCE", "file").strip().lower()
    if log_source not in ("file", "journald"):
        raise ConfigError("MC_LOG_SOURCE: expected 'file' or 'journald'")
    bind_host = os.environ.get("MC_BIND", "127.0.0.1").strip()
    allowed = _list("MC_ALLOWED_HOSTS", "")
    for local in ("127.0.0.1", "localhost", "[::1]", "::1"):
        if local not in allowed:
            allowed.append(local)
    return Config(
        data_dir=data_dir,
        db_path=db_path,
        bind_host=bind_host,
        port=_int("MC_PORT", 8710, 1, 65535),
        log_source=log_source,
        log_path=Path(os.environ.get("MC_LOG_PATH", "/var/log/syslog")),
        log_timezone=_zone("MC_LOG_TIMEZONE", "UTC"),
        postfix_prefixes=_list("MC_POSTFIX_PREFIXES", "postfix"),
        ops_programs=_list("MC_OPS_PROGRAMS", "opendkim,dovecot,mailguard"),
        monitor_units=_units("MC_MONITOR_UNITS", DEFAULT_UNITS),
        postqueue_cmd=os.environ.get("MC_POSTQUEUE", "/usr/sbin/postqueue"),
        systemctl_cmd=os.environ.get("MC_SYSTEMCTL", "/usr/bin/systemctl"),
        journalctl_cmd=os.environ.get("MC_JOURNALCTL", "/usr/bin/journalctl"),
        journal_units=_list(
            "MC_JOURNAL_UNITS",
            "postfix@-.service,opendkim.service,dovecot.service,mailguard.service",
        ),
        poll_interval=_float("MC_POLL_INTERVAL", 2.0, 0.1),
        monitor_interval=_float("MC_MONITOR_INTERVAL", 30.0, 5.0),
        batch_lines=_int("MC_BATCH_LINES", 2000, 10, 100_000),
        max_line_bytes=_int("MC_MAX_LINE_BYTES", 16_384, 512, 1_048_576),
        max_events_per_message=_int("MC_MAX_EVENTS_PER_MESSAGE", 2000, 50),
        queue_reuse_gap_hours=_int("MC_QUEUE_REUSE_GAP_HOURS", 144, 1),
        default_retention_days=_int("MC_RETENTION_DAYS", 90, 1, 3650),
        max_db_mb=_int("MC_MAX_DB_MB", 2048, 16),
        session_idle_minutes=_int("MC_SESSION_IDLE_MINUTES", 30, 1, 24 * 60),
        session_max_hours=_int("MC_SESSION_MAX_HOURS", 12, 1, 24 * 30),
        cookie_secure=_bool("MC_COOKIE_SECURE", True),
        trust_proxy=_bool("MC_TRUST_PROXY", False),
        allowed_hosts=allowed,
        store_raw_lines=_bool("MC_STORE_RAW_LINES", True),
    )
