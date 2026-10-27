"""Parse syslog lines and Postfix log messages into structured events.

Only facts present in the log line are extracted. Nothing is inferred here;
correlation into messages happens in :mod:`mailconsole.correlate`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

# --- syslog envelope -------------------------------------------------------

# Ubuntu 24.04 rsyslog default (RSYSLOG_FileFormat):
#   2026-10-27T10:46:29.123456+00:00 mail postfix/smtp[1234]: message
ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
# Traditional BSD syslog (RSYSLOG_TraditionalFileFormat):
#   Oct 27 10:46:29 mail postfix/smtp[1234]: message
BSD_LINE = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


@dataclass(frozen=True)
class LogRecord:
    ts: int            # microseconds since epoch, UTC
    host: str
    program: str
    pid: int | None
    message: str
    raw: str

    @property
    def line_hash(self) -> bytes:
        key = f"{self.ts}\x1f{self.host}\x1f{self.program}\x1f{self.pid}\x1f{self.message}"
        return hashlib.sha256(key.encode("utf-8", "surrogateescape")).digest()[:16]


def _to_us(dt: datetime) -> int:
    return int(dt.timestamp()) * 1_000_000 + dt.microsecond


def parse_iso_timestamp(text: str, default_tz: ZoneInfo | timezone) -> int:
    text = text.replace(" ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Normalise fractional seconds to 6 digits (datetime accepts at most 6).
    match = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(.*)$", text)
    if match:
        frac = (match.group(2) or "")[:6].ljust(6, "0") if match.group(2) else ""
        offset = match.group(3)
        if offset and re.fullmatch(r"[+-]\d{4}", offset):
            offset = offset[:3] + ":" + offset[3:]
        text = match.group(1) + (("." + frac) if frac else "") + offset
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    return _to_us(dt)


def parse_syslog_line(
    line: str,
    *,
    bsd_tz: ZoneInfo | timezone = timezone.utc,
    reference: datetime | None = None,
) -> LogRecord | None:
    """Parse one syslog line. Returns None for lines in an unknown format.

    ``reference`` is used to infer the missing year of BSD-format lines: the
    line is assumed to be no more than one day in the future of it.
    """
    line = line.rstrip("\r\n")
    m = ISO_LINE.match(line)
    if m:
        try:
            ts = parse_iso_timestamp(m.group("ts"), bsd_tz)
        except ValueError:
            return None
    else:
        m = BSD_LINE.match(line)
        if not m:
            return None
        ref = (reference or datetime.now(timezone.utc)).astimezone(bsd_tz)
        hh, mm, ss = (int(x) for x in m.group("time").split(":"))
        try:
            dt = datetime(ref.year, MONTHS[m.group("mon")], int(m.group("day")), hh, mm, ss, tzinfo=bsd_tz)
            if dt > ref + timedelta(days=1):
                dt = dt.replace(year=ref.year - 1)
        except ValueError:
            return None
        ts = _to_us(dt)
    pid = m.group("pid")
    return LogRecord(
        ts=ts,
        host=m.group("host"),
        program=m.group("prog"),
        pid=int(pid) if pid else None,
        message=m.group("msg"),
        raw=line,
    )


# --- redaction -------------------------------------------------------------

_REDACTIONS = [
    (re.compile(r"(given password: ).*?(\)|$)", re.I), r"\1[redacted]\2"),
    (re.compile(r"\b(pass(?:word|wd)?|secret|token|api[_-]?key)(\s*[=:]\s*)(\"[^\"]*\"|\S+)", re.I),
     r"\1\2[redacted]"),
    (re.compile(r"\b(AUTH\s+(?:PLAIN|LOGIN|XOAUTH2|CRAM-MD5))\s+\S+", re.I), r"\1 [redacted]"),
    (re.compile(r"(Authorization:\s*)\S+(\s+\S+)?", re.I), r"\1[redacted]"),
]


def redact(text: str) -> str:
    """Remove credential-like material before anything is stored."""
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


# --- Postfix messages ------------------------------------------------------

# Short IDs are upper-case hex; long IDs (enable_long_queue_ids) use a
# vowel-free base-52 alphabet, so words such as "warning" never match.
QUEUE_ID = r"(?:[0-9A-F]{6,14}|[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]{10,20})"
QID_PREFIX = re.compile(rf"^(?P<qid>{QUEUE_ID}): (?P<rest>.*)$")
DSN_RE = re.compile(r"(?<![\d.])([245]\.\d{1,3}\.\d{1,3})(?![\d.])")
KV_RE = re.compile(r"(\w[\w-]*)=([^,]*?)(?:, |,$|$)")
DELIVERY_RE = re.compile(
    r"^to=<(?P<to>[^>]*)>,(?: orig_to=<(?P<orig>[^>]*)>,)?(?P<kv>.*?)\bstatus=(?P<status>[\w-]+)"
    r"(?: \((?P<resp>.*)\))?\s*$"
)
QUEUED_RE = re.compile(r"^from=<(?P<from>[^>]*)>, size=(?P<size>\d+), nrcpt=(?P<nrcpt>\d+) \(queue active\)")
EXPIRED_RE = re.compile(r"^from=<(?P<from>[^>]*)>, status=expired(?:, (?P<detail>.*))?$")
NOTICE_RE = re.compile(
    r"^(?P<what>sender non-delivery notification|sender delivery status notification|"
    r"postmaster non-delivery notification|sender delay notification): (?P<child>\S+)$"
)
ENVELOPE_RE = re.compile(r"; from=<(?P<from>[^>]*)>(?: to=<(?P<to>[^>]*)>)?(?: proto=\S+)?(?: helo=<[^>]*>)?")
REJECT_RE = re.compile(
    r"^(?P<action>milter-reject|reject|milter-discard|discard|milter-hold|hold|milter-redirect|redirect): (?P<body>.*)$"
)
HEADER_RE = re.compile(r"^(?:info|warning): header (?P<name>[\w-]+): (?P<value>.*?) from \S+;")
LEVEL_RE = re.compile(r"^(warning|error|fatal|panic):\s", re.I)
OPS_LEVEL_RE = re.compile(
    r"\b(error|fatal|panic|warning|failed|failure|denied|unable|timeout|timed out|mismatch|unknown user)\b", re.I)
AUTH_WORDS = {"mismatch", "unknown user"}


@dataclass
class PostfixEvent:
    kind: str
    queue_id: str | None
    daemon: str
    recipient: str | None = None
    orig_recipient: str | None = None
    status: str | None = None
    dsn: str | None = None
    relay: str | None = None
    delay: float | None = None
    delays: str | None = None
    response: str | None = None
    detail: dict = field(default_factory=dict)


@dataclass
class OpsEvent:
    level: str
    message: str


def _strip_brackets(value: str) -> str:
    value = value.strip()
    if value.startswith("<") and value.endswith(">"):
        return value[1:-1]
    return value


def _dsn_from(text: str | None) -> str | None:
    if not text:
        return None
    m = DSN_RE.search(text)
    return m.group(1) if m else None


def _float_or_none(value: str | None) -> float | None:
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


def _parse_reject(qid: str | None, daemon: str, action: str, body: str) -> PostfixEvent:
    env = ENVELOPE_RE.search(body)
    sender = recipient = None
    response = body
    if env:
        sender, recipient = env.group("from"), env.group("to")
        before, after = body[: env.start()], body[env.end():]
        if after.startswith(":"):
            # header_checks style: "...; from=<> to=<> proto=ESMTP helo=<>: 5.7.1 text"
            response = after[1:].strip()
        else:
            # "...from host[ip]: 554 5.7.1 text; from=<>..." -> text after "]: "
            m = re.search(r"\]: (.*)$", before)
            response = m.group(1) if m else before
    kind = {"milter-reject": "reject", "reject": "reject", "milter-discard": "discard", "discard": "discard",
            "milter-hold": "hold", "hold": "hold"}.get(action, "redirect")
    stage = None
    m = re.match(r"^(\S+(?: \S+)?) from ", body)
    if m:
        stage = m.group(1)
    return PostfixEvent(
        kind=kind,
        queue_id=qid,
        daemon=daemon,
        recipient=recipient,
        status="rejected" if kind == "reject" else kind,
        dsn=_dsn_from(response),
        response=response.strip()[:2000],
        detail={"action": action, "stage": stage, "from": sender, "milter": action.startswith("milter-")},
    )


def parse_postfix_message(daemon: str, message: str) -> PostfixEvent | OpsEvent | None:
    """Interpret the message part of a Postfix log line.

    ``daemon`` is the last path component of the syslog program name
    (``postfix/submission/smtpd`` -> ``smtpd``).
    """
    if message.startswith("NOQUEUE: "):
        rest = message[len("NOQUEUE: "):]
        m = REJECT_RE.match(rest)
        if m:
            event = _parse_reject(None, daemon, m.group("action"), m.group("body"))
            event.kind = "noqueue_" + event.kind
            return event
        return None

    m = QID_PREFIX.match(message)
    if not m:
        lm = LEVEL_RE.match(message)
        if lm:
            return OpsEvent(level=lm.group(1).lower(), message=message[lm.end():])
        return None

    qid, rest = m.group("qid"), m.group("rest")

    if rest.startswith("to="):
        dm = DELIVERY_RE.match(rest)
        if dm:
            kv = dict(KV_RE.findall(dm.group("kv").strip().strip(",")))
            status = dm.group("status").lower()
            if status == "softbounce":
                status = "deferred"
            return PostfixEvent(
                kind="delivery",
                queue_id=qid,
                daemon=daemon,
                recipient=dm.group("to"),
                orig_recipient=dm.group("orig"),
                status=status,
                dsn=kv.get("dsn") or None,
                relay=kv.get("relay") or None,
                delay=_float_or_none(kv.get("delay")),
                delays=kv.get("delays") or None,
                response=(dm.group("resp") or "")[:2000] or None,
                detail={k: v for k, v in kv.items() if k in ("conn_use",)},
            )
    if rest.startswith("client="):
        kv = dict(KV_RE.findall(rest))
        return PostfixEvent(kind="connect", queue_id=qid, daemon=daemon,
                            detail={k: kv[k] for k in ("client", "sasl_method", "sasl_username", "orig_client") if k in kv})
    if daemon == "pickup" and rest.startswith("uid="):
        um = re.match(r"^uid=(?P<uid>\d+) from=<(?P<from>[^>]*)>(?: orig_id=(?P<orig>\S+))?", rest)
        if um:
            detail = {"uid": um.group("uid"), "from": um.group("from")}
            if um.group("orig"):
                detail["orig_id"] = um.group("orig")
            return PostfixEvent(kind="pickup", queue_id=qid, daemon=daemon, detail=detail)
    if rest.startswith(("message-id=", "resent-message-id=")):
        name, _, value = rest.partition("=")
        return PostfixEvent(kind="cleanup", queue_id=qid, daemon=daemon,
                            detail={name.replace("-", "_"): _strip_brackets(value)[:998]})
    qm = QUEUED_RE.match(rest)
    if qm:
        return PostfixEvent(kind="queued", queue_id=qid, daemon=daemon,
                            detail={"from": qm.group("from"), "size": int(qm.group("size")),
                                    "nrcpt": int(qm.group("nrcpt"))})
    em = EXPIRED_RE.match(rest)
    if em:
        return PostfixEvent(kind="expired", queue_id=qid, daemon=daemon, status="expired",
                            response=em.group("detail"), detail={"from": em.group("from")})
    if rest == "removed":
        return PostfixEvent(kind="removed", queue_id=qid, daemon=daemon)
    if rest == "requeued":
        return PostfixEvent(kind="requeued", queue_id=qid, daemon=daemon)
    if rest in ("placed on hold", "released from hold"):
        return PostfixEvent(kind="hold" if rest == "placed on hold" else "release", queue_id=qid, daemon=daemon)
    nm = NOTICE_RE.match(rest)
    if nm:
        return PostfixEvent(kind="notification", queue_id=qid, daemon=daemon,
                            detail={"type": nm.group("what"), "child": nm.group("child")})
    rm = REJECT_RE.match(rest)
    if rm:
        return _parse_reject(qid, daemon, rm.group("action"), rm.group("body"))
    hm = HEADER_RE.match(rest)
    if hm:
        return PostfixEvent(kind="header", queue_id=qid, daemon=daemon,
                            detail={"name": hm.group("name"), "value": hm.group("value")[:998]})
    lm = LEVEL_RE.match(rest)
    return PostfixEvent(kind="other", queue_id=qid, daemon=daemon,
                        detail={"text": rest[:2000], "level": lm.group(1).lower() if lm else None})


@dataclass
class Classified:
    record: LogRecord
    event: PostfixEvent | None = None
    ops: OpsEvent | None = None
    attach_only: bool = False   # milter/opendkim info: attach to an open message, never create


def classify(record: LogRecord, postfix_prefixes: list[str], ops_programs: list[str]) -> Classified | None:
    """Decide what, if anything, a syslog record means to the console."""
    program = record.program
    if any(program == p or program.startswith(p + "/") or program.startswith(p + "-") for p in postfix_prefixes):
        daemon = program.rsplit("/", 1)[-1]
        parsed = parse_postfix_message(daemon, record.message)
        if parsed is None:
            return None
        if isinstance(parsed, OpsEvent):
            return Classified(record, ops=parsed)
        return Classified(record, event=parsed)

    base = program.split("/", 1)[0].lower()
    if base not in {p.lower() for p in ops_programs}:
        return None
    m = QID_PREFIX.match(record.message)
    if m:
        lm = OPS_LEVEL_RE.search(m.group("rest"))
        event = PostfixEvent(kind="milter_info", queue_id=m.group("qid"), daemon=base,
                             detail={"text": m.group("rest")[:2000], "program": base,
                                     "level": lm.group(1).lower() if lm else None})
        return Classified(record, event=event, attach_only=True)
    lm = OPS_LEVEL_RE.search(record.message)
    if lm:
        word = lm.group(1).lower()
        if word in ("error", "fatal", "panic", "warning"):
            level = word
        elif word in AUTH_WORDS or "auth" in record.message.lower():
            level = "auth"
        else:
            level = "error"
        return Classified(record, ops=OpsEvent(level=level, message=record.message))
    return None
