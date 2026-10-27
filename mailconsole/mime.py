"""Streaming MIME structure scanner.

Walks a stored RFC 5322 message once, line by line, and records every MIME
entity with the byte range of its (still encoded) body. Nothing is decoded
or kept in memory beyond one header block and one line at a time, so very
large messages are handled in bounded memory. Bodies are decoded later, on
demand, by streaming the recorded byte range through :func:`decode_stream`.

The archived file itself is never modified.
"""

from __future__ import annotations

import binascii
import contextlib
import email.policy
import email.utils
from dataclasses import dataclass, field
from email.parser import BytesHeaderParser
from typing import BinaryIO, Iterator

MAX_LINE = 64 * 1024            # read granularity for pathological long lines
MAX_HEADER_BYTES = 512 * 1024   # header blocks larger than this are truncated for parsing
MAX_PARTS = 2000
MAX_DEPTH = 32
_header_parser = BytesHeaderParser(policy=email.policy.default)


@dataclass
class Part:
    index: int
    parent: int | None
    depth: int
    content_type: str
    charset: str | None
    transfer_encoding: str
    disposition: str | None
    filename: str | None
    content_id: str | None
    header_start: int
    body_start: int
    body_end: int
    is_multipart: bool = False
    role: str = "other"          # body-text | body-html | inline | attachment | container | other

    @property
    def encoded_size(self) -> int:
        return max(0, self.body_end - self.body_start)


@dataclass
class Scan:
    parts: list[Part] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    header_bytes: bytes = b""
    truncated: bool = False      # structure limits reached; the raw file is still complete

    def first(self, role: str) -> Part | None:
        return next((p for p in self.parts if p.role == role), None)


class _Lines:
    """Line reader that tracks byte offsets and supports one push-back."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.pos = 0
        self.pushed: tuple[int, bytes, bool] | None = None
        self.at_line_start = True

    def next(self) -> tuple[int, bytes, bool] | None:
        """Return (offset, chunk, starts_line) or None at EOF."""
        if self.pushed is not None:
            item, self.pushed = self.pushed, None
            return item
        chunk = self.fh.readline(MAX_LINE)
        if not chunk:
            return None
        item = (self.pos, chunk, self.at_line_start)
        self.pos += len(chunk)
        self.at_line_start = chunk.endswith(b"\n")
        return item

    def push(self, item: tuple[int, bytes, bool]) -> None:
        self.pushed = item


def _eol_len(chunk: bytes) -> int:
    if chunk.endswith(b"\r\n"):
        return 2
    if chunk.endswith(b"\n"):
        return 1
    return 0


def _boundary_kind(chunk: bytes, starts_line: bool, boundaries: list[bytes]) -> tuple[int, bool] | None:
    """If ``chunk`` is a boundary line of one of ``boundaries``, return (depth index, is_close)."""
    if not starts_line or not chunk.startswith(b"--"):
        return None
    text = chunk.rstrip(b"\r\n").rstrip(b" \t")
    for i in range(len(boundaries) - 1, -1, -1):
        b = boundaries[i]
        if text == b"--" + b:
            return i, False
        if text == b"--" + b + b"--":
            return i, True
    return None


def _param(msg, name: str) -> str | None:
    try:
        value = msg.get_param(name)
    except Exception:  # noqa: BLE001 - malformed headers must not stop the scan
        return None
    if isinstance(value, tuple):
        value = email.utils.collapse_rfc2231_value(value)
    return str(value) if value is not None else None


def _header_str(msg, name: str) -> str | None:
    try:
        value = msg.get(name)
    except Exception:  # noqa: BLE001
        return None
    return str(value).strip() if value is not None else None


def scan(fh: BinaryIO) -> Scan:
    """Scan a message from a binary file object positioned at its start."""
    result = Scan()
    lines = _Lines(fh)

    def read_headers() -> tuple[int, bytes]:
        start = lines.pos if lines.pushed is None else lines.pushed[0]
        buf = bytearray()
        while True:
            item = lines.next()
            if item is None:
                break
            _, chunk, _ = item
            if chunk in (b"\n", b"\r\n"):
                break
            if len(buf) < MAX_HEADER_BYTES:
                buf += chunk
        return start, bytes(buf)

    def entity(parent: int | None, depth: int, boundaries: list[bytes]) -> None:
        if len(result.parts) >= MAX_PARTS or depth > MAX_DEPTH:
            result.truncated = True
            skip_to_boundary(boundaries)
            return
        header_start, raw = read_headers()
        msg = _header_parser.parsebytes(raw)
        if parent is None:
            result.header_bytes = raw
            for name in ("Subject", "From", "To", "Cc", "Bcc", "Reply-To", "Date", "Message-ID", "Sender"):
                value = _header_str(msg, name)
                if value is not None:
                    result.headers[name] = value
        ctype = (msg.get_content_type() or "text/plain").lower()
        disposition = filename = None
        with contextlib.suppress(Exception):
            disposition = msg.get_content_disposition()
        with contextlib.suppress(Exception):
            filename = msg.get_filename()
        cid = _header_str(msg, "Content-ID")
        if cid:
            cid = cid.strip("<> ")
        part = Part(
            index=len(result.parts), parent=parent, depth=depth, content_type=ctype,
            charset=_param(msg, "charset"),
            transfer_encoding=(_header_str(msg, "Content-Transfer-Encoding") or "7bit").lower(),
            disposition=disposition, filename=filename, content_id=cid,
            header_start=header_start, body_start=lines.pos if lines.pushed is None else lines.pushed[0],
            body_end=0,
        )
        result.parts.append(part)
        boundary = _param(msg, "boundary") if ctype.startswith("multipart/") else None
        if boundary:
            part.is_multipart = True
            b = boundary.encode("utf-8", "replace")
            inner = boundaries + [b]
            # Preamble: up to the first boundary of this multipart.
            while True:
                item = lines.next()
                if item is None:
                    part.body_end = lines.pos
                    return
                hit = _boundary_kind(item[1], item[2], inner)
                if hit is None:
                    continue
                level, is_close = hit
                if level < len(inner) - 1:   # an ancestor's boundary: malformed, stop here
                    lines.push(item)
                    part.body_end = item[0]
                    return
                if is_close:
                    break
                while True:
                    entity(part.index, depth + 1, inner)
                    item = lines.next()
                    if item is None:
                        part.body_end = lines.pos
                        return
                    hit = _boundary_kind(item[1], item[2], inner)
                    if hit is None:      # should not happen: child stopped on a boundary
                        continue
                    level, is_close = hit
                    if level < len(inner) - 1:
                        lines.push(item)
                        part.body_end = item[0]
                        return
                    if is_close:
                        break
                break
            # Epilogue: until a parent boundary or EOF.
            while True:
                item = lines.next()
                if item is None:
                    part.body_end = lines.pos
                    return
                if _boundary_kind(item[1], item[2], boundaries) is not None:
                    lines.push(item)
                    part.body_end = item[0]
                    return
        # Leaf: body runs until the next boundary of any enclosing multipart.
        prev_eol = 0
        while True:
            item = lines.next()
            if item is None:
                part.body_end = lines.pos
                return
            if _boundary_kind(item[1], item[2], boundaries) is not None:
                lines.push(item)
                # The line break before a boundary belongs to the boundary.
                part.body_end = max(part.body_start, item[0] - prev_eol)
                return
            prev_eol = _eol_len(item[1])

    def skip_to_boundary(boundaries: list[bytes]) -> None:
        while True:
            item = lines.next()
            if item is None:
                return
            if _boundary_kind(item[1], item[2], boundaries) is not None:
                lines.push(item)
                return

    entity(None, 0, [])
    _assign_roles(result)
    return result


def _assign_roles(result: Scan) -> None:
    parts = result.parts
    by_index = {p.index: p for p in parts}

    def ancestors(p: Part):
        while p.parent is not None:
            p = by_index[p.parent]
            yield p

    text_done = html_done = False
    for p in parts:
        if p.is_multipart:
            p.role = "container"
            continue
        is_attachment = p.disposition == "attachment"
        in_related = any(a.content_type == "multipart/related" for a in ancestors(p))
        if not is_attachment and p.content_type == "text/plain" and not text_done and not p.filename:
            p.role, text_done = "body-text", True
        elif not is_attachment and p.content_type == "text/html" and not html_done and not p.filename:
            p.role, html_done = "body-html", True
        elif not is_attachment and p.content_id and (in_related or p.disposition == "inline"):
            p.role = "inline"
        else:
            p.role = "attachment"


# --- decoding ----------------------------------------------------------------

def iter_range(fh: BinaryIO, start: int, end: int, chunk: int = 64 * 1024) -> Iterator[bytes]:
    fh.seek(start)
    remaining = end - start
    while remaining > 0:
        data = fh.read(min(chunk, remaining))
        if not data:
            return
        remaining -= len(data)
        yield data


def decode_stream(chunks: Iterator[bytes], encoding: str) -> Iterator[bytes]:
    """Decode a Content-Transfer-Encoding incrementally."""
    encoding = (encoding or "7bit").lower()
    if encoding == "base64":
        pending = b""
        for data in chunks:
            pending += data.translate(None, b" \t\r\n")
            cut = len(pending) - len(pending) % 4
            if cut:
                try:
                    yield binascii.a2b_base64(pending[:cut])
                except binascii.Error:
                    yield b""
                pending = pending[cut:]
        if pending:
            try:
                yield binascii.a2b_base64(pending + b"=" * (-len(pending) % 4))
            except binascii.Error:
                pass
    elif encoding == "quoted-printable":
        pending = b""
        for data in chunks:
            pending += data
            lines = pending.split(b"\n")
            pending = lines.pop()
            for line in lines:
                yield binascii.a2b_qp(line + b"\n")
        if pending:
            yield binascii.a2b_qp(pending)
    else:
        yield from chunks


def read_part(fh: BinaryIO, part: Part, limit: int | None = None) -> bytes:
    out = bytearray()
    for data in decode_stream(iter_range(fh, part.body_start, part.body_end), part.transfer_encoding):
        out += data
        if limit is not None and len(out) >= limit:
            return bytes(out[:limit])
    return bytes(out)


def decode_text(data: bytes, charset: str | None) -> str:
    for candidate in (charset, "utf-8"):
        if not candidate:
            continue
        try:
            return data.decode(candidate, errors="replace")
        except LookupError:
            continue
    return data.decode("latin-1", errors="replace")
