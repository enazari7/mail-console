"""FastAPI application: server-rendered dashboard pages."""

from __future__ import annotations

import csv
import io
import ipaddress
from html import escape as html_escape
import secrets
import sqlite3
from datetime import datetime, timezone
from importlib import resources
from typing import Iterator
from urllib.parse import quote, urlencode, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, archive, audit, auth, charts, mime, queries
from .config import Config
from .db import connect, get_setting, now_us, pending_migrations, set_setting, tx
from .queries import STATUS_HELP, STATUS_LABELS, US

SESSION_COOKIE = "mc_session"
PENDING_COOKIE = "mc_pending_login"
LOGIN_CSRF_COOKIE = "mc_login_csrf"
PAGE_SIZES = (25, 50, 100)
THEMES = ("system", "dark", "light")
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'none'; frame-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
# Retained email HTML: opaque origin, no scripts, no plugins, nothing remote.
PREVIEW_CSP = ("sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src 'none'; "
               "form-action 'none'; frame-ancestors 'self'; base-uri 'none'")
EXPORT_MAX_ROWS = 50_000
EMAIL_RANGES = [("24h", "Last 24 hours"), ("7d", "Last 7 days"), ("15d", "Last 15 days"),
                ("30d", "Last 30 days"), ("90d", "Last 90 days")]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value) -> str:
    """Render a CSV cell, neutralising spreadsheet formulas (CSV injection)."""
    text = "" if value is None else str(value)
    text = text.replace("\x00", "")
    if text.startswith(_FORMULA_PREFIXES):
        text = "'" + text
    return text


def csv_lines(rows, display: "Display"):
    """Yield CSV text chunks (UTF-8 with BOM for spreadsheet compatibility)."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")

    def take() -> str:
        text = buf.getvalue()
        buf.seek(0)
        buf.truncate()
        return text

    writer.writerow(["sent_at_utc", f"sent_at_{display.tz_name}", "recipient", "status", "sender", "subject",
                     "destination_domain", "dsn", "smtp_response", "relay", "attempts", "queue_id", "message_id"])
    yield "\ufeff" + take()
    for r in rows:
        status = r["row_status"]
        writer.writerow([csv_cell(x) for x in (
            datetime.fromtimestamp(r["first_ts"] / US, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            display.ts(r["first_ts"]), r["address"], STATUS_LABELS.get(status, status), r["sender"],
            r["subject"], r["domain"], r["dsn"], r["response"] if r["address"] is not None else r["last_response"],
            r["relay"], r["attempts"], r["queue_id"], r["message_id"])])
        yield take()


class LoginRequired(Exception):
    def __init__(self, next_url: str):
        self.next_url = next_url


class Forbidden(Exception):
    pass


def _client_ip(request: Request, cfg: Config) -> str:
    peer = request.client.host if request.client else "unknown"
    if cfg.trust_proxy:
        try:
            loopback = ipaddress.ip_address(peer).is_loopback
        except ValueError:
            loopback = False
        forwarded = request.headers.get("x-forwarded-for")
        if loopback and forwarded:
            candidate = forwarded.split(",")[-1].strip()
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                pass
    return peer


def _host_allowed(host_header: str | None, allowed: list[str]) -> bool:
    if not host_header:
        return False
    host = host_header.strip().lower()
    if host.startswith("["):
        host = host.split("]")[0] + "]"
    else:
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return host in {h.lower() for h in allowed}


def _safe_next(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return "/"
    return value


class Display:
    """Per-installation display preferences (stored in the settings table)."""

    def __init__(self, conn: sqlite3.Connection):
        tz_name = get_setting(conn, "display_timezone", "UTC") or "UTC"
        try:
            self.tz = ZoneInfo(tz_name)
        except (ZoneInfoNotFoundError, ValueError):
            self.tz = ZoneInfo("UTC")
            tz_name = "UTC"
        self.tz_name = tz_name
        try:
            size = int(get_setting(conn, "page_size", "50") or 50)
        except ValueError:
            size = 50
        self.page_size = size if size in PAGE_SIZES else 50
        theme = get_setting(conn, "theme", "system")
        self.theme = theme if theme in THEMES else "system"

    def dt(self, us: int | None) -> datetime | None:
        return datetime.fromtimestamp(us / US, self.tz) if us else None

    def ts(self, us: int | None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
        dt = self.dt(us)
        return dt.strftime(fmt) if dt else "—"

    def range_label(self, rng) -> str:
        """Short label for a time range; custom ranges show their dates."""
        if rng.key != "custom":
            return rng.label
        start, end = self.dt(rng.start), self.dt(rng.end)
        midnight = all(d.hour == 0 and d.minute == 0 for d in (start, end))
        fmt = "%b %d" if midnight else "%b %d %H:%M"
        if start.year != end.year:
            fmt = "%b %d, %Y" if midnight else "%b %d, %Y %H:%M"
        return f"{start.strftime(fmt)} – {end.strftime(fmt)}"

    def iso(self, us: int | None) -> str:
        dt = self.dt(us)
        return dt.isoformat(timespec="seconds") if dt else ""

    def ts_ms(self, us: int | None) -> str:
        dt = self.dt(us)
        return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}" if dt else "—"

    def local_input(self, us: int | None) -> str:
        dt = self.dt(us)
        return dt.strftime("%Y-%m-%dT%H:%M") if dt else ""


def ago(us: int | None, now: int) -> str:
    if not us:
        return "never"
    seconds = max(0, (now - us) // US)
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    if seconds < 30 * 86400:
        return f"{seconds // 86400}d ago"
    return datetime.fromtimestamp(us / US, timezone.utc).strftime("%b %d, %Y")


def duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 120:
        return f"{seconds:.1f} s"
    if seconds < 7200:
        return f"{seconds / 60:.0f} min"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} h"
    return f"{seconds / 86400:.1f} d"


def human_bytes(n: int | None) -> str:
    if n is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def summarize_response(text: str | None, limit: int = 90) -> str:
    if not text:
        return ""
    text = " ".join(text.split())
    for prefix in ("host ",):
        if text.startswith(prefix) and " said: " in text:
            text = text.split(" said: ", 1)[1]
    return text if len(text) <= limit else text[: limit - 1] + "…"


def describe_event(e: dict) -> str:
    d = e["detail"]
    kind = e["kind"]
    if kind == "connect":
        text = f"Received over SMTP from {d.get('client', 'unknown client')}"
        if d.get("sasl_username"):
            text += f", authenticated as {d['sasl_username']} ({d.get('sasl_method', 'SASL')})"
        return text
    if kind == "pickup":
        return f"Submitted locally by uid {d.get('uid', '?')} from <{d.get('from', '')}>" + (
            f" (requeued from {d['orig_id']})" if d.get("orig_id") else "")
    if kind == "cleanup":
        if "message_id" in d:
            return f"Message-ID <{d['message_id']}>"
        return f"Resent-Message-ID <{d.get('resent_message_id', '')}>"
    if kind == "header":
        return f"Header {d.get('name')}: {d.get('value')}"
    if kind == "queued":
        return (f"Queue manager scheduled delivery: {d.get('nrcpt', '?')} recipient(s), "
                f"{d.get('size', '?')} bytes, sender <{d.get('from', '')}>")
    if kind == "delivery":
        verb = {"sent": "Accepted by next hop", "deferred": "Deferred (temporary failure)",
                "bounced": "Bounced (permanent failure)", "deliverable": "Address probe: deliverable",
                "undeliverable": "Address probe: undeliverable"}.get(e["status"], f"status={e['status']}")
        return f"{verb} for <{e['recipient']}>" + (f" via {e['relay']}" if e["relay"] else "")
    if kind == "archive_delivery":
        if e["status"] == "sent":
            return "Copy delivered to the Mail Console archive"
        return f"Archive copy {e['status']} (real recipients are not affected)"
    if kind == "expired":
        return "Maximum queue lifetime reached; message returned to sender"
    if kind == "notification":
        return f"Postfix generated a {d.get('type', 'notification')} (queue ID {d.get('child')})"
    if kind == "removed":
        return "Removed from the Postfix queue"
    if kind == "requeued":
        return "Requeued by postsuper (continues under a new queue ID)"
    if kind in ("hold", "noqueue_hold"):
        return "Placed on hold"
    if kind == "release":
        return "Released from hold"
    if kind in ("reject", "noqueue_reject"):
        who = "milter" if d.get("milter") else "Postfix"
        when = f" at {d['stage']}" if d.get("stage") else ""
        return f"Rejected by {who}{when}" + (" before queueing" if kind == "noqueue_reject" else "")
    if kind in ("discard", "noqueue_discard"):
        return "Discarded by policy"
    if kind == "milter_info":
        return f"{d.get('program', 'milter')}: {d.get('text', '')}"
    return d.get("text") or kind


def create_app(cfg: Config) -> FastAPI:
    app = FastAPI(title="BeastPing Mail Console", docs_url=None, redoc_url=None, openapi_url=None)
    template_dir = resources.files("mailconsole") / "templates"
    static_dir = resources.files("mailconsole") / "static"
    templates = Jinja2Templates(directory=str(template_dir))
    env = templates.env
    env.globals.update(STATUS_LABELS=STATUS_LABELS, STATUS_HELP=STATUS_HELP, version=__version__,
                       FILTER_STATUSES=queries.FILTER_STATUSES)
    env.filters.update(duration=duration, human_bytes=human_bytes, summarize=summarize_response,
                       describe=describe_event)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    timezones = sorted(available_timezones())

    def get_db() -> Iterator[sqlite3.Connection]:
        conn = connect(cfg.db_path)
        try:
            yield conn
        finally:
            conn.close()

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if not _host_allowed(request.headers.get("host"), cfg.allowed_hosts):
            return Response("Invalid Host header", status_code=400, media_type="text/plain")
        proto = request.headers.get("x-forwarded-proto", "").lower()
        if cfg.trust_proxy and "x-forwarded-for" in request.headers and proto != "https":
            # Requests relayed by the reverse proxy must have arrived over HTTPS.
            return Response("HTTPS required", status_code=400, media_type="text/plain")
        if request.method == "POST":
            origin = request.headers.get("origin")
            if origin and origin != "null" and not _host_allowed(urlsplit(origin).netloc, cfg.allowed_hosts):
                return Response("Cross-origin request refused", status_code=403, media_type="text/plain")
            if request.headers.get("sec-fetch-site") == "cross-site":
                return Response("Cross-site request refused", status_code=403, media_type="text/plain")
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers["Referrer-Policy"] = "same-origin"
        if cfg.trust_proxy and proto == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired):
        return RedirectResponse("/login?" + urlencode({"next": exc.next_url}), status_code=303)

    @app.exception_handler(Forbidden)
    async def _forbidden(request: Request, exc: Forbidden):
        return Response("Invalid or missing CSRF token. Reload the page and try again.", status_code=403,
                        media_type="text/plain")

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        return HTMLResponse(f"<!doctype html><title>{exc.status_code}</title>"
                            f'<link rel="stylesheet" href="/static/style.css">'
                            f'<main class="center"><h1>{exc.status_code}</h1><p>{html_escape(str(exc.detail))}</p>'
                            f'<p><a href="/">Back to overview</a></p></main>', status_code=exc.status_code)

    def session_dep(request: Request, conn: sqlite3.Connection = Depends(get_db)) -> auth.Session:
        session = auth.load_session(conn, request.cookies.get(SESSION_COOKIE),
                                    idle_minutes=cfg.session_idle_minutes, max_hours=cfg.session_max_hours)
        if session is None:
            target = request.url.path + (("?" + request.url.query) if request.url.query else "")
            raise LoginRequired(_safe_next(target))
        return session

    def render(request: Request, conn: sqlite3.Connection, name: str, session: auth.Session | None,
               status_code: int = 200, **ctx) -> HTMLResponse:
        display = Display(conn)
        now = now_us()
        ctx.update(request=request, session=session, display=display, now=now,
                   ago=lambda us: ago(us, now), schema_pending=pending_migrations(conn),
                   collector_alive=queries.collector_alive(conn, now))
        return templates.TemplateResponse(request, name, ctx, status_code=status_code)

    def check_csrf(session: auth.Session, token: str | None) -> None:
        if not auth.csrf_matches(session.csrf_token, token):
            raise Forbidden()

    def set_cookie(response: Response, name: str, value: str, max_age: int | None) -> None:
        response.set_cookie(name, value, max_age=max_age, httponly=True, secure=cfg.cookie_secure,
                            samesite="strict", path="/")

    # -- public ------------------------------------------------------------

    @app.get("/healthz")
    def healthz():
        return JSONResponse({"status": "ok"})

    @app.get("/favicon.ico")
    def favicon():
        return RedirectResponse("/static/favicon.svg", status_code=301)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, next: str = "/", conn: sqlite3.Connection = Depends(get_db)):
        token = secrets.token_urlsafe(32)
        response = render(request, conn, "login.html", None, next=_safe_next(next), csrf=token,
                          no_admin=auth.admin_count(conn) == 0, error=None)
        set_cookie(response, LOGIN_CSRF_COOKIE, token, 3600)
        return response

    @app.post("/login", response_class=HTMLResponse)
    def login(request: Request, username: str = Form(""), password: str = Form(""), csrf_token: str = Form(""),
              next: str = Form("/"), conn: sqlite3.Connection = Depends(get_db)):
        new_csrf = secrets.token_urlsafe(32)

        def fail(message: str, code: int) -> HTMLResponse:
            response = render(request, conn, "login.html", None, status_code=code, next=_safe_next(next),
                              csrf=new_csrf, no_admin=auth.admin_count(conn) == 0, error=message)
            set_cookie(response, LOGIN_CSRF_COOKIE, new_csrf, 3600)
            return response

        if not auth.csrf_matches(request.cookies.get(LOGIN_CSRF_COOKIE), csrf_token):
            return fail("Your login form expired. Please try again.", 403)
        ip = _client_ip(request, cfg)
        if not auth.login_allowed(conn, ip, username):
            return fail("Too many failed attempts. Wait 15 minutes and try again.", 429)
        attempt = auth.begin_attempt(conn, ip, username)
        try:
            admin_id = auth.authenticate(conn, username, password)
        except auth.AuthBusy:
            return fail("The server is busy. Try again in a few seconds.", 429)
        if admin_id is None:
            auth.finish_attempt(conn, attempt, ip, False)
            audit.record(conn, admin_id=None, username=None, client_ip=ip, action="login_failed")
            return fail("Invalid username or password.", 401)
        if auth.totp_secret_of(conn, admin_id):
            # Correct password, second factor pending: neither clear failures nor
            # mark this address trusted until the code is verified.
            auth.discard_attempt(conn, attempt)
            if not auth.totp_allowed(conn, admin_id):
                return fail("Too many failed authentication codes. Wait 15 minutes and try again.", 429)
            pending = auth.create_pending_login(conn, admin_id, ip)
            response = render(request, conn, "login_totp.html", None, next=_safe_next(next), csrf=new_csrf, error=None)
            set_cookie(response, LOGIN_CSRF_COOKIE, new_csrf, 3600)
            set_cookie(response, PENDING_COOKIE, pending, auth.PENDING_LOGIN_SECONDS)
            return response
        auth.finish_attempt(conn, attempt, ip, True)
        return start_session(request, conn, admin_id, ip, next)

    def start_session(request: Request, conn: sqlite3.Connection, admin_id: int, ip: str, next_url: str) -> Response:
        token = auth.create_session(conn, admin_id, idle_minutes=cfg.session_idle_minutes,
                                    max_hours=cfg.session_max_hours, client_ip=ip,
                                    user_agent=request.headers.get("user-agent"))
        username = conn.execute("SELECT username FROM admins WHERE id = ?", (admin_id,)).fetchone()[0]
        audit.record(conn, admin_id=admin_id, username=username, client_ip=ip, action="login")
        response = RedirectResponse(_safe_next(next_url), status_code=303)
        set_cookie(response, SESSION_COOKIE, token, cfg.session_max_hours * 3600)
        response.delete_cookie(LOGIN_CSRF_COOKIE, path="/")
        response.delete_cookie(PENDING_COOKIE, path="/")
        return response

    @app.post("/login/totp", response_class=HTMLResponse)
    def login_totp(request: Request, code: str = Form(""), csrf_token: str = Form(""), next: str = Form("/"),
                   conn: sqlite3.Connection = Depends(get_db)):
        new_csrf = secrets.token_urlsafe(32)
        ip = _client_ip(request, cfg)

        def again(message: str, code_: int) -> HTMLResponse:
            response = render(request, conn, "login_totp.html", None, status_code=code_, next=_safe_next(next),
                              csrf=new_csrf, error=message)
            set_cookie(response, LOGIN_CSRF_COOKIE, new_csrf, 3600)
            return response

        if not auth.csrf_matches(request.cookies.get(LOGIN_CSRF_COOKIE), csrf_token):
            return again("Your login form expired. Sign in again.", 403)
        pending = auth.take_pending_login(conn, request.cookies.get(PENDING_COOKIE))
        if pending is None:
            response = RedirectResponse("/login", status_code=303)
            response.delete_cookie(PENDING_COOKIE, path="/")
            return response
        token_hash, admin_id = pending
        username = conn.execute("SELECT username FROM admins WHERE id = ?", (admin_id,)).fetchone()[0]
        if not auth.totp_allowed(conn, admin_id) or not auth.login_allowed(conn, ip, username):
            auth.finish_pending_login(conn, token_hash)
            return again("Too many failed attempts. Wait 15 minutes and try again.", 429)
        if not auth.totp_check(conn, admin_id, code):
            auth.record_totp_failure(conn, admin_id, ip)
            auth.record_attempt(conn, ip, username, False)
            audit.record(conn, admin_id=admin_id, username=username, client_ip=ip, action="totp_failed")
            return again("Invalid authentication code.", 401)
        auth.finish_pending_login(conn, token_hash)
        auth.record_attempt(conn, ip, username, True)
        return start_session(request, conn, admin_id, ip, next)

    @app.post("/logout")
    def logout(request: Request, csrf_token: str = Form(""), session: auth.Session = Depends(session_dep),
               conn: sqlite3.Connection = Depends(get_db)):
        check_csrf(session, csrf_token)
        auth.delete_session(conn, session.token_hash)
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    # -- dashboard ---------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def overview_page(request: Request, range: str = "24h", start: str = "", end: str = "",
                      session: auth.Session = Depends(session_dep), conn: sqlite3.Connection = Depends(get_db)):
        display = Display(conn)
        rng = queries.resolve_range(range, start, end, display.tz, now_us())
        data = queries.overview(conn, rng, display.tz)
        fmt = "%H:%M" if rng.bucket < queries.DAY else "%b %d"
        tick_fmt = "%H:%M" if (rng.end - rng.start) <= queries.DAY else "%b %d" if rng.bucket >= 6 * queries.HOUR else "%d %H:%M"
        chart = charts.stacked_bars(data["buckets"], lambda us: display.ts(us, "%Y-%m-%d " + fmt),
                                    lambda us: display.ts(us, tick_fmt))
        range_params = {"range": rng.key}
        if rng.key == "custom":
            range_params.update(start=display.local_input(rng.start), end=display.local_input(rng.end))

        def emails_link(**params) -> str:
            return "/emails?" + urlencode({**params, **range_params})

        return render(request, conn, "overview.html", session, rng=rng, data=data, chart=chart, emails_link=emails_link,
                      domain_chart=charts.domain_bars(data["domains"]),
                      queue_chart=charts.sparkline(data["queue_history"], lambda us: display.ts(us, "%m-%d %H:%M")),
                      refresh=request.query_params.get("refresh") == "1")

    def email_filter(conn: sqlite3.Connection, display: "Display", params) -> tuple:
        """Parse the Emails query string into a filter and the canonical URL parameters."""
        get = lambda key: (params.get(key) or "").strip()  # noqa: E731
        rng = queries.resolve_range(get("range"), get("start"), get("end"), display.tz, now_us(), default="15d")
        status = get("status") if get("status") in queries.FILTER_STATUSES else ""
        sender_raw = params.get("sender")
        sender = None if sender_raw is None or sender_raw.strip() == "" else (
            "" if sender_raw.strip() == "<>" else sender_raw.strip()[:320])
        sort = get("sort") if get("sort") in queries.SORTS else "sent"
        direction = "asc" if get("dir") == "asc" else "desc"
        q = get("q").replace("\x00", "")[:320]
        if not queries.ActivityFilter(q=q).term:
            q = ""  # e.g. "<>" alone: nothing to search for
        flt = queries.ActivityFilter(q=q, status=status, domain=get("domain")[:255].lower(),
                                     sender=sender, start=rng.start, end=rng.end, sort=sort, direction=direction)
        canonical = {
            "q": flt.q, "status": status, "domain": flt.domain,
            "sender": ("<>" if sender == "" else sender) if sender is not None else "",
            "range": rng.key if rng.key != "15d" else "",
            "start": get("start") if rng.key == "custom" else "", "end": get("end") if rng.key == "custom" else "",
            "sort": sort if sort != "sent" else "", "dir": direction if direction != "desc" else "",
        }
        return flt, rng, {k: v for k, v in canonical.items() if v}

    @app.get("/emails", response_class=HTMLResponse)
    def emails_page(request: Request, page: int = 1, session: auth.Session = Depends(session_dep),
                    conn: sqlite3.Connection = Depends(get_db)):
        display = Display(conn)
        flt, rng, state = email_filter(conn, display, request.query_params)
        data = queries.activity(conn, flt, page, display.page_size)
        if flt.term and page <= 1:
            # Searches can match archived message bodies: record who searched for what.
            audit.record(conn, admin_id=session.admin_id, username=session.username,
                         client_ip=_client_ip(request, cfg), action="search", target=flt.term[:200],
                         detail=f"{data['total']}{'+' if data['capped'] else ''} rows")

        def url(_path: str = "/emails", **changes) -> str:
            merged = {**state, **{k: v for k, v in changes.items()}}
            merged = {k: v for k, v in merged.items() if v not in (None, "")}
            return _path + ("?" + urlencode(merged) if merged else "")

        def sort_url(column: str) -> str:
            if flt.sort == column:
                return url(sort=column if column != "sent" else "", dir="" if flt.direction == "asc" else "asc")
            return url(sort=column if column != "sent" else "", dir="asc" if column != "sent" else "")

        sender_options = queries.senders(conn, rng.start, rng.end)
        if flt.sender is not None and flt.sender not in {o["sender"] for o in sender_options}:
            sender_options.insert(0, {"sender": flt.sender, "n": None})
        return render(request, conn, "emails.html", session, data=data, flt=flt, rng=rng, state=state, url=url,
                      sort_url=sort_url, sender_options=sender_options, ranges=EMAIL_RANGES,
                      export_limit=EXPORT_MAX_ROWS, refresh=request.query_params.get("refresh") == "1")

    @app.get("/emails/export.csv")
    def export_csv(request: Request, session: auth.Session = Depends(session_dep),
                   conn: sqlite3.Connection = Depends(get_db)):
        display = Display(conn)
        flt, _, _ = email_filter(conn, display, request.query_params)
        truncated = queries.count_rows(conn, flt, EXPORT_MAX_ROWS + 1) > EXPORT_MAX_ROWS
        audit.record(conn, admin_id=session.admin_id, username=session.username, client_ip=_client_ip(request, cfg),
                     action="export_csv", target=flt.term[:200] or None,
                     detail=f"status={flt.status or 'any'} truncated={truncated}")
        stamp = datetime.now(display.tz).strftime("%Y%m%d-%H%M")
        suffix = f"-first-{EXPORT_MAX_ROWS}-rows" if truncated else ""
        headers = {"Content-Disposition": f'attachment; filename="mail-console-emails-{stamp}{suffix}.csv"',
                   "X-Export-Truncated": "true" if truncated else "false",
                   "X-Export-Max-Rows": str(EXPORT_MAX_ROWS)}

        def generate():
            # Own connection: the generator outlives the request dependency.
            export_conn = connect(cfg.db_path)
            try:
                yield from csv_lines(queries.export_rows(export_conn, flt, EXPORT_MAX_ROWS), display)
            finally:
                export_conn.close()

        return StreamingResponse(generate(), media_type="text/csv; charset=utf-8", headers=headers)

    def archive_store():
        if not cfg.archive_enabled:
            return None
        try:
            return archive.open_store(cfg)
        except (OSError, ValueError):
            return None

    def audit_access(request: Request, conn, session: auth.Session, action: str, target: str, detail: str = ""):
        audit.record(conn, admin_id=session.admin_id, username=session.username, client_ip=_client_ip(request, cfg),
                     action=action, target=target, detail=detail)

    @app.get("/emails/{message_id}", response_class=HTMLResponse)
    def email_detail(request: Request, message_id: int, session: auth.Session = Depends(session_dep),
                     conn: sqlite3.Connection = Depends(get_db)):
        detail = queries.message_detail(conn, message_id)
        if detail is None:
            raise StarletteHTTPException(404, "Message not found.")
        content = None
        if detail["archives"]:
            store = archive_store()
            if store is not None:
                content = archive.load_view(conn, store, detail["archives"][0]["id"])
            else:
                content = {"error": "The message archive is not available (MC_ARCHIVE_ENABLED or key file)."}
            audit_access(request, conn, session, "view_content", f"archive:{detail['archives'][0]['id']}",
                         f"message {message_id}")
        return render(request, conn, "email_detail.html", session, d=detail, content=content)

    @app.get("/archives/{archive_id}", response_class=HTMLResponse)
    def archive_detail(request: Request, archive_id: int, session: auth.Session = Depends(session_dep),
                       conn: sqlite3.Connection = Depends(get_db)):
        store = archive_store()
        a = archive.get_archive(conn, archive_id)
        if a is None:
            raise StarletteHTTPException(404, "Archived message not found.")
        if a["message_id"] is not None:
            return RedirectResponse(f"/emails/{a['message_id']}", status_code=303)
        content = archive.load_view(conn, store, archive_id) if store else {"error": "The message archive is not available."}
        audit_access(request, conn, session, "view_content", f"archive:{archive_id}", "unlinked archive")
        return render(request, conn, "archive_detail.html", session, a=a, content=content)

    def require_archive(conn, archive_id: int):
        store = archive_store()
        a = archive.get_archive(conn, archive_id)
        if store is None or a is None:
            raise StarletteHTTPException(404, "Archived message not found.")
        return store, a

    @app.get("/archives/{archive_id}/preview.html")
    def archive_preview(request: Request, archive_id: int, session: auth.Session = Depends(session_dep),
                        conn: sqlite3.Connection = Depends(get_db)):
        """HTML body for the sandboxed preview frame.

        Served with a sandbox CSP (opaque origin, no scripts, no forms, no
        plugins, no network loads except data: images), so it cannot act in
        the console's origin even if opened directly in a tab.
        """
        store, _ = require_archive(conn, archive_id)
        try:
            html = archive.html_for_preview(conn, store, archive_id)
        except (archive.IntegrityError, OSError) as exc:
            raise StarletteHTTPException(500, f"The stored copy could not be read: {exc}") from None
        if html is None:
            raise StarletteHTTPException(404, "This message has no HTML part.")
        audit_access(request, conn, session, "preview_html", f"archive:{archive_id}")
        return HTMLResponse(html, headers={
            "Content-Security-Policy": PREVIEW_CSP,
            "X-Frame-Options": "SAMEORIGIN",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Referrer-Policy": "no-referrer",
        })

    @app.get("/archives/{archive_id}/raw.eml")
    def archive_raw(request: Request, archive_id: int, session: auth.Session = Depends(session_dep),
                    conn: sqlite3.Connection = Depends(get_db)):
        store, a = require_archive(conn, archive_id)
        audit_access(request, conn, session, "download_eml", f"archive:{archive_id}", f"{a['size']} bytes")
        name = f"{a['queue_id']}-{a['sha256'][:12]}.eml"
        return StreamingResponse(archive.stream_raw(store, a), media_type="message/rfc822", headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Content-Length": str(a["size"]),
            "Content-Security-Policy": "sandbox; default-src 'none'",
        })

    @app.get("/archives/{archive_id}/parts/{part_index}")
    def archive_part(request: Request, archive_id: int, part_index: int, session: auth.Session = Depends(session_dep),
                     conn: sqlite3.Connection = Depends(get_db)):
        store, a = require_archive(conn, archive_id)
        part = next((p for p in archive.get_parts(conn, archive_id) if p.index == part_index), None)
        if part is None or part.role in ("container",):
            raise StarletteHTTPException(404, "Attachment not found.")
        filename = mime.clean_display(part.filename) or f"part-{part_index}.bin"
        ascii_name = "".join(ch if 32 < ord(ch) < 127 and ch not in '"\\;' else "_" for ch in filename)
        audit_access(request, conn, session, "download_attachment", f"archive:{archive_id}/part:{part_index}",
                     filename)
        # Always a download, never rendered in the console's origin (an HTML or
        # SVG attachment could otherwise run script here).
        return StreamingResponse(archive.stream_part(store, a, part), media_type="application/octet-stream",
                                 headers={
                                     "Content-Disposition": f"attachment; filename=\"{ascii_name}\"; "
                                                            f"filename*=UTF-8''{quote(filename)}",
                                     "Content-Security-Policy": "sandbox; default-src 'none'",
                                 })

    @app.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request, action: str = "", session: auth.Session = Depends(session_dep),
                   conn: sqlite3.Connection = Depends(get_db)):
        actions = [r[0] for r in conn.execute("SELECT DISTINCT action FROM audit_log ORDER BY action")]
        action = action if action in actions else ""
        return render(request, conn, "audit.html", session, entries=audit.recent(conn, 300, action),
                      actions=actions, action=action)

    @app.get("/queue/{queue_id}")
    def by_queue_id(queue_id: str, session: auth.Session = Depends(session_dep),
                    conn: sqlite3.Connection = Depends(get_db)):
        message_id = queries.resolve_queue_id(conn, queue_id[:32])
        if message_id is None:
            return RedirectResponse("/emails?" + urlencode({"q": queue_id[:32]}), status_code=303)
        return RedirectResponse(f"/emails/{message_id}", status_code=303)

    @app.get("/monitoring", response_class=HTMLResponse)
    def monitoring_page(request: Request, level: str = "", session: auth.Session = Depends(session_dep),
                        conn: sqlite3.Connection = Depends(get_db)):
        display = Display(conn)
        level = level if level in ("warning", "error", "fatal", "panic", "auth", "info") else ""
        data = queries.monitoring(conn, cfg.db_path, now_us(), level)
        data["archive"] = archive.status(conn, cfg)
        data["archive"]["blocked"] = conn.execute(
            "SELECT value FROM collector_state WHERE key = 'archive_blocked'").fetchone()
        data["unlinked_archives"] = [dict(r) for r in conn.execute(
            "SELECT id, queue_id, captured_ts, subject, link_method, link_note FROM archives"
            " WHERE message_id IS NULL ORDER BY captured_ts DESC LIMIT 20")]
        return render(request, conn, "monitoring.html", session, m=data, level=level,
                      queue_chart=charts.sparkline(data["queue_history"], lambda us: display.ts(us, "%m-%d %H:%M"),
                                                   width=760, height=80))

    # -- settings ----------------------------------------------------------

    def settings_ctx(conn: sqlite3.Connection, session: auth.Session) -> dict:
        admin = conn.execute("SELECT username, created_ts, password_changed_ts, last_login_ts FROM admins"
                             " WHERE id = ?", (session.admin_id,)).fetchone()
        sessions = conn.execute("SELECT token_hash, created_ts, last_seen_ts, expires_ts, client_ip, user_agent"
                                " FROM sessions WHERE admin_id = ? ORDER BY last_seen_ts DESC",
                                (session.admin_id,)).fetchall()
        from .collector import retention_days
        return {"admin": admin, "sessions": sessions, "timezones": timezones, "page_sizes": PAGE_SIZES,
                "themes": THEMES, "retention_days": retention_days(conn, cfg), "max_db_mb": cfg.max_db_mb,
                "idle_minutes": cfg.session_idle_minutes, "max_hours": cfg.session_max_hours,
                "archive_retention_days": archive.archive_retention_days(conn, cfg),
                "totp_enabled": bool(auth.totp_secret_of(conn, session.admin_id)), "totp_setup": None}

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request, saved: str = "", session: auth.Session = Depends(session_dep),
                      conn: sqlite3.Connection = Depends(get_db)):
        return render(request, conn, "settings.html", session, saved=saved, error=None,
                      **settings_ctx(conn, session))

    def settings_error(request, conn, session, message: str, code: int = 400) -> HTMLResponse:
        return render(request, conn, "settings.html", session, status_code=code, saved="", error=message,
                      **settings_ctx(conn, session))

    @app.post("/settings/password")
    def change_password(request: Request, current_password: str = Form(""), new_password: str = Form(""),
                        confirm_password: str = Form(""), csrf_token: str = Form(""),
                        session: auth.Session = Depends(session_dep), conn: sqlite3.Connection = Depends(get_db)):
        check_csrf(session, csrf_token)
        ip = _client_ip(request, cfg)
        if not auth.login_allowed(conn, ip, session.username):
            return settings_error(request, conn, session, "Too many failed attempts. Try again later.", 429)
        attempt = auth.begin_attempt(conn, ip, session.username)
        try:
            ok = auth.authenticate(conn, session.username, current_password) is not None
            auth.finish_attempt(conn, attempt, ip, ok)
            if not ok:
                return settings_error(request, conn, session, "Current password is incorrect.", 403)
            if new_password != confirm_password:
                return settings_error(request, conn, session, "The new passwords do not match.")
            if new_password == current_password:
                return settings_error(request, conn, session, "Choose a password different from the current one.")
            auth.set_password(conn, session.admin_id, new_password, keep_session=session.token_hash)
        except auth.AuthBusy:
            return settings_error(request, conn, session, "The server is busy. Try again in a few seconds.", 429)
        except auth.AuthError as exc:
            return settings_error(request, conn, session, str(exc).capitalize() + ".")
        return RedirectResponse("/settings?saved=password", status_code=303)

    @app.post("/settings/display")
    def save_display(timezone: str = Form("UTC"), page_size: int = Form(50), theme: str = Form("system"),
                     csrf_token: str = Form(""), session: auth.Session = Depends(session_dep),
                     conn: sqlite3.Connection = Depends(get_db)):
        check_csrf(session, csrf_token)
        if timezone not in timezones and timezone != "UTC":
            timezone = "UTC"
        with tx(conn):
            set_setting(conn, "display_timezone", timezone)
            set_setting(conn, "page_size", str(page_size if page_size in PAGE_SIZES else 50))
            set_setting(conn, "theme", theme if theme in THEMES else "system")
        return RedirectResponse("/settings?saved=display", status_code=303)

    @app.post("/settings/retention")
    def save_retention(request: Request, retention_days: int = Form(...), archive_retention_days: int | None = Form(None),
                       csrf_token: str = Form(""), session: auth.Session = Depends(session_dep),
                       conn: sqlite3.Connection = Depends(get_db)):
        check_csrf(session, csrf_token)
        if not 7 <= retention_days <= 3650:
            return settings_error(request, conn, session, "Retention must be between 7 and 3650 days.")
        if archive_retention_days is not None and not 1 <= archive_retention_days <= 3650:
            return settings_error(request, conn, session, "Archive retention must be between 1 and 3650 days.")
        with tx(conn):
            set_setting(conn, "retention_days", str(retention_days))
            if archive_retention_days is not None:
                set_setting(conn, "archive_retention_days", str(archive_retention_days))
        audit.record(conn, admin_id=session.admin_id, username=session.username, client_ip=_client_ip(request, cfg),
                     action="change_retention", detail=f"history {retention_days} d, archive {archive_retention_days} d")
        return RedirectResponse("/settings?saved=retention", status_code=303)

    def verify_password(request: Request, conn, session: auth.Session, password: str) -> HTMLResponse | None:
        ip = _client_ip(request, cfg)
        if not auth.login_allowed(conn, ip, session.username):
            return settings_error(request, conn, session, "Too many failed attempts. Try again later.", 429)
        try:
            ok = auth.authenticate(conn, session.username, password) is not None
        except auth.AuthBusy:
            return settings_error(request, conn, session, "The server is busy. Try again in a few seconds.", 429)
        if not ok:
            auth.record_attempt(conn, ip, session.username, False)
            return settings_error(request, conn, session, "Current password is incorrect.", 403)
        return None

    @app.post("/settings/totp/setup", response_class=HTMLResponse)
    def totp_setup(request: Request, password: str = Form(""), csrf_token: str = Form(""),
                   session: auth.Session = Depends(session_dep), conn: sqlite3.Connection = Depends(get_db)):
        check_csrf(session, csrf_token)
        failed = verify_password(request, conn, session, password)
        if failed:
            return failed
        secret = auth.totp_begin_setup(conn, session.admin_id)
        ctx = settings_ctx(conn, session)
        ctx["totp_setup"] = {"secret": secret, "uri": auth.totp_uri(secret, session.username)}
        return render(request, conn, "settings.html", session, saved="", error=None, **ctx)

    @app.post("/settings/totp/enable")
    def totp_enable(request: Request, code: str = Form(""), csrf_token: str = Form(""),
                    session: auth.Session = Depends(session_dep), conn: sqlite3.Connection = Depends(get_db)):
        check_csrf(session, csrf_token)
        # The secret comes from the server-side pending setup created after the
        # password check, never from the form.
        if not auth.totp_confirm_setup(conn, session.admin_id, code):
            return settings_error(request, conn, session, "The code did not match. Set up two-factor authentication again.")
        auth.delete_other_sessions(conn, session.admin_id, session.token_hash)
        audit.record(conn, admin_id=session.admin_id, username=session.username, client_ip=_client_ip(request, cfg),
                     action="totp_enabled")
        return RedirectResponse("/settings?saved=totp", status_code=303)

    @app.post("/settings/totp/disable")
    def totp_disable(request: Request, password: str = Form(""), code: str = Form(""), csrf_token: str = Form(""),
                     session: auth.Session = Depends(session_dep), conn: sqlite3.Connection = Depends(get_db)):
        check_csrf(session, csrf_token)
        failed = verify_password(request, conn, session, password)
        if failed:
            return failed
        if not auth.totp_check(conn, session.admin_id, code):
            return settings_error(request, conn, session, "Invalid authentication code.", 403)
        auth.totp_disable(conn, session.admin_id)
        audit.record(conn, admin_id=session.admin_id, username=session.username, client_ip=_client_ip(request, cfg),
                     action="totp_disabled")
        return RedirectResponse("/settings?saved=totp-off", status_code=303)

    @app.post("/settings/sessions/revoke")
    def revoke_sessions(csrf_token: str = Form(""), session: auth.Session = Depends(session_dep),
                        conn: sqlite3.Connection = Depends(get_db)):
        check_csrf(session, csrf_token)
        auth.delete_other_sessions(conn, session.admin_id, session.token_hash)
        return RedirectResponse("/settings?saved=sessions", status_code=303)

    return app


def run_server(cfg: Config) -> None:
    import uvicorn

    conn = connect(cfg.db_path)
    try:
        pending = pending_migrations(conn)
    finally:
        conn.close()
    if pending:
        raise SystemExit(f"database schema is not up to date (pending: {', '.join(pending)}); "
                         "run 'mail-console migrate' first")
    uvicorn.run(create_app(cfg), host=cfg.bind_host, port=cfg.port, workers=1, proxy_headers=False,
                server_header=False, date_header=False, access_log=False, log_level="info")

