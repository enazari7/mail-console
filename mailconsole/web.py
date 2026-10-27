"""FastAPI application: server-rendered dashboard pages."""

from __future__ import annotations

import ipaddress
from html import escape as html_escape
import secrets
import sqlite3
from datetime import datetime
from importlib import resources
from typing import Iterator
from urllib.parse import urlencode, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, auth, charts, queries
from .config import Config
from .db import connect, get_setting, now_us, pending_migrations, set_setting, tx
from .queries import STATUS_HELP, STATUS_LABELS, US

SESSION_COOKIE = "mc_session"
LOGIN_CSRF_COOKIE = "mc_login_csrf"
PAGE_SIZES = (25, 50, 100)
THEMES = ("system", "dark", "light")
CSP = ("default-src 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")


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
    return f"{seconds // 86400}d ago"


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
        if request.method == "POST":
            origin = request.headers.get("origin")
            if origin and origin != "null" and not _host_allowed(urlsplit(origin).netloc, cfg.allowed_hosts):
                return Response("Cross-origin request refused", status_code=403, media_type="text/plain")
            if request.headers.get("sec-fetch-site") == "cross-site":
                return Response("Cross-site request refused", status_code=403, media_type="text/plain")
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
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
        auth.finish_attempt(conn, attempt, ip, admin_id is not None)
        if admin_id is None:
            return fail("Invalid username or password.", 401)
        token = auth.create_session(conn, admin_id, idle_minutes=cfg.session_idle_minutes,
                                    max_hours=cfg.session_max_hours, client_ip=ip,
                                    user_agent=request.headers.get("user-agent"))
        response = RedirectResponse(_safe_next(next), status_code=303)
        set_cookie(response, SESSION_COOKIE, token, cfg.session_max_hours * 3600)
        response.delete_cookie(LOGIN_CSRF_COOKIE, path="/")
        return response

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
        return render(request, conn, "overview.html", session, rng=rng, data=data, chart=chart,
                      domain_chart=charts.domain_bars(data["domains"]),
                      queue_chart=charts.sparkline(data["queue_history"], lambda us: display.ts(us, "%m-%d %H:%M")),
                      refresh=request.query_params.get("refresh") == "1")

    @app.get("/emails", response_class=HTMLResponse)
    def emails_page(request: Request, q: str = "", status: str = "", domain: str = "", range: str = "all",
                    start: str = "", end: str = "", page: int = 1,
                    session: auth.Session = Depends(session_dep), conn: sqlite3.Connection = Depends(get_db)):
        display = Display(conn)
        rng = queries.resolve_range(range, start, end, display.tz, now_us(), default="all", allow_all=True)
        status = status if status in queries.FILTER_STATUSES else ""
        flt = queries.ActivityFilter(q=q[:320], status=status, domain=domain[:255], start=rng.start, end=rng.end)
        data = queries.activity(conn, flt, page, display.page_size)
        params = {k: v for k, v in {"q": q, "status": status, "domain": domain, "range": rng.key,
                                    "start": start if rng.key == "custom" else "",
                                    "end": end if rng.key == "custom" else ""}.items() if v}
        def page_url(n: int) -> str:
            return "/emails?" + urlencode({**params, "page": n})
        return render(request, conn, "emails.html", session, data=data, flt=flt, rng=rng, start=start, end=end,
                      page_url=page_url, refresh=request.query_params.get("refresh") == "1",
                      refresh_url="/emails?" + urlencode({**params, "page": data["page"], "refresh": 1}))

    @app.get("/emails/{message_id}", response_class=HTMLResponse)
    def email_detail(request: Request, message_id: int, session: auth.Session = Depends(session_dep),
                     conn: sqlite3.Connection = Depends(get_db)):
        detail = queries.message_detail(conn, message_id)
        if detail is None:
            raise StarletteHTTPException(404, "Message not found.")
        return render(request, conn, "email_detail.html", session, d=detail)

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
                "idle_minutes": cfg.session_idle_minutes, "max_hours": cfg.session_max_hours}

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
    def save_retention(request: Request, retention_days: int = Form(...), csrf_token: str = Form(""),
                       session: auth.Session = Depends(session_dep), conn: sqlite3.Connection = Depends(get_db)):
        check_csrf(session, csrf_token)
        if not 7 <= retention_days <= 3650:
            return settings_error(request, conn, session, "Retention must be between 7 and 3650 days.")
        with tx(conn):
            set_setting(conn, "retention_days", str(retention_days))
        return RedirectResponse("/settings?saved=retention", status_code=303)

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

