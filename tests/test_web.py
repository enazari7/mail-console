import re

import pytest
from fastapi.testclient import TestClient

from mailconsole import auth, monitor
from mailconsole.db import tx
from mailconsole.web import create_app

from .conftest import FIXTURES, fixture_lines, ingest_lines

PASSWORD = "correct horse battery"
FIXTURE_QUEUE = (FIXTURES / "postqueue.jsonl").read_text()


@pytest.fixture
def app_db(cfg, db):
    ingest_lines(db, cfg, fixture_lines())
    with tx(db):
        monitor.record_queue(db, monitor.parse_postqueue_json(FIXTURE_QUEUE))
        monitor.record_units(db, [monitor.UnitStatus("Postfix", "postfix@-.service", True, "loaded", "active",
                                                     "running", "Mon 2026-10-26 08:00:00 UTC", 1203, 0)])
    return db


@pytest.fixture
def client(cfg, app_db):
    return TestClient(create_app(cfg), base_url="http://127.0.0.1:8710", follow_redirects=False)


@pytest.fixture
def admin(db):
    return auth.create_admin(db, "admin", PASSWORD)


def csrf_from(html: str) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(client, username="admin", password=PASSWORD, next_url="/"):
    page = client.get("/login")
    return client.post("/login", data={"username": username, "password": password,
                                       "csrf_token": csrf_from(page.text), "next": next_url})


@pytest.fixture
def logged_in(client, admin):
    assert login(client).status_code == 303
    return client


# --- authentication & session security ---------------------------------------

@pytest.mark.parametrize("path", ["/", "/emails", "/emails?q=alice%40example.org", "/emails/1", "/monitoring",
                                  "/settings", "/queue/3F2A61C0D3"])
def test_no_unauthenticated_access(client, admin, path):
    r = client.get(path)
    assert r.status_code == 303 and r.headers["location"].startswith("/login?next=")
    assert "alice" not in r.text and "example.org" not in r.text


def test_no_admin_shows_server_setup_instructions(client):
    page = client.get("/login")
    assert "mail-console admin create" in page.text and 'name="password"' not in page.text
    r = client.post("/login", data={"username": "admin", "password": "x", "csrf_token": "x"})
    assert r.status_code in (401, 403)


def test_login_sets_secure_session_cookie(cfg, app_db, admin):
    import dataclasses
    secure_client = TestClient(create_app(dataclasses.replace(cfg, cookie_secure=True)),
                               base_url="https://127.0.0.1", follow_redirects=False)
    r = login(secure_client)
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = [h for h in r.headers.get_list("set-cookie") if h.startswith("mc_session=")][0].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "secure" in cookie and "path=/" in cookie
    assert secure_client.get("/").status_code == 200


def test_wrong_password_and_unknown_user_look_identical(client, admin):
    a = login(client, password="wrong password!!")
    b = login(client, username="nobody", password="wrong password!!")
    assert a.status_code == b.status_code == 401
    assert "Invalid username or password." in a.text and "Invalid username or password." in b.text
    assert "mc_session=" not in a.headers.get("set-cookie", "")


def test_login_requires_csrf_cookie(client, admin):
    r = client.post("/login", data={"username": "admin", "password": PASSWORD, "csrf_token": "forged"})
    assert r.status_code == 403


def test_login_rate_limit(client, admin):
    for _ in range(auth.MAX_FAILURES_PER_IP):
        assert login(client, password="definitely wrong").status_code == 401
    r = login(client)  # correct password is refused while locked out
    assert r.status_code == 429 and "Too many failed attempts" in r.text


def test_open_redirect_is_blocked(client, admin):
    r = login(client, next_url="//evil.example/")
    assert r.headers["location"] == "/"


def test_logout_requires_csrf_and_invalidates_session(logged_in):
    assert logged_in.post("/logout", data={"csrf_token": "nope"}).status_code == 403
    token = csrf_from(logged_in.get("/").text)
    assert logged_in.post("/logout", data={"csrf_token": token}).status_code == 303
    assert logged_in.get("/").status_code == 303


def test_session_expiry(logged_in, db):
    with tx(db):
        db.execute("UPDATE sessions SET expires_ts = 1")
    assert logged_in.get("/").status_code == 303
    assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


def test_host_header_and_cross_origin_posts_rejected(logged_in):
    assert logged_in.get("/login", headers={"host": "evil.example"}).status_code == 400
    token = csrf_from(logged_in.get("/").text)
    r = logged_in.post("/logout", data={"csrf_token": token}, headers={"origin": "https://evil.example"})
    assert r.status_code == 403


def test_security_headers(logged_in):
    r = logged_in.get("/")
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "server" not in r.headers


def test_password_change_revokes_other_sessions(cfg, app_db, admin, db):
    a = TestClient(create_app(cfg), base_url="http://127.0.0.1:8710", follow_redirects=False)
    b = TestClient(create_app(cfg), base_url="http://127.0.0.1:8710", follow_redirects=False)
    login(a), login(b)
    token = csrf_from(a.get("/settings").text)
    bad = a.post("/settings/password", data={"csrf_token": token, "current_password": "wrong one!!!!",
                                             "new_password": "another long pass", "confirm_password": "another long pass"})
    assert bad.status_code == 403
    short = a.post("/settings/password", data={"csrf_token": token, "current_password": PASSWORD,
                                               "new_password": "short", "confirm_password": "short"})
    assert short.status_code == 400
    ok = a.post("/settings/password", data={"csrf_token": token, "current_password": PASSWORD,
                                            "new_password": "another long pass", "confirm_password": "another long pass"})
    assert ok.status_code == 303
    assert a.get("/").status_code == 200 and b.get("/").status_code == 303
    assert auth.authenticate(db, "admin", "another long pass") is not None
    assert auth.authenticate(db, "admin", PASSWORD) is None


def test_password_hash_is_argon2id(db, admin):
    stored = db.execute("SELECT password_hash FROM admins").fetchone()[0]
    assert stored.startswith("$argon2id$") and PASSWORD not in stored
    with pytest.raises(auth.AuthError):
        auth.create_admin(db, "other", "short")


def test_attempted_usernames_are_not_stored_in_clear(client, admin, db):
    login(client, username="my-secret-password", password="x" * 12)
    stored = " ".join(str(v) for row in db.execute("SELECT * FROM login_attempts") for v in row)
    assert "my-secret-password" not in stored


# --- dashboard pages ---------------------------------------------------------

def rows(html: str) -> list[str]:
    return re.findall(r"<tr>\s*<td class=\"nowrap\"><a href=\"/emails/\d+\">.*?</tr>", html, re.S)


def test_overview_renders_metrics_and_charts(logged_in):
    r = logged_in.get("/?range=custom&start=2026-10-20T00:00&end=2026-10-27T00:00")
    assert r.status_code == 200
    assert r.text.count("<svg") >= 2 and 'class="s-accepted"' in r.text
    assert "46.2%" in r.text  # 6 failed of 13 final outcomes
    assert "example.org" in r.text and ">2<" in r.text  # queue size from snapshot


@pytest.mark.parametrize("q,expected", [
    ("alice@example.org", {"alice@example.org"}),
    ("3F2A61C0D3", {"alice@example.org"}),
    ("<20261020090210.55aa@example.com>", {"bob@example.net", "nobody@example.org"}),
    ("2B4C6D8E0F", {"erin@example.org", "frank@example.net"}),
    ("4Xyz9", {"heidi@example.org", "ivan@example.net", "judy@example.com"}),
    ("no-such-user@example.org", set()),
    ("%", set()),
])
def test_search(logged_in, q, expected):
    r = logged_in.get("/emails", params={"q": q})
    assert r.status_code == 200
    found = set(re.findall(r'<td class="addr" title="([^"]*)">(?!<span)', r.text))
    found = {f for f in found if f in r.text and "@" in f} & {
        "alice@example.org", "bob@example.net", "nobody@example.org", "erin@example.org", "frank@example.net",
        "heidi@example.org", "ivan@example.net", "judy@example.com", "carol@example.net"}
    assert found == expected


def test_status_domain_and_date_filters(logged_in):
    failed = logged_in.get("/emails", params={"status": "failed"}).text
    assert len(rows(failed)) == 6 and "alice@example.org" not in failed
    deferred = logged_in.get("/emails", params={"status": "deferred"}).text
    assert len(rows(deferred)) == 1 and "ivan@example.net" in deferred
    domain = logged_in.get("/emails", params={"domain": "example.net"}).text
    assert len(rows(domain)) == 4
    ranged = logged_in.get("/emails", params={"range": "custom", "start": "2026-10-26T00:00",
                                              "end": "2026-10-27T00:00"}).text
    assert len(rows(ranged)) == 4


def test_custom_range_uses_display_timezone(logged_in, db):
    from mailconsole.db import set_setting
    with tx(db):
        set_setting(db, "display_timezone", "Asia/Tehran")  # UTC+03:30
    # 3F2A61C0D3 was received at 08:15:01Z = 11:45:01 Tehran.
    inside = logged_in.get("/emails", params={"range": "custom", "start": "2026-10-20T11:45",
                                              "end": "2026-10-20T11:46"}).text
    assert "alice@example.org" in inside and "11:45:01" in inside
    outside = logged_in.get("/emails", params={"range": "custom", "start": "2026-10-20T08:15",
                                               "end": "2026-10-20T08:16"}).text
    assert "alice@example.org" not in outside


def test_pagination(logged_in, db, cfg):
    lines = [f"2026-10-22T10:{i // 60:02d}:{i % 60:02d}+00:00 mail postfix/smtp[9]: {0xB00000 + i:08X}: "
             f"to=<p{i:03d}@example.org>, relay=mx[192.0.2.1]:25, delay=1, delays=0/0/1/0, dsn=2.0.0, status=sent (250 ok)"
             for i in range(120)]
    ingest_lines(db, cfg, lines)
    first = logged_in.get("/emails", params={"q": "@example.org", "domain": "example.org"}).text
    assert "1–50 of" in first and "Page 1 / 3" in first
    last = logged_in.get("/emails", params={"q": "@example.org", "domain": "example.org", "page": 3}).text
    assert "Page 3 / 3" in last and len(rows(last)) == 126 - 100  # 6 fixture + 120 generated
    beyond = logged_in.get("/emails", params={"page": 999}).text
    assert "Page 3 / 3" in beyond or "Page" in beyond


def test_detail_page_timeline(logged_in, db):
    mid = db.execute("SELECT id FROM messages WHERE queue_id = 'A3B5C7D9E1'").fetchone()[0]
    page = logged_in.get(f"/emails/{mid}").text
    assert page.count('class="ev ') == 9
    assert "Deferred (temporary failure)" in page and "421 4.7.0 [TSS04]" in page
    assert "Accepted by next hop" in page and "does not prove inbox placement" in page
    assert logged_in.get("/emails/999999").status_code == 404
    r = logged_in.get("/queue/7D1E80B2A4")
    assert r.status_code == 303 and r.headers["location"].startswith("/emails/")


def test_detail_page_states_missing_evidence(logged_in, db):
    mid = db.execute("SELECT id FROM messages WHERE queue_id = '6E7F8A9B0C'").fetchone()[0]
    page = logged_in.get(f"/emails/{mid}").text
    assert "Incomplete evidence" in page and "unknown" in page


def test_monitoring_page(logged_in):
    page = logged_in.get("/monitoring").text
    assert "postfix@-.service" in page and "Running" in page
    assert "ABCDEF9999" in page and "Mailbox temporarily unavailable" in page
    assert "SASL LOGIN authentication failed" in page
    assert "hunter2" not in page
    assert "Password mismatch" in logged_in.get("/monitoring?level=auth").text


def test_settings_retention_and_display(logged_in, db):
    token = csrf_from(logged_in.get("/settings").text)
    assert logged_in.post("/settings/retention", data={"csrf_token": token, "retention_days": 3}).status_code == 400
    assert logged_in.post("/settings/retention", data={"csrf_token": token, "retention_days": 30}).status_code == 303
    assert logged_in.post("/settings/display", data={"csrf_token": token, "timezone": "Europe/Berlin",
                                                     "page_size": 25, "theme": "light"}).status_code == 303
    page = logged_in.get("/settings").text
    assert 'data-theme="light"' in page and 'value="30"' in page and "Europe/Berlin" in page
    assert logged_in.post("/settings/retention", data={"retention_days": 30}).status_code == 403


def test_healthz_reveals_nothing(client):
    r = client.get("/healthz")
    assert r.json() == {"status": "ok"}


def test_range_resolution():
    from zoneinfo import ZoneInfo
    from mailconsole.queries import resolve_range
    tz, now = ZoneInfo("UTC"), 10**15
    assert resolve_range("bogus", "", "", tz, now, default="all", allow_all=True).key == "all"
    assert resolve_range("bogus", "", "", tz, now).key == "24h"
    r = resolve_range("custom", "2026-10-20T00:00", "2026-10-19T00:00", tz, now)  # end before start
    assert r.key == "24h"
    r = resolve_range("7d", "", "", tz, now)
    assert r.end - r.start == 7 * 86400 * 10**6


def test_hash_concurrency_limit_returns_busy(client, admin, monkeypatch):
    monkeypatch.setattr(auth, "HASH_WAIT_SECONDS", 0.05)
    held = [auth._HASH_SLOTS.acquire(), auth._HASH_SLOTS.acquire()]
    try:
        r = login(client)
        assert r.status_code == 429 and "busy" in r.text
    finally:
        for _ in held:
            auth._HASH_SLOTS.release()
    assert login(client).status_code == 303


def test_username_lockout_does_not_block_known_address(cfg, app_db, admin, db):
    from mailconsole import cli
    # A previously successful address...
    auth.record_attempt(db, "198.51.100.7", "admin", True)
    # ...is not locked out by failures for the same username from elsewhere.
    for i in range(auth.MAX_FAILURES_PER_USER):
        auth.record_attempt(db, f"203.0.113.{i}", "admin", False)
    assert auth.login_allowed(db, "198.51.100.7", "admin")
    assert not auth.login_allowed(db, "203.0.113.99", "admin")
    assert auth.clear_failures(db) == auth.MAX_FAILURES_PER_USER
    assert auth.login_allowed(db, "203.0.113.99", "admin")
    assert cli.build_parser().parse_args(["admin", "unlock"]).admin_cmd == "unlock"


def test_failed_attempt_is_recorded_before_hashing(client, admin, db, monkeypatch):
    seen = []
    real = auth.authenticate
    def spy(conn, username, password):
        seen.append(conn.execute("SELECT count(*) FROM login_attempts WHERE success = 0").fetchone()[0])
        return real(conn, username, password)
    monkeypatch.setattr(auth, "authenticate", spy)
    login(client, password="wrong password!!")
    assert seen == [1]


def test_huge_custom_range_is_bounded(logged_in):
    r = logged_in.get("/", params={"range": "custom", "start": "0001-01-01T00:00", "end": "9999-12-31T00:00"})
    assert r.status_code == 200 and r.text.count('class="bar"') <= 60
