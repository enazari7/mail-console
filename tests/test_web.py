import pytest
from fastapi.testclient import TestClient

from mailconsole import auth
from mailconsole.db import tx
from mailconsole.web import create_app

from .conftest import PASSWORD, csrf_from, login

# --- authentication & session security ---------------------------------------

@pytest.mark.parametrize("path", ["/", "/emails", "/emails?q=alice%40example.org", "/emails/1", "/monitoring",
                                  "/emails/export.csv?q=alice", "/archives/1", "/archives/1/raw.eml",
                                  "/archives/1/parts/0", "/archives/1/preview.html", "/audit",
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

def test_overview_renders_metrics_and_charts(logged_in):
    r = logged_in.get("/?range=custom&start=2026-10-20T00:00&end=2026-10-27T00:00")
    assert r.status_code == 200
    assert r.text.count("<svg") >= 2 and 'class="s-accepted"' in r.text
    assert "46.2%" in r.text  # 6 failed of 13 final outcomes
    assert "example.org" in r.text and ">2<" in r.text  # queue size from snapshot


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


# --- two-factor authentication and HTTPS behind the proxy --------------------

def test_totp_enrolment_login_and_replay(client, admin, db, monkeypatch):
    import re as _re

    from mailconsole import auth as _auth
    assert login(client).status_code == 303
    token = csrf_from(client.get("/settings").text)
    page = client.post("/settings/totp/setup", data={"csrf_token": token, "password": PASSWORD}).text
    secret = _re.search(r'<dd class="mono wrap">([A-Z2-7]{32})</dd>', page).group(1)
    assert 'name="secret"' not in page   # the secret stays on the server
    assert client.post("/settings/totp/enable", data={"csrf_token": token, "code": "000000"}).status_code == 400
    # A secret supplied by the client is ignored (a stolen session cannot enrol its own key).
    attacker = _auth.totp_new_secret()
    assert client.post("/settings/totp/enable", data={"csrf_token": token, "secret": attacker,
                                                      "code": _auth.totp_now(attacker)}).status_code == 400
    import time as _real_time
    clock = [_real_time.time()]
    monkeypatch.setattr(_auth._time, "time", lambda: clock[0])
    assert client.post("/settings/totp/enable", data={"csrf_token": token,
                                                      "code": _auth.totp_now(secret, clock[0])}).status_code == 303
    client.post("/logout", data={"csrf_token": csrf_from(client.get("/settings").text)})
    # Password alone no longer signs in.
    step1 = login(client)
    assert step1.status_code == 200 and "Authentication code" in step1.text
    assert client.get("/").status_code == 303
    csrf = csrf_from(step1.text)
    bad = client.post("/login/totp", data={"code": "123456", "csrf_token": csrf, "next": "/"})
    assert bad.status_code == 401
    clock[0] += 30   # the enrolment code's time step was consumed: use the next one
    ok = client.post("/login/totp", data={"code": _auth.totp_now(secret, clock[0]),
                                          "csrf_token": csrf_from(bad.text), "next": "/"})
    assert ok.status_code == 303 and client.get("/").status_code == 200
    # Replaying the same code for a new login fails.
    client.post("/logout", data={"csrf_token": csrf_from(client.get("/settings").text)})
    again = login(client)
    replay = client.post("/login/totp", data={"code": _auth.totp_now(secret, clock[0]),
                                              "csrf_token": csrf_from(again.text), "next": "/"})
    assert replay.status_code == 401
    actions = {r[0] for r in db.execute("SELECT action FROM audit_log")}
    assert {"totp_enabled", "totp_failed", "login"} <= actions


def test_totp_pending_login_attempts_are_limited(client, admin, db):
    from mailconsole import auth as _auth
    with tx(db):
        db.execute("UPDATE admins SET totp_secret = ?", (_auth.totp_new_secret(),))
    page = login(client)
    for _ in range(_auth.PENDING_LOGIN_ATTEMPTS):
        page = client.post("/login/totp", data={"code": "000000", "csrf_token": csrf_from(page.text), "next": "/"})
    final = client.post("/login/totp", data={"code": "000000", "csrf_token": csrf_from(page.text), "next": "/"})
    assert final.status_code == 303 and final.headers["location"] == "/login"


def test_totp_disable_from_cli(cfg, db, admin, capsys):
    from mailconsole import auth as _auth
    from mailconsole import cli
    with tx(db):
        db.execute("UPDATE admins SET totp_secret = ?", (_auth.totp_new_secret(),))
    assert cli.main(["admin", "totp-disable", "--username", "admin"]) == 0
    assert db.execute("SELECT totp_secret FROM admins").fetchone()[0] is None


def test_proxied_requests_must_be_https(cfg, app_db, admin):
    import dataclasses
    proxied = TestClient(create_app(dataclasses.replace(cfg, trust_proxy=True)), base_url="http://127.0.0.1:8710",
                         follow_redirects=False)
    r = proxied.get("/login", headers={"x-forwarded-for": "198.51.100.7", "x-forwarded-proto": "http"})
    assert r.status_code == 400 and "HTTPS required" in r.text
    r = proxied.get("/login", headers={"x-forwarded-for": "198.51.100.7", "x-forwarded-proto": "https"})
    assert r.status_code == 200 and "max-age" in r.headers["strict-transport-security"]
    assert proxied.get("/login").status_code == 200   # direct loopback (SSH tunnel) still works


def test_totp_cannot_be_brute_forced_by_repeating_the_password_step(client, admin, db):
    from mailconsole import auth as _auth
    secret = _auth.totp_new_secret()
    with tx(db):
        db.execute("UPDATE admins SET totp_secret = ?", (secret,))
    wrong = "000000" if _auth.totp_now(secret) != "000000" else "111111"
    guesses = 0
    for _ in range(10):
        page = login(client)
        if page.status_code != 200 or "Authentication code" not in page.text:
            break
        for _ in range(_auth.PENDING_LOGIN_ATTEMPTS):
            r = client.post("/login/totp", data={"code": wrong, "csrf_token": csrf_from(page.text), "next": "/"})
            if r.status_code != 401:
                break
            guesses += 1
            page = r
    assert guesses <= _auth.TOTP_MAX_FAILURES


def test_totp_code_cannot_be_used_twice_concurrently(db, admin, monkeypatch):
    from mailconsole import auth as _auth
    secret = _auth.totp_new_secret()
    with tx(db):
        db.execute("UPDATE admins SET totp_secret = ?, totp_last_counter = NULL", (secret,))
    code = _auth.totp_now(secret)
    assert _auth.totp_check(db, admin, code)
    # Second request raced the first: it read the old (empty) last counter, so
    # its match succeeds; the conditional UPDATE must still refuse it.
    real = _auth.totp_match
    monkeypatch.setattr(_auth, "totp_match", lambda s, c, at=None, after_counter=None: real(s, c, at, None))
    assert not _auth.totp_check(db, admin, code)
