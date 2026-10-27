#!/usr/bin/env python3
"""Acceptance smoke test against a running console (standard library only).

    printf '%s\n' "$PASSWORD" | python3 deploy/smoke_test.py --username admin --password-stdin \
        --expect 3F2A61C0D3 --expect alice@example.org

Checks: unauthenticated access is refused, login works, every page renders,
and each --expect term is found through the Emails search. Read-only apart
from creating (and then closing) one login session.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from html import escape as html_escape
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.cookies: dict[str, str] = {}
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, path: str, data: dict | None = None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(self.base + path, data=body)  # noqa: S310 - scheme checked in main()
        if self.cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        try:
            resp = self.opener.open(req, timeout=15)
        except urllib.error.HTTPError as err:
            resp = err
        for header in resp.headers.get_all("Set-Cookie") or []:
            name, _, rest = header.partition("=")
            value = rest.split(";", 1)[0].strip('"')
            if value:
                self.cookies[name] = value
            else:
                self.cookies.pop(name, None)
        return resp.status, resp.headers, resp.read().decode("utf-8", "replace")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://127.0.0.1:8710")
    p.add_argument("--username", required=True)
    p.add_argument("--password-stdin", action="store_true", required=True)
    p.add_argument("--expect", action="append", default=[], help="search term that must return results")
    p.add_argument("--days", type=int, default=400, help="search window ending now (default 400 days)")
    args = p.parse_args()
    if not args.url.startswith(("http://", "https://")):
        p.error("--url must be http(s)")
    password = sys.stdin.readline().rstrip("\n")
    failures = []

    def check(ok: bool, text: str) -> None:
        print(("PASS " if ok else "FAIL ") + text)
        if not ok:
            failures.append(text)

    anon = Client(args.url)
    status, headers, _ = anon.request("/emails?q=example")
    check(status == 303 and headers.get("Location", "").startswith("/login"), "anonymous access is redirected to login")
    status, _, _ = anon.request("/healthz")
    check(status == 200, "health endpoint responds")

    c = Client(args.url)
    status, _, html = c.request("/login")
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    check(status == 200 and match is not None, "login page renders")
    if not match:
        return 1
    status, headers, _ = c.request("/login", {"username": args.username, "password": password,
                                              "csrf_token": match.group(1), "next": "/"})
    check(status == 303 and "mc_session" in c.cookies, "administrator login succeeds")
    if "mc_session" not in c.cookies:
        return 1
    for path in ("/", "/?range=7d", "/emails", "/emails?status=accepted&sort=recipient", "/monitoring", "/settings"):
        status, _, html = c.request(path)
        check(status == 200 and "Mail Console" in html, f"GET {path} renders")
    for term in args.expect:
        end = datetime.now(timezone.utc) + timedelta(days=1)
        window = {"range": "custom", "start": (end - timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M"),
                  "end": end.strftime("%Y-%m-%dT%H:%M")}
        status, _, html = c.request("/emails?" + urllib.parse.urlencode({"q": term, **window}))
        detail = re.search(r'href="(/emails/\d+)"', html)
        check(status == 200 and "No emails match" not in html and detail is not None, f"search finds {term!r}")
        if detail:
            status, _, page = c.request(detail.group(1))
            check(status == 200 and "Timeline" in page and html_escape(term).lower() in page.lower(),
                  f"detail page for {term!r} shows it with a timeline")
    status, headers, body = c.request("/emails/export.csv?range=90d")
    check(status == 200 and headers.get("Content-Type", "").startswith("text/csv") and body.startswith("\ufeffsent_at_utc"),
          "CSV export works")
    status, _, html = c.request("/")
    token = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if token:
        c.request("/logout", {"csrf_token": token.group(1)})
    print("OK" if not failures else f"{len(failures)} check(s) failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
