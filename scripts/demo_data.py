#!/usr/bin/env python3
"""Generate a synthetic Postfix syslog for demos, screenshots and benchmarks.

Only reserved example domains (RFC 2606) and documentation IP ranges are used,
and subjects are invented. Nothing here comes from real mail.

    python3 scripts/demo_data.py --messages 2000 --days 15 > /tmp/demo-syslog
"""

from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone

SENDERS = [("notify@example.com", 70), ("billing@example.com", 15), ("security@example.com", 10),
           ("no-reply@example.net", 5)]
DOMAINS = [("example.org", 45), ("mail.example.org", 20), ("example.net", 20), ("inbox.example.com", 10),
           ("example.invalid", 5)]
SUBJECTS = [
    "Your verification code", "Welcome to BeastPing", "Payment received", "Your service expires in 3 days",
    "Your service has expired", "Password reset request", "New sign-in to your account", "Invoice #{n} is ready",
    "کد تأیید شما", "پرداخت شما با موفقیت انجام شد", "سرویس شما فعال شد", "یادآوری تمدید سرویس",
]
FIRST = ["alex", "sam", "maria", "omid", "sara", "li", "noah", "ava", "reza", "nima", "zoe", "kian", "mina", "leo"]
RELAYS = {"example.org": "mx.example.org[203.0.113.25]:25", "mail.example.org": "mx2.example.org[203.0.113.26]:25",
          "example.net": "mx1.example.net[203.0.113.40]:25", "inbox.example.com": "mx.example.com[203.0.113.60]:25",
          "example.invalid": "none"}


def pick(rng: random.Random, weighted):
    return rng.choices([w[0] for w in weighted], [w[1] for w in weighted])[0]


def qid(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789ABCDEF") for _ in range(10))


def line(ts: datetime, prog: str, pid: int, msg: str) -> str:
    return f"{ts.isoformat(timespec='microseconds')} mail {prog}[{pid}]: {msg}"


def message(rng: random.Random, start: datetime, n: int) -> list[tuple[datetime, str]]:
    out = []
    q = qid(rng)
    sender = pick(rng, SENDERS)
    domain = pick(rng, DOMAINS)
    rcpt = f"{rng.choice(FIRST)}{rng.randint(1, 9999)}@{domain}"
    relay = RELAYS[domain]
    t = start
    add = lambda dt, prog, msg: out.append((dt, line(dt, prog, rng.randint(1000, 60000), msg)))  # noqa: E731
    add(t, "postfix/submission/smtpd", f"{q}: client=app.example.net[198.51.100.20], sasl_method=PLAIN, "
                                        f"sasl_username={sender}")
    t += timedelta(milliseconds=80)
    add(t, "postfix/cleanup", f"{q}: message-id=<{t.strftime('%Y%m%d%H%M%S')}.{q.lower()}@example.com>")
    if rng.random() < 0.75:
        subject = rng.choice(SUBJECTS).format(n=rng.randint(1000, 9999))
        add(t, "postfix/cleanup", f"{q}: info: header Subject: {subject} from app.example.net[198.51.100.20]; "
                                  f"from=<{sender}> to=<{rcpt}> proto=ESMTP helo=<app.example.net>")
    roll = rng.random()
    if roll < 0.02:
        add(t + timedelta(milliseconds=5), "postfix/cleanup",
            f"{q}: milter-reject: END-OF-MESSAGE from app.example.net[198.51.100.20]: 5.7.1 Sender address not "
            f"authorized for this login; from=<{sender}> to=<{rcpt}> proto=ESMTP helo=<app.example.net>")
        return out
    t += timedelta(milliseconds=20)
    add(t, "postfix/qmgr", f"{q}: from=<{sender}>, size={rng.randint(2000, 40000)}, nrcpt=1 (queue active)")
    retries = 0
    if domain == "example.invalid" or roll < 0.08:
        retries = rng.randint(1, 3)
    for i in range(retries):
        t += timedelta(seconds=rng.uniform(0.5, 30))
        reason = ("connect to mx.example.invalid[192.0.2.200]:25: Connection timed out" if domain == "example.invalid"
                  else f"host {relay.split(':')[0]} said: 421 4.7.0 Temporarily deferred due to rate limits "
                       "(in reply to MAIL FROM command)")
        dsn = "4.4.1" if domain == "example.invalid" else "4.7.0"
        add(t, "postfix/smtp", f"{q}: to=<{rcpt}>, relay={relay if domain != 'example.invalid' else 'none'}, "
                               f"delay={i * 600 + 1:.1f}, delays=0.1/0/1/0, dsn={dsn}, status=deferred ({reason})")
        if i < retries - 1 or domain != "example.invalid":
            t += timedelta(minutes=rng.choice([5, 10, 20]))
            add(t, "postfix/qmgr", f"{q}: from=<{sender}>, size=1000, nrcpt=1 (queue active)")
    if domain == "example.invalid":
        if rng.random() < 0.5:
            t += timedelta(days=5)
            add(t, "postfix/qmgr", f"{q}: from=<{sender}>, status=expired, returned to sender")
            add(t + timedelta(milliseconds=2), "postfix/qmgr", f"{q}: removed")
        return out  # still deferred otherwise
    t += timedelta(seconds=rng.uniform(0.3, 2.5))
    if roll > 0.96:
        add(t, "postfix/smtp", f"{q}: to=<{rcpt}>, relay={relay}, delay=1.2, delays=0.1/0/0.6/0.5, dsn=5.1.1, "
                               f"status=bounced (host {relay.split(':')[0]} said: 550 5.1.1 <{rcpt}>: Recipient "
                               "address rejected: User unknown (in reply to RCPT TO command))")
    else:
        add(t, "postfix/smtp", f"{q}: to=<{rcpt}>, relay={relay}, delay=0.9, delays=0.1/0/0.4/0.4, dsn=2.0.0, "
                               f"status=sent (250 2.0.0 OK {rng.randint(10**9, 10**10)} - accepted)")
    add(t + timedelta(milliseconds=2), "postfix/qmgr", f"{q}: removed")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--messages", type=int, default=2000)
    p.add_argument("--days", type=float, default=15)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--end", help="ISO end time (default: now)")
    args = p.parse_args()
    rng = random.Random(args.seed)
    end = datetime.fromisoformat(args.end) if args.end else datetime.now(timezone.utc)
    begin = end - timedelta(days=args.days)
    span = (end - begin).total_seconds()
    events = []
    for n in range(args.messages):
        start = begin + timedelta(seconds=span * (n + rng.random()) / args.messages)
        events += [e for e in message(rng, start, n) if e[0] <= end]
    events.sort(key=lambda e: e[0])
    out = sys.stdout
    for _, text in events:
        out.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
