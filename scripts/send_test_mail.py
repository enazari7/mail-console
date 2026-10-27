#!/usr/bin/env python3
"""Send synthetic test messages to a local SMTP server (CI end-to-end test only).

    python3 scripts/send_test_mail.py --host 127.0.0.1 --port 25 --to root@localhost
"""

from __future__ import annotations

import argparse
import smtplib
from email.message import EmailMessage

PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 8


def rich(to: list[str]) -> EmailMessage:
    m = EmailMessage()
    m["Subject"] = "سرویس شما فعال شد ACTIVATION-CI"
    m["From"] = "BeastPing CI <notify@example.com>"
    m["To"] = ", ".join(to)
    m.set_content("کد تأیید شما 482913 است.\nReset link: https://example.com/reset?token=CI-TOKEN")
    m.add_alternative('<html dir="rtl"><body><p>کد <b>482913</b></p><img src="cid:logo"></body></html>',
                      subtype="html")
    m.get_payload()[1].add_related(PNG, maintype="image", subtype="png", cid="<logo>")
    m.add_attachment(b"%PDF-1.4 CI attachment\n", maintype="application", subtype="pdf", filename="invoice-ci.pdf")
    return m


def plain(to: list[str]) -> EmailMessage:
    m = EmailMessage()
    m["Subject"] = "Plain text PLAIN-CI"
    m["From"] = "notify@example.com"
    m["To"] = ", ".join(to)
    m.set_content("Plain body PLAIN-CI-BODY\n")
    return m


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=25)
    p.add_argument("--to", action="append", required=True)
    p.add_argument("--only-plain", action="store_true")
    args = p.parse_args()
    with smtplib.SMTP(args.host, args.port, timeout=30) as s:
        if not args.only_plain:
            s.send_message(rich(args.to), from_addr="notify@example.com", to_addrs=args.to)
        s.send_message(plain(args.to), from_addr="notify@example.com", to_addrs=args.to)
    print("sent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
