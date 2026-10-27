from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from mailconsole.parser import (
    OpsEvent, PostfixEvent, classify, parse_postfix_message, parse_syslog_line, redact,
)

PREFIXES = ["postfix"]
OPS = ["opendkim", "dovecot", "mailguard"]


def us(dt: datetime) -> int:
    return int(dt.timestamp()) * 1_000_000 + dt.microsecond


def test_iso_line_with_utc_offset():
    rec = parse_syslog_line("2026-10-20T08:15:02.731514+00:00 mail postfix/smtp[41018]: 3F2A61C0D3: removed")
    assert rec.ts == us(datetime(2026, 10, 20, 8, 15, 2, 731514, tzinfo=timezone.utc))
    assert (rec.host, rec.program, rec.pid, rec.message) == ("mail", "postfix/smtp", 41018, "3F2A61C0D3: removed")


def test_iso_timestamps_are_normalised_to_utc():
    base = us(datetime(2026, 10, 20, 8, 15, 2, tzinfo=timezone.utc))
    for stamp in ("2026-10-20T08:15:02Z", "2026-10-20T11:45:02+03:30", "2026-10-20T04:15:02-0400",
                  "2026-10-20T08:15:02.000000000+00:00"):
        rec = parse_syslog_line(f"{stamp} mail postfix/qmgr[1]: ABCDEF1234: removed")
        assert rec is not None, stamp
        assert rec.ts == base, stamp


def test_iso_without_offset_uses_configured_zone():
    tz = ZoneInfo("Asia/Tehran")
    rec = parse_syslog_line("2026-10-20T11:45:02 mail postfix/qmgr[1]: ABCDEF1234: removed", bsd_tz=tz)
    assert rec.ts == us(datetime(2026, 10, 20, 8, 15, 2, tzinfo=timezone.utc))


def test_bsd_line_uses_zone_and_infers_year_across_new_year():
    tz = ZoneInfo("Europe/Berlin")
    ref = datetime(2027, 1, 2, 12, 0, tzinfo=timezone.utc)
    rec = parse_syslog_line("Dec 31 23:30:00 mail postfix/qmgr[1203]: ABCDEF1234: removed", bsd_tz=tz, reference=ref)
    assert rec.ts == us(datetime(2026, 12, 31, 22, 30, tzinfo=timezone.utc))
    rec2 = parse_syslog_line("Jan  2 09:00:00 mail postfix/qmgr[1203]: ABCDEF1234: removed", bsd_tz=tz, reference=ref)
    assert rec2.ts == us(datetime(2027, 1, 2, 8, 0, tzinfo=timezone.utc))


def test_bsd_dst_transition():
    tz = ZoneInfo("Europe/Berlin")
    ref = datetime(2026, 10, 30, tzinfo=timezone.utc)
    before = parse_syslog_line("Oct 24 12:00:00 mail postfix/qmgr[1]: ABCDEF1234: removed", bsd_tz=tz, reference=ref)
    after = parse_syslog_line("Oct 26 12:00:00 mail postfix/qmgr[1]: ABCDEF1234: removed", bsd_tz=tz, reference=ref)
    assert before.ts == us(datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc))  # CEST, UTC+2
    assert after.ts == us(datetime(2026, 10, 26, 11, 0, tzinfo=timezone.utc))   # CET, UTC+1


def test_unknown_format_returns_none():
    assert parse_syslog_line("garbage without structure") is None


def test_delivery_line_fields():
    ev = parse_postfix_message(
        "smtp",
        "3F2A61C0D3: to=<alice@example.org>, relay=mx.example.org[203.0.113.25]:25, conn_use=2, delay=1.3, "
        "delays=0.13/0.02/0.61/0.54, dsn=5.1.1, status=bounced (host mx.example.org[203.0.113.25] said: "
        "550 5.1.1 <alice@example.org>: Recipient address rejected (in reply to RCPT TO command))")
    assert isinstance(ev, PostfixEvent)
    assert (ev.kind, ev.queue_id, ev.recipient, ev.status, ev.dsn) == (
        "delivery", "3F2A61C0D3", "alice@example.org", "bounced", "5.1.1")
    assert ev.relay == "mx.example.org[203.0.113.25]:25"
    assert ev.delay == 1.3 and ev.delays == "0.13/0.02/0.61/0.54"
    assert ev.response.endswith("(in reply to RCPT TO command)")
    assert ev.detail["conn_use"] == "2"


def test_delivery_with_orig_to_and_softbounce():
    ev = parse_postfix_message("local", "5A6B7C8D9E: to=<root@mail.example.com>, orig_to=<root>, relay=local, "
                                        "delay=0.09, delays=0.05/0.01/0/0.03, dsn=4.0.0, status=SOFTBOUNCE (x)")
    assert ev.orig_recipient == "root" and ev.status == "deferred"


def test_submission_smtpd_client_line():
    rec = parse_syslog_line("2026-10-20T08:15:01.410772+00:00 mail postfix/submission/smtpd[41012]: 3F2A61C0D3: "
                            "client=app.example.net[198.51.100.20], sasl_method=PLAIN, sasl_username=notify@example.com")
    item = classify(rec, PREFIXES, OPS)
    assert item.event.kind == "connect" and item.event.daemon == "smtpd"
    assert item.event.detail == {"client": "app.example.net[198.51.100.20]", "sasl_method": "PLAIN",
                                 "sasl_username": "notify@example.com"}


def test_qmgr_queued_and_expired():
    ev = parse_postfix_message("qmgr", "A3B5C7D9E1: from=<notify@example.com>, size=3900, nrcpt=2 (queue active)")
    assert ev.kind == "queued" and ev.detail == {"from": "notify@example.com", "size": 3900, "nrcpt": 2}
    ev = parse_postfix_message("qmgr", "C0FFEE1234: from=<notify@example.com>, status=expired, returned to sender")
    assert ev.kind == "expired" and ev.status == "expired"


def test_noqueue_reject():
    ev = parse_postfix_message("smtpd", "NOQUEUE: reject: RCPT from unknown[203.0.113.99]: 554 5.7.1 "
                               "<victim@example.org>: Relay access denied; from=<spam@example.invalid> "
                               "to=<victim@example.org> proto=ESMTP helo=<example.invalid>")
    assert ev.kind == "noqueue_reject" and ev.queue_id is None
    assert ev.recipient == "victim@example.org" and ev.detail["from"] == "spam@example.invalid"
    assert ev.dsn == "5.7.1" and ev.response.startswith("554 5.7.1 <victim@example.org>: Relay access denied")
    assert ev.detail["stage"] == "RCPT"


def test_milter_reject_and_header_checks():
    ev = parse_postfix_message("cleanup", "F1E2D3C4B5: milter-reject: END-OF-MESSAGE from app.example.net"
                               "[198.51.100.20]: 5.7.1 Sender address not authorized; from=<ceo@example.com> "
                               "to=<dave@example.org> proto=ESMTP helo=<app.example.net>")
    assert ev.kind == "reject" and ev.detail["milter"] is True
    assert ev.response == "5.7.1 Sender address not authorized" and ev.recipient == "dave@example.org"
    ev = parse_postfix_message("cleanup", "ABCDEF1234: reject: header Subject: win now from localhost[127.0.0.1]; "
                               "from=<a@example.com> to=<b@example.org> proto=ESMTP helo=<x>: 5.7.1 Spam not welcome")
    assert ev.kind == "reject" and ev.response == "5.7.1 Spam not welcome" and ev.dsn == "5.7.1"
    ev = parse_postfix_message("cleanup", "ABCDEF1234: info: header Subject: Your invoice from "
                               "app.example.net[198.51.100.20]; from=<a@example.com> to=<b@example.org> proto=ESMTP")
    assert ev.kind == "header" and ev.detail == {"name": "Subject", "value": "Your invoice"}


def test_notification_removed_requeue_pickup():
    ev = parse_postfix_message("bounce", "7D1E80B2A4: sender non-delivery notification: 9C4F10B2B7")
    assert ev.kind == "notification" and ev.detail["child"] == "9C4F10B2B7"
    assert parse_postfix_message("qmgr", "7D1E80B2A4: removed").kind == "removed"
    assert parse_postfix_message("postsuper", "7D1E80B2A4: requeued").kind == "requeued"
    ev = parse_postfix_message("pickup", "5A6B7C8D9E: uid=0 from=<root> orig_id=7D1E80B2A4")
    assert ev.kind == "pickup" and ev.detail["orig_id"] == "7D1E80B2A4"


def test_words_are_not_queue_ids_and_long_ids_are():
    assert isinstance(parse_postfix_message("smtpd", "warning: hostname x does not resolve"), OpsEvent)
    assert parse_postfix_message("anvil", "statistics: max connection rate 1/60s") is None
    assert parse_postfix_message("smtpd", "connect from unknown[203.0.113.1]") is None
    ev = parse_postfix_message("qmgr", "4Xyz9Lmn7Qz3wJ: removed")
    assert ev.queue_id == "4Xyz9Lmn7Qz3wJ"


def test_non_postfix_lines_and_milter_attachment():
    rec = parse_syslog_line("2026-10-20T08:17:00.000412+00:00 mail CRON[41050]: (root) CMD (debian-sa1 1 1)")
    assert classify(rec, PREFIXES, OPS) is None
    rec = parse_syslog_line("2026-10-20T08:15:01.533201+00:00 mail opendkim[812]: 3F2A61C0D3: "
                            "DKIM-Signature field added (s=mail, d=example.com)")
    item = classify(rec, PREFIXES, OPS)
    assert item.attach_only and item.event.kind == "milter_info"


def test_redaction():
    assert "hunter2" not in redact("auth: Password mismatch (given password: hunter2)")
    assert "dGVzdA" not in redact("< AUTH PLAIN dGVzdAB0ZXN0AHRlc3Q=")
    assert "s3cret" not in redact("connect password=s3cret user=x")
    assert redact("delivered to mailbox") == "delivered to mailbox"
