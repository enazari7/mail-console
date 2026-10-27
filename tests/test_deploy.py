"""Static checks of the deployment artefacts (ARM64/no-Docker/isolation)."""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
UNITS = sorted((DEPLOY / "systemd").glob("*.service"))
SCRIPTS = sorted(DEPLOY.glob("*.sh")) + sorted((ROOT / "scripts").glob("*.sh"))
MAIL_SERVICES = r"(postfix|dovecot|opendkim|mailguard|rsyslog|ufw|nftables|iptables|bind9|named)"


def test_units_are_sandboxed_and_unprivileged():
    assert {u.name for u in UNITS} == {"mail-console-web.service", "mail-console-collector.service"}
    for unit in UNITS:
        text = unit.read_text()
        for directive in ("User=mailconsole", "NoNewPrivileges=yes", "ProtectSystem=strict",
                          "ReadWritePaths=/var/lib/mail-console", "CapabilityBoundingSet=\n", "UMask=0077",
                          "MemoryMax=", "IPAddressDeny=any"):
            assert directive in text, (unit.name, directive)
        assert "ExecStart=/opt/mail-console/current/venv/bin/python -m mailconsole" in text
    collector = (DEPLOY / "systemd" / "mail-console-collector.service").read_text()
    assert "RestrictAddressFamilies=AF_UNIX\n" in collector  # no network for the collector


def test_web_binds_loopback_by_default():
    env = (ROOT / ".env.example").read_text()
    assert re.search(r"^MC_BIND=127\.0\.0\.1$", env, re.M)
    from mailconsole.config import load_config
    import os
    saved = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("MC_")}
    try:
        assert load_config().bind_host == "127.0.0.1"
    finally:
        os.environ.update(saved)


def test_no_docker_and_no_mail_service_mutation():
    assert not list(ROOT.glob("**/Dockerfile*")) and not list(ROOT.glob("**/docker-compose*"))
    mutating = re.compile(rf"(systemctl|service)\s+(\S+\s+)*(start|stop|restart|reload|enable|disable|mask)\s+\S*{MAIL_SERVICES}",
                          re.I)
    for path in SCRIPTS + UNITS:
        text = path.read_text()
        assert not mutating.search(text), path
        assert "postsuper" not in text and "postqueue -f" not in text and "postfix reload" not in text, path
        assert "/etc/postfix" not in text and "/var/spool/postfix" not in text, path


def test_python_code_runs_only_read_only_commands():
    sources = {p.name: p.read_text() for p in (ROOT / "mailconsole").glob("*.py")}
    assert {n for n, t in sources.items() if "subprocess" in t} == {"monitor.py", "sources.py"}
    calls = re.findall(r"_run\(\[([^\]]*)\]", sources["monitor.py"])
    assert sorted(c.split(",")[1].strip() for c in calls) == ['"-j"', '"show"']
    assert 'cmd = [self.journalctl, "--output=json"' in sources["sources.py"]
    for name, text in sources.items():
        for forbidden in ("smtplib", "os.system", "os.popen", "shell=True"):
            assert forbidden not in text, (name, forbidden)


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_shell_scripts_parse(script):
    subprocess.run(["bash", "-n", str(script)], check=True)
    assert script.stat().st_mode & 0o111, f"{script.name} is not executable"


def test_locked_dependencies_are_hash_pinned():
    lock = (ROOT / "requirements.lock").read_text()
    pins = re.findall(r"^([a-z0-9_.-]+)==([^\s;]+)", lock, re.M)
    assert {"fastapi", "uvicorn", "jinja2", "argon2-cffi", "python-multipart"} <= {p for p, _ in pins}
    blocks = re.split(r"\n(?=[a-z])", lock.split("\n\n", 1)[-1])
    for block in blocks:
        if re.match(r"^[a-z0-9_.-]+==", block):
            assert "--hash=sha256:" in block, block.splitlines()[0]


def test_package_is_pure_python():
    compiled = [p for p in (ROOT / "mailconsole").rglob("*") if p.suffix in (".so", ".c", ".pyx", ".pyd")]
    assert not compiled


def test_repository_contains_no_secrets_or_real_data():
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    if not tracked:
        pytest.skip("not a git checkout")
    for name in tracked:
        assert not name.endswith((".sqlite3", ".db", ".pem", ".key", ".env")), name
        path = ROOT / name
        if path.suffix in (".png", ".gz") or not path.is_file():
            continue
        text = path.read_text(errors="replace")
        assert "PRIVATE " + "KEY-----" not in text, name
        if name.startswith("tests/fixtures/"):
            # Fixtures use only reserved example domains and documentation IP ranges.
            for addr in re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", text):
                assert re.search(r"(^|\.)example\.(com|net|org|invalid)$", addr), (name, addr)
            # IP addresses appear as host[ip], "from ip" or "address ip" in Postfix lines
            # (bare dotted codes such as Yahoo's "4.16.55.1" are not addresses).
            for ip in re.findall(r"(?:\[|from |address )(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b", text):
                assert ip in ("192.0.2", "198.51.100", "203.0.113", "127.0.0"), (name, ip)


def test_install_stops_console_before_migrating():
    text = (DEPLOY / "install.sh").read_text()
    stop = text.index('systemctl stop "${STOPPED[@]}"')
    migrate_call = text.index('run_as_service "$DEST" migrate')
    assert stop < migrate_call and "trap restart_previous EXIT" in text


def test_example_env_sources_cleanly():
    out = subprocess.run(["bash", "-c", "set -euo pipefail; set -a; . ./.env.example; set +a; echo \"$MC_MONITOR_UNITS\""],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    assert "beastping-mailguard.service" in out and "postfix@-.service" in out


def test_capture_preflight_is_read_only():
    text = (DEPLOY / "capture-preflight.sh").read_text()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(("#", "echo")))
    for forbidden in ("postconf -e", "postconf -M ", "postconf -P ", "postconf -X", "postconf -MX", "postconf -PX",
                      "postfix reload", "postfix restart", "postfix stop", "systemctl", "> /etc", ">/etc"):
        assert forbidden not in code.replace('postconf -M submission/inet', '').replace(
            'postconf -M cleanup-archive/unix', '').replace('postconf -P submission/inet/cleanup_service_name', ''), \
            forbidden
    assert "postmap -q" in code and "postmap /" not in code


def test_no_script_changes_postfix():
    for path in SCRIPTS:
        if path.name == "capture-preflight.sh":
            continue
        text = path.read_text()
        assert "postconf" not in text and "postmap" not in text and "master.cf" not in text, path


def test_capture_wrapper_uses_isolated_system_python():
    text = (DEPLOY / "bin" / "mc-capture").read_text()
    assert "/usr/bin/python3 -I \"$SCRIPT\"" in text and "SCRIPT=/opt/mail-console/current/mailconsole/capture.py" in text
    assert "exit 75" in text and "exec " not in text   # every failure must be a temporary failure for pipe(8)
    for snippet in ("master.cf.snippet",):
        assert "argv=/usr/local/libexec/mail-console/mc-capture" in (DEPLOY / "postfix" / snippet).read_text()
