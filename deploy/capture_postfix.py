#!/usr/bin/env python3
"""Plan, apply and reverse the Mail Console capture change in Postfix.

Operator tool (run as root, standard library only). Mail Console's install,
update, rollback and uninstall scripts never call it.

    sudo python3 -I capture_postfix.py plan                 # read-only
    sudo python3 -I capture_postfix.py apply [--listener NAME] [--yes]
    sudo postfix reload                                     # activates
    sudo python3 -I capture_postfix.py deactivate          # listeners restored
    sudo postfix reload                                     # no new archive copies
    sudo python3 -I capture_postfix.py deactivate --finish # once no copy is queued
    sudo postfix reload
    sudo python3 -I capture_postfix.py status

What ``apply`` changes, and nothing else:

* adds the service ``cleanup-archive`` as an exact copy of the cleanup
  service the listener uses today (same private/unpriv/chroot/wakeup/maxproc
  columns and -o options) plus ``always_bcc=archive@mail-console.invalid``;
* adds the pipe service ``mailconsole-archive``;
* writes /etc/postfix/mailconsole_transport and *prepends* it to the
  existing ``transport_maps`` (other maps and their order are kept);
* sets ``mailconsole-archive_destination_recipient_limit = 1``;
* sets ``cleanup_service_name=cleanup-archive`` on the selected listener(s)
  only, leaving every other listener option untouched.

The previous values are recorded in a state file before anything changes, so
``deactivate`` restores them exactly.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

ARCHIVE_ADDRESS = "archive@mail-console.invalid"
ARCHIVE_SERVICE = "cleanup-archive"
PIPE_SERVICE = "mailconsole-archive"
CAPTURE_ENTRY = "/usr/local/libexec/mail-console/mc-capture"
PIPE_LINE = (f"{PIPE_SERVICE} unix - n n - 4 pipe user=mcarchive argv={CAPTURE_ENTRY} "
             "--queue-id=${queue_id} --sender=${sender} --sasl-user=${sasl_username}")
MAP_FILE = "/etc/postfix/mailconsole_transport"
MAP_REF = f"hash:{MAP_FILE}"
MAP_CONTENT = (
    "# Mail Console archive copy -> internal pipe transport only. The .invalid TLD never resolves.\n"
    f"{ARCHIVE_ADDRESS}    {PIPE_SERVICE}:\n"
)
LIMIT_PARAM = f"{PIPE_SERVICE}_destination_recipient_limit"
STATE_FILE = "/etc/postfix/mailconsole-capture.json"
BACKUP_ROOT = "/var/backups/mail-console-postfix"
SUBMISSION_PORTS = {"submission", "587", "submissions", "smtps", "465"}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}


class PlanError(Exception):
    """The listener to configure cannot be identified safely."""


@dataclass
class Service:
    name: str
    type: str
    fields: list[str]                 # private unpriv chroot wakeup maxproc
    command: str
    line: str                         # full master.cf entry as printed by postconf -M
    params: dict[str, str] = field(default_factory=dict)

    @property
    def host(self) -> str | None:
        if ":" not in self.name:
            return None
        return self.name.rsplit(":", 1)[0]

    @property
    def port(self) -> str:
        return self.name.rsplit(":", 1)[-1]

    @property
    def is_loopback(self) -> bool:
        return (self.host or "").lower() in LOOPBACK_HOSTS


# --- Postfix access (real and, in tests, fake) ----------------------------------

class Postfix:
    """Thin wrapper around postconf/postmap/postfix; every change goes through here."""

    def __init__(self, postconf="/usr/sbin/postconf", postmap="/usr/sbin/postmap", postfix="/usr/sbin/postfix",
                 config_dir="/etc/postfix"):
        self.postconf, self.postmap, self.postfix_cmd, self.config_dir = postconf, postmap, postfix, config_dir

    def _run(self, *args: str, check: bool = True) -> str:
        proc = subprocess.run(list(args), capture_output=True, text=True, timeout=60)
        if check and proc.returncode != 0:
            raise RuntimeError(f"{' '.join(args)}: {proc.stderr.strip() or proc.returncode}")
        return proc.stdout

    # read
    def master_lines(self) -> str:
        return self._run(self.postconf, "-M")

    def service_params(self) -> str:
        return self._run(self.postconf, "-P")

    def main_value(self, name: str) -> str:
        return self._run(self.postconf, "-h", name).strip()

    def main_expanded(self, name: str) -> str:
        """Value with $parameter references expanded (postconf -x)."""
        return self._run(self.postconf, "-xh", name).strip()

    def main_explicit(self) -> str:
        return self._run(self.postconf, "-n")

    def main_cf_value(self, name: str) -> str | None:
        """The value written in main.cf, read from the file itself.

        ``postconf -h``/``-n`` hide a transport-specific parameter once its
        master.cf service is gone, so they cannot be used to clean it up.
        """
        found = None
        pattern = re.compile(rf"^{re.escape(name)}\s*=\s*(.*?)\s*$")
        with open(os.path.join(self.config_dir, "main.cf")) as fh:
            for line in fh:
                m = pattern.match(line)
                if m:
                    found = m.group(1)   # last one wins, as in Postfix
        return found

    def processes(self) -> list[str]:
        """Command lines of running processes (master passes -n NAME and -o options to children)."""
        return self._run("/usr/bin/ps", "-eo", "args=").splitlines()

    def archive_copies_queued(self) -> int:
        """Queued messages that still carry the archive recipient."""
        out = self._run("/usr/sbin/postqueue", "-j")
        count = 0
        for line in out.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if any(r.get("address", "").lower() == ARCHIVE_ADDRESS for r in item.get("recipients", [])):
                count += 1
        return count

    def read_map(self) -> str | None:
        try:
            with open(MAP_FILE) as fh:
                return fh.read()
        except FileNotFoundError:
            return None

    def query(self, table: str, key: str) -> str | None:
        proc = subprocess.run([self.postmap, "-q", key, table], capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() if proc.returncode == 0 else None

    # write
    def set_main(self, name: str, value: str) -> None:
        self._run(self.postconf, "-e", f"{name}={value}")

    def remove_main(self, name: str) -> None:
        self._run(self.postconf, "-X", name)

    def set_service(self, name: str, type_: str, line: str) -> None:
        self._run(self.postconf, "-M", f"{name}/{type_}={line}")

    def remove_service(self, name: str, type_: str) -> None:
        self._run(self.postconf, "-MX", f"{name}/{type_}")

    def set_service_param(self, name: str, type_: str, param: str, value: str) -> None:
        self._run(self.postconf, "-P", f"{name}/{type_}/{param}={value}")

    def remove_service_param(self, name: str, type_: str, param: str) -> None:
        self._run(self.postconf, "-PX", f"{name}/{type_}/{param}")

    def write_map(self, content: str) -> None:
        with open(MAP_FILE, "w") as fh:
            fh.write(content)
        os.chmod(MAP_FILE, 0o644)
        self._run(self.postmap, MAP_REF)

    def remove_map(self) -> None:
        for path in (MAP_FILE, MAP_FILE + ".db", MAP_FILE + ".lmdb"):
            if os.path.exists(path):
                os.unlink(path)

    def check(self) -> None:
        self._run(self.postfix_cmd, "check")

    def backup(self, directory: str) -> None:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        for name in ("main.cf", "master.cf"):
            shutil.copy2(os.path.join(self.config_dir, name), os.path.join(directory, name))


# --- parsing and planning ----------------------------------------------------------

def parse_services(master_text: str, params_text: str) -> dict[tuple[str, str], Service]:
    services: dict[tuple[str, str], Service] = {}
    for raw in master_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 8:
            continue
        svc = Service(name=parts[0], type=parts[1], fields=parts[2:7], command=parts[7], line=line)
        services[(svc.name, svc.type)] = svc
    for raw in params_text.splitlines():
        key, sep, value = raw.partition("=")
        if not sep:
            continue
        path = key.strip()
        # service names may contain ':' and '[', never '/'
        bits = path.split("/")
        if len(bits) != 3:
            continue
        svc = services.get((bits[0], bits[1]))
        if svc is not None:
            svc.params[bits[2]] = value.strip()
    return services


def smtpd_listeners(services: dict) -> list[Service]:
    return [s for s in services.values() if s.type == "inet" and s.command == "smtpd"]


def is_authenticated(svc: Service, global_sasl: str) -> bool:
    return svc.params.get("smtpd_sasl_auth_enable", global_sasl).strip().lower() == "yes"


def choose_listeners(services: dict, global_sasl: str, requested: list[str],
                     allow_other_port: bool = False) -> list[Service]:
    listeners = smtpd_listeners(services)
    by_name = {s.name: s for s in listeners}
    if requested:
        chosen = []
        for name in requested:
            svc = by_name.get(name)
            if svc is None:
                raise PlanError(f"--listener {name}: no smtpd inet service with that name "
                                f"(found: {', '.join(sorted(by_name)) or 'none'})")
            if not is_authenticated(svc, global_sasl):
                raise PlanError(f"--listener {name} does not require SMTP AUTH; capturing it could archive "
                                "unrelated inbound mail. Refusing.")
            if svc.port not in SUBMISSION_PORTS and not allow_other_port:
                raise PlanError(f"--listener {name} is not a submission port ({svc.port}); SASL being enabled does "
                                "not mean it is required there, so inbound mail could be archived. Refusing.")
            chosen.append(svc)
        return chosen
    candidates = [s for s in listeners
                  if s.port in SUBMISSION_PORTS and not s.is_loopback and is_authenticated(s, global_sasl)]
    if not candidates:
        raise PlanError("no public authenticated submission listener found among: "
                        + (", ".join(f"{s.name}/inet" for s in listeners) or "none")
                        + ". Pass --listener NAME explicitly after checking master.cf.")
    if len(candidates) > 1:
        raise PlanError("more than one public authenticated submission listener: "
                        + ", ".join(f"{s.name}/inet" for s in candidates)
                        + ". Choose explicitly with --listener NAME (repeat for several).")
    return candidates


def base_cleanup(services: dict, listeners: list[Service], default: str = "cleanup") -> Service:
    """The cleanup service the listeners use today (cleanup-archive copies it)."""
    names = {s.params.get("cleanup_service_name", default) for s in listeners}
    if len(names) != 1:
        raise PlanError(f"the selected listeners use different cleanup services ({', '.join(sorted(names))}); "
                        "configure them one at a time")
    name = names.pop()
    if name == ARCHIVE_SERVICE:
        raise PlanError("the selected listener already uses cleanup-archive (capture is already active)")
    base = services.get((name, "unix"))
    if base is None:
        raise PlanError(f"cleanup service {name}/unix not found in master.cf")
    return base


def archive_cleanup_line(base: Service) -> str:
    """The base cleanup entry with only its name changed (columns and -o options kept)."""
    rest = base.line.split(None, 1)[1]
    return f"{ARCHIVE_SERVICE} {rest}"


def new_transport_maps(current: str) -> str:
    entries = [e for e in re.split(r"[\s,]+", current.strip()) if e]
    if MAP_REF in entries:
        return current.strip()
    return MAP_REF if not entries else f"{MAP_REF}, {current.strip()}"


@dataclass
class Plan:
    listeners: list[Service]
    base: Service
    cleanup_line: str
    transport_maps_before: str
    transport_maps_after: str
    services: dict
    warnings: list[str] = field(default_factory=list)

    def commands(self) -> list[str]:
        cmds = [
            f"install -m 0644 <map> {MAP_FILE}   # {ARCHIVE_ADDRESS} -> {PIPE_SERVICE}:",
            f"postmap {MAP_REF}",
            f"postconf -e 'transport_maps={self.transport_maps_after}'",
            f"postconf -e '{LIMIT_PARAM}=1'",
            f"postconf -M '{ARCHIVE_SERVICE}/unix={self.cleanup_line}'",
            f"postconf -P '{ARCHIVE_SERVICE}/unix/always_bcc={ARCHIVE_ADDRESS}'",
            f"postconf -M '{PIPE_SERVICE}/unix={PIPE_LINE}'",
        ]
        cmds += [f"postconf -P '{s.name}/inet/cleanup_service_name={ARCHIVE_SERVICE}'" for s in self.listeners]
        cmds += ["postfix check", "postfix reload   # run by the operator after reviewing"]
        return cmds


def make_plan(pf, requested: list[str], allow_other_port: bool = False) -> Plan:
    services = parse_services(pf.master_lines(), pf.service_params())
    for name in (ARCHIVE_SERVICE, PIPE_SERVICE):
        if (name, "unix") in services:
            raise PlanError(f"{name}/unix already exists in master.cf; run 'status' or 'deactivate' first")
    listeners = choose_listeners(services, pf.main_value("smtpd_sasl_auth_enable"), requested, allow_other_port)
    base = base_cleanup(services, listeners, pf.main_value("cleanup_service_name") or "cleanup")
    # An existing always_bcc (compliance copy) would be replaced for submitted mail.
    if pf.main_value("always_bcc") or base.params.get("always_bcc"):
        raise PlanError("always_bcc is already in use (main.cf or the base cleanup service); the archive copy "
                        "would replace it. Use sender_bcc_maps for capture instead, or remove always_bcc first.")
    blocked = _bcc_disabled(pf.main_value("receive_override_options"), base.params, listeners)
    if blocked:
        raise PlanError(f"receive_override_options contains no_address_mappings ({blocked}); that turns off "
                        "always_bcc, so nothing would be captured. Adjust the plan by hand.")
    for svc in services.values():
        if svc.command == "trivial-rewrite" and "transport_maps" in svc.params:
            raise PlanError(f"{svc.name}/{svc.type} overrides transport_maps; the archive route would not be "
                            "seen there. Adjust the plan by hand.")
    current_maps = pf.main_value("transport_maps")
    plan = Plan(listeners, base, archive_cleanup_line(base), current_maps, new_transport_maps(current_maps), services)
    relay = pf.main_value("relayhost")
    default_transport = pf.main_value("default_transport")
    if relay or default_transport not in ("", "smtp"):
        plan.warnings.append(
            f"mail without a specific route goes to relayhost={relay or '-'} / default_transport="
            f"{default_transport}. The archive copy is always routed by the first transport map entry, and "
            "'deactivate --finish' refuses to remove that route while archive copies are still queued.")
    return plan


def _bcc_disabled(global_value: str, base_params: dict, listeners) -> str:
    """Where receive_override_options=...no_address_mappings would suppress always_bcc ('' if nowhere)."""
    def off(value):
        return "no_address_mappings" in re.split(r"[\s,]+", value or "")
    where = [f"{s.name}/inet" for s in listeners
             if off(s.params.get("receive_override_options", global_value))]
    if off(base_params.get("receive_override_options")):
        where.append("cleanup service")
    return ", ".join(where)


def foreign_references(pf, state: dict) -> list[str]:
    """Configuration outside our own entries that still points at cleanup-archive or the pipe.

    Removing the two services while such a reference exists would make that
    service temp-fail every message (for example a listener copied from the
    captured one after apply).
    """
    token = re.compile(rf"(?<![\w-])(?:{re.escape(ARCHIVE_SERVICE)}|{re.escape(PIPE_SERVICE)})(?![\w-])")
    services = parse_services(pf.master_lines(), pf.service_params())
    found = []
    for (name, type_), svc in services.items():
        if (name, type_) in ((ARCHIVE_SERVICE, "unix"), (PIPE_SERVICE, "unix")):
            continue
        if state.get("phase") == "applied" and type_ == "inet" and name in state["listeners"]:
            continue   # ours until phase 1 restores it
        for param, value in svc.params.items():
            if token.search(value):
                found.append(f"{name}/{type_} -o {param}={value}")
    for line in pf.main_explicit().splitlines():
        key, _, value = line.partition("=")
        if key.strip() != LIMIT_PARAM and token.search(value):
            found.append(f"main.cf {key.strip()} = {value.strip()}")
    return found


def describe(pf, plan: Plan, out=sys.stdout) -> None:
    print("smtpd listeners found:", file=out)
    for s in smtpd_listeners(plan.services):
        auth = "AUTH" if is_authenticated(s, pf.main_value("smtpd_sasl_auth_enable")) else "no AUTH"
        mark = "  <- capture" if s in plan.listeners else ("  (loopback: not captured)" if s.is_loopback else "")
        print(f"  {s.name}/inet [{auth}] cleanup={s.params.get('cleanup_service_name', 'cleanup')}{mark}", file=out)
    print(f"base cleanup: {plan.base.name}/unix columns={' '.join(plan.base.fields)}", file=out)
    print(f"transport_maps: {plan.transport_maps_before or '(empty)'}", file=out)
    print(f"            ->  {plan.transport_maps_after}", file=out)
    for warning in plan.warnings:
        print(f"note: {warning}", file=out)
    print("commands:", file=out)
    for cmd in plan.commands():
        print(f"  {cmd}", file=out)


# --- apply / verify / deactivate -------------------------------------------------------

def verify(pf, state: dict) -> list[str]:
    """Return problems; empty means the live configuration matches the plan."""
    problems = []
    services = parse_services(pf.master_lines(), pf.service_params())
    for name, before in state["listeners"].items():
        svc = services.get((name, "inet"))
        if svc is None:
            problems.append(f"{name}/inet disappeared")
            continue
        if svc.params.get("cleanup_service_name") != ARCHIVE_SERVICE:
            problems.append(f"{name}/inet does not use {ARCHIVE_SERVICE}")
        expected = dict(before["params"])
        expected["cleanup_service_name"] = ARCHIVE_SERVICE
        if svc.params != expected:
            problems.append(f"{name}/inet options changed beyond cleanup_service_name")
    for (name, type_), svc in services.items():
        if type_ == "inet" and name not in state["listeners"] and svc.params.get("cleanup_service_name") == ARCHIVE_SERVICE:
            problems.append(f"{name}/inet uses {ARCHIVE_SERVICE} but was not selected")
    archive = services.get((ARCHIVE_SERVICE, "unix"))
    if archive is None or archive.fields != state["base_fields"]:
        problems.append(f"{ARCHIVE_SERVICE}/unix missing or its columns differ from {state['base']}/unix")
    elif archive.params.get("always_bcc") != ARCHIVE_ADDRESS:
        problems.append(f"{ARCHIVE_SERVICE}/unix lacks always_bcc={ARCHIVE_ADDRESS}")
    if (PIPE_SERVICE, "unix") not in services:
        problems.append(f"{PIPE_SERVICE}/unix missing")
    blocked = _bcc_disabled(pf.main_value("receive_override_options"),
                            archive.params if archive is not None else {},
                            [services[(n, "inet")] for n in state["listeners"] if (n, "inet") in services])
    if blocked:
        problems.append(f"no_address_mappings in receive_override_options ({blocked}) turns off always_bcc")
    # The archive address must resolve to the internal pipe transport, first.
    maps = [m for m in re.split(r"[\s,]+", pf.main_expanded("transport_maps")) if m]
    first_hit = None
    for table in maps:
        hit = pf.query(table, ARCHIVE_ADDRESS)
        if hit is not None:
            first_hit = (table, hit)
            break
    if first_hit is None or first_hit[1].strip() != f"{PIPE_SERVICE}:":
        problems.append(f"{ARCHIVE_ADDRESS} does not resolve to {PIPE_SERVICE}: first (got {first_hit})")
    archive_params = archive.params if archive is not None else {}
    for param in ("virtual_alias_maps", "canonical_maps", "recipient_canonical_maps"):
        value = archive_params.get(param) or pf.main_expanded(param)   # cleanup-archive -o override wins
        for table in [m for m in re.split(r"[\s,]+", value) if m and ":" in m]:
            if pf.query(table, ARCHIVE_ADDRESS) is not None:
                problems.append(f"{param} {table} rewrites {ARCHIVE_ADDRESS}")
    domains = " ".join(pf.main_expanded(p) for p in ("mydestination", "virtual_mailbox_domains", "virtual_alias_domains",
                                                   "relay_domains"))
    if "mail-console.invalid" in domains:
        problems.append("mail-console.invalid is listed as a local/virtual/relay domain")
    return problems


def snapshot(pf) -> dict:
    return {"main": pf.main_explicit(), "master": pf.master_lines(), "params": pf.service_params()}


def apply(pf, plan: Plan, state_file: str = STATE_FILE, backup_root: str = BACKUP_ROOT, now: str | None = None) -> dict:
    if os.path.exists(state_file):
        raise PlanError(f"{state_file} exists: capture is already applied (run deactivate first)")
    stamp = now or _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = os.path.join(backup_root, stamp)
    pf.backup(backup_dir)
    state = {
        "version": 1, "applied": stamp, "backup_dir": backup_dir,
        "listeners": {s.name: {"cleanup_service_name": s.params.get("cleanup_service_name"),
                               "params": dict(s.params)} for s in plan.listeners},
        "base": plan.base.name, "base_fields": plan.base.fields,
        "transport_maps": plan.transport_maps_before or None,
        "transport_maps_explicit": "transport_maps" in _explicit_names(pf.main_explicit()),
        "limit_explicit": LIMIT_PARAM in _explicit_names(pf.main_explicit()),
        "limit": pf.main_value(LIMIT_PARAM) if LIMIT_PARAM in _explicit_names(pf.main_explicit()) else None,
        "map_existed": os.path.exists(MAP_FILE),
        "map_previous": pf.read_map(),
        "phase": "applied",
        "before": snapshot(pf),
    }
    _write_state(state_file, state)
    try:
        pf.write_map(MAP_CONTENT)
        pf.set_main("transport_maps", plan.transport_maps_after)
        pf.set_main(LIMIT_PARAM, "1")
        pf.set_service(ARCHIVE_SERVICE, "unix", plan.cleanup_line)
        pf.set_service_param(ARCHIVE_SERVICE, "unix", "always_bcc", ARCHIVE_ADDRESS)
        pf.set_service(PIPE_SERVICE, "unix", PIPE_LINE)
        for svc in plan.listeners:
            pf.set_service_param(svc.name, "inet", "cleanup_service_name", ARCHIVE_SERVICE)
        pf.check()
        problems = verify(pf, state)
        if problems:
            raise PlanError("verification failed: " + "; ".join(problems))
    except BaseException:   # includes Ctrl-C / SIGHUP-turned-KeyboardInterrupt
        deactivate(pf, state_file=state_file)
        finish(pf, state_file=state_file, force=True)
        raise
    return state


def _explicit_names(main_n: str) -> set[str]:
    return {line.split("=", 1)[0].strip() for line in main_n.splitlines() if "=" in line}


def _write_state(path: str, state: dict) -> None:
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, path)


def _load_state(state_file: str) -> dict:
    with open(state_file) as fh:
        return json.load(fh)


def deactivate(pf, state_file: str = STATE_FILE) -> list[str]:
    """Phase 1: restore the listeners' exact previous cleanup_service_name.

    After ``postfix reload`` no new archive copies are made. The archive route
    and pipe stay in place so copies already queued are still delivered to
    the archive; ``finish`` removes them once the queue holds none.
    Returns warnings (never raises on a listener edited by hand meanwhile).
    """
    state = _load_state(state_file)
    warnings = []
    for name, before in state["listeners"].items():
        previous = before["cleanup_service_name"]
        try:
            if previous is None:
                pf.remove_service_param(name, "inet", "cleanup_service_name")
            else:
                pf.set_service_param(name, "inet", "cleanup_service_name", previous)
        except RuntimeError:
            pass   # never set (apply failed early) or listener removed by hand
    pf.check()
    services = parse_services(pf.master_lines(), pf.service_params())
    for name, before in state["listeners"].items():
        svc = services.get((name, "inet"))
        if svc is None:
            warnings.append(f"{name}/inet no longer exists")
            continue
        now = {k: v for k, v in svc.params.items() if k != "cleanup_service_name"}
        was = {k: v for k, v in before["params"].items() if k != "cleanup_service_name"}
        if svc.params.get("cleanup_service_name") != before["cleanup_service_name"]:
            warnings.append(f"{name}/inet cleanup_service_name is {svc.params.get('cleanup_service_name')!r}, "
                            f"expected {before['cleanup_service_name']!r}")
        if now != was:
            warnings.append(f"{name}/inet has other options that were edited since apply; they were left as they are")
    state["phase"] = "listeners-restored"
    for ref in foreign_references(pf, state):
        warnings.append(f"{ref} still uses the archive services; change it before 'deactivate --finish'")
    _write_state(state_file, state)
    return warnings


def finish(pf, state_file: str = STATE_FILE, force: bool = False) -> dict:
    """Phase 2: remove the archive route, services and map once nothing can still use them.

    ``force`` is only for apply's own rollback, before any reload made the
    change live; the command line does not offer it.
    """
    state = _load_state(state_file)
    if state.get("phase") != "listeners-restored":
        raise PlanError("run 'deactivate' and 'postfix reload' first")
    if not force:
        refs = foreign_references(pf, state)
        if refs:
            raise PlanError("still in use, removing the archive services would make these temp-fail all mail: "
                            + "; ".join(refs))
        live = [a for a in pf.processes()
                if f"cleanup_service_name={ARCHIVE_SERVICE}" in a or re.search(rf"-n {re.escape(ARCHIVE_SERVICE)}\b", a)]
        if live:
            raise PlanError(f"{len(live)} running Postfix process(es) still use {ARCHIVE_SERVICE} (was 'postfix "
                            "reload' run after 'deactivate'? long SMTP sessions end on their own). Retry shortly.")
        queued = pf.archive_copies_queued()
        if queued:
            raise PlanError(f"{queued} queued message(s) still carry the archive copy; removing the archive route "
                            "now could send them elsewhere. Wait until 'postqueue -j' shows none, then retry.")
    # The limit first: postconf hides it once the pipe service is gone. Decide from main.cf itself.
    if pf.main_cf_value(LIMIT_PARAM) == "1":
        if state["limit_explicit"]:
            pf.set_main(LIMIT_PARAM, state["limit"])
        else:
            pf.remove_main(LIMIT_PARAM)
    for name in (PIPE_SERVICE, ARCHIVE_SERVICE):
        try:
            pf.remove_service(name, "unix")
        except RuntimeError:
            pass
    # Remove only our map from the *current* transport_maps; later edits stay.
    current = pf.main_value("transport_maps")
    if MAP_REF in _entries(current):
        remaining = _without_map_ref(current)
        if _entries(remaining) == _entries(state["transport_maps"]):
            if state["transport_maps_explicit"]:
                pf.set_main("transport_maps", state["transport_maps"] or "")   # exact previous text
            else:
                pf.remove_main("transport_maps")
        else:
            pf.set_main("transport_maps", remaining)   # edited since apply: keep exactly what the admin left
    if state.get("map_previous") is not None:
        pf.write_map(state["map_previous"])
    elif not state["map_existed"]:
        pf.remove_map()
    pf.check()
    os.replace(state_file, state_file + f".deactivated-{state['applied']}")
    return state


def _entries(value: str | None) -> list[str]:
    return [e for e in re.split(r"[\s,]+", (value or "").strip()) if e]


def _without_map_ref(value: str) -> str:
    """value with our map reference removed as literal text (other tables, e.g. inline:{..}, untouched)."""
    out = re.sub(rf"(^|[\s,])\s*{re.escape(MAP_REF)}(?=[\s,]|$)[\s,]*", r"\1", value.strip())
    return out.strip(" ,\t")


def main(argv: list[str] | None = None, pf=None) -> int:
    p = argparse.ArgumentParser(prog="capture_postfix.py", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    plan_p = sub.add_parser("plan", help="show what apply would change (read-only)")
    plan_p.add_argument("--listener", action="append", default=[])
    apply_p = sub.add_parser("apply", help="apply the capture change (does not reload Postfix)")
    apply_p.add_argument("--listener", action="append", default=[])
    apply_p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    deact = sub.add_parser("deactivate", help="phase 1: restore the listeners (then postfix reload); "
                                               "--finish: phase 2, remove the archive route once the queue is clear")
    deact.add_argument("--finish", action="store_true")
    plan_p.add_argument("--allow-other-port", action="store_true", help=argparse.SUPPRESS)
    apply_p.add_argument("--allow-other-port", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("status", help="show the recorded state")
    args = p.parse_args(argv)
    pf = pf or Postfix()
    try:
        if args.cmd == "plan":
            describe(pf, make_plan(pf, args.listener, args.allow_other_port))
            return 0
        if os.geteuid() != 0:
            print("run as root", file=sys.stderr)
            return 1
        if args.cmd == "status":
            if not os.path.exists(STATE_FILE):
                print("capture is not applied (no state file)")
                return 0
            with open(STATE_FILE) as fh:
                state = json.load(fh)
            print(f"applied {state['applied']} to: {', '.join(n + '/inet' for n in state['listeners'])}"
                  f" (phase: {state.get('phase', 'applied')})")
            if state.get("phase") == "listeners-restored":
                print(f"archive copies still queued: {pf.archive_copies_queued()}")
                for ref in foreign_references(pf, state):
                    print(f"still uses the archive services: {ref}")
                return 0
            problems = verify(pf, state)
            print("verification: " + ("ok" if not problems else "; ".join(problems)))
            return 0 if not problems else 1
        if args.cmd == "apply":
            plan = make_plan(pf, args.listener, args.allow_other_port)
            describe(pf, plan)
            if not args.yes and input("Apply these changes? Type 'yes': ").strip() != "yes":
                print("aborted; nothing changed")
                return 1
            state = apply(pf, plan)
            print(f"applied and verified; backups in {state['backup_dir']}; state in {STATE_FILE}")
            print("Activate with:  postfix reload")
            return 0
        if args.cmd == "deactivate" and not args.finish:
            for warning in deactivate(pf):
                print(f"warning: {warning}")
            print("listener overrides restored. Now run:  postfix reload")
            print("then, once 'postqueue -j' holds no archive copies:  capture_postfix.py deactivate --finish")
            return 0
        if args.cmd == "deactivate":
            finish(pf)
            print("archive route, services and map removed; transport_maps keeps any later edits.")
            print("Activate with:  postfix reload")
            return 0
    except PlanError as exc:
        print(f"refusing: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
