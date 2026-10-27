"""The operator tool that plans, applies and reverses the Postfix capture change.

Uses a fake Postfix that understands postconf -M/-P/-e/-X/-MX/-PX and postmap -q
over a production-style master.cf (two named submission listeners)."""

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("capture_postfix", ROOT / "deploy" / "capture_postfix.py")
cp = importlib.util.module_from_spec(spec)
sys.modules["capture_postfix"] = cp
spec.loader.exec_module(cp)

PRODUCTION_MASTER = (Path(__file__).parent / "fixtures" / "postconf-M-production.txt").read_text()


class FakePostfix:
    def __init__(self, master=PRODUCTION_MASTER, main=None, tables=None):
        self.services = {}      # (name, type) -> [fields..., command, args-without-o]
        self.params = {}        # (name, type) -> {param: value}
        self.order = []
        for line in master.splitlines():
            if line.strip():
                self._load(line)
        self.main = dict(main or {"transport_maps": "hash:/etc/postfix/transport", "smtpd_sasl_auth_enable": "no"})
        self.tables = tables or {"hash:/etc/postfix/transport": {"bounces@example.com": "bouncecoll:"}}
        self.map_written = None
        self.checks = 0

    def _load(self, line):
        parts = line.split()
        name, type_ = parts[0], parts[1]
        rest, params, i = [], {}, 8
        while i < len(parts):
            if parts[i] == "-o":
                k, _, v = parts[i + 1].partition("=")
                params[k] = v
                i += 2
            else:
                rest.append(parts[i])
                i += 1
        if (name, type_) not in self.services:
            self.order.append((name, type_))
        self.services[(name, type_)] = parts[2:8] + rest
        self.params[(name, type_)] = params

    def master_lines(self):
        out = []
        for key in self.order:
            if key in self.services:
                opts = " ".join(f"-o {k}={v}" for k, v in self.params[key].items())
                out.append(" ".join([key[0], key[1], *self.services[key]] + ([opts] if opts else [])))
        return "\n".join(out) + "\n"

    def service_params(self):
        return "".join(f"{n}/{t}/{k} = {v}\n" for (n, t) in self.order if (n, t) in self.params
                       for k, v in self.params[(n, t)].items())

    def main_value(self, name):
        return self.main.get(name, "")

    def main_explicit(self):
        return "".join(f"{k} = {v}\n" for k, v in sorted(self.main.items()))

    def query(self, table, key):
        return self.tables.get(table, {}).get(key)

    def set_main(self, name, value):
        self.main[name] = value

    def remove_main(self, name):
        if name not in self.main:
            raise RuntimeError("not set")
        del self.main[name]

    def set_service(self, name, type_, line):
        self._load(line)

    def remove_service(self, name, type_):
        if (name, type_) not in self.services:
            raise RuntimeError("no such service")
        del self.services[(name, type_)]
        del self.params[(name, type_)]

    def set_service_param(self, name, type_, param, value):
        self.params[(name, type_)][param] = value

    def remove_service_param(self, name, type_, param):
        if param not in self.params[(name, type_)]:
            raise RuntimeError("not set")
        del self.params[(name, type_)][param]

    def write_map(self, content):
        self.map_written = content
        entries = {}
        for line in content.splitlines():
            if line.strip() and not line.startswith("#"):
                k, v = line.split()
                entries[k] = v
        self.tables[cp.MAP_REF] = entries

    def remove_map(self):
        self.tables.pop(cp.MAP_REF, None)
        self.map_written = None

    def check(self):
        self.checks += 1

    def backup(self, directory):
        Path(directory).mkdir(parents=True, exist_ok=True)

    def snapshot(self):
        return self.main_explicit(), self.master_lines(), self.service_params()


@pytest.fixture
def paths(tmp_path, monkeypatch):
    state = tmp_path / "state.json"
    monkeypatch.setattr(cp, "STATE_FILE", str(state))
    monkeypatch.setattr(cp, "MAP_FILE", str(tmp_path / "mailconsole_transport"))
    return state, tmp_path / "backups"


def test_plan_selects_only_the_public_authenticated_listener():
    pf = FakePostfix()
    plan = cp.make_plan(pf, [])
    assert [s.name for s in plan.listeners] == ["91.107.182.219:submission"]
    assert plan.base.name == "cleanup" and plan.base.fields == ["n", "-", "y", "-", "0"]
    assert plan.cleanup_line.split()[:7] == ["cleanup-archive", "unix", "n", "-", "y", "-", "0"]
    cmds = "\n".join(plan.commands())
    assert "'91.107.182.219:submission/inet/cleanup_service_name=cleanup-archive'" in cmds
    assert "127.0.0.1:submission" not in cmds and "'submission/inet" not in cmds
    assert plan.transport_maps_after == f"{cp.MAP_REF}, hash:/etc/postfix/transport"


def test_plan_refuses_when_ambiguous_or_missing():
    two_public = PRODUCTION_MASTER.replace("127.0.0.1:submission", "203.0.113.5:submission")
    with pytest.raises(cp.PlanError, match="more than one"):
        cp.make_plan(FakePostfix(two_public), [])
    no_auth = re.sub(r"91\.107\.182\.219:submission.*\n", "", PRODUCTION_MASTER)
    with pytest.raises(cp.PlanError, match="no public authenticated submission listener"):
        cp.make_plan(FakePostfix(no_auth), [])
    with pytest.raises(cp.PlanError, match="no smtpd inet service"):
        cp.make_plan(FakePostfix(), ["submission"])          # never invents a generic service
    with pytest.raises(cp.PlanError, match="does not require SMTP AUTH"):
        cp.make_plan(FakePostfix(), ["smtp"])                # port 25 inbound is never captured


def test_loopback_listener_only_on_explicit_request():
    plan = cp.make_plan(FakePostfix(), ["91.107.182.219:submission", "127.0.0.1:submission"])
    assert [s.name for s in plan.listeners] == ["91.107.182.219:submission", "127.0.0.1:submission"]


def test_cleanup_archive_mirrors_a_custom_base_cleanup():
    master = PRODUCTION_MASTER.replace(
        "-o milter_macro_daemon_name=ORIGINATING\n127.0.0.1",
        "-o milter_macro_daemon_name=ORIGINATING -o cleanup_service_name=subcleanup\n127.0.0.1", 1)
    master += "subcleanup unix  n       -       n       -       0       cleanup -o header_checks=regexp:/etc/postfix/hc\n"
    plan = cp.make_plan(FakePostfix(master), [])
    assert plan.base.name == "subcleanup"
    assert plan.cleanup_line.split()[:7] == ["cleanup-archive", "unix", "n", "-", "n", "-", "0"]
    assert "-o header_checks=regexp:/etc/postfix/hc" in plan.cleanup_line


def test_apply_changes_only_the_selected_listener_and_verifies(paths):
    state_file, backups = paths
    pf = FakePostfix()
    before_loopback = dict(pf.params[("127.0.0.1:submission", "inet")])
    before_public = dict(pf.params[("91.107.182.219:submission", "inet")])
    cp.apply(pf, cp.make_plan(pf, []), state_file=str(state_file), backup_root=str(backups), now="T1")
    public = pf.params[("91.107.182.219:submission", "inet")]
    assert public == {**before_public, "cleanup_service_name": "cleanup-archive"}
    assert pf.params[("127.0.0.1:submission", "inet")] == before_loopback
    assert pf.params[("cleanup-archive", "unix")]["always_bcc"] == cp.ARCHIVE_ADDRESS
    assert pf.main["transport_maps"].endswith("hash:/etc/postfix/transport")      # existing routing kept
    assert pf.query("hash:/etc/postfix/transport", "bounces@example.com") == "bouncecoll:"
    assert cp.verify(pf, json.loads(state_file.read_text())) == []


def test_deactivate_restores_exactly(paths):
    state_file, backups = paths
    # Pre-existing explicit override on the public listener and no transport_maps.
    master = PRODUCTION_MASTER.replace("-o milter_macro_daemon_name=ORIGINATING\n127.0.0.1",
                                       "-o milter_macro_daemon_name=ORIGINATING -o cleanup_service_name=cleanup\n"
                                       "127.0.0.1", 1)
    for main in ({"smtpd_sasl_auth_enable": "no"}, None):
        pf = FakePostfix(master, main=main)
        before = pf.snapshot()
        cp.apply(pf, cp.make_plan(pf, []), state_file=str(state_file), backup_root=str(backups), now="T2")
        assert pf.snapshot() != before
        cp.deactivate(pf, state_file=str(state_file))
        assert pf.snapshot() == before
        assert not state_file.exists()


def test_apply_rolls_back_when_verification_fails(paths):
    state_file, backups = paths
    pf = FakePostfix(tables={"hash:/etc/postfix/transport": {"bounces@example.com": "bouncecoll:"},
                             "hash:/etc/postfix/virtual": {cp.ARCHIVE_ADDRESS: "someone@example.org"}},
                     main={"transport_maps": "hash:/etc/postfix/transport", "smtpd_sasl_auth_enable": "no",
                           "virtual_alias_maps": "hash:/etc/postfix/virtual"})
    before = pf.snapshot()
    with pytest.raises(cp.PlanError, match="rewrites"):
        cp.apply(pf, cp.make_plan(pf, []), state_file=str(state_file), backup_root=str(backups), now="T3")
    assert pf.snapshot() == before


def test_apply_refuses_twice_and_when_services_exist(paths):
    state_file, backups = paths
    pf = FakePostfix()
    cp.apply(pf, cp.make_plan(pf, []), state_file=str(state_file), backup_root=str(backups), now="T4")
    with pytest.raises(cp.PlanError, match="already exists"):
        cp.make_plan(pf, [])


def test_never_called_by_lifecycle_scripts():
    for name in ("install.sh", "update.sh", "rollback.sh", "uninstall.sh"):
        assert "capture_postfix" not in (ROOT / "deploy" / name).read_text()
