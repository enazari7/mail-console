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
        self.queued_archive = 0
        self.running = []

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
        # like postconf -h: a transport-specific parameter is unknown once its service is gone
        if name.startswith(cp.PIPE_SERVICE + "_") and (cp.PIPE_SERVICE, "unix") not in self.services:
            return ""
        return self.main.get(name, "")

    def main_cf_value(self, name):
        return self.main.get(name)

    def processes(self):
        return list(self.running)

    def main_expanded(self, name):
        value = self.main.get(name, "")
        return re.sub(r"\$(\w+)", lambda m: self.main.get(m.group(1), ""), value)

    def archive_copies_queued(self):
        return self.queued_archive

    def read_map(self):
        return self.map_written

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
        assert cp.deactivate(pf, state_file=str(state_file)) == []
        cp.finish(pf, state_file=str(state_file))
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


# --- review regressions ----------------------------------------------------------

def applied(paths, pf=None, **kw):
    state_file, backups = paths
    pf = pf or FakePostfix(**kw)
    cp.apply(pf, cp.make_plan(pf, []), state_file=str(state_file), backup_root=str(backups), now="T9")
    return pf


def test_finish_refuses_while_archive_copies_are_queued(paths):
    pf = applied(paths)
    cp.deactivate(pf, state_file=str(paths[0]))
    # Listener restored, but the route to the pipe stays while copies are queued.
    assert pf.query(cp.MAP_REF, cp.ARCHIVE_ADDRESS) == "mailconsole-archive:"
    assert ("mailconsole-archive", "unix") in pf.services
    pf.queued_archive = 3
    with pytest.raises(cp.PlanError, match="still carry the archive copy"):
        cp.finish(pf, state_file=str(paths[0]))
    pf.queued_archive = 0
    cp.finish(pf, state_file=str(paths[0]))
    assert ("mailconsole-archive", "unix") not in pf.services


def test_finish_requires_phase_one(paths):
    pf = applied(paths)
    with pytest.raises(cp.PlanError, match="run 'deactivate'"):
        cp.finish(pf, state_file=str(paths[0]))


def test_later_transport_map_edits_survive_deactivation(paths):
    pf = applied(paths)
    pf.main["transport_maps"] += ", hash:/etc/postfix/bounce_transport"   # admin edit after apply
    cp.deactivate(pf, state_file=str(paths[0]))
    cp.finish(pf, state_file=str(paths[0]))
    assert pf.main["transport_maps"] == "hash:/etc/postfix/transport, hash:/etc/postfix/bounce_transport"


def test_existing_always_bcc_is_refused():
    with pytest.raises(cp.PlanError, match="always_bcc is already in use"):
        cp.make_plan(FakePostfix(main={"transport_maps": "", "always_bcc": "compliance@example.org"}), [])
    master = PRODUCTION_MASTER.replace("cleanup    unix  n       -       y       -       0       cleanup",
                                       "cleanup    unix  n       -       y       -       0       cleanup "
                                       "-o always_bcc=compliance@example.org")
    with pytest.raises(cp.PlanError, match="always_bcc is already in use"):
        cp.make_plan(FakePostfix(master), [])


def test_manual_listener_edit_warns_and_still_finishes(paths):
    pf = applied(paths)
    pf.params[("91.107.182.219:submission", "inet")]["smtpd_tls_auth_only"] = "no"   # edited by hand
    warnings = cp.deactivate(pf, state_file=str(paths[0]))
    assert any("edited since apply" in w for w in warnings)
    cp.finish(pf, state_file=str(paths[0]))
    assert not paths[0].exists()
    assert cp.make_plan(pf, [])   # can be applied again


def test_interrupt_during_apply_restores(paths, monkeypatch):
    state_file, backups = paths
    pf = FakePostfix()
    before = pf.snapshot()
    real = pf.set_service

    def boom(name, type_, line):
        if name == cp.PIPE_SERVICE:
            raise KeyboardInterrupt
        return real(name, type_, line)
    monkeypatch.setattr(pf, "set_service", boom)
    with pytest.raises(KeyboardInterrupt):
        cp.apply(pf, cp.make_plan(pf, []), state_file=str(state_file), backup_root=str(backups), now="T10")
    assert pf.snapshot() == before


def test_port_25_is_refused_even_with_global_sasl():
    pf = FakePostfix(main={"transport_maps": "", "smtpd_sasl_auth_enable": "yes"})
    with pytest.raises(cp.PlanError, match="not a submission port"):
        cp.make_plan(pf, ["smtp"])


def test_verify_expands_variables_and_service_overrides(paths):
    pf = FakePostfix(main={"transport_maps": "hash:/etc/postfix/transport", "smtpd_sasl_auth_enable": "no",
                           "my_aliases": "hash:/etc/postfix/virtual", "virtual_alias_maps": "$my_aliases"},
                     tables={"hash:/etc/postfix/transport": {},
                             "hash:/etc/postfix/virtual": {cp.ARCHIVE_ADDRESS: "elsewhere@example.org"}})
    with pytest.raises(cp.PlanError, match="rewrites"):
        applied(paths, pf)
    master = (PRODUCTION_MASTER
              + "rewrite    unix  -       -       y       -       -       trivial-rewrite -o transport_maps=hash:/x\n")
    with pytest.raises(cp.PlanError, match="overrides transport_maps"):
        cp.make_plan(FakePostfix(master), [])


def test_global_cleanup_service_name_is_the_base(paths):
    master = PRODUCTION_MASTER + "mycleanup  unix  n       -       n       -       0       cleanup\n"
    plan = cp.make_plan(FakePostfix(master, main={"transport_maps": "", "cleanup_service_name": "mycleanup"}), [])
    assert plan.base.name == "mycleanup"


def test_existing_map_file_is_restored(paths):
    pf = FakePostfix()
    pf.map_written = "# operator's own content\n"
    applied(paths, pf)
    cp.deactivate(pf, state_file=str(paths[0]))
    cp.finish(pf, state_file=str(paths[0]))
    assert pf.map_written == "# operator's own content\n"


# --- second review regressions -------------------------------------------------------

def test_recipient_limit_is_removed_although_postconf_hides_it(paths):
    pf = applied(paths)
    assert pf.main[cp.LIMIT_PARAM] == "1"
    cp.deactivate(pf, state_file=str(paths[0]))
    cp.finish(pf, state_file=str(paths[0]))
    assert cp.LIMIT_PARAM not in pf.main      # main.cf itself, not what postconf -h shows


def test_rollback_after_failed_apply_removes_the_limit(paths):
    pf = FakePostfix(main={"transport_maps": "hash:/etc/postfix/transport", "smtpd_sasl_auth_enable": "no",
                           "virtual_alias_maps": "hash:/etc/postfix/virtual"},
                     tables={"hash:/etc/postfix/transport": {},
                             "hash:/etc/postfix/virtual": {cp.ARCHIVE_ADDRESS: "elsewhere@example.org"}})
    with pytest.raises(cp.PlanError):
        applied(paths, pf)
    assert cp.LIMIT_PARAM not in pf.main


def test_finish_refuses_while_another_service_uses_cleanup_archive(paths):
    pf = applied(paths)
    # An admin copied the captured listener (with its override) to a new IPv6 listener after apply.
    pf.set_service("[2001:db8::1]:submission", "inet",
                   "[2001:db8::1]:submission inet n - y - - smtpd -o smtpd_sasl_auth_enable=yes "
                   "-o cleanup_service_name=cleanup-archive")
    warnings = cp.deactivate(pf, state_file=str(paths[0]))
    assert any("[2001:db8::1]:submission/inet" in w for w in warnings)
    with pytest.raises(cp.PlanError, match=r"still in use.*2001:db8::1"):
        cp.finish(pf, state_file=str(paths[0]))
    assert ("cleanup-archive", "unix") in pf.services          # nothing removed
    pf.remove_service_param("[2001:db8::1]:submission", "inet", "cleanup_service_name")
    cp.finish(pf, state_file=str(paths[0]))


def test_finish_refuses_a_main_cf_reference_to_the_pipe(paths):
    pf = applied(paths)
    pf.main["content_filter"] = "mailconsole-archive:dummy"
    cp.deactivate(pf, state_file=str(paths[0]))
    with pytest.raises(cp.PlanError, match="content_filter"):
        cp.finish(pf, state_file=str(paths[0]))


def test_finish_refuses_while_processes_still_use_cleanup_archive(paths):
    pf = applied(paths)
    cp.deactivate(pf, state_file=str(paths[0]))
    # 'postfix reload' not run yet, or a long SMTP session from before it.
    pf.running = ["smtpd -n 91.107.182.219:submission -t inet -u -c -o cleanup_service_name=cleanup-archive"]
    with pytest.raises(cp.PlanError, match="running Postfix process"):
        cp.finish(pf, state_file=str(paths[0]))
    pf.running = ["cleanup -z -n cleanup-archive -t unix -u -c -o always_bcc=archive@mail-console.invalid"]
    with pytest.raises(cp.PlanError, match="running Postfix process"):
        cp.finish(pf, state_file=str(paths[0]))
    pf.running = ["cleanup -z -t unix -u -c", "smtpd -n 127.0.0.1:submission -t inet -u -c"]
    cp.finish(pf, state_file=str(paths[0]))


def test_finish_does_not_bring_back_a_map_removed_after_apply(paths):
    pf = applied(paths)
    pf.main["transport_maps"] = cp.MAP_REF            # admin dropped hash:/etc/postfix/transport on purpose
    cp.deactivate(pf, state_file=str(paths[0]))
    cp.finish(pf, state_file=str(paths[0]))
    assert pf.main["transport_maps"] == ""


def test_finish_leaves_other_tables_byte_for_byte(paths):
    inline = "inline:{ a@example.com=discard:, b@example.com=bouncecoll: }"
    pf = FakePostfix(main={"transport_maps": inline, "smtpd_sasl_auth_enable": "no"})
    applied(paths, pf)
    pf.main["transport_maps"] += ", hash:/etc/postfix/later"
    cp.deactivate(pf, state_file=str(paths[0]))
    cp.finish(pf, state_file=str(paths[0]))
    assert pf.main["transport_maps"] == inline + ", hash:/etc/postfix/later"


def test_no_address_mappings_is_refused_and_detected():
    with pytest.raises(cp.PlanError, match="no_address_mappings"):
        cp.make_plan(FakePostfix(main={"transport_maps": "", "receive_override_options": "no_address_mappings"}), [])
    master = PRODUCTION_MASTER.replace("-o milter_macro_daemon_name=ORIGINATING\n127.0.0.1",
                                       "-o milter_macro_daemon_name=ORIGINATING "
                                       "-o receive_override_options=no_header_body_checks,no_address_mappings\n"
                                       "127.0.0.1", 1)
    with pytest.raises(cp.PlanError, match="no_address_mappings"):
        cp.make_plan(FakePostfix(master), [])


def test_verify_reports_no_address_mappings_added_after_apply(paths):
    pf = applied(paths)
    pf.main["receive_override_options"] = "no_address_mappings"
    assert any("no_address_mappings" in p for p in cp.verify(pf, json.loads(paths[0].read_text())))


def test_command_line_offers_no_force(paths, monkeypatch, capsys):
    monkeypatch.setattr(cp.os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit):
        cp.main(["deactivate", "--finish", "--force"], pf=FakePostfix())
    assert "unrecognized arguments: --force" in capsys.readouterr().err


def test_main_cf_value_reads_the_file(tmp_path):
    (tmp_path / "main.cf").write_text(f"# x\n{cp.LIMIT_PARAM} = 7\n{cp.LIMIT_PARAM}=1\nother = 2\n")
    assert cp.Postfix(config_dir=str(tmp_path)).main_cf_value(cp.LIMIT_PARAM) == "1"
    assert cp.Postfix(config_dir=str(tmp_path)).main_cf_value("missing") is None
