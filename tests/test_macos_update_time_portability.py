"""Machine-scoped update/time regressions; no native command executes here.

Fixtures distinguish the invoking user's application search from exact machine
configuration. Missing evidence and unrelated daemon/server observations never
stand in for an enabled or disabled security setting.
"""

import json
from types import SimpleNamespace

import pytest

from cyberassess.collectors import macos
from test_macos_remaining_four import (
    AUTO_TIME, SCHEDULE, SYSTEM_TIME, TIME, UPDATE, assess, cocoa, preferences,
    probe,
)


UPDATE_PROBE = probe(UPDATE, "AutomaticCheckEnabled")
TIME_PROBE = probe(TIME, "TMAutomaticTimeOnlyEnabled")


@pytest.fixture(autouse=True)
def no_console_user_native_query(monkeypatch):
    # These tests exercise machine policy only; never inspect the test host.
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: False)


@pytest.mark.parametrize("field", ["machine_current_host", "machine_any_host"])
@pytest.mark.parametrize("value,status", [(True, "PASS"), (False, "FAIL")])
def test_exact_machine_update_configuration_survives_missing_app_value(field, value, status):
    bundle, _, results, runner = assess({
        UPDATE_PROBE: preferences(None, **{field: value}),
    })
    result = results["MAC-005"]
    assert result["status"] == status
    assert result["actual"] is value
    scope = bundle["evidence"]["update_check"]["_scope"]
    assert "explicit machine configuration" in scope
    assert "CoreFoundation" in scope
    assert "effective resolved machine preference" not in scope
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)


@pytest.mark.parametrize("reason", [
    "ambiguous-user-context", "native-preference-read-unavailable",
    "unsupported-query", "unsupported-platform", "unexpected-probe-failure",
])
def test_partial_machine_payload_cannot_bypass_a_failed_or_unsafe_native_probe(reason):
    _, _, results, _ = assess({
        UPDATE_PROBE: preferences(None, reason=reason, machine_any_host=True),
    })
    assert results["MAC-005"]["status"] == "ERROR"
    assert results["MAC-005"]["actual"] is None


@pytest.mark.parametrize("machine,app,status", [(True, False, "PASS"), (False, True, "FAIL")])
@pytest.mark.parametrize("field", ["machine_current_host", "machine_any_host"])
def test_user_app_value_does_not_override_exact_unmanaged_machine_update_configuration(machine, app, status, field):
    _, _, results, _ = assess({
        UPDATE_PROBE: preferences(app, explicit_any_host=app, **{field: machine}),
    })
    assert results["MAC-005"]["status"] == status
    assert results["MAC-005"]["actual"] is machine


@pytest.mark.parametrize("value", [True, False, None])
def test_user_only_update_value_cannot_become_machine_evidence(value):
    _, _, results, _ = assess({
        UPDATE_PROBE: preferences(value, explicit_current_host=value, explicit_any_host=value),
    })
    assert results["MAC-005"]["status"] == "ERROR"
    assert results["MAC-005"]["actual"] is None


@pytest.mark.parametrize("managed,managed_available", [(False, False), (True, False), (True, True)])
@pytest.mark.parametrize("value", [True, False])
def test_exact_machine_update_configuration_cannot_bypass_unresolved_management(managed, managed_available, value):
    _, _, results, _ = assess({
        UPDATE_PROBE: preferences(
            value, managed=managed, managed_available=managed_available,
            machine_current_host=value, machine_any_host=value,
        ),
    })
    assert results["MAC-005"]["status"] == "ERROR"
    assert results["MAC-005"]["actual"] is None


@pytest.mark.parametrize("host,anyhost,status", [(True, False, "PASS"), (False, True, "FAIL")])
def test_exact_machine_current_host_update_value_precedes_any_host(host, anyhost, status):
    _, _, results, _ = assess({
        UPDATE_PROBE: preferences(None, machine_current_host=host, machine_any_host=anyhost),
    })
    assert results["MAC-005"]["status"] == status
    assert results["MAC-005"]["actual"] is host


@pytest.mark.parametrize("value", [True, False])
def test_unreadable_current_host_is_not_absence_for_machine_update_fallback(value):
    _, _, results, _ = assess({
        UPDATE_PROBE: preferences(
            None, machine_any_host=value, unreadable_scopes=["machine_current_host"],
        ),
    })
    assert results["MAC-005"]["status"] == "ERROR"
    assert results["MAC-005"]["actual"] is None


@pytest.mark.parametrize("malformed", ["true", 2, -1, 0.5, {}, []])
def test_malformed_current_host_cannot_fall_through_to_valid_machine_any_host(malformed):
    _, _, results, _ = assess({
        UPDATE_PROBE: preferences(None, machine_current_host=malformed, machine_any_host=True),
    })
    assert results["MAC-005"]["status"] == "ERROR"
    assert results["MAC-005"]["actual"] is None


@pytest.mark.parametrize("schedule,machine", [("on", False), ("off", True)])
def test_native_update_status_and_exact_machine_configuration_disagreement_is_error(schedule, machine):
    _, _, results, _ = assess({
        SCHEDULE: "Automatic check is " + schedule,
        UPDATE_PROBE: preferences(None, machine_any_host=machine),
    })
    assert results["MAC-005"]["status"] == "ERROR"
    assert results["MAC-005"]["actual"] is None
    assert "disagree" in results["MAC-005"]["raw_evidence"]


@pytest.mark.parametrize("home,username,uid,hostname", [
    ("/Users/student.one", "student.one", 501, "Seminar-Mac"),
    ("/Volumes/External Users/Researcher", "researcher", 782, "Research-Lab"),
    ("/Network/Servers/Accounts/instructor", "instructor", 1042, "Department-Desktop"),
])
@pytest.mark.parametrize("value,status", [(True, "PASS"), (False, "FAIL")])
def test_machine_update_collection_is_independent_of_user_home_and_hostname(monkeypatch, home, username, uid, hostname, value, status):
    import os
    import socket
    import sys

    monkeypatch.setenv("HOME", home)
    monkeypatch.setattr(os, "getuid", lambda: uid, raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: uid, raising=False)
    account = SimpleNamespace(pw_dir=home, pw_name=username, pw_uid=uid)
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwuid=lambda _: account))
    monkeypatch.setattr(socket, "gethostname", lambda: hostname)
    bundle, _, results, runner = assess({
        UPDATE_PROBE: preferences(None, machine_any_host=value),
    })
    assert results["MAC-005"]["status"] == status
    evidence = json.dumps(bundle["evidence"]["update_check"])
    assert all(identifier not in evidence for identifier in (home, username, hostname))
    machine_commands = [command for command, _ in runner.calls if command == SCHEDULE or command == UPDATE_PROBE]
    assert machine_commands == [SCHEDULE, UPDATE_PROBE]


@pytest.mark.parametrize("timed_value", [True, False, None])
def test_unforced_timed_value_and_daemon_server_observations_do_not_establish_automatic_time(timed_value):
    daemon = ("/bin/launchctl", "print", "system/com.apple.timed")
    server = ("/usr/sbin/systemsetup", "-getnetworktimeserver")
    bundle, _, results, runner = assess({
        TIME_PROBE: preferences(timed_value, machine_any_host=timed_value),
        daemon: "system/com.apple.timed = { state = running }",
        server: "Network Time Server: time.example.test",
    })
    assert results["MAC-012"]["status"] == "ERROR"
    assert results["MAC-012"]["actual"] is None
    calls = [command for command, _ in runner.calls]
    assert daemon not in calls
    assert server not in calls
    assert "time.example.test" not in json.dumps(bundle)


@pytest.mark.parametrize("command,response,status,value", [
    (SYSTEM_TIME, "Network Time: On", "PASS", True),
    (SYSTEM_TIME, (0, "", "Network Time: Off"), "FAIL", False),
    (SYSTEM_TIME, (0, "", cocoa("Network Time: On", "systemsetup")), "PASS", True),
    (AUTO_TIME, "Automatic time is enabled", "PASS", True),
    (AUTO_TIME, (0, "", cocoa("automaticTime is disabled")), "FAIL", False),
])
def test_explicit_supported_time_status_still_resolves_without_preferences(command, response, status, value):
    _, _, results, runner = assess({command: response})
    assert results["MAC-012"]["status"] == status
    assert results["MAC-012"]["actual"] is value
    assert not any(call[0] == "/usr/bin/sudo" for call, _ in runner.calls)


@pytest.mark.parametrize("failure", [
    (0, "", ""),
    (127, "", "unsupported getter: private diagnostic"),
    (1, "Network Time: On", ""),
    (0, "Network Time Server: time.example.test", ""),
    (0, "Network Time: On\nNetwork Time: Off", ""),
    (0, "Network Time: On", "permission denied: private diagnostic"),
    PermissionError("private diagnostic"),
])
def test_unavailable_time_state_never_becomes_false_or_true_and_never_prompts(failure):
    bundle, _, results, runner = assess({SYSTEM_TIME: failure, AUTO_TIME: failure})
    assert results["MAC-012"]["status"] == "ERROR"
    assert results["MAC-012"]["actual"] is None
    assert "private diagnostic" not in json.dumps(bundle)
    assert "time.example.test" not in json.dumps(bundle)
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)
    for _, options in runner.calls:
        assert options["stdin"] is not None
        assert options["timeout"] == 10
        assert options["shell"] is False


@pytest.mark.parametrize("command,control", [
    (SCHEDULE, "MAC-005"), (SYSTEM_TIME, "MAC-012"),
    (AUTO_TIME, "MAC-012"),
])
@pytest.mark.parametrize("response,reason", [
    ((0, "", ""), "returned no status output"),
    ((1, "", "private diagnostic"), "returned a nonzero exit status"),
    ((0, "private diagnostic", ""), "unrecognized or ambiguous"),
])
def test_status_diagnostics_distinguish_failures_without_disclosing_raw_output(command, control, response, reason):
    bundle, _, results, _ = assess({command: response})
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None
    assert reason in results[control]["raw_evidence"]
    assert "private diagnostic" not in json.dumps(bundle)
