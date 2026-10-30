"""Actionable privilege limits; every native response is injected."""

import json

import pytest

from cyberassess.collectors import macos
from test_macos_elevation import (
    DENIED, SCHEDULE, SUDO, TIME, collect, elevated_calls, extracted, plist,
    preference, probe,
)


TARGETS = [(SCHEDULE, "MAC-005"), (TIME, "MAC-012")]
AUTO_TIME = ("/usr/sbin/sysadminctl", "-automaticTime", "status")


@pytest.fixture(autouse=True)
def no_real_console_context(monkeypatch):
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: False)


@pytest.mark.parametrize("command,control", TARGETS)
@pytest.mark.parametrize("denied", [DENIED, PermissionError("private diagnostic")])
def test_unresolved_denied_getter_explains_existing_opt_in_without_running_sudo(command, control, denied):
    bundle, results, runner = collect({command: denied})
    result = results[control]
    assert result["status"] == "ERROR"
    assert result["actual"] is None
    assert "No privileged read was attempted" in result["raw_evidence"]
    assert "--allow-elevated-read" in result["raw_evidence"]
    assert "administrator-approved passwordless access" in result["raw_evidence"]
    assert "unsupported or ambiguous status remains ERROR" in result["raw_evidence"]
    assert "private diagnostic" not in json.dumps(bundle)
    assert elevated_calls(runner) == []


@pytest.mark.parametrize("command,control", TARGETS)
@pytest.mark.parametrize("failure", [
    (0, "", ""),
    (0, "unrecognized status private diagnostic", ""),
    (127, "", "unsupported command private diagnostic"),
    FileNotFoundError("private diagnostic"),
])
def test_unsupported_or_empty_getter_does_not_receive_unproven_privilege_advice(command, control, failure):
    bundle, results, runner = collect({command: failure})
    result = results[control]
    assert result["status"] == "ERROR"
    assert result["actual"] is None
    assert "No privileged read was attempted" not in result["raw_evidence"]
    assert "--allow-elevated-read" not in result["raw_evidence"]
    assert "private diagnostic" not in json.dumps(bundle)
    assert elevated_calls(runner) == []


@pytest.mark.parametrize("command,control,output,status", [
    (SCHEDULE, "MAC-005", "Automatic check is on", "PASS"),
    (SCHEDULE, "MAC-005", "Automatic check is off", "FAIL"),
    (TIME, "MAC-012", "Network Time: On", "PASS"),
    (TIME, "MAC-012", "Network Time: Off", "FAIL"),
])
def test_reliable_normal_status_has_no_privilege_guidance(command, control, output, status):
    _, results, runner = collect({command: output})
    assert results[control]["status"] == status
    assert "No privileged read was attempted" not in results[control]["raw_evidence"]
    assert "--allow-elevated-read" not in results[control]["raw_evidence"]
    assert elevated_calls(runner) == []


@pytest.mark.parametrize("value,status", [(True, "PASS"), (False, "FAIL")])
def test_reliable_machine_update_configuration_prevents_unneeded_privilege_advice(value, status):
    _, results, runner = collect({
        SCHEDULE: DENIED,
        probe("com.apple.SoftwareUpdate", "AutomaticCheckEnabled"): preference(value, machine_any_host=value),
    })
    assert results["MAC-005"]["status"] == status
    assert "--allow-elevated-read" not in results["MAC-005"]["raw_evidence"]
    assert elevated_calls(runner) == []


def test_verified_enforced_time_policy_prevents_unneeded_privilege_advice():
    _, results, runner = collect({
        TIME: DENIED,
        probe("com.apple.timed", "TMAutomaticTimeOnlyEnabled"): preference(True, managed=True),
        plist("TMAutomaticTimeOnlyEnabled", "/Library/Managed Preferences/com.apple.timed.plist"): extracted(True),
    })
    assert results["MAC-012"]["status"] == "PASS"
    assert "--allow-elevated-read" not in results["MAC-012"]["raw_evidence"]
    assert elevated_calls(runner) == []


@pytest.mark.parametrize("output,status", [
    ("Automatic time is enabled", "PASS"),
    ("Automatic time is disabled", "FAIL"),
])
def test_reliable_alternate_time_status_prevents_unneeded_privilege_advice(output, status):
    _, results, runner = collect({TIME: DENIED, AUTO_TIME: output})
    assert results["MAC-012"]["status"] == status
    assert "--allow-elevated-read" not in results["MAC-012"]["raw_evidence"]
    assert elevated_calls(runner) == []


@pytest.mark.parametrize("command,control", TARGETS)
def test_explicitly_requested_but_denied_retry_retains_actual_attempt_reason(command, control):
    _, results, runner = collect({
        command: DENIED,
        SUDO + command: (1, "", "sudo: a password is required"),
    }, allow=True)
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None
    assert "Explicit elevated read failed" in results[control]["raw_evidence"]
    assert "No privileged read was attempted" not in results[control]["raw_evidence"]
    assert elevated_calls(runner) == [SUDO + command]
