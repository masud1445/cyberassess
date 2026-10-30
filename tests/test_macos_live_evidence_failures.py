"""Live-style source failures with injected output; never query the test host."""

import json
import plistlib
import subprocess

import pytest

from cyberassess.collectors import macos
from test_macos_remaining_four import (
    AUTO_TIME, LOCK, SCHEDULE, SCREEN, SYSTEM_TIME, TIME, UPDATE,
    assess, preferences, probe,
)


@pytest.fixture(autouse=True)
def matching_context(monkeypatch):
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: True)


@pytest.mark.parametrize("control", ["MAC-010", "MAC-011"])
@pytest.mark.parametrize("failure,reason", [
    ((0, "", ""), "returned no status output"),
    ((127, "", "unknown option private-value"), "returned a nonzero exit status"),
    ((0, "unsupported format private-value", ""), "unrecognized or ambiguous"),
    ((0, "", "Operation not permitted private-value"), "requires additional local privileges"),
    (PermissionError("private-value"), "requires additional local privileges"),
    (FileNotFoundError("private-value"), "could not be executed"),
    (subprocess.TimeoutExpired(["native"], 10), "timed out"),
])
def test_screen_error_retains_sanitized_native_stage_failure(control, failure, reason):
    bundle, _, results, runner = assess({SCREEN: failure})
    result = results[control]
    assert result["status"] == "ERROR"
    assert result["actual"] is None
    assert "Native screen-lock getter:" in result["raw_evidence"]
    assert reason in result["raw_evidence"]
    assert "private-value" not in json.dumps(bundle)
    assert [command for command, _ in runner.calls].count(SCREEN) == 1
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)


def test_skipped_screen_getter_is_visible_without_inspecting_another_user(monkeypatch):
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: False)
    _, _, results, runner = assess({SCREEN: "screenLock delay is immediate"})
    for control in ("MAC-010", "MAC-011"):
        assert results[control]["status"] == "ERROR"
        assert "Native screen-lock getter skipped" in results[control]["raw_evidence"]
        assert "context could not be verified" in results[control]["raw_evidence"]
        assert "logged-in console user" in results[control]["raw_evidence"]
    commands = [command for command, _ in runner.calls]
    assert SCREEN not in commands
    assert probe(LOCK, "askForPassword") not in commands
    assert probe(LOCK, "askForPasswordDelay") not in commands


@pytest.mark.parametrize("key,value,control,status", [
    ("askForPassword", True, "MAC-010", "PASS"),
    ("askForPassword", False, "MAC-010", "FAIL"),
    ("askForPasswordDelay", 0, "MAC-011", "PASS"),
    ("askForPasswordDelay", 60, "MAC-011", "FAIL"),
])
def test_readable_own_user_preferences_remain_a_fallback_for_unavailable_native_status(key, value, control, status):
    _, _, results, runner = assess({
        SCREEN: PermissionError("denied"),
        probe(LOCK, key): preferences(value, explicit_current_host=value),
    })
    assert results[control]["status"] == status
    assert results[control]["actual"] == value
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)


@pytest.mark.parametrize("native", [
    "screenLock delay is immediate\nscreenLock is off",
    "screenLock delay is 0 seconds\nscreenLock delay is 60 seconds",
    (0, "screenLock delay is immediate", "screenLock is off"),
])
def test_conflicting_native_screen_states_cannot_fall_back_to_secure_preferences(native):
    _, _, results, _ = assess({
        SCREEN: native,
        probe(LOCK, "askForPassword"): preferences(True, managed=True),
        probe(LOCK, "askForPasswordDelay"): preferences(0, managed=True),
    })
    for control in ("MAC-010", "MAC-011"):
        assert results[control]["status"] == "ERROR"
        assert results[control]["actual"] is None
        assert "contradictory known states" in results[control]["raw_evidence"]


def test_conflicting_schedule_states_cannot_fall_back_to_a_readable_machine_setting():
    _, _, results, _ = assess({
        SCHEDULE: "Automatic check is on\nAutomatic check is off",
        probe(UPDATE, "AutomaticCheckEnabled"): preferences(True, machine_any_host=True),
    })
    assert results["MAC-005"]["status"] == "ERROR"
    assert results["MAC-005"]["actual"] is None
    assert "contradictory known states" in results["MAC-005"]["raw_evidence"]


@pytest.mark.parametrize("conflicting,output,other,other_output", [
    (SYSTEM_TIME, "Network Time: On\nNetwork Time: Off", AUTO_TIME, "Automatic time is enabled"),
    (AUTO_TIME, "Automatic time is enabled\nAutomatic time is disabled", SYSTEM_TIME, "Network Time: On"),
])
def test_conflicting_native_time_states_cannot_use_another_getter_or_managed_policy(conflicting, output, other, other_output):
    policy = (
        "/usr/bin/plutil", "-extract", "TMAutomaticTimeOnlyEnabled", "xml1", "-o", "-",
        "/Library/Managed Preferences/com.apple.timed.plist",
    )
    _, _, results, _ = assess({
        conflicting: output,
        other: other_output,
        probe(TIME, "TMAutomaticTimeOnlyEnabled"): preferences(True, managed=True),
        policy: plistlib.dumps(True).decode(),
    })
    assert results["MAC-012"]["status"] == "ERROR"
    assert results["MAC-012"]["actual"] is None
    assert "contradictory known states" in results["MAC-012"]["raw_evidence"]
