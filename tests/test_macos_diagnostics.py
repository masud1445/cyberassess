"""Sanitized diagnostic snapshots; no native macOS command executes here."""

import json
import re
import subprocess

import pytest

from cyberassess.collectors import macos
from scripts import diagnose_macos as diagnostics
from test_macos_remaining_four import (
    AUTO_TIME, LOCK, SCREEN, SYSTEM_TIME, TIME, NativeOutput, cocoa,
    preferences, probe,
)


SOURCES = {"screen_lock", "screen_lock_delay", "network_time"}


@pytest.fixture(autouse=True)
def synthetic_macos_context(monkeypatch):
    monkeypatch.setattr(diagnostics.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: True)


def diagnose(responses=None):
    runner = NativeOutput(responses)
    return diagnostics.diagnose(runner=runner), runner


@pytest.mark.parametrize("message,required,delay", [
    ("screenLock delay is immediate", True, 0),
    ("screenLock delay is 45 seconds", True, 45),
    ("screenLock is off", False, None),
])
def test_native_screen_snapshot_preserves_known_requirement_and_delay(message, required, delay):
    result, runner = diagnose({SCREEN: (0, "", cocoa(message))})
    native = result["native_probes"]["screen_lock"]
    assert native["status"] == "known"
    assert native["reason"] == "recognized"
    assert native["state"] == {"password_required": required, "seconds": delay}
    assert native["exit_status"] == 0
    assert native["stdout_present"] is False
    assert native["stderr_present"] is True
    assert result["selected_evidence"]["screen_lock"]["value"] is required
    assert result["selected_evidence"]["screen_lock_delay"]["value"] == delay
    assert result["selected_evidence"]["screen_lock_delay"]["available"] is (delay is not None)
    assert [command for command, _ in runner.calls].count(SCREEN) == 1
    assert "314:2718" not in json.dumps(result)
    assert "2026-10-25" not in json.dumps(result)


@pytest.mark.parametrize("command,key,output,value", [
    (SYSTEM_TIME, "system_network_time", "Network Time: On", True),
    (SYSTEM_TIME, "system_network_time", "Network Time: Off", False),
    (AUTO_TIME, "automatic_time", "Automatic time is enabled", True),
    (AUTO_TIME, "automatic_time", "Automatic time is disabled", False),
])
def test_native_time_snapshot_retains_explicit_on_off_values(command, key, output, value):
    result, _ = diagnose({command: output})
    assert result["native_probes"][key]["status"] == "known"
    assert result["native_probes"][key]["state"] is value
    assert result["selected_evidence"]["network_time"]["available"] is True
    assert result["selected_evidence"]["network_time"]["value"] is value


@pytest.mark.parametrize("key,value,source", [
    ("askForPassword", True, "screen_lock"),
    ("askForPassword", False, "screen_lock"),
    ("askForPasswordDelay", 0, "screen_lock_delay"),
    ("askForPasswordDelay", 45, "screen_lock_delay"),
])
def test_resolved_preference_snapshot_is_distinct_from_an_unavailable_native_getter(key, value, source):
    result, _ = diagnose({probe(LOCK, key): preferences(value, explicit_current_host=value)})
    assert result["selected_evidence"][source]["available"] is True
    assert result["selected_evidence"][source]["value"] == value
    assert result["native_probes"]["screen_lock"]["status"] == "unavailable"
    pref = result["preferences"][source]
    assert pref["status"] == "known"
    assert pref["value"] == value
    assert pref["explicit_current_host"] == value


def test_missing_keys_and_native_status_do_not_create_false_or_zero_values():
    result, _ = diagnose({
        probe(LOCK, "askForPassword"): preferences(None),
        probe(LOCK, "askForPasswordDelay"): preferences(None),
        probe(TIME, "TMAutomaticTimeOnlyEnabled"): preferences(None),
    })
    assert set(result["selected_evidence"]) == SOURCES
    for item in result["selected_evidence"].values():
        assert item["available"] is False
        assert item["value"] is None
    for item in result["preferences"].values():
        assert item["available"] is False
        assert item["value"] is None


@pytest.mark.parametrize("failure,reason", [
    ((0, "", ""), "empty-output"),
    ((0, "unknown native status private-token", ""), "unrecognized-output"),
    ((0, "Network Time: On\nNetwork Time: Off", ""), "unrecognized-output"),
    ((1, "Network Time: On", ""), "nonzero-exit"),
    ((0, "", "permission denied private-token"), "permission-denied"),
    (FileNotFoundError("/Users/private-person/private-token"), "command-unavailable"),
    (subprocess.TimeoutExpired(["native"], 10, output="private-token"), "timeout"),
])
def test_native_failures_are_classified_without_serializing_diagnostics(failure, reason):
    result, _ = diagnose({SCREEN: failure, SYSTEM_TIME: failure, AUTO_TIME: failure})
    for item in result["selected_evidence"].values():
        assert item["available"] is False
        assert item["value"] is None
    for item in result["native_probes"].values():
        assert item["status"] == "unavailable"
        assert item["state"] is None
        assert item["reason"] == reason
    serialized = json.dumps(result)
    assert "private-token" not in serialized
    assert "private-person" not in serialized
    assert "/Users/" not in serialized


def test_managed_time_enforcement_is_labelled_and_independently_verified():
    import plistlib

    policy = (
        "/usr/bin/plutil", "-extract", "TMAutomaticTimeOnlyEnabled", "xml1", "-o", "-",
        "/Library/Managed Preferences/com.apple.timed.plist",
    )
    result, _ = diagnose({
        probe(TIME, "TMAutomaticTimeOnlyEnabled"): preferences(True, managed=True),
        policy: plistlib.dumps(True).decode(),
    })
    assert result["selected_evidence"]["network_time"]["available"] is True
    assert result["selected_evidence"]["network_time"]["value"] is True
    pref = result["preferences"]["network_time_enforcement"]
    assert pref["managed"] is True
    assert pref["value"] is True
    assert pref["interpretation"] == "enforcement-only-not-automatic-time-status"
    assert all(item["status"] == "unavailable" for item in result["native_probes"].values())


@pytest.mark.parametrize("value", [True, False])
def test_unforced_timed_preference_never_becomes_an_automatic_time_status(value):
    result, _ = diagnose({probe(TIME, "TMAutomaticTimeOnlyEnabled"): preferences(value, machine_any_host=value)})
    assert result["preferences"]["network_time_enforcement"]["value"] is value
    assert result["selected_evidence"]["network_time"]["available"] is False
    assert result["selected_evidence"]["network_time"]["value"] is None


def test_unverified_console_context_does_not_probe_screen_or_user_preferences(monkeypatch):
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: False)
    result, runner = diagnose({SCREEN: "screenLock delay is immediate"})
    assert result["console_context_safe_at_start"] is False
    assert result["native_probes"]["screen_lock"]["status"] == "not-run"
    for source in ("screen_lock", "screen_lock_delay"):
        assert result["selected_evidence"][source]["available"] is False
        assert result["preferences"][source]["status"] == "not-run"
    assert SCREEN not in [command for command, _ in runner.calls]
    assert not any(command[-2:] in ((LOCK, "askForPassword"), (LOCK, "askForPasswordDelay")) for command, _ in runner.calls)


def test_unknown_preference_fields_and_reason_are_not_serialized():
    payload = json.loads(preferences(True, explicit_any_host=True))
    payload["private-token"] = {"path": "/Users/private-person/private-token"}
    payload["reason"] = "private-token"
    result, _ = diagnose({probe(LOCK, "askForPassword"): json.dumps(payload)})
    assert result["preferences"]["screen_lock"]["reason"] == "invalid-payload"
    assert "private-token" not in json.dumps(result)
    assert "/Users/private-person" not in json.dumps(result)


@pytest.mark.parametrize("reason", [
    "ambiguous-user-context", "unsupported-platform", "native-preference-read-unavailable",
])
def test_failed_preference_probe_cannot_promote_injected_partial_scalars(reason):
    result, _ = diagnose({
        probe(LOCK, "askForPassword"): preferences(
            None, reason=reason, explicit_current_host=True,
        ),
    })
    selected = result["selected_evidence"]["screen_lock"]
    pref = result["preferences"]["screen_lock"]
    assert selected["available"] is False
    assert selected["value"] is None
    assert pref["available"] is False
    assert pref["value"] is None
    assert pref["status"] != "known"


def test_partial_configuration_is_not_mislabelled_as_a_resolved_native_value():
    result, _ = diagnose({
        probe(LOCK, "askForPassword"): preferences(None, explicit_current_host=True),
    })
    pref = result["preferences"]["screen_lock"]
    assert pref["available"] is False
    assert pref["value"] is None
    assert pref["explicit_current_host"] is True
    selected = result["selected_evidence"]["screen_lock"]
    assert selected["available"] is True
    assert selected["value"] is True
    assert "explicit configured current-user" in selected["summary"]
    assert "native screen-lock status unavailable" in selected["summary"]


def test_unreadable_scope_is_distinguished_from_an_absent_value():
    result, _ = diagnose({
        probe(LOCK, "askForPassword"): preferences(
            None, explicit_any_host=True, unreadable_scopes=["explicit_current_host"],
        ),
    })
    pref = result["preferences"]["screen_lock"]
    assert pref["value"] is None
    assert pref["explicit_current_host"] is None
    assert pref["unreadable_scopes"] == ["explicit_current_host"]
    assert result["selected_evidence"]["screen_lock"]["available"] is False
    assert result["selected_evidence"]["screen_lock"]["value"] is None


def test_untrusted_scope_names_are_not_serialized():
    result, _ = diagnose({
        probe(LOCK, "askForPassword"): preferences(
            None, unreadable_scopes=["/Users/private-person/private-token"],
        ),
    })
    pref = result["preferences"]["screen_lock"]
    assert pref["reason"] == "invalid-payload"
    assert pref["unreadable_scopes"] == []
    assert "private-person" not in json.dumps(result)
    assert "private-token" not in json.dumps(result)


def test_diagnostic_scope_is_fixed_read_only_and_never_enables_sudo():
    result, runner = diagnose({
        SCREEN: (1, "", "permission denied"),
        SYSTEM_TIME: (1, "", "permission denied"),
        AUTO_TIME: (1, "", "permission denied"),
        ("/usr/bin/sudo", "-n", "-k", "--", *SYSTEM_TIME): "Network Time: On",
    })
    assert result["format"] == "cyberassess-macos-diagnostics-v1"
    assert result["available"] is True
    assert result["read_only"] is True
    assert result["elevated_reads"] is False
    assert result["reason"] == "completed"
    fingerprints = result["source_fingerprints"]
    assert set(fingerprints) == {"macos.py", "_macos_status.py", "_macos_preferences.py"}
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in fingerprints.values())
    for command, options in runner.calls:
        assert command[0] != "/usr/bin/sudo"
        assert command in (SCREEN, SYSTEM_TIME, AUTO_TIME) or (
            command[0] == macos.sys.executable
            and command[-2:] in (
                (LOCK, "askForPassword"), (LOCK, "askForPasswordDelay"),
                (TIME, "TMAutomaticTimeOnlyEnabled"),
            )
        )
        assert options["stdin"] == subprocess.DEVNULL
        assert options["timeout"] == 10
        assert options["shell"] is False
        assert "input" not in options


def test_unsupported_platform_refuses_before_any_collector_or_native_command(monkeypatch):
    monkeypatch.setattr(diagnostics.platform, "system", lambda: "Linux")
    monkeypatch.setattr(macos, "MacOSCollector", lambda **_: pytest.fail("unsupported platform must not construct a collector"))
    result = diagnostics.diagnose()
    assert result["available"] is False
    assert result["reason"] == "unsupported-platform"
    assert all(item["status"] == "not-run" for item in result["native_probes"].values())


def test_main_invalid_arguments_do_not_collect_or_echo_argument_values(monkeypatch, capsys):
    monkeypatch.setattr(diagnostics, "diagnose", lambda **_: pytest.fail("invalid arguments must not collect"))
    assert diagnostics.main(["--allow-elevated-read", "private-token"]) == 2
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result["reason"] == "invalid-arguments"
    assert result["available"] is False
    assert "private-token" not in output.out + output.err


def test_main_emits_only_json_and_returns_nonzero_on_unsupported_platform(monkeypatch, capsys):
    monkeypatch.setattr(diagnostics.platform, "system", lambda: "Windows")
    monkeypatch.setattr(macos, "MacOSCollector", lambda **_: pytest.fail("unsupported platform must not collect"))
    assert diagnostics.main([]) == 2
    output = capsys.readouterr()
    assert json.loads(output.out)["reason"] == "unsupported-platform"
    assert output.err == ""


def test_main_success_writes_the_sanitized_snapshot_as_json(monkeypatch, capsys):
    snapshot, _ = diagnose({SCREEN: "screenLock delay is 45 seconds", SYSTEM_TIME: "Network Time: Off"})
    monkeypatch.setattr(diagnostics, "diagnose", lambda: snapshot)
    assert diagnostics.main([]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == snapshot
    assert output.err == ""
