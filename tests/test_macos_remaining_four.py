"""Remaining macOS effective-state regressions using injected native output.

The sysadminctl time sentences test a strict interpretation contract, not a
claim that every macOS release emits that wording. Unknown output stays ERROR.
No command, preference API, privilege escalation or live Mac is used here.
"""

import json
from pathlib import Path
import plistlib
import subprocess
import sys

import pytest

from cyberassess.collectors import macos
from cyberassess.evaluator import evaluate_baseline
from cyberassess.profiles import build_profile_report


SCHEDULE = ("/usr/sbin/softwareupdate", "--schedule")
SYSTEM_TIME = ("/usr/sbin/systemsetup", "-getusingnetworktime")
AUTO_TIME = ("/usr/sbin/sysadminctl", "-automaticTime", "status")
SCREEN = ("/usr/sbin/sysadminctl", "-screenLock", "status")
UPDATE = "com.apple.SoftwareUpdate"
LOCK = "com.apple.screensaver"
TIME = "com.apple.timed"
CONTROLS = {"MAC-005", "MAC-010", "MAC-011", "MAC-012"}
MISSING = object()


def probe(domain, key):
    return (sys.executable, macos._PREFERENCE_HELPER, domain, key)


def preferences(value, *, managed=False, **observations):
    result = {
        "available": value is not None, "value": value,
        "managed": managed, "managed_available": True,
        "explicit_current_host": None, "explicit_any_host": None,
        "machine_current_host": None, "machine_any_host": None,
        "reason": "effective-preference-value" if value is not None else "missing-or-unreadable-effective-value",
    }
    result.update(observations)
    return json.dumps(result, allow_nan=False)


def cocoa(message, process="sysadminctl"):
    return f"2026-10-25 12:34:56.123 {process}[314:2718] {message}"


class NativeOutput:
    """Unspecified queries fail explicitly rather than receiving defaults."""

    def __init__(self, responses=None):
        self.responses = dict(responses or {})
        self.calls = []

    def __call__(self, command, **options):
        command = tuple(command)
        self.calls.append((command, {k: v for k, v in options.items() if k != "env"}))
        baseline = {
            ("/usr/bin/fdesetup", "status"): "FileVault is On.",
            ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"): "Firewall is enabled. (State = 1)",
            ("/usr/bin/csrutil", "status"): "System Integrity Protection status: enabled.",
            ("/usr/sbin/spctl", "--status"): "assessments enabled",
            ("/usr/sbin/systemsetup", "-getremotelogin"): "Remote Login: Off",
        }
        for key in ("AutomaticDownload", "CriticalUpdateInstall", "ConfigDataInstall"):
            baseline[("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", key)] = "1"
        response = self.responses.get(command, baseline.get(command, MISSING))
        if isinstance(response, Exception):
            raise response
        if response is MISSING:
            return subprocess.CompletedProcess(command, 127, "", "")
        if isinstance(response, tuple):
            code, stdout, stderr = response
            return subprocess.CompletedProcess(command, code, stdout, stderr)
        return subprocess.CompletedProcess(command, 0, response, "")


@pytest.fixture(autouse=True)
def matched_invoking_console_user(monkeypatch):
    # Real identity safety is exercised in the native-status module's tests.
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: True)


def assess(responses=None):
    runner = NativeOutput(responses)
    bundle = macos.MacOSCollector(runner=runner).collect()
    controls = json.loads(Path("config/profiles/macos.json").read_text(encoding="utf-8"))
    assessment = evaluate_baseline(controls, bundle["evidence"])
    results = {result["control_id"]: result for result in assessment["results"]}
    return bundle, assessment, results, runner


@pytest.mark.parametrize("status,expected", [("on", "PASS"), ("off", "FAIL")])
@pytest.mark.parametrize("location", ["stdout", "stderr", "banner-and-cocoa"])
def test_update_status_can_resolve_absent_key_from_one_clean_native_stream(status, expected, location):
    message = "Automatic check is " + status
    response = message if location == "stdout" else (0, "", message)
    if location == "banner-and-cocoa":
        response = (0, "Software Update Tool\n", cocoa(message, "softwareupdate"))
    bundle, _, results, runner = assess({SCHEDULE: response})
    assert results["MAC-005"]["status"] == expected
    assert "explicit any-host value unavailable" in bundle["evidence"]["update_check"]["_scope"]
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)
    assert "314:2718" not in json.dumps(bundle)
    assert "2026-10-25 12:34:56" not in json.dumps(bundle)


@pytest.mark.parametrize("message,required,delay,delay_status", [
    ("screenLock delay is immediate", True, 0, "PASS"),
    ("screenLock delay is 0 seconds", True, 0, "PASS"),
    ("screenLock delay is 30 seconds", True, 30, "FAIL"),
    ("screenLock is off", False, None, "ERROR"),
])
@pytest.mark.parametrize("logged", [False, True])
def test_migrated_native_screen_state_resolves_without_legacy_preference_keys(message, required, delay, delay_status, logged):
    response = (0, "", cocoa(message)) if logged else message
    bundle, _, results, runner = assess({SCREEN: response})
    assert results["MAC-010"]["status"] == ("PASS" if required else "FAIL")
    assert results["MAC-010"]["actual"] is required
    assert results["MAC-011"]["status"] == delay_status
    assert results["MAC-011"]["actual"] == delay
    assert len([cmd for cmd, _ in runner.calls if cmd == SCREEN]) == 1
    assert not any(cmd[0] == "/usr/bin/defaults" and LOCK in cmd for cmd, _ in runner.calls)
    assert "314:2718" not in json.dumps(bundle)


def test_native_off_does_not_invent_zero_even_when_an_old_stored_delay_was_zero():
    _, _, results, _ = assess({
        SCREEN: "screenLock is off",
        probe(LOCK, "askForPasswordDelay"): preferences(0, explicit_any_host=0),
    })
    assert results["MAC-010"]["status"] == "FAIL"
    assert results["MAC-011"]["status"] == "ERROR"
    assert results["MAC-011"]["actual"] is None


def test_current_native_screen_status_can_supersede_stale_unforced_anyhost_values():
    _, _, results, _ = assess({
        SCREEN: "screenLock delay is immediate",
        probe(LOCK, "askForPassword"): preferences(False, explicit_any_host=False),
        probe(LOCK, "askForPasswordDelay"): preferences(300, explicit_any_host=300),
    })
    assert results["MAC-010"]["status"] == "PASS"
    assert results["MAC-011"]["status"] == "PASS"
    assert "explicit configured value=false" in results["MAC-010"]["raw_evidence"]
    assert "explicit configured value=300" in results["MAC-011"]["raw_evidence"]


@pytest.mark.parametrize("key,value,control", [
    ("askForPassword", False, "MAC-010"),
    ("askForPasswordDelay", 30, "MAC-011"),
])
def test_native_screen_state_conflicting_with_enforced_policy_is_error(key, value, control):
    _, _, results, _ = assess({
        SCREEN: "screenLock delay is immediate",
        probe(LOCK, key): preferences(value, managed=True),
    })
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None


@pytest.mark.parametrize("label", ["Automatic Time", "Automatic time", "automaticTime"])
@pytest.mark.parametrize("state,value,status", [("enabled", True, "PASS"), ("disabled", False, "FAIL")])
def test_automatic_time_accepts_only_complete_explicit_property_sentences(label, state, value, status):
    _, _, results, runner = assess({AUTO_TIME: (0, "", cocoa(f"{label} is {state}"))})
    assert results["MAC-012"]["status"] == status
    assert results["MAC-012"]["actual"] is value
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)


@pytest.mark.parametrize("state,status", [("On", "PASS"), ("Off", "FAIL")])
def test_systemsetup_time_status_can_be_a_clean_stderr_status(state, status):
    _, _, results, _ = assess({SYSTEM_TIME: (0, "", "Network Time: " + state)})
    assert results["MAC-012"]["status"] == status


def test_two_effective_time_getters_disagreeing_remain_error():
    _, _, results, _ = assess({SYSTEM_TIME: "Network Time: On", AUTO_TIME: "Automatic time is disabled"})
    assert results["MAC-012"]["status"] == "ERROR"
    assert results["MAC-012"]["actual"] is None


def test_native_automatic_time_off_conflicting_with_forced_machine_policy_is_error():
    policy_path = "/Library/Managed Preferences/com.apple.timed.plist"
    policy = ("/usr/bin/plutil", "-extract", "TMAutomaticTimeOnlyEnabled", "xml1", "-o", "-", policy_path)
    _, _, results, _ = assess({
        AUTO_TIME: "Automatic time is disabled",
        probe(TIME, "TMAutomaticTimeOnlyEnabled"): preferences(True, managed=True),
        policy: plistlib.dumps(True, fmt=plistlib.FMT_XML).decode(),
    })
    assert results["MAC-012"]["status"] == "ERROR"


@pytest.mark.parametrize("field", ["machine_current_host", "machine_any_host", "explicit_any_host"])
def test_bad_irrelevant_lower_preference_scope_does_not_discard_valid_effective_user_state(field):
    observations = {field: None, "unreadable_scopes": [field]}
    if field == "explicit_any_host":
        observations["explicit_current_host"] = True
    _, _, results, _ = assess({probe(LOCK, "askForPassword"): preferences(True, **observations)})
    assert results["MAC-010"]["status"] == "PASS"


def test_bad_higher_priority_user_scope_is_not_treated_as_absent():
    _, _, results, _ = assess({probe(LOCK, "askForPassword"): preferences(
        True, explicit_any_host=True, unreadable_scopes=["explicit_current_host"],
    )})
    assert results["MAC-010"]["status"] == "ERROR"


def test_verified_managed_effective_user_state_can_override_bad_configured_scope():
    _, _, results, _ = assess({probe(LOCK, "askForPassword"): preferences(
        True, managed=True, unreadable_scopes=["explicit_current_host"],
    )})
    assert results["MAC-010"]["status"] == "PASS"


def test_bad_current_host_machine_scope_never_falls_through_to_secure_anyhost_value():
    _, _, results, _ = assess({probe(UPDATE, "AutomaticCheckEnabled"): preferences(
        True, machine_any_host=True, unreadable_scopes=["machine_current_host"],
    )})
    assert results["MAC-005"]["status"] == "ERROR"
    assert results["MAC-005"]["actual"] is None


@pytest.mark.parametrize("failure", [
    (0, "", ""),
    (127, "", "unsupported native option"),
    (0, "malformed status output", ""),
    (1, "Automatic check is on", ""),
    (0, "Automatic check is on", "permission denied private-user token=hidden"),
    PermissionError("private-user token=hidden"),
    subprocess.TimeoutExpired(["native"], 10, output="private-user token=hidden"),
])
def test_missing_malformed_denied_or_unsupported_sources_never_become_pass_or_fail(failure):
    bundle, assessment, results, _ = assess({SCHEDULE: failure, SCREEN: failure, SYSTEM_TIME: failure, AUTO_TIME: failure})
    assert {control for control, result in results.items() if result["status"] == "ERROR"} == CONTROLS
    assert assessment["failed"] == 0
    assert assessment["passed"] == 8
    assert "private-user" not in json.dumps(bundle)
    assert "hidden" not in json.dumps(bundle)


@pytest.mark.parametrize("command,response,control", [
    (SCHEDULE, (0, "Automatic check is on", "Automatic check is off"), "MAC-005"),
    (SCHEDULE, (0, "Automatic check is on", "warning private token=hidden"), "MAC-005"),
    (SCREEN, (0, "screenLock delay is immediate", "screenLock is off"), "MAC-010"),
    (SCREEN, (0, "screenLock delay is -1 seconds", ""), "MAC-011"),
    (SCREEN, (0, "screenLock delay is 2147483647 seconds", ""), "MAC-011"),
    (AUTO_TIME, (0, "Automatic time is enabled", "Automatic time is disabled"), "MAC-012"),
    (AUTO_TIME, (0, "warning: automatic time is enabled by default", ""), "MAC-012"),
])
def test_ambiguous_or_misleading_native_output_stays_error(command, response, control):
    _, _, results, _ = assess({command: response})
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None


def test_console_mismatch_prevents_native_screen_query_without_reading_other_users(monkeypatch):
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: False)
    _, _, results, runner = assess({SCREEN: "screenLock delay is immediate"})
    assert results["MAC-010"]["status"] == "ERROR"
    assert results["MAC-011"]["status"] == "ERROR"
    assert SCREEN not in [command for command, _ in runner.calls]


def test_console_user_change_during_native_query_discards_the_observed_state(monkeypatch):
    checks = []
    def context():
        checks.append(True)
        return len(checks) == 1
    monkeypatch.setattr(macos, "current_user_status_context_safe", context)
    _, _, results, runner = assess({SCREEN: "screenLock delay is immediate"})
    assert results["MAC-010"]["status"] == "ERROR"
    assert results["MAC-010"]["actual"] is None
    assert "identity changed" in results["MAC-010"]["raw_evidence"]
    assert results["MAC-011"]["status"] == "ERROR"
    assert [command for command, _ in runner.calls].count(SCREEN) == 1


@pytest.mark.parametrize("command,control", [
    (SCHEDULE, "MAC-005"),
    (("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"), "MAC-005"),
    (("/usr/bin/plutil", "-extract", "AutomaticCheckEnabled", "xml1", "-o", "-", "/Library/Preferences/com.apple.SoftwareUpdate.plist"), "MAC-005"),
    (probe(UPDATE, "AutomaticCheckEnabled"), "MAC-005"),
    (probe(LOCK, "askForPassword"), "MAC-010"),
    (probe(LOCK, "askForPasswordDelay"), "MAC-011"),
    (SCREEN, "MAC-010"),
    (SCREEN, "MAC-011"),
    (SYSTEM_TIME, "MAC-012"),
    (AUTO_TIME, "MAC-012"),
])
def test_malformed_native_bytes_are_error_without_aborting_unrelated_controls(command, control):
    failure = UnicodeDecodeError("utf-8", b"private\xffdata", 7, 8, "invalid byte")
    _, _, results, runner = assess({command: failure})
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None
    assert results["MAC-009"]["status"] == "PASS"
    assert "private" not in json.dumps(results)
    assert [cmd for cmd, _ in runner.calls].count(command) == 1


@pytest.mark.parametrize("command,source", [(SCHEDULE, "update_check"), (SYSTEM_TIME, "network_time")])
def test_existing_opted_in_retry_with_malformed_bytes_remains_unknown(command, source):
    sudo = ("/usr/bin/sudo", "-n", "-k", "--", *command)
    runner = NativeOutput({
        command: (1, "", "You need administrator access to run this tool"),
        sudo: UnicodeDecodeError("utf-8", b"private\xffdata", 7, 8, "invalid byte"),
    })
    bundle = macos.MacOSCollector(runner=runner, allow_elevated_read=True).collect()
    assert bundle["evidence"][source]["_collection_ok"] is False
    assert "decoded reliably" in bundle["evidence"][source]["_raw"]
    assert "private" not in json.dumps(bundle)
    assert [cmd for cmd, _ in runner.calls].count(sudo) == 1


def test_malformed_managed_policy_read_does_not_supply_a_machine_state():
    command = ("/usr/bin/plutil", "-extract", "TMAutomaticTimeOnlyEnabled", "xml1", "-o", "-", "/Library/Managed Preferences/com.apple.timed.plist")
    _, _, results, _ = assess({
        probe(TIME, "TMAutomaticTimeOnlyEnabled"): preferences(True, managed=True),
        command: UnicodeDecodeError("utf-8", b"private\xffdata", 7, 8, "invalid byte"),
    })
    assert results["MAC-012"]["status"] == "ERROR"
    assert "private" not in json.dumps(results)


def test_nonconsole_user_can_still_assess_their_own_guarded_native_preferences(monkeypatch):
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: False)
    _, _, results, runner = assess({
        SCREEN: "screenLock is off",
        probe(LOCK, "askForPassword"): preferences(True, explicit_current_host=True),
        probe(LOCK, "askForPasswordDelay"): preferences(0, explicit_current_host=0),
    })
    assert results["MAC-010"]["status"] == "PASS"
    assert results["MAC-011"]["status"] == "PASS"
    assert SCREEN not in [command for command, _ in runner.calls]


@pytest.mark.parametrize("home", ["/Users/instructor", "/Users/student with spaces", "/Network/Users/account", "/var/root"])
def test_synthetic_home_and_hostname_variants_do_not_change_native_state_selection(monkeypatch, home):
    monkeypatch.setattr(macos, "_invoking_user_home", lambda: Path(home))
    monkeypatch.setattr(macos.platform, "node", lambda: "changed-generic-host")
    bundle, _, results, runner = assess({
        SCHEDULE: (0, "", "Automatic check is on"),
        SCREEN: (0, "", cocoa("screenLock delay is immediate")),
        AUTO_TIME: "Automatic time is enabled",
    })
    assert bundle["target_name"] == "changed-generic-host"
    assert {results[control]["status"] for control in CONTROLS} == {"PASS"}
    for command, options in runner.calls:
        assert home not in command
        assert options["shell"] is False
        assert options["stdin"] == subprocess.DEVNULL
        assert options["timeout"] == 10
        assert command[0] != "/usr/bin/sudo"


@pytest.mark.parametrize("command", [SCREEN, AUTO_TIME])
def test_new_sysadminctl_getters_never_enter_the_existing_elevation_allowlist(command):
    runner = NativeOutput()
    collector = macos.MacOSCollector(runner=runner, allow_elevated_read=True)
    query = macos._Query("network_time", "enabled", command, lambda text: True)
    assert collector._optional_elevated_status(query, collector._unknown(query, macos._PRIVILEGE_REQUIRED)) is None
    assert runner.calls == []


def test_effective_native_sources_preserve_public_report_and_evidence_key_structure():
    old_bundle, _, _, _ = assess()
    new_bundle, _, results, _ = assess({SCHEDULE: "Automatic check is on", SCREEN: "screenLock delay is immediate", AUTO_TIME: "Automatic time is enabled"})
    old_report = build_profile_report("macos", old_bundle)
    new_report = build_profile_report("macos", new_bundle)
    assert set(old_report) == set(new_report)
    assert set(old_report["collector"]) == set(new_report["collector"])
    assert set(old_report["assessment"]) == set(new_report["assessment"])
    for before, after in zip(old_report["assessment"]["results"], new_report["assessment"]["results"]):
        assert set(before) == set(after)
    for source in ("update_check", "screen_lock", "screen_lock_delay", "network_time"):
        assert set(old_bundle["evidence"][source]) == set(new_bundle["evidence"][source])
    assert {results[control]["status"] for control in CONTROLS} == {"PASS"}
