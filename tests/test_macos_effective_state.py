"""Effective-state integration fixtures; none executes a native macOS query."""

import json
from pathlib import Path
import plistlib
import subprocess
import sys

import pytest

from cyberassess.collectors import macos
from cyberassess.evaluator import evaluate_baseline


@pytest.fixture(autouse=True)
def matching_invoking_console_context(monkeypatch):
    # Identity restrictions are exercised independently of source fixtures.
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: True)


SCHEDULE = ("/usr/sbin/softwareupdate", "--schedule")
REMOTE_STATUS = ("/usr/sbin/systemsetup", "-getremotelogin")
TIME_STATUS = ("/usr/sbin/systemsetup", "-getusingnetworktime")
OVERRIDES = ("/bin/launchctl", "print-disabled", "system")
SERVICE = ("/bin/launchctl", "print", "system/com.openssh.sshd")
SSH_DEFINITION = "/System/Library/LaunchDaemons/ssh.plist"
UPDATE_DOMAIN = "com.apple.SoftwareUpdate"
LOCK_DOMAIN = "com.apple.screensaver"
TIME_DOMAIN = "com.apple.timed"
MISSING = object()


def preference(value, *, managed=False, managed_available=True, **observations):
    payload = {
        "available": value is not None,
        "value": value,
        "managed": managed,
        "managed_available": managed_available,
        "explicit_current_host": None,
        "explicit_any_host": None,
        "machine_current_host": None,
        "machine_any_host": None,
        "reason": "effective-preference-value" if value is not None else "missing-or-unreadable-effective-value",
    }
    payload.update(observations)
    return json.dumps(payload, allow_nan=False)


def probe(domain, key):
    return ("preferences", domain, key)


def extracted(value):
    return plistlib.dumps(value, fmt=plistlib.FMT_XML).decode("utf-8")


def plist_command(key, path):
    return ("/usr/bin/plutil", "-extract", key, "xml1", "-o", "-", str(path))


class NativeRunner:
    """Absent fixtures fail explicitly; they never receive a generic '1'."""

    def __init__(self, responses=None):
        self.responses = dict(responses or {})
        self.calls = []

    def __call__(self, command, **options):
        command = tuple(command)
        # Retain only bounded execution options, never the process environment.
        recorded = {key: value for key, value in options.items() if key != "env"}
        recorded["locale"] = options.get("env", {}).get("LC_ALL")
        self.calls.append((command, recorded))
        key = command
        if command[:2] == (sys.executable, macos._PREFERENCE_HELPER) and len(command) == 4:
            key = probe(command[2], command[3])
        response = self.responses.get(key, MISSING)
        if response is MISSING:
            baseline = {
                ("/usr/bin/fdesetup", "status"): "FileVault is On.",
                ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"): "Firewall is enabled. (State = 1)",
                ("/usr/bin/csrutil", "status"): "System Integrity Protection status: enabled.",
                ("/usr/sbin/spctl", "--status"): "assessments enabled",
            }
            for name in ("AutomaticDownload", "CriticalUpdateInstall", "ConfigDataInstall"):
                baseline[("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", name)] = "1"
            response = baseline.get(command, MISSING)
        if isinstance(response, Exception):
            raise response
        if response is MISSING:
            return subprocess.CompletedProcess(command, 127, "", "")
        if isinstance(response, tuple):
            code, stdout, stderr = response
            return subprocess.CompletedProcess(command, code, stdout, stderr)
        return subprocess.CompletedProcess(command, 0, response, "")


def assess(responses=None, runner=None):
    runner = NativeRunner(responses) if runner is None else runner
    bundle = macos.MacOSCollector(runner=runner).collect()
    controls = json.loads(Path("config/profiles/macos.json").read_text(encoding="utf-8"))
    assessment = evaluate_baseline(controls, bundle["evidence"])
    results = {result["control_id"]: result for result in assessment["results"]}
    return bundle, assessment, results, runner


def registered_service(state="not running"):
    return """system/com.openssh.sshd = {
    active count = 0
    path = /System/Library/LaunchDaemons/ssh.plist
    type = LaunchDaemon
    state = """ + state + """
    sockets = {
        Listeners = {
            service name = ssh
        }
    }
}
"""


@pytest.mark.parametrize("configured,effective,status", [("1", "on", "PASS"), ("0", "off", "FAIL"), ("1", "off", "FAIL")])
def test_explicit_update_key_is_recorded_separately_from_native_effective_state(configured, effective, status):
    command = ("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled")
    bundle, _, results, _ = assess({command: configured, SCHEDULE: "Automatic check is " + effective})
    assert results["MAC-005"]["status"] == status
    assert "effective machine state" in bundle["evidence"]["update_check"]["_scope"]
    assert "explicit configured value=" + ("true" if configured == "1" else "false") in results["MAC-005"]["raw_evidence"]


@pytest.mark.parametrize("status,expected", [("on", "PASS"), ("off", "FAIL")])
def test_missing_update_key_can_use_authoritative_native_schedule(status, expected):
    bundle, _, results, _ = assess({SCHEDULE: "Automatic check is " + status})
    assert results["MAC-005"]["status"] == expected
    assert "explicit any-host value unavailable" in bundle["evidence"]["update_check"]["_scope"]


@pytest.mark.parametrize("field", ["machine_current_host", "machine_any_host"])
def test_resolved_machine_update_preference_is_available_without_explicit_file_key(field):
    _, _, results, _ = assess({probe(UPDATE_DOMAIN, "AutomaticCheckEnabled"): preference(True, **{field: True})})
    assert results["MAC-005"]["status"] == "PASS"
    assert "CoreFoundation" in results["MAC-005"]["raw_evidence"]


def test_user_only_update_suite_value_cannot_masquerade_as_machine_state():
    _, _, results, _ = assess({probe(UPDATE_DOMAIN, "AutomaticCheckEnabled"): preference(True, explicit_any_host=True)})
    assert results["MAC-005"]["status"] == "ERROR"
    assert results["MAC-005"]["actual"] is None


@pytest.mark.parametrize("schedule,machine", [("on", False), ("off", True)])
def test_contradictory_native_schedule_and_machine_resolution_remain_error(schedule, machine):
    _, _, results, _ = assess({
        SCHEDULE: "Automatic check is " + schedule,
        probe(UPDATE_DOMAIN, "AutomaticCheckEnabled"): preference(machine, machine_any_host=machine),
    })
    assert results["MAC-005"]["status"] == "ERROR"
    assert results["MAC-005"]["actual"] is None
    assert "disagree" in results["MAC-005"]["raw_evidence"]


def test_managed_update_policy_requires_independent_machine_scope():
    responses = {probe(UPDATE_DOMAIN, "AutomaticCheckEnabled"): preference(True, managed=True)}
    _, _, unavailable, _ = assess(responses)
    assert unavailable["MAC-005"]["status"] == "ERROR"
    responses[plist_command("AutomaticCheckEnabled", "/Library/Managed Preferences/com.apple.SoftwareUpdate.plist")] = extracted(True)
    _, _, verified, _ = assess(responses)
    assert verified["MAC-005"]["status"] == "PASS"


@pytest.mark.parametrize("state", ["not running", "waiting", "running"])
def test_registered_socket_activated_ssh_is_enabled_even_without_override_or_live_process(state):
    _, _, results, _ = assess({OVERRIDES: "disabled services = {\n}", SERVICE: registered_service(state)})
    assert results["MAC-009"]["status"] == "FAIL"
    assert results["MAC-009"]["actual"] is True


def test_absent_ssh_override_uses_actual_disabled_definition_plus_confirmed_service_absence():
    responses = {
        OVERRIDES: "disabled services = {\n}",
        SERVICE: (113, "", 'Could not find service "com.openssh.sshd" in domain for system'),
        plist_command("Label", SSH_DEFINITION): extracted("com.openssh.sshd"),
        plist_command("Disabled", SSH_DEFINITION): extracted(True),
    }
    _, _, results, _ = assess(responses)
    assert results["MAC-009"]["status"] == "PASS"
    del responses[plist_command("Disabled", SSH_DEFINITION)]
    _, _, missing, _ = assess(responses)
    assert missing["MAC-009"]["status"] == "ERROR"


def test_registered_ssh_conflicts_with_explicit_disabled_override():
    _, _, results, _ = assess({
        OVERRIDES: 'disabled services = {\n "com.openssh.sshd" => disabled\n}',
        SERVICE: registered_service(),
    })
    assert results["MAC-009"]["status"] == "ERROR"


@pytest.mark.parametrize("managed", [False, True])
def test_missing_lock_key_can_use_native_byhost_or_managed_resolution(managed):
    _, _, results, runner = assess({
        probe(LOCK_DOMAIN, "askForPassword"): preference(True, managed=managed, explicit_current_host=True),
        probe(LOCK_DOMAIN, "askForPasswordDelay"): preference(0, managed=managed, explicit_current_host=0),
    })
    assert results["MAC-010"]["status"] == "PASS"
    assert results["MAC-011"]["status"] == "PASS"
    assert ("effective managed" if managed else "current-user/ByHost") in results["MAC-010"]["raw_evidence"]
    requirement_calls = [cmd for cmd, _ in runner.calls if cmd[-2:] == (LOCK_DOMAIN, "askForPassword")]
    assert len(requirement_calls) == 1


def test_explicit_native_user_observation_and_effective_requirement_are_both_preserved():
    _, _, results, _ = assess({probe(LOCK_DOMAIN, "askForPassword"): preference(True, explicit_any_host=True)})
    assert results["MAC-010"]["status"] == "PASS"
    assert "explicit configured value=true" in results["MAC-010"]["raw_evidence"]


def test_byhost_resolution_legitimately_overrides_anyhost_without_guessing():
    _, _, results, _ = assess({probe(LOCK_DOMAIN, "askForPassword"): preference(False, explicit_current_host=False, explicit_any_host=True)})
    assert results["MAC-010"]["status"] == "FAIL"
    assert results["MAC-010"]["actual"] is False
    assert "explicit configured value=true" in results["MAC-010"]["raw_evidence"]


def test_verified_managed_resolution_can_override_explicit_user_preference():
    _, _, results, _ = assess({
        probe(LOCK_DOMAIN, "askForPassword"): preference(True, managed=True, explicit_current_host=False, explicit_any_host=False),
        probe(LOCK_DOMAIN, "askForPasswordDelay"): preference(0, managed=True, explicit_current_host=60, explicit_any_host=300),
    })
    assert results["MAC-010"]["status"] == "PASS"
    assert results["MAC-011"]["status"] == "PASS"
    assert "effective managed" in results["MAC-010"]["raw_evidence"]
    assert "explicit configured value=false" in results["MAC-010"]["raw_evidence"]


@pytest.mark.parametrize("key,value,explicit,control", [
    ("askForPassword", True, False, "MAC-010"),
    ("askForPasswordDelay", 0, 60, "MAC-011"),
])
@pytest.mark.parametrize("field", ["explicit_current_host", "explicit_any_host"])
def test_unmanaged_effective_observation_that_contradicts_highest_priority_user_value_is_error(key, value, explicit, control, field):
    responses = {probe(LOCK_DOMAIN, "askForPassword"): preference(True)}
    responses[probe(LOCK_DOMAIN, key)] = preference(value, **{field: explicit})
    _, _, results, _ = assess(responses)
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None


def test_password_requirement_and_known_delay_remain_independent_controls():
    _, _, results, _ = assess({
        probe(LOCK_DOMAIN, "askForPassword"): preference(False),
        probe(LOCK_DOMAIN, "askForPasswordDelay"): preference(0),
    })
    assert results["MAC-010"]["status"] == "FAIL"
    assert results["MAC-011"]["status"] == "PASS"
    assert results["MAC-011"]["actual"] == 0


@pytest.mark.parametrize("delay,status", [(0, "PASS"), (0.0, "PASS"), (0.5, "FAIL"), (60, "FAIL")])
def test_effective_delay_is_assessed_only_with_enabled_requirement(delay, status):
    _, _, results, _ = assess({
        probe(LOCK_DOMAIN, "askForPassword"): preference(True),
        probe(LOCK_DOMAIN, "askForPasswordDelay"): preference(delay),
    })
    assert results["MAC-011"]["status"] == status
    assert results["MAC-011"]["actual"] == delay


def test_known_zero_delay_does_not_invent_an_unknown_password_requirement():
    _, _, results, _ = assess({probe(LOCK_DOMAIN, "askForPasswordDelay"): preference(0)})
    assert results["MAC-010"]["status"] == "ERROR"
    assert results["MAC-011"]["status"] == "PASS"
    assert results["MAC-011"]["actual"] == 0


@pytest.mark.parametrize("value", [True, False])
def test_unforced_time_enforcement_preference_does_not_prove_actual_time_state(value):
    _, _, results, _ = assess({probe(TIME_DOMAIN, "TMAutomaticTimeOnlyEnabled"): preference(value, machine_any_host=value)})
    assert results["MAC-012"]["status"] == "ERROR"
    assert results["MAC-012"]["actual"] is None


@pytest.mark.parametrize("state,status", [("On", "PASS"), ("Off", "FAIL")])
def test_native_network_time_on_off_remains_authoritative(state, status):
    _, _, results, _ = assess({TIME_STATUS: "Network Time: " + state})
    assert results["MAC-012"]["status"] == status


def test_forced_automatic_time_requires_matching_machine_managed_evidence():
    responses = {probe(TIME_DOMAIN, "TMAutomaticTimeOnlyEnabled"): preference(True, managed=True)}
    _, _, missing_scope, _ = assess(responses)
    assert missing_scope["MAC-012"]["status"] == "ERROR"
    responses[plist_command("TMAutomaticTimeOnlyEnabled", "/Library/Managed Preferences/com.apple.timed.plist")] = extracted(True)
    _, _, verified, _ = assess(responses)
    assert verified["MAC-012"]["status"] == "PASS"
    assert "enforced machine" in verified["MAC-012"]["raw_evidence"]
    responses[TIME_STATUS] = "Network Time: Off"
    _, _, conflict, _ = assess(responses)
    assert conflict["MAC-012"]["status"] == "ERROR"
    assert conflict["MAC-012"]["actual"] is None


@pytest.mark.parametrize("failure", [
    (0, "", ""), (127, "", "unsupported command"),
    (0, "Automatic check is on", "permission denied private-user token=hidden"),
    (1, "Automatic check is on", ""),
    PermissionError("private-user token=hidden"),
    FileNotFoundError("private-user token=hidden"),
    subprocess.TimeoutExpired(["native-tool"], 10, output="private-user token=hidden"),
])
def test_empty_denied_unsupported_or_failed_native_reads_never_turn_into_pass(failure):
    _, assessment, results, _ = assess({SCHEDULE: failure})
    assert results["MAC-005"]["status"] == "ERROR"
    assert {result["control_id"] for result in assessment["results"] if result["status"] == "ERROR"} == {
        "MAC-005", "MAC-009", "MAC-010", "MAC-011", "MAC-012",
    }
    assert "private-user" not in json.dumps(results)
    assert "hidden" not in json.dumps(results)


def test_missing_every_native_source_preserves_all_five_errors_without_poisoning_other_checks():
    _, assessment, results, _ = assess()
    assert assessment["passed"] == 7
    assert assessment["failed"] == 0
    assert assessment["errors"] == 5
    assert results["MAC-001"]["status"] == "PASS"


@pytest.mark.parametrize("reason,retained", [
    ("ambiguous-user-context", True),
    ("missing-or-unreadable-effective-value", True),
    ("private-user password=hidden-untrusted-diagnostic", False),
])
def test_only_allowlisted_unavailable_probe_reasons_enter_evidence(reason, retained):
    payload = json.loads(preference(None))
    payload["reason"] = reason
    _, _, results, _ = assess({probe(LOCK_DOMAIN, "askForPassword"): json.dumps(payload)})
    assert results["MAC-010"]["status"] == "ERROR"
    assert (reason in results["MAC-010"]["raw_evidence"]) is retained
    assert "hidden-untrusted-diagnostic" not in json.dumps(results)


def test_non_scalar_probe_reason_stays_unknown_without_aborting_other_controls():
    payload = json.loads(preference(None))
    payload["reason"] = {"password": "hidden-untrusted-diagnostic"}
    _, _, results, _ = assess({probe(LOCK_DOMAIN, "askForPassword"): json.dumps(payload)})
    assert results["MAC-010"]["status"] == "ERROR"
    assert results["MAC-001"]["status"] == "PASS"
    assert "hidden-untrusted-diagnostic" not in json.dumps(results)


def test_extra_native_dump_fields_and_stderr_are_never_retained_in_evidence():
    payload = json.loads(preference(True))
    payload["unrestricted_dump"] = {"password": "hidden-private-credential"}
    service_dump = registered_service().replace("    sockets = {", '    environment = {\n        token = "hidden-private-credential"\n    }\n    sockets = {')
    bundle, _, results, _ = assess({
        probe(LOCK_DOMAIN, "askForPassword"): json.dumps(payload),
        SCHEDULE: (0, "Automatic check is on", "warning: hidden-private-credential"),
        OVERRIDES: "disabled services = {\n}", SERVICE: service_dump,
    })
    assert results["MAC-010"]["status"] == "PASS"
    assert results["MAC-009"]["status"] == "FAIL"
    assert results["MAC-005"]["status"] == "ERROR"
    serialized = json.dumps(bundle)
    assert "hidden-private-credential" not in serialized
    assert "unrestricted_dump" not in serialized
    assert "environment" not in serialized


@pytest.mark.parametrize("home", ["/Users/professor", "/Users/student with spaces", "/Network/Users/account", "/var/root"])
def test_home_locations_and_changing_hostnames_do_not_select_security_values(home, monkeypatch):
    monkeypatch.setattr(macos, "_invoking_user_home", lambda: Path(home))
    responses = {
        SCHEDULE: "Automatic check is on", REMOTE_STATUS: "Remote Login: Off", TIME_STATUS: "Network Time: On",
        probe(LOCK_DOMAIN, "askForPassword"): preference(True, explicit_any_host=True),
        probe(LOCK_DOMAIN, "askForPasswordDelay"): preference(0, explicit_any_host=0),
    }
    previous = None
    for name in ("generic-lab-host", "generic-company-host"):
        monkeypatch.setattr(macos.platform, "node", lambda: name)
        bundle, assessment, _, runner = assess(responses)
        assert bundle["target_name"] == name
        assert assessment["passed"] == 12
        if previous is not None:
            assert assessment == previous
        previous = assessment
        for command, _ in runner.calls:
            assert home not in command
            assert not (command[0] == "/usr/bin/defaults" and "com.apple.screensaver" in command)
            assert not any("com.apple.screensaver.plist" in argument for argument in command)


def test_native_commands_remain_read_only_bounded_noninteractive_and_cache_per_assessment():
    runner = NativeRunner({
        SCHEDULE: "Automatic check is on",
        probe(LOCK_DOMAIN, "askForPassword"): preference(True),
        probe(LOCK_DOMAIN, "askForPasswordDelay"): preference(0),
    })
    collector = macos.MacOSCollector(runner=runner)
    first = collector.collect()
    assert first["evidence"]["screen_lock"]["password_required"] is True
    for command, options in runner.calls:
        assert options["shell"] is False
        assert options["stdin"] == subprocess.DEVNULL
        assert options["timeout"] == 10
        assert options["locale"] == "C"
        assert "sudo" not in command
        assert not any(argument.startswith(("-set", "--set", "-replace", "-insert", "--enable", "--disable")) for argument in command)
        if command[0] == sys.executable:
            assert command[1] == macos._PREFERENCE_HELPER
            assert len(command) == 4
            assert command[2] in {UPDATE_DOMAIN, LOCK_DOMAIN, TIME_DOMAIN}
    runner.responses[probe(LOCK_DOMAIN, "askForPassword")] = preference(False)
    second = collector.collect()
    assert second["evidence"]["screen_lock"]["password_required"] is False
    assert second["evidence"]["screen_lock_delay"]["_collection_ok"] is True
    assert second["evidence"]["screen_lock_delay"]["seconds"] == 0
