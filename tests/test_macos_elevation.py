"""Opted-in read-only elevation fixtures; no sudo or native command executes."""

import json
from pathlib import Path
import plistlib
import subprocess
import sys

import pytest

from cyberassess.collectors import macos
from cyberassess.evaluator import evaluate_baseline
from cyberassess.profiles import build_profile_report


@pytest.fixture(autouse=True)
def matching_invoking_console_context(monkeypatch):
    # Screen preferences belong to a matching non-root console-user fixture.
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: True)


REMOTE = ("/usr/sbin/systemsetup", "-getremotelogin")
TIME = ("/usr/sbin/systemsetup", "-getusingnetworktime")
SCHEDULE = ("/usr/sbin/softwareupdate", "--schedule")
ALLOWED = {REMOTE, TIME, SCHEDULE}
SUDO = ("/usr/bin/sudo", "-n", "-k", "--")
OVERRIDES = ("/bin/launchctl", "print-disabled", "system")
SERVICE = ("/bin/launchctl", "print", "system/com.openssh.sshd")
TARGETS = (
    (REMOTE, "MAC-009", "remote_login", "Remote Login: Off", False, "PASS"),
    (REMOTE, "MAC-009", "remote_login", "Remote Login: On", True, "FAIL"),
    (TIME, "MAC-012", "network_time", "Network Time: On", True, "PASS"),
    (TIME, "MAC-012", "network_time", "Network Time: Off", False, "FAIL"),
    (SCHEDULE, "MAC-005", "update_check", "Automatic check is on", True, "PASS"),
    (SCHEDULE, "MAC-005", "update_check", "Automatic check is off", False, "FAIL"),
)
DENIED = (1, "", "You need administrator access to run this tool... exiting!")
MISSING = object()


def preference(value, *, managed=False, **observations):
    result = {
        "available": value is not None, "value": value,
        "managed": managed, "managed_available": True,
        "explicit_current_host": None, "explicit_any_host": None,
        "machine_current_host": None, "machine_any_host": None,
        "reason": "effective-preference-value" if value is not None else "missing-or-unreadable-effective-value",
    }
    result.update(observations)
    return json.dumps(result, allow_nan=False)


def probe(domain, key):
    return (sys.executable, macos._PREFERENCE_HELPER, domain, key)


def plist(key, path):
    return ("/usr/bin/plutil", "-extract", key, "xml1", "-o", "-", path)


def extracted(value):
    return plistlib.dumps(value, fmt=plistlib.FMT_XML).decode("utf-8")


class ReadOnlyRunner:
    """Every unspecified query fails; no empty response receives a value."""

    def __init__(self, responses=None):
        self.responses = dict(responses or {})
        self.calls = []

    def __call__(self, command, **options):
        command = tuple(command)
        retained = {key: value for key, value in options.items() if key != "env"}
        retained["locale"] = options.get("env", {}).get("LC_ALL")
        self.calls.append((command, retained))
        response = self.responses.get(command, MISSING)
        if response is MISSING:
            passing = {
                ("/usr/bin/fdesetup", "status"): "FileVault is On.",
                ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"): "Firewall is enabled. (State = 1)",
                ("/usr/bin/csrutil", "status"): "System Integrity Protection status: enabled.",
                ("/usr/sbin/spctl", "--status"): "assessments enabled",
            }
            for key in ("AutomaticDownload", "CriticalUpdateInstall", "ConfigDataInstall"):
                passing[("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", key)] = "1"
            response = passing.get(command, MISSING)
        if isinstance(response, Exception):
            raise response
        if response is MISSING:
            return subprocess.CompletedProcess(command, 127, "", "")
        if isinstance(response, tuple):
            code, stdout, stderr = response
            return subprocess.CompletedProcess(command, code, stdout, stderr)
        return subprocess.CompletedProcess(command, 0, response, "")


def collect(responses=None, *, allow=False, runner=None):
    runner = ReadOnlyRunner(responses) if runner is None else runner
    bundle = macos.MacOSCollector(runner=runner, allow_elevated_read=allow).collect()
    controls = json.loads(Path("config/profiles/macos.json").read_text(encoding="utf-8"))
    assessment = evaluate_baseline(controls, bundle["evidence"])
    results = {result["control_id"]: result for result in assessment["results"]}
    return bundle, results, runner


def elevated_calls(runner):
    return [command for command, _ in runner.calls if command[0] == "/usr/bin/sudo"]


@pytest.mark.parametrize("command,control", [(REMOTE, "MAC-009"), (TIME, "MAC-012"), (SCHEDULE, "MAC-005")])
def test_elevation_is_disabled_by_default_even_with_permission_failure(command, control):
    bundle, results, runner = collect({command: DENIED, SUDO + command: "unused secure status"})
    assert results[control]["status"] == "ERROR"
    assert elevated_calls(runner) == []
    assert "Elevated reads are disabled" in bundle["collector"]["limitations"]


@pytest.mark.parametrize("command,control,source,output,actual,status", TARGETS)
def test_explicit_permission_retry_accepts_only_clean_native_status(command, control, source, output, actual, status):
    bundle, results, runner = collect({command: DENIED, SUDO + command: output}, allow=True)
    assert elevated_calls(runner) == [SUDO + command]
    assert results[control]["status"] == status
    assert results[control]["actual"] is actual
    assert "explicit sudo -n read" in results[control]["raw_evidence"]
    assert "invoking user" in bundle["evidence"][source]["_scope"]
    commands = [cmd for cmd, _ in runner.calls]
    assert commands.index(command) < commands.index(SUDO + command)
    for cmd, options in runner.calls:
        assert options["shell"] is False
        assert options["check"] is False
        assert options["stdin"] == subprocess.DEVNULL
        assert options["timeout"] == 10
        assert options["locale"] == "C"
        assert "input" not in options
        if cmd[0] == "/usr/bin/sudo":
            assert cmd[:len(SUDO)] == SUDO
            assert cmd[len(SUDO):] in ALLOWED
            assert "-S" not in cmd and "-A" not in cmd and "-v" not in cmd


@pytest.mark.parametrize("native_failure", [
    (0, "You need administrator access to run this tool... exiting!", ""),
    (1, "", "Permission denied: private-user token=hidden"),
    (0, "Remote Login: Off", "operation not permitted private-user token=hidden"),
    PermissionError("private-user token=hidden"),
])
def test_zero_exit_and_exception_permission_failures_can_retry_safely(native_failure):
    _, results, runner = collect({REMOTE: native_failure, SUDO + REMOTE: "Remote Login: Off"}, allow=True)
    assert results["MAC-009"]["status"] == "PASS"
    assert elevated_calls(runner) == [SUDO + REMOTE]
    assert "private-user" not in json.dumps(results)
    assert "hidden" not in json.dumps(results)


@pytest.mark.parametrize("diagnostic", [
    "softwareupdate: You must be root to perform this operation.",
    "This command must run as root.",
    "You must have root privileges to run this tool.",
])
def test_schedule_root_requirement_variants_enable_only_the_opted_in_getter(diagnostic):
    _, results, runner = collect({SCHEDULE: (1, "", diagnostic), SUDO + SCHEDULE: "Automatic check is on"}, allow=True)
    assert results["MAC-005"]["status"] == "PASS"
    assert elevated_calls(runner) == [SUDO + SCHEDULE]


@pytest.mark.parametrize("native_failure", [
    (0, "", ""),
    (0, "unsupported status format", ""),
    (1, "", "unsupported command"),
    (1, "Remote Login: Off", ""),
    (0, "Remote Login: Off", "unrecognized diagnostic"),
    FileNotFoundError("missing native command"),
    subprocess.TimeoutExpired(["native-tool"], 10),
])
def test_unsupported_ambiguous_nonzero_and_timeout_reads_do_not_trigger_sudo(native_failure):
    _, results, runner = collect({REMOTE: native_failure, SUDO + REMOTE: "Remote Login: Off"}, allow=True)
    assert results["MAC-009"]["status"] == "ERROR"
    assert elevated_calls(runner) == []


@pytest.mark.parametrize("elevated_failure", [
    (1, "", "sudo: a password is required private-user token=hidden"),
    (1, "", "private-user is not in the sudoers file token=hidden"),
    (1, "Remote Login: Off", ""),
    (0, "Remote Login: Off", "unsupported diagnostic private-user token=hidden"),
    (0, "Remote Login: Off\nRemote Login: On", ""),
    (0, "", ""),
    (0, "remote login looks disabled", ""),
    (1, "", "operation not permitted private-user token=hidden"),
    PermissionError("private-user token=hidden"),
    FileNotFoundError("missing sudo private-user token=hidden"),
    subprocess.TimeoutExpired(["sudo"], 10, output="private-user token=hidden"),
])
def test_denied_unavailable_or_ambiguous_elevation_stays_error_with_sanitized_reason(elevated_failure):
    _, results, runner = collect({REMOTE: DENIED, SUDO + REMOTE: elevated_failure}, allow=True)
    result = results["MAC-009"]
    assert elevated_calls(runner) == [SUDO + REMOTE]
    assert result["status"] == "ERROR"
    assert result["actual"] is None
    assert "Explicit elevated read failed" in result["raw_evidence"]
    assert "No password was requested" in result["raw_evidence"]
    assert "no setting was changed" in result["raw_evidence"]
    assert "private-user" not in json.dumps(results)
    assert "hidden" not in json.dumps(results)


@pytest.mark.parametrize("command,control,on,off", [
    (TIME, "MAC-012", "Network Time: On", "Network Time: Off"),
    (SCHEDULE, "MAC-005", "Automatic check is on", "Automatic check is off"),
])
@pytest.mark.parametrize("failure", [
    "password-required", "permission-denied", "command-unavailable", "unsupported",
    "timeout", "empty", "nonzero", "conflict", "diagnostic", "unknown-format",
])
def test_update_and_time_privileged_failures_stay_error_without_credentials_or_raw_output(command, control, on, off, failure):
    failures = {
        "password-required": (1, "", "sudo: a password is required private-token"),
        "permission-denied": PermissionError("private-token"),
        "command-unavailable": FileNotFoundError("private-token"),
        "unsupported": (127, "", "unsupported native command private-token"),
        "timeout": subprocess.TimeoutExpired(["native"], 10, output="private-token"),
        "empty": (0, "", ""),
        "nonzero": (1, on, ""),
        "conflict": (0, on, off),
        "diagnostic": (0, on, "unrecognized diagnostic private-token"),
        "unknown-format": (0, "state cannot be established private-token", ""),
    }
    bundle, results, runner = collect({command: DENIED, SUDO + command: failures[failure]}, allow=True)
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None
    assert "Explicit elevated read failed" in results[control]["raw_evidence"]
    assert "private-token" not in json.dumps(bundle)
    assert elevated_calls(runner) == [SUDO + command]
    for native_command, options in runner.calls:
        assert options["stdin"] == subprocess.DEVNULL
        assert options["shell"] is False
        assert options["timeout"] == 10
        assert "input" not in options
        if native_command[0] == "/usr/bin/sudo":
            # -k with the fixed getter ignores cached authentication and does
            # not update it; -n and closed stdin rule out password collection.
            assert native_command[:len(SUDO)] == ("/usr/bin/sudo", "-n", "-k", "--")
            assert native_command[len(SUDO):] in ALLOWED
            assert not {"-v", "-S", "-A", "-K"}.intersection(native_command)


@pytest.mark.parametrize("command,control,output,actual,status", [
    (TIME, "MAC-012", "Network Time: On", True, "PASS"),
    (TIME, "MAC-012", "Network Time: Off", False, "FAIL"),
    (SCHEDULE, "MAC-005", "Automatic check is on", True, "PASS"),
    (SCHEDULE, "MAC-005", "Automatic check is off", False, "FAIL"),
])
def test_privileged_native_status_on_stderr_uses_the_same_safe_cache_prefix(command, control, output, actual, status):
    _, results, runner = collect({command: DENIED, SUDO + command: (0, "", output)}, allow=True)
    assert results[control]["status"] == status
    assert results[control]["actual"] is actual
    assert elevated_calls(runner) == [SUDO + command]


@pytest.mark.parametrize("command,source", [(REMOTE, "remote_login"), (TIME, "network_time"), (SCHEDULE, "update_check")])
def test_denied_retry_is_the_final_read_for_that_control(command, source):
    runner = ReadOnlyRunner({command: DENIED, SUDO + command: (1, "", "sudo: a password is required")})
    collector = macos.MacOSCollector(runner=runner, allow_elevated_read=True)
    query = next(query for query in macos._QUERIES if query.source == source)
    result = collector._collect_query(query)
    assert result["_collection_ok"] is False
    assert result[query.key] is None
    assert "Explicit elevated read failed" in result["_raw"]
    assert runner.calls[-1][0] == SUDO + command
    assert elevated_calls(runner) == [SUDO + command]


def test_reliable_launchd_state_is_resolved_before_optional_sudo():
    absent = (113, "", 'Could not find service "com.openssh.sshd" in domain for system')
    definition = "/System/Library/LaunchDaemons/ssh.plist"
    _, results, runner = collect({
        REMOTE: DENIED,
        OVERRIDES: "disabled services = {\n}", SERVICE: absent,
        plist("Label", definition): extracted("com.openssh.sshd"),
        plist("Disabled", definition): extracted(True),
        SUDO + REMOTE: (1, "", "sudo: a password is required"),
    }, allow=True)
    assert results["MAC-009"]["status"] == "PASS"
    assert elevated_calls(runner) == []


@pytest.mark.parametrize("enabled_override,service", [
    ("disabled", "system/com.openssh.sshd = {\n path = /System/Library/LaunchDaemons/ssh.plist\n type = LaunchDaemon\n state = not running\n}"),
    ("enabled", (113, "", 'Could not find service "com.openssh.sshd" in domain for system')),
])
def test_conflicting_known_ssh_state_is_not_replaced_by_an_elevated_secure_value(enabled_override, service):
    _, results, runner = collect({
        REMOTE: DENIED,
        OVERRIDES: 'disabled services = {\n "com.openssh.sshd" => ' + enabled_override + '\n}',
        SERVICE: service,
        SUDO + REMOTE: "Remote Login: Off",
    }, allow=True)
    assert results["MAC-009"]["status"] == "ERROR"
    assert "contradictory" in results["MAC-009"]["raw_evidence"]
    assert elevated_calls(runner) == []


def test_reliable_managed_time_state_is_resolved_before_optional_sudo():
    _, results, runner = collect({
        TIME: DENIED,
        probe("com.apple.timed", "TMAutomaticTimeOnlyEnabled"): preference(True, managed=True),
        plist("TMAutomaticTimeOnlyEnabled", "/Library/Managed Preferences/com.apple.timed.plist"): extracted(True),
        SUDO + TIME: (1, "", "sudo: a password is required"),
    }, allow=True)
    assert results["MAC-012"]["status"] == "PASS"
    assert elevated_calls(runner) == []


def test_reliable_machine_update_state_is_resolved_before_optional_sudo():
    _, results, runner = collect({
        SCHEDULE: DENIED,
        probe("com.apple.SoftwareUpdate", "AutomaticCheckEnabled"): preference(True, machine_any_host=True),
        SUDO + SCHEDULE: (1, "", "sudo: a password is required"),
    }, allow=True)
    assert results["MAC-005"]["status"] == "PASS"
    assert elevated_calls(runner) == []


def test_successful_unprivileged_status_never_runs_sudo_even_when_enabled():
    _, results, runner = collect({REMOTE: "Remote Login: Off", TIME: "Network Time: On", SCHEDULE: "Automatic check is on"}, allow=True)
    assert {results[c]["status"] for c in ("MAC-005", "MAC-009", "MAC-012")} == {"PASS"}
    assert elevated_calls(runner) == []


@pytest.mark.parametrize("command", [
    ("/usr/sbin/systemsetup", "-setremotelogin", "off"),
    (*REMOTE, "-setusingnetworktime", "on"),
    ("/usr/sbin/systemsetup", "-getremotelogin; touch /tmp/not-allowed"),
    ("systemsetup", "-getremotelogin"),
    ("/usr/sbin/systemsetup", "-gettimezone"),
    (*SCHEDULE, "on"), (*SCHEDULE, "off"),
    ("/usr/sbin/softwareupdate", "--install", "--all"),
    ("/usr/bin/defaults", "read", "com.apple.screensaver", "askForPassword"),
    ("/usr/bin/plutil", "-extract", "askForPassword", "xml1", "-o", "-", "/private/user-preferences"),
    (sys.executable, macos._PREFERENCE_HELPER, "com.apple.screensaver", "askForPassword"),
    ("/usr/bin/sudo", "-n", "--", *REMOTE),
    (*SUDO, *REMOTE),
])
def test_no_other_command_or_argument_combination_can_reach_elevation(command):
    runner = ReadOnlyRunner()
    collector = macos.MacOSCollector(runner=runner, allow_elevated_read=True)
    query = macos._Query("remote_login", "enabled", command, lambda text: False)
    normal = collector._unknown(query, macos._PRIVILEGE_REQUIRED)
    assert collector._optional_elevated_status(query, normal) is None
    assert runner.calls == []


def test_fixed_elevation_allowlist_contains_only_three_read_only_getters():
    assert macos._ELEVATED_READ_COMMANDS == ALLOWED


def test_user_preferences_stay_unprivileged_and_known_delay_keeps_independent_semantics():
    bundle, results, runner = collect({
        REMOTE: DENIED, SUDO + REMOTE: "Remote Login: Off",
        TIME: DENIED, SUDO + TIME: "Network Time: On",
        SCHEDULE: DENIED, SUDO + SCHEDULE: "Automatic check is on",
        probe("com.apple.screensaver", "askForPassword"): preference(False, explicit_current_host=False),
        probe("com.apple.screensaver", "askForPasswordDelay"): preference(0, explicit_current_host=0),
    }, allow=True)
    assert results["MAC-010"]["status"] == "FAIL"
    assert results["MAC-011"]["status"] == "PASS"
    assert bundle["evidence"]["screen_lock_delay"]["seconds"] == 0
    assert set(elevated_calls(runner)) == {SUDO + cmd for cmd in ALLOWED}
    for command, _ in runner.calls:
        if command[0] == "/usr/bin/sudo":
            assert command[:len(SUDO)] == SUDO
            assert command[len(SUDO):] in ALLOWED
            assert not any("python" in arg or "_macos_preferences.py" in arg for arg in command)
        if command[0] == sys.executable:
            assert command[1] == macos._PREFERENCE_HELPER
            assert len(command) == 4


def key_shape(value):
    if isinstance(value, dict):
        return {key: key_shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [key_shape(item) for item in value]
    return "scalar"


def test_public_json_key_structure_is_identical_with_elevation_enabled():
    responses = {
        REMOTE: DENIED, SUDO + REMOTE: "Remote Login: Off",
        TIME: DENIED, SUDO + TIME: "Network Time: On",
        SCHEDULE: DENIED, SUDO + SCHEDULE: "Automatic check is on",
    }
    normal, normal_results, _ = collect(responses)
    elevated, elevated_results, _ = collect(responses, allow=True)
    assert key_shape(normal) == key_shape(elevated)
    assert key_shape(build_profile_report("macos", normal)) == key_shape(build_profile_report("macos", elevated))
    for source in ("remote_login", "network_time", "update_check"):
        assert set(normal["evidence"][source]) == {"enabled", "_collection_ok", "_raw", "_scope"}
        assert set(elevated["evidence"][source]) == set(normal["evidence"][source])
    assert normal_results["MAC-009"]["status"] == "ERROR"
    assert elevated_results["MAC-009"]["status"] == "PASS"
    json.dumps(normal, allow_nan=False)
    json.dumps(elevated, allow_nan=False)


def test_elevation_cache_is_per_assessment_and_retries_once_per_allowed_query():
    runner = ReadOnlyRunner({REMOTE: DENIED, SUDO + REMOTE: "Remote Login: Off"})
    collector = macos.MacOSCollector(runner=runner, allow_elevated_read=True)
    first = collector.collect()
    assert first["evidence"]["remote_login"]["enabled"] is False
    assert elevated_calls(runner) == [SUDO + REMOTE]
    query = next(query for query in macos._QUERIES if query.source == "remote_login")
    collector._collect_query(query)
    assert elevated_calls(runner) == [SUDO + REMOTE]
    runner.responses[SUDO + REMOTE] = "Remote Login: On"
    second = collector.collect()
    assert second["evidence"]["remote_login"]["enabled"] is True
    assert elevated_calls(runner) == [SUDO + REMOTE, SUDO + REMOTE]


@pytest.mark.parametrize("value", [None, 0, 1, "yes", "false", [], {}, object()])
def test_elevation_constructor_requires_an_explicit_boolean(value):
    with pytest.raises(TypeError, match="explicit Boolean"):
        macos.MacOSCollector(runner=ReadOnlyRunner(), allow_elevated_read=value)
