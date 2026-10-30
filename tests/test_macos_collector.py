"""Fixture-based native-query validation; these tests do not assess a live Mac."""

import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
from types import SimpleNamespace

import pytest

from cyberassess.collectors.macos import MacOSCollectionError, MacOSCollector
from cyberassess.collectors import macos
from cyberassess.evaluator import evaluate_baseline


@pytest.fixture(autouse=True)
def matching_invoking_console_context(monkeypatch):
    # Native-query fixtures model an authorized, logged-in console user.
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: True)


def controls():
    return json.loads(Path("config/profiles/macos.json").read_text(encoding="utf-8"))


def effective_payload(value, *, domain="com.apple.screensaver", managed=False):
    return json.dumps({
        "available": value is not None, "value": value,
        "managed": managed, "managed_available": True,
        "explicit_current_host": None, "explicit_any_host": value,
        "machine_current_host": None,
        "machine_any_host": value if domain == "com.apple.SoftwareUpdate" else None,
    })


def native_output(command):
    """Representative native output for a fully explicit passing fixture."""
    if command[-1] == "status" and command[0].endswith("fdesetup"):
        return "FileVault is On.\n"
    if command[-1] == "--getglobalstate":
        return "Firewall is enabled. (State = 1)\n"
    if command[0].endswith("csrutil"):
        return "System Integrity Protection status: enabled.\n"
    if command[-1] == "--status":
        return "assessments enabled\n"
    if command[-1] == "-getremotelogin":
        return "Remote Login: Off\n"
    if command[-1] == "-getusingnetworktime":
        return "Network Time: On\n"
    if command[-1] == "askForPasswordDelay":
        return "0\n"
    if command[0] in {"/usr/bin/plutil", "/bin/launchctl"} or command[-1] == "TMAutomaticTimeOnlyEnabled":
        # These older fixtures supply no fallback evidence. Do not invent it
        # with the generic '1' used for the original explicit preferences.
        return ""
    return "1\n"


def runner_with_override(match=None, output=None, returncode=0, stderr="", error=None, calls=None):
    def run(command, **kwargs):
        if calls is not None:
            calls.append((command, kwargs))
        if command[0] == sys.executable or command[0] == "/usr/sbin/softwareupdate":
            domain, key = command[-2:] if command[0] == sys.executable else ("com.apple.SoftwareUpdate", "AutomaticCheckEnabled")
            original = ["/usr/bin/defaults", "read", domain, key]
            raw = output or "" if match is not None and match in original else native_output(original)
            valid = not (match is not None and match in original and (returncode or stderr or error))
            value = (macos._delay(raw) if key == "askForPasswordDelay" else macos._preference(raw)) if valid else None
            if domain == "com.apple.timed":
                value = None  # No machine-enforcement evidence in this fixture.
            if command[0] == sys.executable:
                return subprocess.CompletedProcess(command, 0, effective_payload(value, domain=domain), "")
            schedule = "" if value is None else ("Automatic check is on" if value else "Automatic check is off")
            return subprocess.CompletedProcess(command, 0, schedule, "")
        if match is not None and match in command:
            if error is not None:
                raise error
            return subprocess.CompletedProcess(command, returncode, output or "", stderr)
        return subprocess.CompletedProcess(command, 0, native_output(command), "")
    return run


def collect_override(*args, **kwargs):
    return MacOSCollector(runner=runner_with_override(*args, **kwargs)).collect()["evidence"]


def evaluate_source(source, evidence):
    selected = [control for control in controls() if control["source"] == source]
    assert len(selected) == 1
    return evaluate_baseline(selected, evidence)["results"][0]


def test_passing_native_fixtures_and_fixed_read_only_commands():
    calls = []
    bundle = MacOSCollector(runner=runner_with_override(calls=calls)).collect()
    result = evaluate_baseline(controls(), bundle["evidence"])
    assert result["total_controls"] == 12
    assert result["passed"] == 12
    assert result["compliance_score"] == 100.0
    assert bundle["platform"] == "macOS"
    assert bundle["collector"]["mode"] == "local"
    assert bundle["collector"]["read_only"] is True
    assert "invoking user" in bundle["collector"]["scope"]
    assert len(calls) == len({tuple(command) for command, _ in calls})
    for command, options in calls:
        assert command[0].startswith(("/usr/bin/", "/usr/sbin/", "/usr/libexec/")) or command[0] == sys.executable
        if command[0] == sys.executable:
            assert Path(command[1]).is_absolute() and command[1].endswith("_macos_preferences.py")
        assert options["shell"] is False
        assert options["check"] is False
        assert options["timeout"] == 10
        assert options["stdin"] == subprocess.DEVNULL
        assert options["env"]["LC_ALL"] == "C"
        assert not any(arg.startswith(("-set", "--set", "--enable", "--disable")) for arg in command)
        assert "sudo" not in command


@pytest.mark.parametrize("match,source,output,actual", [
    ("/usr/bin/fdesetup", "filevault", "FileVault is Off.\n", False),
    ("--getglobalstate", "application_firewall", "Firewall is disabled. (State = 0)", False),
    ("--getglobalstate", "application_firewall", "Firewall is set to block all non-essential incoming connections. (State = 2)", True),
    ("/usr/bin/csrutil", "system_integrity", "System Integrity Protection status: disabled.", False),
    ("--status", "gatekeeper", "assessments disabled", False),
    ("-getremotelogin", "remote_login", "Remote Login: On", True),
    ("-getusingnetworktime", "network_time", "Network Time: Off", False),
    ("AutomaticCheckEnabled", "update_check", "false", False),
    ("AutomaticDownload", "update_download", "true\n", True),
    ("askForPassword", "screen_lock", "0", False),
    ("askForPasswordDelay", "screen_lock_delay", "5.5", 5.5),
])
def test_known_native_variants(match, source, output, actual):
    evidence = collect_override(match, output)
    result = evaluate_source(source, evidence)
    assert evidence[source]["_collection_ok"] is True
    assert result["actual"] == actual
    assert result["status"] in {"PASS", "FAIL"}


@pytest.mark.parametrize("match,source,output", [
    ("/usr/bin/fdesetup", "filevault", "Encryption in progress: Percent completed = 50"),
    ("/usr/bin/fdesetup", "filevault", "FileVault is Off.\nFileVault is On."),
    ("--getglobalstate", "application_firewall", "Firewall is enabled. (State = 0)"),
    ("/usr/bin/csrutil", "system_integrity", "System Integrity Protection status: enabled (Custom Configuration)."),
    ("/usr/bin/csrutil", "system_integrity", "System Integrity Protection status: unknown (Custom Configuration)."),
    ("--status", "gatekeeper", "This operation is no longer supported."),
    ("AutomaticCheckEnabled", "update_check", ""),
    ("AutomaticCheckEnabled", "update_check", "2"),
    ("AutomaticCheckEnabled", "update_check", "1\n0"),
    ("askForPasswordDelay", "screen_lock_delay", "-1"),
    ("askForPasswordDelay", "screen_lock_delay", "nan"),
    ("askForPasswordDelay", "screen_lock_delay", "Infinity"),
    ("askForPasswordDelay", "screen_lock_delay", "2147483648"),
    ("-getremotelogin", "remote_login", "You need administrator access to run this tool... exiting!"),
    ("-getusingnetworktime", "network_time", "unknown"),
])
def test_ambiguous_unsupported_or_missing_values_are_error(match, source, output):
    evidence = collect_override(match, output)
    result = evaluate_source(source, evidence)
    assert evidence[source]["_collection_ok"] is False
    assert result["status"] == "ERROR"
    assert result["actual"] is None


def test_missing_preference_is_error_and_other_update_keys_are_independent():
    evidence = collect_override("CriticalUpdateInstall", returncode=1, stderr="Domain/default pair does not exist")
    assert evaluate_source("security_updates", evidence)["status"] == "ERROR"
    assert evaluate_source("update_check", evidence)["status"] == "PASS"
    assert evaluate_source("update_download", evidence)["status"] == "PASS"
    assert "no default was inferred" in evidence["security_updates"]["_raw"]


@pytest.mark.parametrize("error", [
    FileNotFoundError("native tool missing /private/user-path"),
    PermissionError("private data should not enter reports"),
    subprocess.TimeoutExpired(["native-tool"], 10, output="secret stdout", stderr="secret stderr"),
])
def test_execution_failures_are_error_and_do_not_abort_other_checks(error):
    evidence = collect_override("/usr/bin/fdesetup", error=error)
    assert evaluate_source("filevault", evidence)["status"] == "ERROR"
    assert evaluate_source("gatekeeper", evidence)["status"] == "PASS"
    assert "private" not in evidence["filevault"]["_raw"]
    assert "secret" not in evidence["filevault"]["_raw"]


def test_unprivileged_nonzero_does_not_infer_pass_from_stdout():
    evidence = collect_override("-getremotelogin", "Remote Login: Off", returncode=1, stderr="You need administrator access to run this tool")
    result = evaluate_source("remote_login", evidence)
    assert result["status"] == "ERROR"
    assert result["actual"] is None
    assert "privileges" in result["raw_evidence"]


@pytest.mark.parametrize("stderr", ["Permission denied", "Unsupported platform diagnostic /private/user"])
def test_diagnostic_cannot_pass_even_with_recognized_stdout_and_zero_exit(stderr):
    evidence = collect_override("/usr/bin/fdesetup", "FileVault is On.", stderr=stderr)
    result = evaluate_source("filevault", evidence)
    assert result["status"] == "ERROR"
    assert result["actual"] is None
    assert "/private/user" not in result["raw_evidence"]


def test_unknown_native_output_is_not_retained_in_evidence():
    evidence = collect_override("--status", "password=hunter2 token=secret /Users/private-user", stderr="private diagnostic")
    serialized = json.dumps(evidence)
    assert "hunter2" not in serialized
    assert "secret" not in serialized
    assert "private-user" not in serialized
    assert "private diagnostic" not in serialized


def test_effective_scope_distinguishes_configured_values_and_invoking_user():
    evidence = collect_override()
    assert "current-user/ByHost resolved" in evidence["screen_lock"]["_scope"]
    assert "explicit configured value=true" in evidence["screen_lock"]["_raw"]
    assert "effective machine state" in evidence["update_check"]["_scope"]


def test_default_runner_rejects_a_non_macos_host(monkeypatch):
    monkeypatch.setattr("cyberassess.collectors.macos.platform.system", lambda: "Linux")
    with pytest.raises(MacOSCollectionError, match="requires macOS"):
        MacOSCollector().collect()


def test_demo_is_marked_synthetic_and_includes_failures_and_errors():
    bundle = json.loads(Path("samples/macos_demo_evidence.json").read_text(encoding="utf-8"))
    result = evaluate_baseline(controls(), bundle["evidence"])
    assert bundle["collector"]["mode"] == "demo"
    assert "sample" in bundle["collector"]["method"]
    assert "Synthetic" in bundle["collector"]["scope"]
    assert result["passed"] == 7
    assert result["failed"] == 3
    assert result["errors"] == 2


def test_missing_hostname_is_explicitly_unknown(monkeypatch):
    monkeypatch.setattr('cyberassess.collectors.macos.platform.node', lambda: '')
    bundle = MacOSCollector(runner=runner_with_override()).collect()
    assert bundle['target_name'] == 'Unknown (local macOS host)'


def extracted_plist(value):
    return plistlib.dumps(value, fmt=plistlib.FMT_XML).decode("utf-8")


def fallback_runner(replacements=None, *, calls=None):
    """Five failed legacy reads; only explicitly supplied fallback evidence."""
    replacements = replacements or {}

    def run(command, **options):
        if calls is not None:
            calls.append((command, options))
        if command[0] == sys.executable:
            name = "effective:" + ":".join(command[-2:])
        elif command[0] == "/usr/sbin/softwareupdate":
            name = "schedule"
        elif command[:2] == ["/bin/launchctl", "print"]:
            name = "service"
        elif command[0] == "/usr/bin/plutil":
            name = command[2]
        elif command[:2] == ["/bin/launchctl", "print-disabled"]:
            name = "launchd"
        elif command[-1] == "TMAutomaticTimeOnlyEnabled":
            name = "timed"
        else:
            name = None
        if name is not None:
            response = replacements.get(name)
            if isinstance(response, Exception):
                raise response
            if isinstance(response, tuple):
                code, stdout, stderr = response
                return subprocess.CompletedProcess(command, code, stdout, stderr)
            return subprocess.CompletedProcess(command, 0 if response is not None else 1, response or "", "")
        if command[-1] in {"AutomaticCheckEnabled", "askForPassword", "askForPasswordDelay"}:
            return subprocess.CompletedProcess(command, 1, "", "Domain/default pair does not exist /Users/private")
        if command[-1] in {"-getremotelogin", "-getusingnetworktime"}:
            return subprocess.CompletedProcess(command, 1, "", "You need administrator access to run this tool")
        return subprocess.CompletedProcess(command, 0, native_output(command), "")

    return run


@pytest.fixture
def invoking_home(monkeypatch):
    home = Path("/Users/test-scope")
    monkeypatch.setattr(macos, "_invoking_user_home", lambda: home)
    return home


def test_five_legacy_errors_recover_with_authoritative_effective_evidence(invoking_home):
    calls = []
    responses = {
        "AutomaticCheckEnabled": extracted_plist(True),
        "launchd": 'disabled services = {\n "com.openssh.sshd" => disabled\n}',
        "askForPassword": extracted_plist(True),
        "askForPasswordDelay": extracted_plist(0),
        "timed": "1\n",
        "schedule": "Automatic check is on",
        "service": (113, "", 'Could not find service "com.openssh.sshd" in domain for system'),
        "effective:com.apple.screensaver:askForPassword": effective_payload(True),
        "effective:com.apple.screensaver:askForPasswordDelay": effective_payload(0),
        "effective:com.apple.timed:TMAutomaticTimeOnlyEnabled": effective_payload(True, domain="com.apple.timed", managed=True),
        "TMAutomaticTimeOnlyEnabled": extracted_plist(True),
    }
    bundle = MacOSCollector(runner=fallback_runner(responses, calls=calls)).collect()
    result = evaluate_baseline(controls(), bundle["evidence"])
    assert result["passed"] == 12
    assert result["errors"] == 0
    assert result["compliance_score"] == 100.0
    plist_commands = [cmd for cmd, _ in calls if cmd[0] == "/usr/bin/plutil"]
    assert len([cmd for cmd in plist_commands if cmd[2] in {"AutomaticCheckEnabled", "askForPassword", "askForPasswordDelay"}]) == 1
    assert all(cmd[1:2] == ["-extract"] and cmd[3:6] == ["xml1", "-o", "-"] for cmd in plist_commands)
    assert not any(cmd[2] in {"askForPassword", "askForPasswordDelay"} for cmd in plist_commands)
    assert ["/bin/launchctl", "print-disabled", "system"] in [cmd for cmd, _ in calls]
    for cmd, options in calls:
        assert options["shell"] is False
        assert options["stdin"] == subprocess.DEVNULL
        assert options["timeout"] == 10
        assert options["env"]["LC_ALL"] == "C"
        assert "sudo" not in cmd
        assert not any(arg.startswith(("-set", "--set", "--enable", "--disable", "-replace", "-insert")) for arg in cmd)
    assert "effective launchd" in bundle["evidence"]["remote_login"]["_scope"]
    assert "synchronization" in bundle["evidence"]["network_time"]["_scope"]
    assert "private" not in json.dumps(bundle["evidence"])


@pytest.mark.parametrize("key,source,output,actual", [
    ("AutomaticCheckEnabled", "update_check", extracted_plist(False), False),
    ("AutomaticCheckEnabled", "update_check", extracted_plist(1), True),
    ("askForPassword", "screen_lock", extracted_plist(False), False),
    ("askForPassword", "screen_lock", extracted_plist(0), False),
    ("askForPasswordDelay", "screen_lock_delay", extracted_plist(5.5), 5.5),
    ("askForPasswordDelay", "screen_lock_delay", extracted_plist(0.00001), 0.00001),
    ("timed", "network_time", "0", False),
    ("TMAutomaticTimeOnlyEnabled", "network_time", extracted_plist(False), False),
])
def test_explicit_fallback_alone_does_not_claim_effective_state(key, source, output, actual, invoking_home):
    evidence = MacOSCollector(runner=fallback_runner({key: output})).collect()["evidence"]
    result = evaluate_source(source, evidence)
    assert evidence[source]["_collection_ok"] is False
    assert result["actual"] is None
    assert result["status"] == "ERROR"


@pytest.mark.parametrize("state,actual", [("disabled", False), ("enabled", True), ("true", False), ("false", True)])
def test_launchctl_exact_ssh_override_supports_modern_and_older_output(state, actual, invoking_home):
    output = 'disabled services = {\n "com.company.unrelated" => enabled\n "com.openssh.sshd" => ' + state + '\n}'
    service = ('system/com.openssh.sshd = {\n path = /System/Library/LaunchDaemons/ssh.plist\n type = LaunchDaemon\n state = not running\n}') if actual else (113, "", 'Could not find service "com.openssh.sshd" in domain for system')
    evidence = MacOSCollector(runner=fallback_runner({"launchd": output, "service": service})).collect()["evidence"]
    result = evaluate_source("remote_login", evidence)
    assert result["actual"] is actual
    assert result["status"] == ("FAIL" if actual else "PASS")


@pytest.mark.parametrize("output", [
    "", "disabled services = {\n}",
    'disabled services = {\n "com.openssh.sshd-keygen-wrapper" => disabled\n}',
    'disabled services = {\n "com.openssh.sshd" => unknown\n}',
    'disabled services = {\n "com.openssh.sshd" => disabled\n "com.openssh.sshd" => enabled\n}',
    'disabled services = {\n "com.openssh.sshd" => disabled\n "com.openssh.sshd" => disabled\n}',
    'disabled services = {\n "com.openssh.sshd" => disabled\n Unexpected diagnostic\n}',
    'Could not find service "com.openssh.sshd" in domain for system',
])
def test_missing_or_ambiguous_launchd_state_is_never_inferred(output, invoking_home):
    evidence = MacOSCollector(runner=fallback_runner({"launchd": output})).collect()["evidence"]
    result = evaluate_source("remote_login", evidence)
    assert result["status"] == "ERROR"
    assert result["actual"] is None


@pytest.mark.parametrize("key,source,value", [
    ("AutomaticCheckEnabled", "update_check", "true"),
    ("AutomaticCheckEnabled", "update_check", 2),
    ("askForPassword", "screen_lock", {"value": True}),
    ("askForPassword", "screen_lock", [True]),
    ("askForPasswordDelay", "screen_lock_delay", False),
    ("askForPasswordDelay", "screen_lock_delay", "0"),
    ("askForPasswordDelay", "screen_lock_delay", -1),
    ("askForPasswordDelay", "screen_lock_delay", float("nan")),
    ("askForPasswordDelay", "screen_lock_delay", float("inf")),
    ("askForPasswordDelay", "screen_lock_delay", 2_147_483_648),
])
def test_wrong_type_or_invalid_extracted_scalar_remains_error(key, source, value, invoking_home):
    evidence = MacOSCollector(runner=fallback_runner({key: extracted_plist(value)})).collect()["evidence"]
    result = evaluate_source(source, evidence)
    assert result["status"] == "ERROR"
    assert result["actual"] is None


def test_missing_all_five_values_stays_error_without_defaults_or_user_substitution(invoking_home):
    calls = []
    evidence = MacOSCollector(runner=fallback_runner(calls=calls)).collect()["evidence"]
    assessment = evaluate_baseline(controls(), evidence)
    assert {r["control_id"] for r in assessment["results"] if r["status"] == "ERROR"} == {
        "MAC-005", "MAC-009", "MAC-010", "MAC-011", "MAC-012",
    }
    assert assessment["passed"] == 7
    assert assessment["failed"] == 0
    assert "absent delay is not zero" in evidence["screen_lock_delay"]["_raw"]
    assert ["/usr/sbin/softwareupdate", "--schedule"] in [cmd for cmd, _ in calls]
    assert not any("-currentHost" in cmd for cmd, _ in calls)
    assert all(
        tuple(cmd) in {
            ("/usr/sbin/sysadminctl", "-screenLock", "status"),
            ("/usr/sbin/sysadminctl", "-automaticTime", "status"),
        }
        for cmd, _ in calls if cmd[0] == "/usr/sbin/sysadminctl"
    )


@pytest.mark.parametrize("response", [
    (1, extracted_plist(True), "permission denied /Users/private token=hidden"),
    (0, extracted_plist(True), "Unrecognized diagnostic token=hidden"),
    (0, "malformed XML /Users/private token=hidden", ""),
    (0, '<plist><string>private token=hidden</string></plist>', ""),
    (0, "x" * 4097, ""),
    PermissionError("private token=hidden"),
    FileNotFoundError("private token=hidden"),
    subprocess.TimeoutExpired(["plutil"], 10, output="private token=hidden"),
])
def test_failed_fallbacks_remain_unknown_and_do_not_retain_diagnostics(response, invoking_home):
    evidence = MacOSCollector(runner=fallback_runner({"askForPassword": response})).collect()["evidence"]
    result = evaluate_source("screen_lock", evidence)
    assert result["status"] == "ERROR"
    assert result["actual"] is None
    assert "private" not in json.dumps(evidence)
    assert "hidden" not in json.dumps(evidence)
    assert evaluate_source("filevault", evidence)["status"] == "PASS"


def test_successful_original_reads_are_not_replaced_or_queried_twice(monkeypatch):
    def unexpected_fallback(query):
        pytest.fail("Successful evidence must not be replaced with a fallback")
    monkeypatch.setattr(macos, "_fallback_queries", unexpected_fallback)
    assessment = evaluate_baseline(controls(), MacOSCollector(runner=runner_with_override()).collect()["evidence"])
    assert assessment["passed"] == 12


def test_user_plist_home_comes_from_real_uid_not_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", "/Users/other-home")
    monkeypatch.setenv("SUDO_USER", "another-user")
    monkeypatch.setattr(os, "getuid", lambda: 0, raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    uid_home = tmp_path / "root-home"
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_dir=str(uid_home))))
    assert macos._invoking_user_home() == uid_home


def test_unknown_or_mismatched_invoking_user_never_reads_another_home(monkeypatch):
    monkeypatch.setattr(macos, "_invoking_user_home", lambda: None)
    calls = []
    evidence = MacOSCollector(runner=fallback_runner(calls=calls)).collect()["evidence"]
    for source in ("screen_lock", "screen_lock_delay"):
        assert evaluate_source(source, evidence)["status"] == "ERROR"
        assert evidence[source]["_scope"] == "unavailable effective local state"
    assert not any(cmd[0] == "/usr/bin/plutil" and cmd[2] in {"askForPassword", "askForPasswordDelay"} for cmd, _ in calls)


@pytest.mark.parametrize("xml", [
    "<plist><true/><false/></plist>",
    "<plist><integer>1</integer><integer>0</integer></plist>",
    "<plist><true><false/></true></plist>",
    "<plist><true>garbage</true></plist>",
    "<plist><dict/><true/></plist>",
    "<plist>unexpected text<true/></plist>",
    "<plist><true/>unexpected text</plist>",
    "<plist><integer>" + "9" * 309 + "</integer></plist>",
])
def test_malformed_extracted_xml_never_selects_a_convenient_scalar(xml, invoking_home):
    evidence = MacOSCollector(runner=fallback_runner({"askForPassword": xml, "askForPasswordDelay": xml})).collect()["evidence"]
    assert evaluate_source("screen_lock", evidence)["status"] == "ERROR"
    assert evaluate_source("screen_lock_delay", evidence)["status"] == "ERROR"
    assert evaluate_source("filevault", evidence)["status"] == "PASS"


def test_mismatched_process_identities_prevent_user_home_lookup(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 501, raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwuid=lambda uid: pytest.fail("Cannot select a user with mixed identities")))
    assert macos._invoking_user_home() is None


def test_primary_false_is_valid_evidence_and_never_replaced(monkeypatch):
    monkeypatch.setattr(macos, "_fallback_queries", lambda query: pytest.fail("False is a valid collected value"))
    evidence = collect_override("AutomaticCheckEnabled", "0")
    assert evidence["update_check"]["enabled"] is False
    assert evaluate_source("update_check", evidence)["status"] == "FAIL"
