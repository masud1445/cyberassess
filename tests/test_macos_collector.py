"""Fixture-based native-query validation; these tests do not assess a live Mac."""

import json
from pathlib import Path
import subprocess

import pytest

from cyberassess.collectors.macos import MacOSCollectionError, MacOSCollector
from cyberassess.evaluator import evaluate_baseline


def controls():
    return json.loads(Path("config/profiles/macos.json").read_text(encoding="utf-8"))


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
    return "1\n"


def runner_with_override(match=None, output=None, returncode=0, stderr="", error=None, calls=None):
    def run(command, **kwargs):
        if calls is not None:
            calls.append((command, kwargs))
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
    assert len(calls) == 12
    for command, options in calls:
        assert command[0].startswith(("/usr/bin/", "/usr/sbin/", "/usr/libexec/"))
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


def test_preference_scope_does_not_claim_effective_or_all_user_policy():
    evidence = collect_override()
    assert "invoking user's" in evidence["screen_lock"]["_scope"]
    assert "effective/ByHost/MDM policy is not verified" in evidence["screen_lock"]["_raw"]
    assert "effective MDM policy is not verified" in evidence["update_check"]["_raw"]


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
