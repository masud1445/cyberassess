"""Mocked Windows collection tests; these do not claim native Windows validation."""
import copy
import json
from pathlib import Path
import re
import subprocess

import pytest

from cyberassess.collectors import windows
from cyberassess.collectors.windows import WindowsCollectionError, WindowsCollector
from cyberassess.evaluator import evaluate_baseline


ROOT = Path(__file__).resolve().parents[1]
CONTROLS = json.loads((ROOT / "config/profiles/windows.json").read_text(encoding="utf-8"))
SUCCESS = json.loads((ROOT / "tests/fixtures/windows_powershell_success.json").read_text(encoding="utf-8"))


def runner_for(fixtures=None, overrides=None, calls=None):
    payloads = copy.deepcopy(SUCCESS if fixtures is None else fixtures)
    overrides = overrides or {}
    remaining = iter(windows._QUERIES)

    def run(args, **kwargs):
        source = next(remaining)
        if calls is not None:
            calls.append((args, kwargs))
        if source in overrides:
            response = overrides[source]
            if isinstance(response, BaseException):
                raise response
            return response
        return subprocess.CompletedProcess(args, 0, json.dumps(payloads[source]).encode("utf-8"))

    return run


def evaluate(fixtures=None, overrides=None):
    bundle = WindowsCollector(runner_for(fixtures, overrides)).collect()
    return bundle, evaluate_baseline(CONTROLS, bundle["evidence"])


def test_windows_fixture_all_controls_pass_without_changing_evaluator():
    bundle, result = evaluate()
    assert len(CONTROLS) == 13
    assert len({c["id"] for c in CONTROLS}) == 13
    assert all(c["id"].startswith("WIN-") for c in CONTROLS)
    assert all(c["profile"] == "windows" and c["description"] and c["category"] for c in CONTROLS)
    assert result["passed"] == 13
    assert result["errors"] == result["failed"] == 0
    assert result["compliance_score"] == 100.0
    assert bundle["platform"] == "Windows"
    assert bundle["collector"]["method"] == "local / PowerShell"
    assert bundle["collector"]["read_only"] is True
    assert bundle["collector"]["sample_data"] is False


def test_runner_is_noninteractive_bounded_and_queries_are_read_only():
    calls = []
    WindowsCollector(runner_for(calls=calls)).collect()
    assert len(calls) == len(windows._QUERIES)
    for args, kwargs in calls:
        assert args[0].lower().endswith(r"system32\windowspowershell\v1.0\powershell.exe")
        assert args[1:5] == ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
        assert "ConvertTo-Json -Compress" in args[-1]
        assert "UTF8Encoding" in args[-1]
        assert not re.search(r"\b(?:Set|Enable|Disable|Remove|Add|New|Start|Stop|Restart)-(?!(?:Object)\b)", args[-1], re.I)
        assert kwargs == {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE,
                          "stderr": subprocess.DEVNULL, "timeout": 20, "check": False}


@pytest.mark.parametrize("source,field,bad", [
    ("defender", "antivirus_enabled", None),
    ("defender", "realtime_enabled", "false"),
    ("defender", "realtime_enabled", 0),
    ("bitlocker", "protection_status", "Unknown"),
    ("rdp", "deny_connections", None),
    ("rdp", "deny_connections", True),
    ("rdp_nla", "user_authentication", 2),
    ("guest", "enabled", None),
    ("uac", "enable_lua", -1),
    ("smb", "smb1_enabled", "False"),
    ("inactivity", "timeout_seconds", None),
    ("inactivity", "timeout_seconds", False),
    ("inactivity", "timeout_seconds", -1),
    ("inactivity", "timeout_seconds", 4294967296),
    ("secure_boot", "enabled", "not supported"),
    ("eventlog", "status", "Unknown"),
])
def test_unknown_or_ambiguous_values_are_errors_never_assumed_false(source, field, bad):
    fixture = copy.deepcopy(SUCCESS)
    fixture[source][field] = bad
    bundle, result = evaluate(fixture)
    assert bundle["evidence"][source]["_collection_ok"] is False
    ids = {control["id"] for control in CONTROLS if control["source"] == source}
    assert all(r["status"] == "ERROR" and r["actual"] is None
               for r in result["results"] if r["control_id"] in ids)
    assert result["errors"] == len(ids)


@pytest.mark.parametrize("profiles", [
    [],
    [{"name": "Domain", "enabled": "True"}],
    [{"name": name, "enabled": "True"} for name in ("Domain", "Private", "Private")],
    [{"name": name, "enabled": "True"} for name in ("Domain", "Private", "Unknown")],
    [{"name": name, "enabled": "NotConfigured"} for name in ("Domain", "Private", "Public")],
    [{"name": name, "enabled": None} for name in ("Domain", "Private", "Public")],
    [{"name": name, "enabled": True} for name in ("Domain", "Private", "Public")],
    [{"name": name, "enabled": "True"} for name in ("Domain", "Private", "Public", "Public")],
])
def test_firewall_requires_exactly_three_distinct_known_profiles(profiles):
    fixture = copy.deepcopy(SUCCESS)
    fixture["firewall"]["profiles"] = profiles
    bundle, result = evaluate(fixture)
    assert bundle["evidence"]["firewall"]["all_profiles_enabled"] is None
    assert next(r for r in result["results"] if r["control_id"] == "WIN-NET-001")["status"] == "ERROR"


@pytest.mark.parametrize("source,values,key,expected", [
    ("defender", {"antivirus_enabled": False, "realtime_enabled": False}, "antivirus_enabled", False),
    ("bitlocker", {"protection_status": "Off"}, "protection_enabled", False),
    ("rdp", {"deny_connections": 0}, "disabled", False),
    ("rdp_nla", {"user_authentication": 0}, "required", False),
    ("guest", {"enabled": True}, "disabled", False),
    ("uac", {"enable_lua": 0}, "enabled", False),
    ("smb", {"smb1_enabled": True}, "smb1_disabled", False),
    ("secure_boot", {"enabled": False}, "enabled", False),
    ("eventlog", {"status": "Stopped"}, "running", False),
])
def test_known_insecure_values_remain_failures(source, values, key, expected):
    fixture = copy.deepcopy(SUCCESS)
    fixture[source] = values
    bundle, result = evaluate(fixture)
    assert bundle["evidence"][source]["_collection_ok"] is True
    assert bundle["evidence"][source][key] is expected
    assert result["errors"] == 0
    assert result["failed"] >= 1


def test_one_disabled_firewall_profile_fails_the_control():
    fixture = copy.deepcopy(SUCCESS)
    fixture["firewall"]["profiles"][2]["enabled"] = "False"
    _, result = evaluate(fixture)
    assert result["failed"] == 1
    assert result["errors"] == 0


@pytest.mark.parametrize("timeout,lower,upper", [(0, "FAIL", "PASS"), (1, "PASS", "PASS"),
                                                    (900, "PASS", "PASS"), (901, "PASS", "FAIL")])
def test_inactivity_policy_checks_both_explicit_bounds(timeout, lower, upper):
    fixture = copy.deepcopy(SUCCESS)
    fixture["inactivity"]["timeout_seconds"] = timeout
    _, result = evaluate(fixture)
    by_id = {r["control_id"]: r for r in result["results"]}
    assert by_id["WIN-LOCK-001"]["status"] == lower
    assert by_id["WIN-LOCK-002"]["status"] == upper


@pytest.mark.parametrize("response", [
    subprocess.CompletedProcess([], 1, b"", b"private credential must never be echoed"),
    subprocess.TimeoutExpired("PowerShell", 20, output=b"private credential"),
    FileNotFoundError("private path must never be echoed"),
    PermissionError("private user must never be echoed"),
])
def test_collection_failures_are_sanitized_and_other_checks_continue(response):
    bundle, result = evaluate(overrides={"bitlocker": response})
    assert result["errors"] == 1
    assert result["passed"] == 12
    assert "private" not in json.dumps(bundle)
    assert bundle["evidence"]["bitlocker"]["protection_enabled"] is None


@pytest.mark.parametrize("stdout", [b"", b"not json", b"[]", b"null", b"{}", b"\xff", b"\xff\xfe{\x00}\x00",
                                    b'{"enabled":true,"enabled":false}', b'{"enabled":true}SECRET',
                                    b'{"enabled":true,"extra":"' + b"x" * 32768 + b'"}'])
def test_invalid_encoding_malformed_oversized_or_ambiguous_json_is_error(stdout):
    bundle, result = evaluate(overrides={"secure_boot": subprocess.CompletedProcess([], 0, stdout)})
    assert result["errors"] == 1
    assert bundle["evidence"]["secure_boot"]["_collection_ok"] is False
    assert len(bundle["evidence"]["secure_boot"]["_raw"]) < 150


@pytest.mark.parametrize("stdout", [b'\xef\xbb\xbf{"enabled":true}', '\ufeff{"enabled":true}',
                                    '  {"enabled":true}\r\n'])
def test_json_utf8_bom_and_normal_whitespace_are_supported(stdout):
    _, result = evaluate(overrides={"secure_boot": subprocess.CompletedProcess([], 0, stdout)})
    assert result["passed"] == 13


def test_raw_evidence_only_contains_allowlisted_scalars():
    fixture = copy.deepcopy(SUCCESS)
    for source in fixture:
        fixture[source]["password"] = "TEST-SECRET-DO-NOT-EXPOSE"
        fixture[source]["arbitrary_registry_dump"] = {"secret": "TEST-SECRET-DO-NOT-EXPOSE"}
    fixture["firewall"]["profiles"][0]["credential"] = "TEST-SECRET-DO-NOT-EXPOSE"
    bundle, result = evaluate(fixture)
    assert result["passed"] == 13
    assert "TEST-SECRET-DO-NOT-EXPOSE" not in json.dumps(bundle)
    for source in bundle["evidence"].values():
        raw = json.loads(source["_raw"])
        assert all(type(value) in (bool, int, str) for value in raw.values())


def test_non_windows_native_collection_fails_without_starting_a_process(monkeypatch):
    monkeypatch.setattr(windows.platform, "system", lambda: "Linux")
    monkeypatch.setattr(windows.subprocess, "run", lambda *a, **kw: pytest.fail("must not execute"))
    with pytest.raises(WindowsCollectionError, match="native Windows"):
        WindowsCollector().collect()


def test_default_runner_is_subprocess_run_on_native_windows(monkeypatch):
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows.subprocess, "run", runner_for())
    assert WindowsCollector().collect()["evidence"]["secure_boot"]["enabled"] is True


def test_hostname_is_bounded_sanitized_and_no_environment_credentials_are_copied(monkeypatch):
    monkeypatch.setattr(windows.platform, "node", lambda: "not-a-host\nSECRET")
    monkeypatch.setenv("PASSWORD", "TEST-SECRET-DO-NOT-EXPOSE")
    bundle, _ = evaluate()
    assert bundle["target_name"] == "Unknown (local Windows host)"
    assert "TEST-SECRET-DO-NOT-EXPOSE" not in json.dumps(bundle)


def test_guest_query_uses_rid_not_localized_account_name():
    query = windows._QUERIES["guest"]
    assert "-501$" in query
    assert "-Name" not in query
    assert "Count -ne 1" in query


def test_bitlocker_query_only_reads_os_volume_protection_status():
    query = windows._QUERIES["bitlocker"]
    assert "Get-BitLockerVolume" not in query
    assert "root/CIMV2/Security/MicrosoftVolumeEncryption" in query
    assert "-ClassName 'Win32_EncryptableVolume' -Property 'DriveLetter'" in query
    assert "Where-Object { $_.DriveLetter -eq $env:SystemDrive }" in query
    assert "Count -ne 1" in query
    assert re.findall(r"-MethodName\s+'([^']+)'", query) == ["GetProtectionStatus"]
    assert "$null -eq $protection.ReturnValue -or $protection.ReturnValue -ne 0" in query
    assert "$null -ne $protection.ProtectionStatus" in query
    assert "$protection.ProtectionStatus -eq 0) { $status = 'Off' }" in query
    assert "$protection.ProtectionStatus -eq 1) { $status = 'On' }" in query
    assert "$status = 'Unknown'" in query
    assert "@{ protection_status = $status }" in query
    assert not re.search(r"KeyProtector|RecoveryPassword|RecoveryKey", query, re.I)


def test_demo_is_explicit_sample_data_and_contains_pass_fail_error():
    bundle = json.loads((ROOT / "samples/windows_demo_evidence.json").read_text(encoding="utf-8"))
    assert bundle["collector"]["method"] == "sample data"
    assert bundle["collector"]["mode"] == "demo"
    assert bundle["collector"]["sample_data"] is True
    result = evaluate_baseline(CONTROLS, bundle["evidence"])
    assert result["passed"] > 0 and result["failed"] > 0 and result["errors"] > 0
