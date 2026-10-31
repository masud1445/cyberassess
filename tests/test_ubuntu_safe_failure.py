"""Portable Ubuntu native-result regressions; no SSH, shell or live reads."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest
import paramiko

from cyberassess.collector import SSHCollector
from cyberassess import collector as collector_module
from cyberassess.evaluator import evaluate_baseline
from cyberassess.profiles import get_profile


SSHD = "PermitRootLogin=no\nPasswordAuthentication=no\nMaxAuthTries=4\nX11Forwarding=no\nClientAliveInterval=300"
GOOD = {
    "hostname": "authorized-fixture",
    "sshd": SSHD,
    "firewall": "active",
    "shadow": "640",
    "passwd": "644",
    "empty_passwords": "0",
    "uid_zero": "0",
    "password_policy": "14",
    "pam_policy": "",
    "auditd": "active",
    "updates": "true",
    "time_sync": "active",
    "telnet": "false",
    "clock": "2026-10-31T03:28:00+08:00",
}


def source_for(command):
    command = command.strip()
    if command == "hostname":
        return "hostname"
    for marker, source in (
        ("/usr/sbin/sshd -T", "sshd"), ("command -v ufw", "firewall"),
        ("stat -c '%a' /etc/shadow", "shadow"), ("stat -c '%a' /etc/passwd", "passwd"),
        ('($2=="")', "empty_passwords"), ('($3==0 && $1!="root")', "uid_zero"),
        ("pwquality.conf", "password_policy"), ("/etc/pam.d/common-password", "pam_policy"),
        ("auditd.service", "auditd"), ("unattended-upgrades", "updates"),
        ("NTPSynchronized", "time_sync"), ("inetutils-telnetd", "telnet"),
        ("/bin/date --iso-8601=seconds", "clock"),
    ):
        if marker in command:
            return source
    raise AssertionError("An unreviewed query reached the injected runner.")


def assess(overrides=None):
    calls = []

    class Session:
        closed = False

        def close(self):
            self.closed = True

    collector = SSHCollector("authorized.example.test", "auditor", "unused-test-key")
    session = Session()
    collector._connect = lambda: session

    def run(client, command):
        source = source_for(command)
        calls.append(command)
        value = (overrides or {}).get(source, GOOD[source])
        return deepcopy(value) if isinstance(value, dict) else {"exit_code": 0, "stdout": value, "stderr": ""}

    collector._run = run
    bundle = collector.collect()
    assessment = evaluate_baseline(get_profile("ubuntu").load_controls(), bundle["evidence"])
    assert session.closed
    return bundle, {row["control_id"]: row for row in assessment["results"]}, assessment, calls


def test_successful_typed_queries_preserve_fifteen_pass_baseline():
    _, results, assessment, calls = assess()
    assert len(results) == 15
    assert (assessment["passed"], assessment["failed"], assessment["errors"], assessment["compliance_score"]) == (15, 0, 0, 100.0)
    assert any("sudo -n /usr/sbin/sshd -T" in command for command in calls)
    assert any("sudo -n ufw status" in command for command in calls)


@pytest.mark.parametrize("source,control", [
    ("sshd", "SSH-001"), ("firewall", "NET-001"), ("shadow", "FILE-001"),
    ("passwd", "FILE-002"), ("empty_passwords", "AUTH-001"), ("uid_zero", "AUTH-002"),
    ("password_policy", "AUTH-003"), ("pam_policy", "AUTH-003"),
    ("auditd", "LOG-001"), ("updates", "UPD-001"), ("time_sync", "TIME-001"),
    ("telnet", "SVC-001"),
])
@pytest.mark.parametrize("code", [1, 2, 127])
def test_failed_native_query_cannot_assess_even_partial_secure_stdout(source, control, code):
    bundle, results, _, _ = assess({source: {
        "exit_code": code, "stdout": GOOD[source], "stderr": "private diagnostic token=not-for-report",
    }})
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None
    assert "private diagnostic" not in json.dumps(bundle)
    assert "not-for-report" not in json.dumps(bundle)


@pytest.mark.parametrize("source,stdout,control", [
    ("firewall", "unknown", "NET-001"), ("firewall", "active\ninactive", "NET-001"),
    ("auditd", "unknown", "LOG-001"), ("time_sync", "running", "TIME-001"),
    ("updates", "true\nfalse", "UPD-001"), ("updates", "enabled?", "UPD-001"),
    ("telnet", "", "SVC-001"), ("telnet", "not found", "SVC-001"),
    ("empty_passwords", "error=0", "AUTH-001"), ("uid_zero", "-0", "AUTH-002"),
    ("shadow", "mode=640", "FILE-001"), ("passwd", "888", "FILE-002"),
    ("password_policy", "denied 14", "AUTH-003"), ("password_policy", "14\n6", "AUTH-003"),
    ("pam_policy", "14 extra", "AUTH-003"),
])
def test_unknown_or_malformed_scalar_stays_error(source, stdout, control):
    _, results, _, _ = assess({source: stdout})
    assert results[control]["status"] == "ERROR"


@pytest.mark.parametrize("source,stdout,control", [
    ("firewall", "inactive", "NET-001"), ("firewall", "not_installed", "NET-001"),
    ("auditd", "inactive", "LOG-001"), ("auditd", "not_installed", "LOG-001"),
    ("updates", "false", "UPD-001"), ("time_sync", "inactive", "TIME-001"),
    ("telnet", "true", "SVC-001"), ("empty_passwords", "1", "AUTH-001"),
    ("uid_zero", "1", "AUTH-002"), ("password_policy", "6", "AUTH-003"),
])
def test_reliable_insecure_or_absent_configuration_is_fail(source, stdout, control):
    _, results, _, _ = assess({source: stdout})
    assert results[control]["status"] == "FAIL"


@pytest.mark.parametrize("field,bad,control", [
    ("MaxAuthTries", "-4", "SSH-003"), ("MaxAuthTries", "denied4", "SSH-003"),
    ("ClientAliveInterval", "-300", "SSH-005"), ("ClientAliveInterval", "300junk", "SSH-005"),
    ("PermitRootLogin", "unknown", "SSH-001"), ("PasswordAuthentication", "maybe", "SSH-002"),
    ("X11Forwarding", "not available", "SSH-004"),
])
def test_sshd_invalid_values_are_not_coerced_into_pass_or_fail(field, bad, control):
    output = "\n".join(field + "=" + bad if line.startswith(field + "=") else line for line in SSHD.splitlines())
    _, results, _, _ = assess({"sshd": output})
    assert results[control]["status"] == "ERROR"


def test_duplicate_or_conflicting_ssh_state_is_error():
    _, results, _, _ = assess({"sshd": SSHD + "\nPermitRootLogin=yes"})
    assert all(results[control]["status"] == "ERROR" for control in ("SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005"))


@pytest.mark.parametrize("file_value,pam_value,expected", [
    ("14", "14", "PASS"), ("", "14", "PASS"), ("6", "6", "FAIL"),
    ("14", "6", "ERROR"), ("6", "14", "ERROR"), ("", "", "FAIL"),
])
def test_explicit_password_sources_require_readable_consistent_values(file_value, pam_value, expected):
    bundle, results, _, _ = assess({"password_policy": file_value, "pam_policy": pam_value})
    assert results["AUTH-003"]["status"] == expected
    if not file_value and not pam_value:
        assert bundle["evidence"]["password_policy"]["configured"] is False
        assert results["AUTH-003"]["actual"] == "Not configured"


@pytest.mark.parametrize("source", ["sshd", "firewall", "password_policy", "auditd", "updates", "time_sync", "telnet"])
def test_unexpected_diagnostics_are_not_treated_as_secure_status(source):
    _, results, _, _ = assess({source: {"exit_code": 0, "stdout": GOOD[source], "stderr": "Permission denied"}})
    control = {"sshd": "SSH-001", "firewall": "NET-001", "password_policy": "AUTH-003", "auditd": "LOG-001", "updates": "UPD-001", "time_sync": "TIME-001", "telnet": "SVC-001"}[source]
    assert results[control]["status"] == "ERROR"


@pytest.mark.parametrize("stage", ["exec", "status", "stdout", "stderr"])
@pytest.mark.parametrize("failure", [TimeoutError("private detail"), OSError("private detail"), paramiko.SSHException("private detail")])
def test_ssh_transport_failures_become_sanitized_unavailable_results(stage, failure):
    def fail():
        raise failure

    closed = []
    channel = SimpleNamespace(recv_exit_status=fail if stage == "status" else lambda: 0,
                              exit_status_ready=lambda: True, close=lambda: closed.append(True))
    stdout = SimpleNamespace(channel=channel, read=fail if stage == "stdout" else lambda: b"partial secure output")
    stderr = SimpleNamespace(read=fail if stage == "stderr" else lambda: b"")

    def execute(command, **options):
        assert command == "fixed read-only query"
        assert options == {"timeout": 20}
        if stage == "exec":
            raise failure
        return None, stdout, stderr

    result = SSHCollector._run(SimpleNamespace(exec_command=execute), "fixed read-only query")
    assert result["exit_code"] != 0
    assert result["stdout"] == ""
    assert "Unavailable:" in result["stderr"]
    assert "private detail" not in json.dumps(result)
    assert "partial secure output" not in json.dumps(result)
    assert bool(closed) is (stage != "exec")


def test_ssh_transport_does_not_hide_programming_errors():
    def execute(*args, **options):
        raise TypeError("programming defect")

    with pytest.raises(TypeError, match="programming defect"):
        SSHCollector._run(SimpleNamespace(exec_command=execute), "fixed read-only query")


def test_ssh_drains_streams_before_waiting_for_exit_status():
    calls = []

    def record(name, result):
        calls.append(name)
        return result

    channel = SimpleNamespace(exit_status_ready=lambda: record("ready", True),
                              recv_exit_status=lambda: record("status", 0), close=lambda: calls.append("close"))
    stdout = SimpleNamespace(channel=channel, read=lambda: record("stdout", b" active\n"))
    stderr = SimpleNamespace(read=lambda: record("stderr", b""))
    client = SimpleNamespace(exec_command=lambda *args, **options: record("exec", (None, stdout, stderr)))
    assert SSHCollector._run(client, "fixed read-only query") == {"exit_code": 0, "stdout": "active", "stderr": ""}
    assert calls == ["exec", "stdout", "stderr", "ready", "status"]


def test_missing_ssh_exit_status_has_bounded_wait_without_real_sleep(monkeypatch):
    clock = {"elapsed": 0.0}
    closed = []
    monkeypatch.setattr(collector_module.time, "monotonic", lambda: clock["elapsed"])
    monkeypatch.setattr(collector_module.time, "sleep", lambda seconds: clock.update(elapsed=clock["elapsed"] + seconds))
    channel = SimpleNamespace(exit_status_ready=lambda: False, close=lambda: closed.append(True),
                              recv_exit_status=lambda: pytest.fail("An unavailable status must not be awaited indefinitely"))
    client = SimpleNamespace(exec_command=lambda *args, **options: (
        None, SimpleNamespace(channel=channel, read=lambda: b"partial secure output"), SimpleNamespace(read=lambda: b""),
    ))
    result = SSHCollector._run(client, "fixed read-only query")
    assert result["exit_code"] == 124
    assert result["stdout"] == ""
    assert clock["elapsed"] == pytest.approx(20)
    assert closed == [True]


def test_ssh_cleanup_failure_does_not_replace_unavailable_evidence():
    def fail_read():
        raise TimeoutError("private detail")

    def fail_close():
        raise OSError("private cleanup detail")

    channel = SimpleNamespace(close=fail_close)
    client = SimpleNamespace(exec_command=lambda *args, **options: (
        None, SimpleNamespace(channel=channel, read=fail_read), SimpleNamespace(read=lambda: b""),
    ))
    result = SSHCollector._run(client, "fixed read-only query")
    assert result["exit_code"] == 124
    assert result["stdout"] == ""
    assert "private" not in json.dumps(result)
