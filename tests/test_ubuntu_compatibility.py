from copy import deepcopy
import json
from pathlib import Path
import subprocess

import pytest

from cyberassess.collector import SSHCollector
from cyberassess.collectors.ubuntu import UbuntuLocalCollector
from cyberassess.evaluator import evaluate_baseline
from cyberassess.profiles import build_profile_report, get_profile


ROOT = Path(__file__).resolve().parent.parent
NEW_RESULT_FIELDS = {"profile", "category", "description", "evidence_source"}


def test_ubuntu_control_adapter_preserves_every_original_definition():
    original_bytes = (ROOT / "config" / "controls.json").read_bytes()
    original = json.loads(original_bytes)
    adapted = get_profile("ubuntu").load_controls()
    assert [{k: v for k, v in control.items() if k not in {"profile", "category", "description"}} for control in adapted] == original
    assert (ROOT / "config" / "controls.json").read_bytes() == original_bytes


def test_profile_demo_matches_existing_baseline_results_and_score_exactly():
    controls = json.loads((ROOT / "config" / "controls.json").read_text())
    bundle = json.loads((ROOT / "samples" / "demo_evidence.json").read_text())
    legacy = evaluate_baseline(controls, bundle["evidence"])
    assessment = deepcopy(build_profile_report("ubuntu", bundle)["assessment"])
    for result in assessment["results"]:
        for field in NEW_RESULT_FIELDS:
            del result[field]
    assert assessment == legacy
    assert legacy["compliance_score"] == 54.3
    assert (legacy["total_controls"], legacy["passed"], legacy["failed"], legacy["errors"]) == (15, 7, 8, 0)


def compliant_evidence():
    controls = get_profile("ubuntu").load_controls()
    evidence = {}
    for control in controls:
        source = evidence.setdefault(control["source"], {"_collection_ok": True, "_raw": "fixture evidence"})
        source[control["key"]] = control["expected"]
    evidence["password_policy"]["configured"] = True
    return evidence


def test_ubuntu_profile_retains_error_weight_and_not_configured_semantics():
    evidence = compliant_evidence()
    evidence["time_sync"]["_collection_ok"] = False
    report = build_profile_report("ubuntu", {"evidence": evidence})
    assert report["assessment"]["compliance_score"] == 97.1
    assert (report["assessment"]["passed"], report["assessment"]["failed"], report["assessment"]["errors"]) == (14, 0, 1)

    evidence = compliant_evidence()
    evidence["password_policy"].update(minimum_length=None, configured=False)
    report = build_profile_report("ubuntu", {"evidence": evidence})
    policy = next(r for r in report["assessment"]["results"] if r["control_id"] == "AUTH-003")
    assert policy["status"] == "FAIL"
    assert policy["actual"] == "Not configured"


def _command_result(command):
    """Representative native outputs for the shared Ubuntu command set."""
    command = command.strip()
    if command == "hostname":
        output = "ubuntu-fixture"
    elif command == "LC_ALL=C /bin/date --iso-8601=seconds":
        output = "2026-10-31T03:28:00+08:00"
    elif "/usr/sbin/sshd -T" in command:
        output = "PermitRootLogin=no\nPasswordAuthentication=no\nMaxAuthTries=4\nX11Forwarding=no\nClientAliveInterval=300"
    elif "command -v ufw" in command:
        output = "active"
    elif "stat -c '%a' /etc/shadow" in command:
        output = "640"
    elif "stat -c '%a' /etc/passwd" in command:
        output = "644"
    elif '($2=="")' in command:
        output = "0"
    elif '($3==0 && $1!="root")' in command:
        output = "0"
    elif "pwquality.conf" in command:
        output = "14"
    elif "/etc/pam.d/common-password" in command:
        output = "14"
    elif "auditd.service" in command:
        output = "active"
    elif "unattended-upgrades" in command:
        output = "true"
    elif "NTPSynchronized" in command:
        output = "active"
    elif "inetutils-telnetd" in command:
        output = "false"
    else:
        raise AssertionError(f"Unexpected Ubuntu collection command: {command}")
    return {"exit_code": 0, "stdout": output, "stderr": ""}


class FakeSession:
    closed = False

    def close(self):
        self.closed = True


def test_local_collector_reuses_exact_ssh_commands_and_normalization(monkeypatch):
    remote_commands, local_commands = [], []
    session = FakeSession()
    remote = SSHCollector("ubuntu-fixture", "tester", "unused-key")
    monkeypatch.setattr(remote, "_connect", lambda: session)

    def remote_run(client, command):
        remote_commands.append(command)
        return _command_result(command)

    monkeypatch.setattr(remote, "_run", remote_run)
    remote_bundle = remote.collect()
    local = UbuntuLocalCollector()

    def local_run(client, command):
        local_commands.append(command)
        return _command_result(command)

    monkeypatch.setattr(local, "_run", local_run)
    local_bundle = local.collect()
    assert remote_commands == local_commands
    assert remote_bundle["evidence"] == local_bundle["evidence"]
    assert remote_bundle["target_name"] == local_bundle["target_name"]
    assert session.closed
    assert local_bundle["collector"]["method"] == "Local / subprocess"
    assert local_bundle["collector"]["read_only"] is True
    assert "collected_at" in local_bundle
    assert not any(k in local_bundle for k in ("os_version", "os_build"))
    assert evaluate_baseline(get_profile("ubuntu").load_controls(), local_bundle["evidence"])["compliance_score"] == 100.0


def test_local_command_execution_is_noninteractive_and_bounded(monkeypatch):
    captured = {}

    def run(argv, **kwargs):
        captured.update(argv=argv, **kwargs)
        return subprocess.CompletedProcess(argv, 0, " active\n", "")

    monkeypatch.setattr("cyberassess.collectors.ubuntu.subprocess.run", run)
    collector = UbuntuLocalCollector(timeout=7)
    result = collector._run(collector._connect(), "hostname")
    assert captured["argv"] == ["/bin/sh", "-c", "hostname"]
    assert captured["stdin"] is subprocess.DEVNULL
    assert captured["timeout"] == 7
    assert captured["check"] is False
    assert result == {"exit_code": 0, "stdout": "active", "stderr": ""}


@pytest.mark.parametrize("failure", [subprocess.TimeoutExpired("hostname", 1), FileNotFoundError("shell unavailable")])
def test_local_command_failures_remain_unavailable_evidence(monkeypatch, failure):
    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr("cyberassess.collectors.ubuntu.subprocess.run", fail)
    collector = UbuntuLocalCollector(timeout=1)
    bundle = collector.collect()
    assessment = evaluate_baseline(get_profile("ubuntu").load_controls(), bundle["evidence"])
    assert bundle["evidence"]["firewall"]["_collection_ok"] is False
    assert bundle["evidence"]["sshd"]["_collection_ok"] is False
    assert assessment["passed"] == 0
    assert assessment["errors"] == 15
    # Failed reads cannot prove that a password setting is absent. Confirmed,
    # readable absence still has the evaluator's existing Not configured FAIL.
    assert assessment["failed"] == 0


def test_local_timeout_must_be_positive():
    with pytest.raises(ValueError, match="greater than zero"):
        UbuntuLocalCollector(timeout=0)
