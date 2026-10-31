import json
from pathlib import Path

from cyberassess.evaluator import evaluate_baseline
from cyberassess.reporting import _verdict, render_html


def load_controls() -> list[dict]:
    return json.loads(Path("config/controls.json").read_text(encoding="utf-8"))


def compliant_evidence() -> dict:
    return {
        "sshd": {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "MaxAuthTries": 4,
            "X11Forwarding": "no",
            "ClientAliveInterval": 300,
            "_collection_ok": True,
            "_raw": "test SSH evidence",
        },
        "firewall": {"status": "active", "_collection_ok": True, "_raw": "active"},
        "files": {"shadow_mode": "640", "passwd_mode": "644", "_collection_ok": True, "_raw": "640/644"},
        "accounts": {"empty_password_count": 0, "uid0_nonroot_count": 0, "_collection_ok": True, "_raw": "0/0"},
        "password_policy": {"minimum_length": 14, "configured": True, "_collection_ok": True, "_raw": "14"},
        "auditd": {"status": "active", "_collection_ok": True, "_raw": "active"},
        "updates": {"enabled": True, "_collection_ok": True, "_raw": "true"},
        "time_sync": {"status": "active", "_collection_ok": True, "_raw": "active"},
        "services": {"telnet_installed": False, "_collection_ok": True, "_raw": "false"},
    }


def test_baseline_has_15_controls():
    assert len(load_controls()) == 15


def test_all_compliant_evidence_is_100_percent():
    result = evaluate_baseline(load_controls(), compliant_evidence())
    assert result["total_controls"] == 15
    assert result["passed"] == 15
    assert result["failed"] == 0
    assert result["errors"] == 0
    assert result["compliance_score"] == 100.0


def test_not_configured_password_policy_is_fail_not_error():
    control = next(c for c in load_controls() if c["id"] == "AUTH-003")
    evidence = {"password_policy": {"minimum_length": None, "configured": False, "_collection_ok": True, "_raw": "missing"}}
    result = evaluate_baseline([control], evidence)
    assert result["results"][0]["status"] == "FAIL"
    assert result["results"][0]["actual"] == "Not configured"
    assert result["errors"] == 0


def test_collection_failure_is_error():
    control = next(c for c in load_controls() if c["id"] == "NET-001")
    evidence = {"firewall": {"status": None, "_collection_ok": False, "_raw": "collector failed"}}
    result = evaluate_baseline([control], evidence)
    assert result["results"][0]["status"] == "ERROR"
    assert result["errors"] == 1


def test_verdict_thresholds_are_documented_behavior():
    assert _verdict(90.0)[0] == "Compliant"
    assert _verdict(70.0)[0] == "Partially compliant"
    assert _verdict(69.9)[0] == "Non-compliant"


def test_report_renders_key_sections():
    assessment = evaluate_baseline(load_controls(), compliant_evidence())
    report = {"target_name": "test-host", "platform": "Ubuntu Linux", "assessment": assessment}
    html = render_html(report)
    assert "Security Baseline Report" in html
    assert "90%+ Compliant" in html
    assert "Pass rate by category" in html


def test_error_control_reduces_weighted_score():
    controls = load_controls()
    evidence = compliant_evidence()

    # Simulate a live collection failure for TIME-001.
    evidence["time_sync"]["_collection_ok"] = False
    evidence["time_sync"]["_raw"] = "Simulated time synchronization collection failure."

    result = evaluate_baseline(controls, evidence)

    assert result["passed"] == 14
    assert result["failed"] == 0
    assert result["errors"] == 1
    assert result["compliance_score"] == 97.1

    time_result = next(
        item for item in result["results"]
        if item["control_id"] == "TIME-001"
    )

    assert time_result["status"] == "ERROR"
    assert time_result["actual"] is None
