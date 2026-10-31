"""The historical helper compares synthetic serialized snapshots, not live hosts."""

from copy import deepcopy
from html.parser import HTMLParser
import json
from pathlib import Path
import runpy

import pytest


_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "comparison_report.py"


def snapshot(*statuses):
    results = [
        {"control_id": f"SYN-{index:03}", "title": "Synthetic baseline condition",
         "status": status, "severity": "MEDIUM", "expected": True,
         "actual": None if status == "ERROR" else status == "PASS", "nist": "CM-7"}
        for index, status in enumerate(statuses, 1)
    ]
    passed = statuses.count("PASS")
    return {
        "target_name": "synthetic-target.example.test", "platform": "Ubuntu Linux",
        "profile": {"id": "ubuntu", "version": "1"},
        "assessment_mode": "demo", "collector": {"method": "sample data"},
        "assessment": {"total_controls": len(results), "passed": passed,
                       "failed": statuses.count("FAIL"), "errors": statuses.count("ERROR"),
                       "compliance_score": round(passed / len(results) * 100, 1), "results": results},
    }


def inputs(tmp_path, monkeypatch, before, after):
    project = tmp_path / "comparison case café"
    directory = project / "reports"
    directory.mkdir(parents=True)
    before_file = directory / "BEFORE_54.3.json"
    after_file = directory / "AFTER_100.json"
    before_file.write_text(json.dumps(before), encoding="utf-8")
    after_file.write_text(json.dumps(after), encoding="utf-8")
    monkeypatch.chdir(project)
    return directory / "COMPARISON_54.3_TO_100.html", before_file, after_file


class Text(HTMLParser):
    def __init__(self, document):
        super().__init__()
        self.parts = []
        self.feed(document)

    def handle_data(self, value):
        if value.strip():
            self.parts.append(value.strip())


def visible(document):
    return " ".join(" ".join(Text(document).parts).split())


def test_original_same_baseline_scores_and_fixed_paths_remain_supported(tmp_path, monkeypatch):
    before = json.loads((_ROOT / "tests/fixtures/ubuntu_legacy_demo_report.json").read_text(encoding="utf-8"))
    after = deepcopy(before)
    after["assessment"].update(passed=15, failed=0, errors=0, compliance_score=100.0)
    for result in after["assessment"]["results"]:
        result.update(status="PASS", actual=result["expected"])
    output, first, second = inputs(tmp_path, monkeypatch, before, after)
    original = first.read_bytes(), second.read_bytes()
    state = runpy.run_path(str(_SCRIPT), run_name="__main__")
    assert state["before_score"] == 54.3
    assert state["after_score"] == 100
    assert state["improvement"] == 45.7
    assert len(state["fixed_controls"]) == 8
    assert state["BEFORE_FILE"] == Path("reports/BEFORE_54.3.json")
    assert state["AFTER_FILE"] == Path("reports/AFTER_100.json")
    assert state["OUTPUT_FILE"] == Path("reports/COMPARISON_54.3_TO_100.html")
    document = output.read_text(encoding="utf-8")
    assert "Demonstration snapshot comparison" in document
    assert "45.7" in document and "not formal compliance certification" in document
    assert original == (first.read_bytes(), second.read_bytes())


@pytest.mark.parametrize("previous", ["FAIL", "ERROR"])
def test_transitions_to_pass_do_not_assert_remediation_or_authorization(tmp_path, monkeypatch, previous):
    output, _, _ = inputs(tmp_path, monkeypatch, snapshot("PASS", previous), snapshot("PASS", "PASS"))
    runpy.run_path(str(_SCRIPT), run_name="__main__")
    document = output.read_text(encoding="utf-8")
    text = visible(document)
    assert "Controls Transitioning to PASS" in text
    assert "ERROR means unavailable evidence, not a confirmed insecure setting." in text
    assert "Snapshots do not prove remediation, authorization" in text
    assert "After authorized remediation" not in text
    assert "Remediation was performed" not in text
    if previous == "ERROR":
        assert "0 from FAIL and 1 previously unassessed (ERROR)" in text
        assert 'class="badge error"' in document
    else:
        assert "1 from FAIL and 0 previously unassessed (ERROR)" in text


def test_declining_score_uses_correct_signed_difference(tmp_path, monkeypatch, capsys):
    output, _, _ = inputs(tmp_path, monkeypatch, snapshot("PASS", "PASS"), snapshot("PASS", "FAIL"))
    runpy.run_path(str(_SCRIPT), run_name="__main__")
    document = output.read_text(encoding="utf-8")
    assert "-50.0" in document and "+-50.0" not in document
    assert "Score change: -50.0 points" in capsys.readouterr().out
    assert "No recorded FAIL or ERROR results changed to PASS." in document


@pytest.mark.parametrize("score", [0, 99.9, "100", True], ids=["all-pass-zero", "wrong-rounded-score", "string-score", "boolean-score"])
def test_known_weighted_score_mismatch_or_nonnumeric_grade_is_rejected(tmp_path, monkeypatch, score):
    before, after = snapshot("FAIL", "PASS"), snapshot("PASS", "PASS")
    after["assessment"]["compliance_score"] = score
    output, _, _ = inputs(tmp_path, monkeypatch, before, after)
    with pytest.raises(ValueError, match="score"):
        runpy.run_path(str(_SCRIPT), run_name="__main__")
    assert not output.exists()


@pytest.mark.parametrize("severity", [None, "UNSUPPORTED"], ids=["missing-weight", "unknown-weight"])
def test_unknown_historical_weights_are_not_invented_and_reported_basis_is_unverified(tmp_path, monkeypatch, severity):
    before, after = snapshot("FAIL", "PASS"), snapshot("PASS", "PASS")
    for report in (before, after):
        for result in report["assessment"]["results"]:
            if severity is None:
                result.pop("severity")
            else:
                result["severity"] = severity
    output, _, _ = inputs(tmp_path, monkeypatch, before, after)
    runpy.run_path(str(_SCRIPT), run_name="__main__")
    text = visible(output.read_text(encoding="utf-8"))
    assert "Before snapshot score basis is unverified" in text
    assert "After snapshot score basis is unverified" in text
    assert "severity weights are absent or unsupported" in text


@pytest.mark.parametrize("mismatch", ["target", "platform", "profile", "version", "control-set",
                                      "duplicate", "condition", "weight", "counts", "score", "status"])
def test_proven_mismatches_are_rejected_before_existing_output_is_overwritten(tmp_path, monkeypatch, mismatch):
    before, after = snapshot("FAIL", "PASS"), snapshot("PASS", "PASS")
    if mismatch == "target":
        after["target_name"] = "different-synthetic-target.example.test"
    elif mismatch == "platform":
        after["platform"] = "Windows"
    elif mismatch == "profile":
        after["profile"]["id"] = "windows"
    elif mismatch == "version":
        after["profile"]["version"] = "2"
    elif mismatch == "control-set":
        after["assessment"]["results"][0]["control_id"] = "SYN-999"
    elif mismatch == "duplicate":
        after["assessment"]["results"][1]["control_id"] = "SYN-001"
    elif mismatch == "condition":
        after["assessment"]["results"][0]["expected"] = False
    elif mismatch == "weight":
        after["assessment"]["results"][0]["severity"] = "HIGH"
    elif mismatch == "counts":
        after["assessment"]["passed"] = 1
    elif mismatch == "score":
        after["assessment"]["compliance_score"] = float("nan")
    else:
        after["assessment"]["results"][0]["status"] = "UNKNOWN"
    output, _, _ = inputs(tmp_path, monkeypatch, before, after)
    output.write_text("existing record", encoding="utf-8")
    with pytest.raises(ValueError):
        runpy.run_path(str(_SCRIPT), run_name="__main__")
    assert output.read_text(encoding="utf-8") == "existing record"


@pytest.mark.parametrize("marker", ["method", "sample-flag", "collector-mode", "report-mode"])
def test_known_demonstration_live_mix_cannot_be_published(tmp_path, monkeypatch, marker):
    before, after = snapshot("FAIL"), snapshot("PASS")
    before.pop("assessment_mode")
    before["collector"] = {"method": "local / injected test responses"}
    if marker == "method":
        before["collector"]["method"] = "sample data"
    elif marker == "sample-flag":
        before["collector"]["sample_data"] = True
    elif marker == "collector-mode":
        before["collector"]["mode"] = "demo"
    else:
        before["assessment_mode"] = "demo"
    after["assessment_mode"] = "local"
    after["collector"] = {"method": "local / injected test responses"}
    output, _, _ = inputs(tmp_path, monkeypatch, before, after)
    with pytest.raises(ValueError, match="Demonstration and live"):
        runpy.run_path(str(_SCRIPT), run_name="__main__")
    assert not output.exists()


def test_missing_historical_metadata_is_labelled_unknown_without_profile_or_live_inference(tmp_path, monkeypatch):
    before, after = snapshot("FAIL"), snapshot("PASS")
    for report in (before, after):
        report.pop("profile")
        report.pop("assessment_mode")
        report["collector"] = {}
    output, _, _ = inputs(tmp_path, monkeypatch, before, after)
    runpy.run_path(str(_SCRIPT), run_name="__main__")
    text = visible(output.read_text(encoding="utf-8"))
    assert "Not recorded (version not recorded) / Not recorded (version not recorded)" in text
    assert "Source, before / after: Not recorded / Not recorded" in text
    assert "Not recorded with a timezone" in text
    assert "it was not inferred" in text
    assert "Live local" not in text


def test_same_target_can_be_compared_across_local_and_ssh_collection(tmp_path, monkeypatch):
    before, after = snapshot("FAIL"), snapshot("PASS")
    before["assessment_mode"], after["assessment_mode"] = "ssh", "local"
    before["collector"]["method"] = "SSH / Paramiko"
    after["collector"]["method"] = "local / injected test responses"
    before["collected_at"] = "2026-10-31T03:28:00+08:00"
    after["collected_at"] = "2026-10-30T19:30:00+00:00"
    output, _, _ = inputs(tmp_path, monkeypatch, before, after)
    runpy.run_path(str(_SCRIPT), run_name="__main__")
    text = visible(output.read_text(encoding="utf-8"))
    assert "Live SSH / Live local" in text
    assert "Collection: 30 Oct 2026 · 19:28:00 UTC" in text
    assert "Collection: 30 Oct 2026 · 19:30:00 UTC" in text
