"""Excessive JSON nesting is unavailable evidence, never a process failure.

Native collector output is normally shallow. These tests cover bounded but
malformed output and interpreter-dependent JSON recursion limits without
putting large payloads in pytest IDs or Windows environment variables.
"""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from cyberassess.collectors import macos, windows
from cyberassess.profiles import get_profile
from cyberassess.evaluator import evaluate_baseline
from cyberassess.reporting import render_html


_MARKER = "DEEP_JSON_PRIVATE_DIAGNOSTIC"
_ROOT = Path(__file__).resolve().parents[1]


def nested_json(depth):
    return "[" * depth + json.dumps(_MARKER) + "]" * depth


@pytest.mark.parametrize("depth", [1500, 15000], ids=["deep-invalid-shape", "decoder-recursion-limit"])
def test_windows_nested_json_keeps_other_controls_assessable(depth):
    payloads = json.loads((_ROOT / "tests/fixtures/windows_powershell_success.json").read_text(encoding="utf-8"))
    remaining = iter(windows._QUERIES)
    malformed = nested_json(depth).encode("utf-8")
    assert len(malformed) < windows._MAX_OUTPUT_BYTES

    def run(command, **options):
        source = next(remaining)
        output = malformed if source == "secure_boot" else json.dumps(payloads[source]).encode("utf-8")
        return subprocess.CompletedProcess(command, 0, output)

    bundle = windows.WindowsCollector(runner=run).collect()
    assessment = evaluate_baseline(get_profile("windows").load_controls(), bundle["evidence"])
    assert (assessment["passed"], assessment["failed"], assessment["errors"]) == (12, 0, 1)
    evidence = bundle["evidence"]["secure_boot"]
    assert evidence["_collection_ok"] is False
    assert evidence["enabled"] is None
    assert _MARKER not in json.dumps(bundle)
    assert "RecursionError" not in json.dumps(bundle)


def fail_decoder_for(monkeypatch, malformed):
    """Exercise the catch independently of a Python version's depth threshold."""
    original = json.loads

    def loads(value, *args, **options):
        if value == malformed:
            raise RecursionError(_MARKER)
        return original(value, *args, **options)

    monkeypatch.setattr(json, "loads", loads)


@pytest.mark.parametrize("source", ["update_check", "screen_lock", "screen_lock_delay", "network_time"])
def test_macos_preference_decoder_depth_failure_remains_error(monkeypatch, source):
    malformed = nested_json(3000)
    assert len(malformed) < 8192
    fail_decoder_for(monkeypatch, malformed)
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: True)

    def run(command, **options):
        if command[:2] == [sys.executable, macos._PREFERENCE_HELPER]:
            return subprocess.CompletedProcess(command, 0, malformed, "")
        return subprocess.CompletedProcess(command, 127, "", "")

    query = next(item for item in macos._QUERIES if item.source == source)
    evidence = macos.MacOSCollector(runner=run)._collect_query(query)
    control = next(item for item in get_profile("macos").load_controls() if item["source"] == source)
    assessment = evaluate_baseline([control], {source: evidence})
    assert assessment["results"][0]["status"] == "ERROR"
    assert evidence["_collection_ok"] is False
    assert evidence[query.key] is None
    assert _MARKER not in json.dumps(evidence)
    assert "RecursionError" not in json.dumps(evidence)


def test_imported_report_omits_raw_json_when_decoder_depth_is_exceeded(monkeypatch):
    malformed = nested_json(1500)
    assert len(malformed) < 4000
    fail_decoder_for(monkeypatch, malformed)
    report = {
        "platform": "Windows", "assessment_mode": "local",
        "profile": {"id": "windows", "name": "Windows baseline"},
        "assessment": {
            "total_controls": 1, "passed": 0, "failed": 0, "errors": 1, "compliance_score": 0,
            "results": [{
                "control_id": "WIN-BOOT-001", "title": "Secure Boot is enabled", "status": "ERROR",
                "profile": "windows", "severity": "MEDIUM", "expected": True, "actual": None,
                "evidence_source": "secure_boot.enabled", "raw_evidence": malformed,
            }],
        },
    }
    document = render_html(report)
    assert "Assessment errors" in document
    assert "not a confirmed insecure setting" in document
    assert _MARKER not in document
    assert "RecursionError" not in document
