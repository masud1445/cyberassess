"""Console-policy scope regressions with injected, read-only source output."""

import json
from pathlib import Path

import pytest

from cyberassess.collectors import macos
from cyberassess.evaluator import evaluate_baseline
from test_macos_remaining_four import LOCK, SCREEN, NativeOutput, preferences, probe


TARGETS = [
    ("screen_lock", "askForPassword", "MAC-010", True),
    ("screen_lock_delay", "askForPasswordDelay", "MAC-011", 0),
]


def responses_for(kind, key, value):
    if kind == "native":
        return {SCREEN: "screenLock delay is immediate"}
    if kind == "resolved":
        return {probe(LOCK, key): preferences(value, explicit_any_host=value)}
    if kind == "managed":
        return {probe(LOCK, key): preferences(value, managed=True)}
    assert kind == "partial"
    return {probe(LOCK, key): preferences(None, explicit_current_host=value)}


def collect_control(source, control, responses):
    runner = NativeOutput(responses)
    collector = macos.MacOSCollector(runner=runner)
    query = next(query for query in macos._QUERIES if query.source == source)
    evidence = collector._collect_query(query)
    definitions = json.loads(Path("config/profiles/macos.json").read_text())
    definition = next(item for item in definitions if item["id"] == control)
    result = evaluate_baseline([definition], {source: evidence})["results"][0]
    return evidence, result, runner


@pytest.mark.parametrize("source,key,control,value", TARGETS)
@pytest.mark.parametrize("kind", ["native", "resolved", "managed", "partial"])
def test_unverified_console_context_blocks_every_screen_evidence_source(monkeypatch, source, key, control, value, kind):
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: False)
    evidence, result, runner = collect_control(source, control, responses_for(kind, key, value))
    assert evidence["_collection_ok"] is False
    assert result["status"] == "ERROR"
    assert result["actual"] is None
    assert "context could not be verified" in result["raw_evidence"]
    assert "logged-in console user" in result["raw_evidence"]
    assert runner.calls == []


@pytest.mark.parametrize("source,key,control,value", TARGETS)
@pytest.mark.parametrize("kind", ["native", "resolved", "managed", "partial"])
def test_console_identity_change_discards_every_successful_screen_source(monkeypatch, source, key, control, value, kind):
    checks = []

    def same_user():
        checks.append(True)
        return len(checks) == 1

    monkeypatch.setattr(macos, "current_user_status_context_safe", same_user)
    evidence, result, runner = collect_control(source, control, responses_for(kind, key, value))
    assert len(checks) == 2
    assert evidence["_collection_ok"] is False
    assert result["status"] == "ERROR"
    assert result["actual"] is None
    assert "identity changed" in result["raw_evidence"]
    assert runner.calls
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)


@pytest.mark.parametrize("source,key,control,value,status", [
    ("screen_lock", "askForPassword", "MAC-010", True, "PASS"),
    ("screen_lock", "askForPassword", "MAC-010", False, "FAIL"),
    ("screen_lock_delay", "askForPasswordDelay", "MAC-011", 0, "PASS"),
    ("screen_lock_delay", "askForPasswordDelay", "MAC-011", 90, "FAIL"),
])
@pytest.mark.parametrize("kind", ["resolved", "managed", "partial"])
def test_matching_console_keeps_known_preference_pass_fail_semantics(monkeypatch, source, key, control, value, status, kind):
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: True)
    evidence, result, runner = collect_control(source, control, responses_for(kind, key, value))
    assert evidence["_collection_ok"] is True
    assert result["status"] == status
    assert result["actual"] == value
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)


@pytest.mark.parametrize("native,control,status,actual", [
    ("screenLock delay is immediate", "MAC-010", "PASS", True),
    ("screenLock is off", "MAC-010", "FAIL", False),
    ("screenLock delay is immediate", "MAC-011", "PASS", 0),
    ("screenLock delay is 90 seconds", "MAC-011", "FAIL", 90),
    ("screenLock is off", "MAC-011", "ERROR", None),
])
def test_matching_console_keeps_explicit_native_state_and_no_delay_inference(monkeypatch, native, control, status, actual):
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: True)
    source = "screen_lock" if control == "MAC-010" else "screen_lock_delay"
    _, result, _ = collect_control(source, control, {SCREEN: native})
    assert result["status"] == status
    assert result["actual"] == actual
