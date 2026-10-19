from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import json
from pathlib import Path
import re

import pytest

from cyberassess.platforms import detect_local_profile
from cyberassess.profiles import Profile, build_profile_report, get_profile, list_profiles


@pytest.mark.parametrize(
    ("system", "release", "expected"),
    [
        ("Windows", {}, "windows"),
        ("Darwin", {}, "macos"),
        ("Linux", {"ID": "ubuntu", "VERSION_ID": "24.04"}, "ubuntu"),
        ("Linux", {"ID": "Ubuntu"}, "ubuntu"),
    ],
)
def test_platform_detection(system, release, expected):
    assert detect_local_profile(system=system, os_release=release) == expected


@pytest.mark.parametrize(
    ("system", "release"),
    [
        ("Linux", {"ID": "debian", "ID_LIKE": "ubuntu"}),
        ("Linux", {"ID": "linuxmint", "ID_LIKE": "ubuntu debian"}),
        ("Linux", {}),
        ("FreeBSD", {}),
        ("", {}),
    ],
)
def test_platform_detection_does_not_guess_unsupported_profiles(system, release):
    with pytest.raises(ValueError, match="Unsupported"):
        detect_local_profile(system=system, os_release=release)


def test_default_platform_detection_reads_actual_system_and_release(monkeypatch):
    monkeypatch.setattr("cyberassess.platforms.platform.system", lambda: "Linux")
    monkeypatch.setattr("cyberassess.platforms.platform.freedesktop_os_release", lambda: {"ID": "ubuntu"})
    assert detect_local_profile() == "ubuntu"


def test_unreadable_linux_release_is_actionable(monkeypatch):
    def unreadable():
        raise OSError("os-release unavailable")

    monkeypatch.setattr("cyberassess.platforms.platform.freedesktop_os_release", unreadable)
    with pytest.raises(ValueError, match="requires Ubuntu"):
        detect_local_profile(system="Linux")


def test_profiles_are_versioned_and_immutable():
    profiles = list_profiles()
    assert isinstance(profiles, tuple)
    assert [p.id for p in profiles] == ["ubuntu", "windows", "macos"]
    assert all(p.version == "1" for p in profiles)
    with pytest.raises(FrozenInstanceError):
        profiles[0].version = "2"


def test_unknown_profile_has_clear_choices():
    with pytest.raises(ValueError, match="ubuntu, windows, macos"):
        get_profile("unknown")


@pytest.mark.parametrize(("profile_id", "expected_count"), [("ubuntu", 15), ("windows", 13), ("macos", 12)])
def test_all_profiles_have_consistent_controls_and_nist_mappings(profile_id, expected_count):
    profile = get_profile(profile_id)
    controls = profile.load_controls()
    assert len(controls) == expected_count
    assert len({control["id"] for control in controls}) == expected_count
    for control in controls:
        assert control["profile"] == profile_id
        assert control["category"] and control["description"] and control["title"]
        assert control["severity"] in {"HIGH", "MEDIUM", "LOW"}
        assert re.fullmatch(r"[A-Z]{2}-\d+(?:\(\d+\))?", control["nist"])
        assert control["source"] and control["key"] and control["remediation"]
        assert control["operator"] in {"EQUALS", "GREATER_OR_EQUAL", "LESS_OR_EQUAL", "MODE_AT_MOST"}


def test_profile_paths_are_independent_of_current_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert len(get_profile("ubuntu").load_controls()) == 15
    assert get_profile("ubuntu").load_demo()["target_name"] == "demo-host"


def example_control():
    return {
        "id": "EXAMPLE-001", "title": "Example", "source": "example",
        "key": "enabled", "operator": "EQUALS", "severity": "HIGH",
        "expected": True, "nist": "CM-6", "remediation": "Review approved policy.",
    }


def write_example_profile(tmp_path, controls):
    path = tmp_path / "controls.json"
    path.write_text(json.dumps(controls), encoding="utf-8")
    return Profile("example", "Example", "1", "Example OS", "Test baseline", path, tmp_path / "demo.json")


def test_metadata_adapter_preserves_declared_category_and_description(tmp_path):
    control = {**example_control(), "category": "Custom category", "description": "Custom description"}
    profile = write_example_profile(tmp_path, [control])
    assert profile.load_controls() == [{**control, "profile": "example"}]


@pytest.mark.parametrize("field", ["id", "title", "source", "key", "operator", "severity", "nist", "remediation"])
@pytest.mark.parametrize("invalid", [None, "", "  ", 7, []])
def test_control_required_string_fields_reject_missing_or_invalid_values(tmp_path, field, invalid):
    control = example_control()
    if invalid is None:
        del control[field]
    else:
        control[field] = invalid
    with pytest.raises(ValueError, match=f"Profile 'example' control #1: field '{field}' must be a non-empty string"):
        write_example_profile(tmp_path, [control]).load_controls()


def test_duplicate_control_ids_fail_with_profile_and_control_context(tmp_path):
    with pytest.raises(ValueError, match=r"Profile 'example' control #2 \('EXAMPLE-001'\): duplicate control ID"):
        write_example_profile(tmp_path, [example_control(), example_control()]).load_controls()


@pytest.mark.parametrize(("field", "invalid", "reason"), [
    ("operator", "EXECUTE", "unsupported operator"),
    ("severity", "CRITICAL", "severity must be HIGH, MEDIUM or LOW"),
    ("profile", "other", "must match selected profile 'example'"),
    ("profile", None, "must match selected profile 'example'"),
    ("category", "", "field 'category' must be a non-empty string"),
    ("category", [], "field 'category' must be a non-empty string"),
    ("description", " ", "field 'description' must be a non-empty string"),
    ("description", 4, "field 'description' must be a non-empty string"),
])
def test_unified_control_fields_are_validated(tmp_path, field, invalid, reason):
    control = {**example_control(), field: invalid}
    with pytest.raises(ValueError, match=reason):
        write_example_profile(tmp_path, [control]).load_controls()


def test_missing_expected_value_fails_clearly(tmp_path):
    control = example_control()
    del control["expected"]
    with pytest.raises(ValueError, match="required field 'expected' is missing"):
        write_example_profile(tmp_path, [control]).load_controls()


@pytest.mark.parametrize("invalid", [None, [], {}])
def test_expected_value_rejects_unsupported_structured_values(tmp_path, invalid):
    with pytest.raises(ValueError, match="field 'expected' must be a Boolean, number or string"):
        write_example_profile(tmp_path, [{**example_control(), "expected": invalid}]).load_controls()


@pytest.mark.parametrize("expected", [False, True, 0, 14, 0.5, "no", "640", ""])
def test_supported_expected_scalars_are_preserved_without_coercion(tmp_path, expected):
    loaded = write_example_profile(tmp_path, [{**example_control(), "expected": expected}]).load_controls()
    assert loaded[0]["expected"] == expected
    assert type(loaded[0]["expected"]) is type(expected)


def test_invalid_control_json_reports_profile_context(tmp_path):
    profile = write_example_profile(tmp_path, [])
    profile.controls_path.write_text("[{invalid json", encoding="utf-8")
    with pytest.raises(ValueError, match="Profile 'example' control definitions are not valid JSON"):
        profile.load_controls()


@pytest.mark.parametrize("document", [{}, ["invalid"], None])
def test_invalid_profile_definitions_fail_clearly(tmp_path, document):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(document))
    profile = Profile("example", "Example", "1", "Example OS", "Test baseline", path, path)
    with pytest.raises(ValueError, match="list of controls"):
        profile.load_controls()


def test_profile_report_adds_metadata_without_mutating_demo_bundle():
    profile = get_profile("ubuntu")
    bundle = profile.load_demo()
    original = json.dumps(bundle, sort_keys=True)
    when = datetime(2026, 10, 19, 10, 30, tzinfo=timezone.utc)
    report = build_profile_report(profile, bundle, assessment_mode="demo", started_at=when, completed_at=when)
    assert json.dumps(bundle, sort_keys=True) == original
    assert "assessment" not in bundle
    assert report["schema_version"] == "2.0"
    assert report["application"] == {"name": "CyberAssess", "version": "2.0.0"}
    assert report["profile"] == {"id": "ubuntu", "name": profile.name, "version": "1", "platform": "Ubuntu Linux", "description": profile.description}
    assert report["assessment_mode"] == "demo"
    assert report["assessment_completed_at"] == when.isoformat()
    assert "collected_at" not in report
    assert not any(key in report for key in ("os_version", "os_build"))
    assert report["assessment"]["results"][0]["evidence_source"] == "sshd.PermitRootLogin"


@pytest.mark.parametrize("mode", ["local", "ssh"])
def test_completed_live_report_records_provided_completion_timestamp(mode):
    when = "2026-10-19T10:30:00+00:00"
    report = build_profile_report("ubuntu", get_profile("ubuntu").load_demo(), assessment_mode=mode, completed_at=when)
    assert report["collected_at"] == when


def test_collector_collection_time_is_preserved():
    bundle = get_profile("ubuntu").load_demo()
    bundle["collected_at"] = "2026-10-19T10:00:00+00:00"
    report = build_profile_report("ubuntu", bundle, assessment_mode="local", completed_at="2026-10-19T10:00:01+00:00")
    assert report["collected_at"] == bundle["collected_at"]


def test_missing_evidence_bundle_is_rejected():
    with pytest.raises(ValueError, match="evidence object"):
        build_profile_report("ubuntu", {})


@pytest.mark.parametrize("profile_id", ["ubuntu", "windows", "macos"])
def test_every_demo_supports_profile_evaluation_without_live_collection(profile_id):
    profile = get_profile(profile_id)
    report = build_profile_report(profile, profile.load_demo(), assessment_mode="demo")
    assessment = report["assessment"]
    assert assessment["total_controls"] == len(profile.load_controls())
    assert assessment["passed"] + assessment["failed"] + assessment["errors"] == assessment["total_controls"]
    assert all(r["status"] in {"PASS", "FAIL", "ERROR"} for r in assessment["results"])
