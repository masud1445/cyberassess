"""Provenance and interpretation requirements of every generated HTML report."""

from copy import deepcopy

import pytest

from cyberassess.profiles import build_profile_report, get_profile
from cyberassess.reporting import render_html


@pytest.mark.parametrize("profile", ["ubuntu", "windows", "macos"])
def test_legacy_and_versioned_demo_reports_never_look_like_live_results(profile):
    sample = get_profile(profile).load_demo()
    report = build_profile_report(profile, sample, assessment_mode="demo")
    for item in (report, {**sample, "assessment": report["assessment"]}):
        document = render_html(item)
        assert "Demonstration data · illustrative results, not a live device assessment." in document
        assert "point-in-time snapshot" in document
        assert "does not refresh automatically" in document
        assert "not formal compliance certification" in document
        assert "Live native assessment" not in document


@pytest.mark.parametrize("mode,method,notice", [
    ("local", "local / native commands", "Live native assessment"),
    ("ssh", "SSH / Paramiko", "Live Ubuntu SSH assessment"),
])
def test_report_source_and_safety_language_does_not_modify_assessment(mode, method, notice):
    bundle = {"target_name": "authorized-test-target", "platform": "Ubuntu Linux",
              "collector": {"method": method, "mode": mode}, "evidence": {}}
    report = build_profile_report("ubuntu", bundle, assessment_mode=mode)
    before = deepcopy(report)
    document = render_html(report)
    assert notice in document
    assert "not a confirmed insecure setting" in document
    assert "never run automatically" in document
    assert "Baseline verdict" in document
    assert "not formal compliance certification" in document
    assert report == before


def test_conflicting_live_provenance_is_not_silently_resolved():
    report = build_profile_report("macos", {"evidence": {}, "collector": {"method": "SSH / Paramiko"}}, assessment_mode="local")
    document = render_html(report)
    assert "Assessment source not verified" in document
    assert "Live native assessment" not in document


def test_sample_data_flag_keeps_demo_warning_even_with_a_conflicting_live_mode():
    report = build_profile_report("macos", {"evidence": {}, "collector": {
        "method": "local / native commands", "sample_data": True,
    }}, assessment_mode="demo")
    # Imported historical documents still get a defensive warning even though
    # the typed builder now rejects creating this inconsistent live envelope.
    report["assessment_mode"] = "local"
    document = render_html(report)
    assert "Demonstration data" in document
    assert "Live native assessment" not in document


def test_collection_limitations_are_visible_redacted_and_escaped():
    report = build_profile_report("windows", {"evidence": {}, "collector": {
        "method": "local / PowerShell", "limitations": 'Denied access; token=hidden-token; <script>unsafe</script>',
    }}, assessment_mode="local")
    document = render_html(report)
    assert "Evidence limitations" in document and "Denied access" in document
    assert "hidden-token" not in document
    assert "<script>" not in document
    assert "&lt;script&gt;" in document
