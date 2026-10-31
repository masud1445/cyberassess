"""The report adapter must not promote known samples into live evidence."""

from copy import deepcopy

import pytest

import main as cli
from cyberassess.profiles import build_profile_report, get_profile
from cyberassess.reporting import render_html


@pytest.mark.parametrize("profile", ["ubuntu", "windows", "macos"])
@pytest.mark.parametrize("mode", ["local", "ssh"])
def test_known_demonstration_evidence_cannot_be_declared_live(profile, mode):
    sample = get_profile(profile).load_demo()
    original = deepcopy(sample)
    with pytest.raises(ValueError, match="Demonstration evidence"):
        build_profile_report(profile, sample, assessment_mode=mode)
    assert sample == original


@pytest.mark.parametrize("method", ["local / native commands", "SSH / Paramiko", "unknown"])
@pytest.mark.parametrize("mode", ["local", "ssh"])
def test_explicit_sample_flag_blocks_live_declaration_even_when_method_looks_native(method, mode):
    with pytest.raises(ValueError, match="Demonstration evidence"):
        build_profile_report("ubuntu", {"evidence": {}, "collector": {
            "method": method, "sample_data": True,
        }}, assessment_mode=mode)


@pytest.mark.parametrize("marker", ["collector-demo", "collector-uppercase-demo", "report-demo"])
@pytest.mark.parametrize("mode", ["local", "ssh"])
def test_known_demo_mode_cannot_be_overwritten_as_live(marker, mode):
    bundle = {"evidence": {}, "collector": {"method": "local / native commands"}}
    if marker == "report-demo":
        bundle["assessment_mode"] = "demo"
    else:
        bundle["collector"]["mode"] = "DEMO" if marker == "collector-uppercase-demo" else "demo"
    with pytest.raises(ValueError, match="Demonstration evidence"):
        build_profile_report("ubuntu", bundle, assessment_mode=mode)


@pytest.mark.parametrize("profile", ["ubuntu", "windows", "macos"])
def test_cli_does_not_publish_native_collector_accidentally_returning_a_sample(monkeypatch, tmp_path, capsys, profile):
    monkeypatch.setattr(cli, "detect_local_profile", lambda: profile)
    monkeypatch.setattr(cli, "_collect_profile", lambda *args: get_profile(profile).load_demo())
    assert cli.main(["--auto-detect", "--local", "--output", str(tmp_path)]) == 2
    assert "Demonstration evidence" in capsys.readouterr().out
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("mode", ["local", "ssh"])
def test_imported_live_bundle_without_collection_clock_does_not_invent_one(mode):
    report = build_profile_report("ubuntu", {"evidence": {}, "collector": {
        "method": mode + " / injected test responses",
    }}, assessment_mode=mode, completed_at="2026-10-31T03:28:00+08:00")
    assert report["assessment_completed_at"] == "2026-10-30T19:28:00+00:00"
    assert "collected_at" not in report


@pytest.mark.parametrize("metadata", [[], "invalid", 7, True, False])
def test_nonobject_collector_metadata_is_a_clear_validation_error(metadata):
    with pytest.raises(ValueError, match="Collector metadata must be an object"):
        build_profile_report("ubuntu", {"evidence": {}, "collector": metadata})


def test_legacy_ssh_does_not_publish_a_collector_returning_known_sample_data(monkeypatch, tmp_path, capsys):
    class WrongSource:
        def __init__(self, **options):
            pass

        def collect(self):
            return get_profile("ubuntu").load_demo()

    monkeypatch.setattr("cyberassess.collector.SSHCollector", WrongSource)
    assert cli.main(["--host", "authorized.example.test", "--user", "auditor", "--key", "unused-key",
                     "--output", str(tmp_path)]) == 2
    assert "Demonstration evidence" in capsys.readouterr().out
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("source,diagnostic", [
    ("sshd", "Unavailable: effective SSH configuration could not be read reliably."),
    ("services", "Unavailable: read-only Ubuntu query failed or returned ambiguous evidence."),
    ("password_policy", "Unavailable: password configuration is unreadable, malformed or contradictory."),
])
def test_new_ubuntu_errors_show_only_fixed_reviewed_diagnostics(source, diagnostic):
    report = build_profile_report("ubuntu", {"evidence": {source: {
        "_collection_ok": False, "_raw": diagnostic,
    }}, "collector": {"method": "SSH / Paramiko"}}, assessment_mode="ssh")
    assert diagnostic in render_html(report)
    # An arbitrary suffix is not a reviewed diagnostic, even with its prefix.
    for result in report["assessment"]["results"]:
        result["raw_evidence"] = diagnostic + " user=PRIVATE_DIAGNOSTIC"
    assert "PRIVATE_DIAGNOSTIC" not in render_html(report)
