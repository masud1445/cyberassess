"""Clock provenance, UTC normalization and portable timezone boundaries."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

import pytest

import main as cli
from cyberassess import timestamps
from cyberassess.profiles import build_profile_report, get_profile
from cyberassess.reporting import render_html, save_html, save_json


@pytest.mark.parametrize("stamp,local,utc", [
    ("2026-10-31T03:28:00+08:00", "31 Oct 2026 · 03:28:00 UTC+08:00", "30 Oct 2026 · 19:28:00 UTC"),
    ("2026-10-30T23:30:00-07:00", "30 Oct 2026 · 23:30:00 UTC-07:00", "31 Oct 2026 · 06:30:00 UTC"),
    ("2026-01-01T00:15:00+05:45", "01 Jan 2026 · 00:15:00 UTC+05:45", "31 Dec 2025 · 18:30:00 UTC"),
    ("2026-11-01T01:30:00-04:00", "01 Nov 2026 · 01:30:00 UTC-04:00", "01 Nov 2026 · 05:30:00 UTC"),
    ("2026-11-01T01:30:00-05:00", "01 Nov 2026 · 01:30:00 UTC-05:00", "01 Nov 2026 · 06:30:00 UTC"),
    ("2026-03-08T01:59:59-05:00", "08 Mar 2026 · 01:59:59 UTC-05:00", "08 Mar 2026 · 06:59:59 UTC"),
    ("2026-03-08T03:00:00-04:00", "08 Mar 2026 · 03:00:00 UTC-04:00", "08 Mar 2026 · 07:00:00 UTC"),
    ("2026-10-30T19:28:00Z", "30 Oct 2026 · 19:28:00 UTC", "30 Oct 2026 · 19:28:00 UTC"),
])
def test_recorded_offset_handles_midnight_and_dst_without_host_zone_database(stamp, local, utc):
    assert timestamps.display_timestamp(stamp) == local
    assert timestamps.display_timestamp(stamp, utc=True) == utc
    assert timestamps.canonical_timestamp(stamp).endswith("+00:00")


@pytest.mark.parametrize("value", [None, "", "2026-10-30", "2026-10-30T19:28:00",
                                        "2026-10-30T19:28:00+25:00", "invalid", "x" * 81,
                                        "2026-10-30T19:28:00Z\n", 1793388480,
                                        "0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-14:00",
                                        datetime(2026, 10, 30, 19, 28)])
def test_missing_malformed_and_naive_timestamps_never_adopt_renderer_timezone(value):
    assert timestamps.aware_datetime(value) is None
    assert timestamps.display_timestamp(value) == "Not recorded with a timezone"
    with pytest.raises(ValueError, match="explicit UTC offset"):
        timestamps.canonical_timestamp(value)


def test_local_clock_records_same_instant_with_utc_and_real_local_offset(monkeypatch):
    class Instant(datetime):
        def astimezone(self, tz=None):
            return super().astimezone(tz or timezone(timedelta(hours=8)))

    class Clock:
        @staticmethod
        def now(tz):
            return Instant(2026, 10, 30, 19, 28, tzinfo=timezone.utc)

    monkeypatch.setattr(timestamps, "datetime", Clock)
    result = timestamps.collection_clock()
    assert result["collected_at"] == "2026-10-30T19:28:00+00:00"
    assert result["target_local_time"] == "2026-10-31T03:28:00+08:00"


@pytest.mark.parametrize("target", [None, "", "Permission denied", "2026-10-31T03:28:00", "false"])
def test_missing_ssh_target_clock_does_not_inherit_operator_zone(target):
    result = timestamps.collection_clock(remote=True, target_time=target)
    assert result["target_local_time"] is None
    assert "unavailable" in result["time_limitations"]
    assert timestamps.aware_datetime(result["collected_at"]).utcoffset() == timedelta(0)


def timed_report():
    bundle = get_profile("macos").load_demo()
    bundle["collector"] = {
        "method": "local / injected test responses", "mode": "local",
        "collected_at": "2026-10-30T19:28:00+00:00",
        "target_local_time": "2026-10-31T03:28:00+08:00",
        "time_limitations": "Clock accuracy is not verified.",
    }
    return build_profile_report("macos", bundle, assessment_mode="local",
                                started_at="2026-10-31T03:27:00+08:00",
                                completed_at="2026-10-31T03:28:01+08:00")


def test_json_html_print_metadata_share_recorded_instants_and_preserve_input(tmp_path):
    report = timed_report()
    original = deepcopy(report)
    json_path = save_json(report, str(tmp_path))
    html_path = save_html(report, str(tmp_path))
    assert json.loads(json_path.read_text(encoding="utf-8")) == original
    document = html_path.read_text(encoding="utf-8")
    for key in ("assessment_started_at", "assessment_completed_at", "collected_at"):
        assert report[key] in document
        assert timestamps.aware_datetime(report[key]).utcoffset() == timedelta(0)
    assert "31 Oct 2026 · 03:28:00 UTC+08:00" in document
    assert "30 Oct 2026 · 19:28:00 UTC" in document
    assert "Clock accuracy is not verified." in document
    assert "@page" in document and "size: A4" in document
    assert report == original


def test_renderer_does_not_reuse_target_completion_offset_for_a_different_instant():
    report = timed_report()
    report["assessment_started_at"] = "2026-11-01T01:59:59-04:00"
    report["assessment_completed_at"] = "2026-11-01T01:00:01-05:00"
    report["collector"]["target_local_time"] = "2026-11-01T01:00:00-05:00"
    document = render_html(report)
    assert report["assessment_started_at"] in document
    assert report["assessment_completed_at"] in document
    assert "01 Nov 2026 · 01:00:00 UTC-05:00" in document
    assert "01 Nov 2026 · 06:00:00 UTC" in document


def test_legacy_unknown_time_remains_unknown_and_generation_matches_footer():
    report = get_profile("ubuntu").load_demo()
    report = {**report, "assessment": build_profile_report("ubuntu", report)["assessment"]}
    report["collector"] = {"method": "SSH / Paramiko"}
    document = render_html(report)
    assert "target local timezone unavailable" in document
    assert "<dt>Assessment time</dt><dd>Not recorded</dd>" in document
    generated = document.split("<dt>Report generated</dt><dd>", 1)[1].split("</dd>", 1)[0]
    assert f"Generated {generated}" in document
    assert generated.endswith("UTC")


def test_cli_completion_is_recorded_after_evaluation(monkeypatch, tmp_path):
    instants = iter(datetime(2026, 10, 30, 19, 28, second, tzinfo=timezone.utc) for second in (0, 2))
    phase = {"evaluated": False}
    original = cli.build_profile_report

    def build(*args, **kwargs):
        report = original(*args, **kwargs)
        phase["evaluated"] = True
        return report

    class Clock:
        @staticmethod
        def now(tz):
            instant = next(instants)
            if instant.second == 2:
                assert phase["evaluated"]
            return instant

    monkeypatch.setattr(cli, "datetime", Clock)
    monkeypatch.setattr(cli, "build_profile_report", build)
    monkeypatch.setattr(cli, "detect_local_profile", lambda: "macos")
    monkeypatch.setattr(cli, "_collect_profile", lambda *args: {
        "target_name": "authorized-test-target", "platform": "macOS", "evidence": {},
        "collector": {"method": "local / injected test responses", "collected_at": "2026-10-30T19:28:01+00:00"},
    })
    assert cli.main(["--auto-detect", "--local", "--output", str(tmp_path)]) == 0
    report = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert report["assessment_started_at"] == "2026-10-30T19:28:00+00:00"
    assert report["collected_at"] == "2026-10-30T19:28:01+00:00"
    assert report["assessment_completed_at"] == "2026-10-30T19:28:02+00:00"


def test_legacy_live_clock_metadata_preserves_original_outer_json_contract(monkeypatch, tmp_path):
    class SSH:
        def __init__(self, **options):
            pass

        def collect(self):
            return {"target_name": "authorized-injected-target", "platform": "Ubuntu Linux", "evidence": {},
                    "collector": {"method": "SSH / Paramiko", "collected_at": "2026-10-30T19:28:00+00:00",
                                  "target_local_time": "2026-10-31T03:28:00+08:00"}}

    monkeypatch.setattr("cyberassess.collector.SSHCollector", SSH)
    assert cli.main(["--host", "authorized.example.test", "--user", "auditor", "--key", "unused-key",
                     "--output", str(tmp_path)]) == 0
    report = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert set(report) == {"target_name", "platform", "collector", "evidence", "assessment"}
    for key in ("collected_at", "assessment_started_at", "assessment_completed_at"):
        assert timestamps.aware_datetime(report["collector"][key]) is not None
    document = next(tmp_path.glob("*.html")).read_text(encoding="utf-8")
    assert "Live Ubuntu SSH assessment" in document
    assert "31 Oct 2026 · 03:28:00 UTC+08:00" in document
