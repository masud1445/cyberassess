"""Offline dispatch/freshness regressions; these do not certify native state."""

from collections import Counter
import json
import platform
import subprocess

import pytest
import paramiko

import main as cli
from cyberassess.collector import CollectionError, SSHCollector
from cyberassess.collectors import macos, windows
from cyberassess.collectors.ubuntu import UbuntuLocalCollector
from cyberassess.platforms import detect_local_profile
from cyberassess.profiles import Profile
from cyberassess.timestamps import aware_datetime


def test_native_runner_os_detection_uses_actual_environment_without_collecting():
    system = platform.system()
    expected = {"Darwin": "macos", "Windows": "windows"}.get(system)
    if system == "Linux":
        try:
            release = platform.freedesktop_os_release()
        except OSError:
            release = {}
        if release.get("ID", "").strip().lower() == "ubuntu":
            expected = "ubuntu"
    if expected is None:
        with pytest.raises(ValueError):
            detect_local_profile()
    else:
        assert detect_local_profile() == expected


@pytest.mark.parametrize("system,release,profile,count,collector", [
    ("Darwin", {}, "macos", 12, "cyberassess.collectors.macos.MacOSCollector"),
    ("Windows", {}, "windows", 13, "cyberassess.collectors.windows.WindowsCollector"),
    ("Linux", {"ID": "ubuntu"}, "ubuntu", 15, "cyberassess.collectors.ubuntu.UbuntuLocalCollector"),
])
@pytest.mark.parametrize("failure", [False, True], ids=["fresh-native-bundle", "collection-failed"])
def test_auto_detect_selects_only_matching_native_collector_never_demo(monkeypatch, tmp_path, system, release, profile, count, collector, failure):
    monkeypatch.setattr(cli, "detect_local_profile", lambda: detect_local_profile(system=system, os_release=release))
    monkeypatch.setattr(Profile, "load_demo", lambda self: pytest.fail("Live collection must not load sample evidence"))
    calls = []

    class Native:
        def collect(self):
            calls.append(profile)
            if failure:
                raise CollectionError("Native evidence unavailable")
            return {"target_name": "authorized-injected-target", "platform": system, "evidence": {},
                    "collector": {"method": "local / injected test responses", "sample_data": False}}

    monkeypatch.setattr(collector, Native)
    status = cli.main(["--auto-detect", "--local", "--output", str(tmp_path)])
    assert calls == [profile]
    if failure:
        assert status == 2
        assert not list(tmp_path.iterdir())
    else:
        assert status == 0
        report = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
        assert report["profile"]["id"] == profile
        assert report["assessment_mode"] == "local"
        assert report["assessment"]["total_controls"] == count
        assert report["assessment"]["errors"] == count
        assert report["target_name"] == "authorized-injected-target"


@pytest.mark.parametrize("system,release", [("FreeBSD", {}), ("Linux", {"ID": "debian", "ID_LIKE": "ubuntu"}), ("Linux", {})])
def test_unsupported_platform_is_rejected_before_collection(monkeypatch, tmp_path, system, release):
    monkeypatch.setattr(cli, "detect_local_profile", lambda: detect_local_profile(system=system, os_release=release))
    monkeypatch.setattr(cli, "_collect_profile", lambda *args: pytest.fail("Unsupported OS must not collect"))
    with pytest.raises(SystemExit) as error:
        cli.main(["--auto-detect", "--local", "--output", str(tmp_path)])
    assert error.value.code == 2
    assert not list(tmp_path.iterdir())


def test_reused_mac_collector_refreshes_commands_and_clock(monkeypatch):
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: False)
    current = {"enabled": True}
    calls = []

    def run(command, **kwargs):
        calls.append(tuple(command))
        text = "FileVault is On." if current["enabled"] else "FileVault is Off."
        return subprocess.CompletedProcess(command, 0 if command[0] == "/usr/bin/fdesetup" else 127,
                                           text if command[0] == "/usr/bin/fdesetup" else "", "")

    collector = macos.MacOSCollector(runner=run)
    first = collector.collect()
    current["enabled"] = False
    second = collector.collect()
    assert first["evidence"]["filevault"]["enabled"] is True
    assert second["evidence"]["filevault"]["enabled"] is False
    assert calls.count(("/usr/bin/fdesetup", "status")) == 2
    assert aware_datetime(first["collector"]["collected_at"]) <= aware_datetime(second["collector"]["collected_at"])
    assert aware_datetime(second["collector"]["target_local_time"]) is not None


def test_reused_windows_collector_refreshes_actual_queries_and_clock():
    current = {"enabled": 1}
    calls = []

    def run(command, **kwargs):
        calls.append(command[-1])
        return subprocess.CompletedProcess(command, 0, json.dumps({"enable_lua": current["enabled"]}).encode(), b"")

    collector = windows.WindowsCollector(runner=run)
    first = collector.collect()
    first_calls = Counter(calls)
    current["enabled"] = 0
    second = collector.collect()
    assert first["evidence"]["uac"]["enabled"] is True
    assert second["evidence"]["uac"]["enabled"] is False
    assert len(first_calls) == len(windows._QUERIES)
    assert Counter(calls) == first_calls + first_calls
    assert aware_datetime(first["collector"]["collected_at"]) <= aware_datetime(second["collector"]["collected_at"])


@pytest.mark.parametrize("local", [False, True], ids=["ubuntu-ssh", "ubuntu-local"])
def test_reused_ubuntu_collector_executes_fresh_reads_on_each_run(monkeypatch, local):
    class Session:
        closes = 0

        def close(self):
            self.closes += 1

    session = Session()
    calls = []
    collector = UbuntuLocalCollector() if local else SSHCollector("authorized.example.test", "auditor", "unused-test-key")
    monkeypatch.setattr(collector, "_connect", lambda: session)

    def run(client, command):
        calls.append(command)
        return {"exit_code": 0 if command == "hostname" else 127,
                "stdout": "authorized-injected-target" if command == "hostname" else "", "stderr": ""}

    monkeypatch.setattr(collector, "_run", run)
    first = collector.collect()
    per_run = Counter(calls)
    second = collector.collect()
    assert Counter(calls) == per_run + per_run
    assert session.closes == 2
    assert first["evidence"] == second["evidence"]
    assert aware_datetime(second["collector"]["collected_at"]) is not None
    assert (second["collector"]["target_local_time"] is not None) is local


@pytest.mark.parametrize("status,stdout,stderr", [
    (0, "2026-10-31T03:28:00+08:00", ""),
    (0, "2026-10-31T03:28:00", ""),
    (0, "", ""), (0, "not a timestamp", ""),
    (1, "", "permission denied"), (127, "", "command unavailable"),
    (0, "2026-10-31T03:28:00+08:00", "ambiguous diagnostic"),
])
def test_ssh_clock_query_is_read_only_optional_and_cannot_supply_security_values(monkeypatch, status, stdout, stderr):
    collector = SSHCollector("authorized.example.test", "auditor", "unused-test-key")
    monkeypatch.setattr(collector, "_connect", lambda: type("Session", (), {"close": lambda self: None})())
    calls = []
    clock_response = {"exit_code": status, "stdout": stdout, "stderr": stderr}

    def run(client, command):
        calls.append(command)
        if command == "LC_ALL=C /bin/date --iso-8601=seconds":
            return dict(clock_response)
        return {"exit_code": 127, "stdout": "", "stderr": ""}

    monkeypatch.setattr(collector, "_run", run)
    bundle = collector.collect()
    assert calls.count("LC_ALL=C /bin/date --iso-8601=seconds") == 1
    known = status == 0 and not stderr and aware_datetime(stdout) is not None
    assert (bundle["collector"]["target_local_time"] is not None) is known
    clock_response.update(exit_code=127, stdout="", stderr="")
    without_clock = collector.collect()
    assert bundle["evidence"] == without_clock["evidence"]
    assert "permission denied" not in json.dumps(bundle)


@pytest.mark.parametrize("failure", [TimeoutError("private diagnostic"), paramiko.SSHException("private diagnostic")])
def test_ssh_clock_transport_failure_does_not_discard_security_results(monkeypatch, failure):
    collector = SSHCollector("authorized.example.test", "auditor", "unused-test-key")
    monkeypatch.setattr(collector, "_connect", lambda: type("Session", (), {"close": lambda self: None})())

    def run(client, command):
        if command == "LC_ALL=C /bin/date --iso-8601=seconds":
            raise failure
        return {"exit_code": 127, "stdout": "", "stderr": ""}

    monkeypatch.setattr(collector, "_run", run)
    bundle = collector.collect()
    assert bundle["collector"]["target_local_time"] is None
    assert "unavailable" in bundle["collector"]["time_limitations"]
    assert bundle["evidence"]
    assert "private diagnostic" not in json.dumps(bundle)
