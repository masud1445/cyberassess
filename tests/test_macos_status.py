"""Native-output and scope fixtures only; these do not query a real Mac.

Status forms are backed by the public native-help/actual-Mac references in
``_macos_status``. Numeric dates, PIDs and user IDs below are synthetic.
"""

import stat
from types import SimpleNamespace

import pytest

from cyberassess.collectors import _macos_status as status


@pytest.mark.parametrize("message,expected", [
    ("screenLock delay is immediate", (True, 0)),
    ("screenLock delay is 0 seconds", (True, 0)),
    ("screenLock delay is 5 seconds", (True, 5)),
    ("screenLock delay is 3600 seconds", (True, 3600)),
    ("screenLock delay is 2147483646 seconds", (True, 2147483646)),
    ("screenLock is off", (False, None)),
])
@pytest.mark.parametrize("prefix", [
    "",
    "2025-10-24 14:32:47.618 sysadminctl[12345:67890] ",
    "2024-02-29 00:00:01.123456 sysadminctl[12345] ",
    "2024-02-29 00:00:01 sysadminctl[12345:67890] ",
])
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_known_current_and_older_native_status_formats(message, expected, prefix, stream):
    output = "\n  " + prefix + message + "\n\n"
    stdout, stderr = (output, "") if stream == "stdout" else ("", output)
    assert status.screen_lock_status(stdout, stderr, 0) == expected


@pytest.mark.parametrize("stdout,stderr,code", [
    ("", "", 0),
    ("screenLock delay is immediate", "", 1),
    ("screenLock is off", "", -9),
    ("screenLock delay is immediate", "permission denied", 0),
    ("", "You need administrator access to run this tool", 0),
    ("screenLock delay is immediate", "screenLock is off", 0),
    ("screenLock delay is immediate\nscreenLock delay is immediate", "", 0),
    ("screenLock delay is immediate", "screenLock delay is immediate", 0),
    ("screenLock delay is 5 seconds\nwarning: private-user", "", 0),
    ("Usage: sysadminctl -screenLock <status || immediate || off || seconds>", "", 0),
    ("screenLock delay is -1 seconds", "", 0),
    ("screenLock delay is 05 seconds", "", 0),
    ("screenLock delay is 0.5 seconds", "", 0),
    ("screenLock delay is nan seconds", "", 0),
    ("screenLock delay is Infinity seconds", "", 0),
    ("screenLock delay is 2147483647 seconds", "", 0),
    ("screenLock delay is 9999999999 seconds", "", 0),
    ("screenLock delay is " + "9" * 300 + " seconds", "", 0),
    ("screenLock is on", "", 0),
    ("screenLock is disabled", "", 0),
    ("screenLock delay is immediate.", "", 0),
    ("screenLock delay is Immediate", "", 0),
    ("2025-10-24 14:32:47.618 other-tool[12345:67890] screenLock is off", "", 0),
    ("2025-99-24 14:32:47.618 sysadminctl[12345:67890] screenLock is off", "", 0),
    ("2025-02-29 14:32:47.618 sysadminctl[12345] screenLock is off", "", 0),
    ("2025-10-24 14:32:47.618 sysadminctl[pid:thread] screenLock is off", "", 0),
    ("prefix screenLock is off", "", 0),
    ("x" * 4097, "", 0),
    (None, "screenLock is off", 0),
    ("screenLock is off", None, 0),
    ("screenLock is off", "", False),
])
def test_missing_ambiguous_denied_malformed_and_failed_status_is_unknown(stdout, stderr, code):
    assert status.screen_lock_status(stdout, stderr, code) is None


@pytest.fixture
def context(monkeypatch):
    state = {
        "platform": "Darwin", "uid": 501, "euid": 501,
        "owner": 501, "mode": stat.S_IFCHR | 0o600,
        "home_safe": True, "stat_error": None,
    }
    calls = []

    def public_console_stat(path, **options):
        calls.append(("stat", path, options))
        if state["stat_error"] is not None:
            raise state["stat_error"]
        return SimpleNamespace(st_uid=state["owner"], st_mode=state["mode"])

    def user_guard():
        calls.append(("user_guard",))
        return state["home_safe"]

    monkeypatch.setattr(status, "platform", SimpleNamespace(system=lambda: state["platform"]))
    monkeypatch.setattr(status, "os", SimpleNamespace(
        getuid=lambda: state["uid"], geteuid=lambda: state["euid"], stat=public_console_stat,
    ))
    monkeypatch.setattr(status, "_safe_user_context", user_guard)
    return state, calls


@pytest.mark.parametrize("uid", [501, 1003, 12345])
def test_any_matching_non_root_invoking_console_user_is_supported(uid, context):
    state, calls = context
    state.update(uid=uid, euid=uid, owner=uid)
    assert status.current_user_status_context_safe() is True
    assert calls == [("user_guard",), ("stat", "/dev/console", {"follow_symlinks": False})]


@pytest.mark.parametrize("changes", [
    {"platform": "Linux"},
    {"platform": "Windows"},
    {"uid": 0, "euid": 0, "owner": 0},
    {"uid": 501, "euid": 0},
    {"uid": -1, "euid": -1},
    {"uid": True, "euid": True},
    {"uid": 501.0, "euid": 501.0},
    {"home_safe": False},
])
def test_unavailable_identity_or_redirect_never_queries_console_metadata(changes, context):
    state, calls = context
    state.update(changes)
    assert status.current_user_status_context_safe() is False
    assert not any(call[0] == "stat" for call in calls)


@pytest.mark.parametrize("changes", [
    {"owner": 1003},
    {"owner": 0},
    {"owner": None},
    {"owner": "501"},
    {"mode": stat.S_IFREG | 0o600},
    {"mode": stat.S_IFLNK | 0o777},
    {"mode": None},
    {"stat_error": PermissionError("private path must not be retained")},
    {"stat_error": FileNotFoundError("no console")},
])
def test_console_mismatch_non_device_or_unreadable_metadata_stays_unknown(changes, context):
    state, _ = context
    state.update(changes)
    assert status.current_user_status_context_safe() is False


def test_missing_posix_identity_api_is_unavailable_on_other_hosts(monkeypatch, context):
    monkeypatch.setattr(status, "os", SimpleNamespace())
    assert status.current_user_status_context_safe() is False


@pytest.mark.parametrize("parser,tool,on,off", [
    (status.software_update_status, "softwareupdate", "Automatic check is on", "Automatic check is off"),
    (status.network_time_status, "systemsetup", "Network Time: On", "Network Time: Off"),
    (status.automatic_time_status, "sysadminctl", "Automatic Time is enabled", "Automatic Time is disabled"),
])
@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.parametrize("prefixed", [True, False])
@pytest.mark.parametrize("stderr", [True, False])
def test_explicit_update_and_time_states_across_normal_native_log_streams(parser, tool, on, off, enabled, prefixed, stderr):
    message = on if enabled else off
    if prefixed:
        message = "2025-01-02 03:04:05.678 " + tool + "[123:456] " + message
    assert parser("" if stderr else message, message if stderr else "", 0) is enabled


@pytest.mark.parametrize("label", ["Automatic Time", "Automatic time", "automaticTime"])
def test_automatic_time_accepts_only_explicit_property_status_sentences(label):
    # These are strict contract forms, not a claim of native validation on all
    # releases. The getter exists in native help; unfamiliar wording is unknown.
    assert status.automatic_time_status(label + " is enabled", "", 0) is True
    assert status.automatic_time_status("", label + " is disabled", 0) is False


@pytest.mark.parametrize("message,expected", [
    ("Automatic Time is enabled.", True),
    ("automaticTime is disabled.", False),
    ("Automatic time is on", True),
    ("automaticTime is off", False),
    ("Automatic Time is On.", True),
    ("Automatic Time is Off.", False),
    ("Automatic Time may be on", None),
    ("Automatic Time is not disabled", None),
    ("Automatic Time is enabled..", None),
    ("Automatic Time is enabled but unreadable", None),
])
def test_automatic_time_property_punctuation_and_explicit_state_words(message, expected):
    assert status.automatic_time_status(message, "", 0) is expected


@pytest.mark.parametrize("parser,on,off", [
    (status.software_update_status, "Automatic check is on", "Automatic check is off"),
    (status.network_time_status, "Network Time: On", "Network Time: Off"),
    (status.automatic_time_status, "Automatic Time is enabled", "Automatic Time is disabled"),
])
@pytest.mark.parametrize("case", ["empty", "nonzero", "conflict", "duplicate", "warning", "denied", "unknown", "oversized"])
def test_unavailable_or_malformed_status_never_becomes_enabled_or_disabled(parser, on, off, case):
    examples = {
        "empty": ("", "", 0),
        "nonzero": (on, "", 1),
        "conflict": (on, off, 0),
        "duplicate": (on, on, 0),
        "warning": (off, "warning: status could not be obtained", 0),
        "denied": ("", "permission denied; " + on, 0),
        "unknown": ("the setting might be enabled", "", 0),
        "oversized": (on, " " * 4097, 0),
    }
    assert parser(*examples[case]) is None


def test_known_softwareupdate_banner_is_not_a_status_or_a_default():
    assert status.software_update_status("Software Update Tool\n", "Automatic check is on", 0) is True
    assert status.software_update_status("Software Update Tool", "", 0) is None
    assert status.software_update_status("Software Update Tool\nSoftware Update Tool\nAutomatic check is on", "", 0) is None
    assert status.software_update_status("Software Update Tool\nwarning: unsupported\nAutomatic check is off", "", 0) is None
