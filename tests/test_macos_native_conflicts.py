"""Pure contradiction detection; fixtures execute no native macOS command."""

import pytest

from cyberassess.collectors import _macos_status as status


SOURCES = [
    (status.software_update_status, "softwareupdate", "Automatic check is on", "Automatic check is off"),
    (status.network_time_status, "systemsetup", "Network Time: On", "Network Time: Off"),
    (status.automatic_time_status, "sysadminctl", "Automatic time is enabled", "Automatic time is disabled"),
    (status.screen_lock_status, "sysadminctl", "screenLock delay is immediate", "screenLock is off"),
]


def cocoa(process, message):
    return f"2026-10-26 12:34:56.123 {process}[314:2718] {message}"


@pytest.mark.parametrize("parser,process,first,second", SOURCES)
def test_distinct_supported_native_values_are_a_conflict_within_one_stream(parser, process, first, second):
    assert status.conflicting_status(first + "\n" + second, "", 0, parser) is True
    assert status.conflicting_status("", first + "\n" + second, 0, parser) is True


@pytest.mark.parametrize("parser,process,first,second", SOURCES)
def test_prefixed_native_values_can_conflict_across_output_streams(parser, process, first, second):
    assert status.conflicting_status(cocoa(process, first), cocoa(process, second), 0, parser) is True


@pytest.mark.parametrize("parser,process,first,second", SOURCES)
def test_duplicate_same_state_is_not_itself_a_proven_conflict(parser, process, first, second):
    assert status.conflicting_status(first, cocoa(process, first), 0, parser) is False
    assert status.conflicting_status(second + "\n" + second, "", 0, parser) is False
    # This helper does not declare duplicate native evidence usable.
    assert parser(first, first, 0) is None


def test_two_reported_screen_lock_delays_are_conflicting_without_guessing_a_delay():
    parser = status.screen_lock_status
    assert status.conflicting_status("screenLock delay is 5 seconds", "screenLock delay is 300 seconds", 0, parser) is True
    # Immediate and an explicitly reported zero have the same meaning.
    assert status.conflicting_status("screenLock delay is immediate", "screenLock delay is 0 seconds", 0, parser) is False


@pytest.mark.parametrize("parser,process,first,second", SOURCES)
def test_unknown_lines_alone_or_beside_one_known_state_do_not_prove_conflict(parser, process, first, second):
    assert status.conflicting_status("", "", 0, parser) is False
    assert status.conflicting_status("unsupported getter", "permission denied", 0, parser) is False
    assert status.conflicting_status(first, "unrecognized diagnostic", 0, parser) is False
    assert status.conflicting_status("permission denied: " + first, "", 0, parser) is False
    # Unknown text cannot erase two independent recognized observations.
    assert status.conflicting_status(first + "\nunknown diagnostic\n" + second, "", 0, parser) is True


@pytest.mark.parametrize("code", [1, 127, -9, False, None])
def test_failed_or_invalid_exit_status_is_not_used_as_proof_of_native_conflict(code):
    assert status.conflicting_status("Network Time: On", "Network Time: Off", code, status.network_time_status) is False


@pytest.mark.parametrize("stdout,stderr", [
    (None, "Network Time: Off"),
    ("Network Time: On", None),
    (b"Network Time: On", "Network Time: Off"),
    ("Network Time: On\n" + "x" * 4096, "Network Time: Off"),
])
def test_invalid_or_oversized_streams_are_not_partially_interpreted(stdout, stderr):
    assert status.conflicting_status(stdout, stderr, 0, status.network_time_status) is False


def test_no_new_status_formats_are_accepted_while_detecting_conflicts():
    text = "Network Time: On\nNetwork time might be Off"
    assert status.conflicting_status(text, "", 0, status.network_time_status) is False
    text = "2026-99-26 12:34:56.123 systemsetup[314:2718] Network Time: Off"
    assert status.conflicting_status("Network Time: On", text, 0, status.network_time_status) is False


def test_known_update_banner_does_not_hide_two_conflicting_explicit_statuses():
    text = "Software Update Tool\nAutomatic check is on\nAutomatic check is off"
    assert status.conflicting_status(text, "", 0, status.software_update_status) is True
