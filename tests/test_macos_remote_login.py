"""Portable launchd fixtures; no native Mac or host identity is required."""

import pytest

from cyberassess.collectors._macos_remote_login import (
    parse_override_map,
    parse_service,
    resolve_remote_login,
)


EMPTY_MAP = "disabled services = {\n}\n"
ABSENT = 'Could not find service "com.openssh.sshd" in domain for system'


def overrides(state):
    return 'disabled services = {\n "com.company.unrelated" => enabled\n "com.openssh.sshd" => ' + state + '\n}\n'


def service(state="not running"):
    return """system/com.openssh.sshd = {
    active count = 0
    path = /System/Library/LaunchDaemons/ssh.plist
    type = LaunchDaemon
    state = """ + state + """
    program = /usr/libexec/sshd-keygen-wrapper
    arguments = {
        sshd-keygen-wrapper
    }
    sockets = {
        Listeners = {
            type = stream
            service name = ssh
        }
    }
}
"""


@pytest.mark.parametrize("state,expected", [("enabled", True), ("false", True), ("disabled", False), ("true", False)])
def test_exact_override_supports_current_and_older_boolean_forms(state, expected):
    assert parse_override_map(overrides(state)) == (True, expected)


def test_valid_map_without_ssh_does_not_infer_a_state():
    assert parse_override_map(EMPTY_MAP) == (True, None)
    assert parse_override_map('disabled services = {\n "com.openssh.sshd-keygen-wrapper" => disabled\n}') == (True, None)


@pytest.mark.parametrize("text", [
    "", "disabled services = {}", "permission denied", "disabled services = {\n",
    overrides("unknown"), overrides("disabled").replace("}\n", ' "com.openssh.sshd" => enabled\n}\n'),
    overrides("disabled").replace("}\n", ' "com.openssh.sshd" => disabled\n}\n'),
    EMPTY_MAP + "Unexpected diagnostic", 'disabled services = {\n "com.openssh.sshd" = true\n}',
])
def test_malformed_or_duplicate_override_map_is_not_valid(text):
    assert parse_override_map(text) == (False, None)


@pytest.mark.parametrize("state", ["running", "waiting", "not running"])
def test_registered_socket_activated_service_does_not_require_a_running_process(state):
    assert parse_service(service(state), "", 0) == "registered"


@pytest.mark.parametrize("stdout,stderr,code", [
    ("", ABSENT, 113), (ABSENT, "", 113), ("", "Bad request.\n" + ABSENT, 113),
])
def test_only_the_exact_known_service_absence_result_is_recognized(stdout, stderr, code):
    assert parse_service(stdout, stderr, code) == "absent"


@pytest.mark.parametrize("stdout,stderr,code", [
    ("", "", 0), ("", "", 113), ("", "Permission denied", 113),
    ("", "Operation not permitted", 1), ("", ABSENT, 0), ("", ABSENT, -9),
    ("", ABSENT + "\nAdditional diagnostic", 113),
    ("", ABSENT.replace("com.openssh.sshd", "com.company.other"), 113),
    (service(), "Permission denied", 0), (service(), "", 1),
    (service().replace("system/com.openssh.sshd", "gui/501/com.openssh.sshd"), "", 0),
    (service().replace("ssh.plist", "different.plist"), "", 0),
    (service().replace("LaunchDaemon", "LaunchAgent"), "", 0),
    (service("unsupported-state"), "", 0),
    (service().replace("    state = not running\n", ""), "", 0),
    (service().replace("    path = /System/Library/LaunchDaemons/ssh.plist\n", ""), "", 0),
    (service().replace("    state = not running", "    state = not running\n    state = running"), "", 0),
    (service().replace("    path =", "    path = /System/Library/LaunchDaemons/ssh.plist\n    path ="), "", 0),
    (service() + "Unexpected diagnostic", "", 0),
    (service().replace("    active count = 0", "    Unexpected diagnostic"), "", 0),
    (service().replace("    active count = 0", "    Warning: unsupported format"), "", 0),
    (service().replace("    active count = 0", "    active count = }{"), "", 0),
    (service().rstrip()[:-1], "", 0), (service() + "}\n", "", 0),
])
def test_unsupported_denied_partial_or_contradictory_service_output_stays_unknown(stdout, stderr, code):
    assert parse_service(stdout, stderr, code) == "unknown"


def test_nested_fields_cannot_supply_missing_top_level_status():
    text = service().replace("    state = not running\n", "").replace("        Listeners = {", "        Listeners = {\n            state = running")
    assert parse_service(text, "", 0) == "unknown"


@pytest.mark.parametrize("map_text,stdout,stderr,code,label,disabled,expected", [
    (EMPTY_MAP, service(), "", 0, "com.openssh.sshd", True, True),
    (EMPTY_MAP, service("running"), "", 0, None, None, True),
    (overrides("enabled"), service(), "", 0, "com.openssh.sshd", True, True),
    (overrides("false"), service("waiting"), "", 0, None, None, True),
    (overrides("disabled"), "", ABSENT, 113, None, None, False),
    (overrides("true"), "", ABSENT, 113, "com.openssh.sshd", False, False),
    (EMPTY_MAP, "", ABSENT, 113, "com.openssh.sshd", True, False),
    (EMPTY_MAP, "", ABSENT, 113, "com.openssh.sshd", None, None),
    (EMPTY_MAP, "", ABSENT, 113, "com.openssh.sshd", False, None),
    (EMPTY_MAP, "", ABSENT, 113, "com.company.other", True, None),
    (overrides("enabled"), "", ABSENT, 113, "com.openssh.sshd", True, None),
    (overrides("disabled"), service(), "", 0, "com.openssh.sshd", True, None),
    (overrides("disabled"), "", "Permission denied", 113, "com.openssh.sshd", True, None),
    ("", service(), "", 0, "com.openssh.sshd", True, None),
    (EMPTY_MAP, "", "", 0, "com.openssh.sshd", True, None),
])
def test_effective_resolution_requires_agreeing_independent_native_evidence(map_text, stdout, stderr, code, label, disabled, expected):
    assert resolve_remote_login(map_text, stdout, stderr, code, label, disabled) is expected
