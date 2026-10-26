"""Managed Boolean representations; injected evidence only, never native calls.

Apple's CF preference Boolean reader accepts the ASCII true/false and YES/NO
lexemes. An independent managed-machine observation must use the same narrow
interpretation, while missing or conflicting observations stay unavailable.
"""

import json
import plistlib

import pytest

from cyberassess.collectors import macos
from test_macos_remaining_four import (
    AUTO_TIME, SCHEDULE, SYSTEM_TIME, TIME, UPDATE, assess, preferences, probe,
)


TARGETS = [
    (UPDATE, "AutomaticCheckEnabled", "MAC-005"),
    (TIME, "TMAutomaticTimeOnlyEnabled", "MAC-012"),
]


def managed_plist(domain, key):
    return (
        "/usr/bin/plutil", "-extract", key, "xml1", "-o", "-",
        f"/Library/Managed Preferences/{domain}.plist",
    )


def xml_scalar(value):
    return plistlib.dumps(value, fmt=plistlib.FMT_XML).decode("utf-8")


@pytest.fixture(autouse=True)
def no_console_user_query(monkeypatch):
    # User screen-lock collection is independent of these machine controls.
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: False)


@pytest.mark.parametrize("domain,key,control", TARGETS)
@pytest.mark.parametrize("lexeme,value", [
    ("true", True), ("TRUE", True), ("TrUe", True),
    ("YES", True), ("yes", True), ("yEs", True),
    ("false", False), ("FALSE", False), ("FaLsE", False),
    ("NO", False), ("no", False), ("nO", False),
])
def test_managed_legacy_boolean_strings_match_the_native_effective_scalar(domain, key, control, lexeme, value):
    _, _, results, runner = assess({
        probe(domain, key): preferences(value, managed=True),
        managed_plist(domain, key): xml_scalar(lexeme),
    })
    result = results[control]
    # False removes enforced automatic time; it does not establish time Off.
    expected = "PASS" if value else ("FAIL" if control == "MAC-005" else "ERROR")
    assert result["status"] == expected
    assert result["actual"] is (value if expected != "ERROR" else None)
    if expected != "ERROR":
        assert "CoreFoundation" in result["raw_evidence"]
        assert "machine" in result["raw_evidence"]
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)


@pytest.mark.parametrize("domain,key,control", TARGETS)
@pytest.mark.parametrize("value", [
    "", " YES", "YES ", "\tYES", "YES\n", "0", "1", "on", "off",
    "enabled", "disabled", "tru\u0435", "\uff39\uff25\uff33", "Y" * 33,
    "private-policy-token-do-not-disclose",
])
def test_unsupported_managed_strings_never_supply_a_boolean_default(domain, key, control, value):
    bundle, _, results, _ = assess({
        probe(domain, key): preferences(True, managed=True),
        managed_plist(domain, key): xml_scalar(value),
    })
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None
    assert "private-policy-token-do-not-disclose" not in json.dumps(bundle)


@pytest.mark.parametrize("domain,key,control", TARGETS)
@pytest.mark.parametrize("configured", [True, False, "YES", "NO"])
@pytest.mark.parametrize("getter", ["missing", "system", "alternative"])
def test_known_managed_scope_contradictions_are_not_discarded_for_a_native_status(domain, key, control, configured, getter):
    machine_value = configured is True or configured == "YES"
    effective = not machine_value
    responses = {
        probe(domain, key): preferences(effective, managed=True),
        managed_plist(domain, key): xml_scalar(configured),
    }
    if getter != "missing":
        if control == "MAC-005":
            responses[SCHEDULE] = "Automatic check is " + ("on" if effective else "off")
        elif getter == "system":
            responses[SYSTEM_TIME] = "Network Time: " + ("On" if effective else "Off")
        else:
            responses[AUTO_TIME] = "Automatic time is " + ("enabled" if effective else "disabled")
    _, _, results, runner = assess(responses)
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)


@pytest.mark.parametrize("domain,key,control", TARGETS)
@pytest.mark.parametrize("configured", ["YES", "NO"])
def test_unforced_legacy_managed_file_does_not_substitute_for_effective_policy(domain, key, control, configured):
    _, _, results, _ = assess({
        probe(domain, key): preferences(configured == "YES", managed=False),
        managed_plist(domain, key): xml_scalar(configured),
    })
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None


@pytest.mark.parametrize("domain,key,control", TARGETS)
@pytest.mark.parametrize("unavailable", [
    (0, "", ""),
    (1, "", "permission denied private-policy-token-do-not-disclose"),
    (127, "", "unsupported native getter"),
    PermissionError("private-policy-token-do-not-disclose"),
])
def test_unavailable_managed_read_does_not_become_a_known_boolean(domain, key, control, unavailable):
    bundle, _, results, runner = assess({
        probe(domain, key): preferences(True, managed=True),
        managed_plist(domain, key): unavailable,
    })
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None
    assert "private-policy-token-do-not-disclose" not in json.dumps(bundle)
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)
