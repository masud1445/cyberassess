"""Exact own-user configuration survives an unavailable composite preference.

All native responses are injected. These tests do not read real preferences,
query another account, execute macOS commands or establish runtime enforcement.
"""

import json

import pytest

from cyberassess.collectors import macos
from test_macos_remaining_four import LOCK, SCREEN, assess, preferences, probe


TARGETS = [
    ("askForPassword", True, "MAC-010", "PASS"),
    ("askForPassword", False, "MAC-010", "FAIL"),
    ("askForPasswordDelay", 0, "MAC-011", "PASS"),
    ("askForPasswordDelay", 45, "MAC-011", "FAIL"),
]


@pytest.fixture(autouse=True)
def matching_user_context(monkeypatch):
    monkeypatch.setattr(macos, "current_user_status_context_safe", lambda: True)


@pytest.mark.parametrize("field", ["explicit_current_host", "explicit_any_host"])
@pytest.mark.parametrize("key,value,control,status", TARGETS)
def test_typed_own_user_configuration_survives_missing_composite_value(field, key, value, control, status):
    bundle, _, results, runner = assess({
        probe(LOCK, key): preferences(None, **{field: value}),
    })
    result = results[control]
    assert result["status"] == status
    assert result["actual"] == value
    source = "screen_lock_delay" if control == "MAC-011" else "screen_lock"
    scope = bundle["evidence"][source]["_scope"]
    assert "explicit configured current-user" in scope
    assert "CoreFoundation" in scope
    assert "effective current-user/ByHost" not in scope
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)


@pytest.mark.parametrize("key,control", [
    ("askForPassword", "MAC-010"), ("askForPasswordDelay", "MAC-011"),
])
def test_absent_composite_and_absent_own_scopes_remain_error(key, control):
    _, _, results, _ = assess({probe(LOCK, key): preferences(None)})
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None


@pytest.mark.parametrize("key,value,control,status", TARGETS)
@pytest.mark.parametrize("managed,available", [(True, True), (False, False), (True, False)])
def test_partial_own_configuration_cannot_replace_unresolved_managed_policy(key, value, control, status, managed, available):
    _, _, results, _ = assess({
        probe(LOCK, key): preferences(
            None, managed=managed, managed_available=available,
            explicit_current_host=value, explicit_any_host=value,
        ),
    })
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None


@pytest.mark.parametrize("key,host,anyhost,control,status", [
    ("askForPassword", False, True, "MAC-010", "FAIL"),
    ("askForPassword", True, False, "MAC-010", "PASS"),
    ("askForPasswordDelay", 0, 45, "MAC-011", "PASS"),
    ("askForPasswordDelay", 45, 0, "MAC-011", "FAIL"),
])
def test_own_current_host_precedes_any_host_without_composite_value(key, host, anyhost, control, status):
    _, _, results, _ = assess({
        probe(LOCK, key): preferences(None, explicit_current_host=host, explicit_any_host=anyhost),
    })
    assert results[control]["status"] == status
    assert results[control]["actual"] == host


@pytest.mark.parametrize("key,value,control,status", TARGETS)
def test_unreadable_own_current_host_is_not_treated_as_absence(key, value, control, status):
    _, _, results, _ = assess({
        probe(LOCK, key): preferences(
            None, explicit_any_host=value, unreadable_scopes=["explicit_current_host"],
        ),
    })
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None


@pytest.mark.parametrize("key,invalid,fallback,control", [
    ("askForPassword", 2, True, "MAC-010"),
    ("askForPassword", 0.5, False, "MAC-010"),
    ("askForPassword", "true", True, "MAC-010"),
    ("askForPasswordDelay", -1, 0, "MAC-011"),
    ("askForPasswordDelay", True, 0, "MAC-011"),
    ("askForPasswordDelay", "0", 0, "MAC-011"),
])
def test_invalid_highest_priority_scalar_does_not_select_lower_secure_value(key, invalid, fallback, control):
    _, _, results, _ = assess({
        probe(LOCK, key): preferences(None, explicit_current_host=invalid, explicit_any_host=fallback),
    })
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None


@pytest.mark.parametrize("key,value,control,status", TARGETS)
def test_machine_fields_cannot_supply_current_user_configuration(key, value, control, status):
    _, _, results, _ = assess({
        probe(LOCK, key): preferences(None, machine_current_host=value, machine_any_host=value),
    })
    assert results[control]["status"] == "ERROR"
    assert results[control]["actual"] is None


@pytest.mark.parametrize("reason", [
    "ambiguous-user-context", "native-preference-read-unavailable",
    "unsupported-platform", "unsupported-query", "unrecognized-probe-reason",
])
def test_partial_values_cannot_bypass_failed_native_probe_or_unsafe_user_context(reason):
    _, _, results, _ = assess({
        probe(LOCK, "askForPassword"): preferences(
            None, reason=reason, explicit_current_host=True,
        ),
    })
    assert results["MAC-010"]["status"] == "ERROR"
    assert results["MAC-010"]["actual"] is None


@pytest.mark.parametrize("failure", [
    PermissionError("private native diagnostic"),
    (127, "", "unsupported native getter private native diagnostic"),
])
@pytest.mark.parametrize("key,value,control,status", TARGETS)
def test_denied_or_unsupported_native_status_can_use_known_own_configuration(failure, key, value, control, status):
    bundle, _, results, runner = assess({
        SCREEN: failure,
        probe(LOCK, key): preferences(None, explicit_any_host=value),
    })
    assert results[control]["status"] == status
    assert results[control]["actual"] == value
    assert "private native diagnostic" not in json.dumps(bundle)
    assert not any(command[0] == "/usr/bin/sudo" for command, _ in runner.calls)


def test_native_off_takes_precedence_and_never_invents_a_zero_delay_from_partial_preferences():
    _, _, results, _ = assess({
        SCREEN: "screenLock is off",
        probe(LOCK, "askForPassword"): preferences(None, explicit_any_host=True),
        probe(LOCK, "askForPasswordDelay"): preferences(None, explicit_any_host=0),
    })
    assert results["MAC-010"]["status"] == "FAIL"
    assert results["MAC-010"]["actual"] is False
    assert results["MAC-011"]["status"] == "ERROR"
    assert results["MAC-011"]["actual"] is None


def test_native_current_state_keeps_precedence_over_stale_unforced_partial_preferences():
    _, _, results, _ = assess({
        SCREEN: "screenLock delay is immediate",
        probe(LOCK, "askForPassword"): preferences(None, explicit_current_host=False),
        probe(LOCK, "askForPasswordDelay"): preferences(None, explicit_current_host=45),
    })
    assert results["MAC-010"]["status"] == "PASS"
    assert results["MAC-010"]["actual"] is True
    assert results["MAC-011"]["status"] == "PASS"
    assert results["MAC-011"]["actual"] == 0
