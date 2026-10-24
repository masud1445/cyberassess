"""CoreFoundation FFI fixtures; no test reads live macOS preferences."""

import ctypes
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from cyberassess.collectors import _macos_preferences as probe


class Function:
    def __init__(self, callback):
        self.callback = callback
        self.calls = []

    def __call__(self, *arguments):
        self.calls.append(arguments)
        return self.callback(*arguments)


class NativeLibrary:
    """Copied CF objects have independent references and explicit ownership."""

    def __init__(self, effective=("boolean", True), configured=None, managed=False):
        self.effective = effective
        self.configured = configured or {}
        self.managed = managed
        self.constants = {
            "kCFPreferencesCurrentUser": 1,
            "kCFPreferencesAnyUser": 2,
            "kCFPreferencesCurrentHost": 3,
            "kCFPreferencesAnyHost": 4,
        }
        self.objects = {}
        self.created = []
        self.copied = []
        self.released = []
        self.conversion_ok = True
        self.string_conversion_ok = True
        self.fail_string = None
        self.CFStringCreateWithCString = Function(self.create_string)
        self.CFPreferencesCopyAppValue = Function(lambda key, app: self.copy(self.effective))
        self.CFPreferencesCopyValue = Function(lambda key, app, user, host: self.copy(self.configured.get((user, host))))
        self.CFPreferencesAppValueIsForced = Function(lambda key, app: int(self.managed))
        self.CFGetTypeID = Function(lambda reference: {"boolean": 10, "integer": 20, "real": 20, "string": 30}.get(self.objects[reference][0], 40))
        self.CFBooleanGetTypeID = Function(lambda: 10)
        self.CFNumberGetTypeID = Function(lambda: 20)
        self.CFBooleanGetValue = Function(lambda reference: int(self.objects[reference][1]))
        self.CFNumberIsFloatType = Function(lambda reference: int(self.objects[reference][0] == "real"))
        self.CFNumberGetValue = Function(self.get_number)
        self.CFStringGetTypeID = Function(lambda: 30)
        self.CFStringGetLength = Function(lambda reference: len(self.objects[reference][1].encode("utf-16-le")) // 2)
        self.CFStringGetCString = Function(self.get_string)
        self.CFRelease = Function(self.released.append)

    def create_string(self, allocator, text, encoding):
        assert allocator is None
        assert encoding == probe._UTF8
        if text.decode("utf-8") == self.fail_string:
            return None
        reference = 100 + len(self.objects)
        self.objects[reference] = ("string", text.decode("utf-8"))
        self.created.append(reference)
        return reference

    def copy(self, observation):
        if observation is None:
            return None
        reference = 100 + len(self.objects)
        self.objects[reference] = observation
        self.copied.append(reference)
        return reference

    def get_number(self, reference, number_type, output):
        if not self.conversion_ok:
            return 0
        expected = probe._NUMBER_DOUBLE if self.objects[reference][0] == "real" else probe._NUMBER_SINT64
        assert number_type == expected
        output._obj.value = self.objects[reference][1]
        return 1

    def get_string(self, reference, output, capacity, encoding):
        assert encoding == probe._UTF8
        assert capacity == 33
        if not self.string_conversion_ok:
            return 0
        encoded = self.objects[reference][1].encode("utf-8")
        if len(encoded) + 1 > capacity:
            return 0
        ctypes.memmove(output, encoded + b"\0", len(encoded) + 1)
        return 1

    def assert_released(self):
        assert sorted(self.released) == sorted(self.created + self.copied)
        assert len(self.released) == len(set(self.released))
        assert not set(self.released) & set(self.constants.values())


@pytest.fixture
def native(monkeypatch, tmp_path):
    library = NativeLibrary()
    monkeypatch.setattr(probe.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(probe.os, "getuid", lambda: 501, raising=False)
    monkeypatch.setattr(probe.os, "geteuid", lambda: 501, raising=False)
    home = tmp_path / "native-user"
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_dir=str(home))))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CFFIXED_USER_HOME", raising=False)

    def load(path):
        assert path == "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        return library

    monkeypatch.setattr(probe.ctypes, "CDLL", load)
    monkeypatch.setattr(probe, "_constant_pointer", lambda supplied, name: supplied.constants[name])
    return library


def observe():
    return probe.read_preferences("com.apple.screensaver", "askForPassword")


@pytest.mark.parametrize("domain,key", [
    ("com.apple.SoftwareUpdate", "AutomaticCheckEnabled"),
    ("com.apple.screensaver", "askForPassword"),
    ("com.apple.screensaver", "askForPasswordDelay"),
    ("com.apple.timed", "TMAutomaticTimeOnlyEnabled"),
])
def test_only_fixed_native_keys_are_read(domain, key, native):
    result = probe.read_preferences(domain, key)
    assert result["available"] is True
    assert result["value"] is True
    assert [native.objects[reference][1] for reference in native.created] == [domain, key]
    native.assert_released()


@pytest.mark.parametrize("tag,value", [
    ("boolean", False), ("boolean", True),
    ("integer", 0), ("integer", 1), ("integer", 300),
    ("integer", 9_223_372_036_854_775_807),
    ("real", 0.0), ("real", 5.5),
])
def test_native_scalar_types_are_preserved_without_coercing_defaults(tag, value, native):
    native.effective = (tag, value)
    result = observe()
    assert result["available"] is True
    assert result["value"] == value
    assert type(result["value"]) is type(value)
    native.assert_released()


@pytest.mark.parametrize("domain,key", [
    ("com.apple.SoftwareUpdate", "AutomaticCheckEnabled"),
    ("com.apple.screensaver", "askForPassword"),
    ("com.apple.timed", "TMAutomaticTimeOnlyEnabled"),
])
@pytest.mark.parametrize("text,expected", [
    ("true", True), ("TRUE", True), ("TrUe", True), ("YES", True),
    ("false", False), ("FALSE", False), ("FaLsE", False), ("no", False),
])
def test_legacy_boolean_strings_use_the_verified_native_lexemes(domain, key, text, expected, native):
    native.effective = ("string", text)
    result = probe.read_preferences(domain, key)
    assert result["available"] is True
    assert result["value"] is expected
    assert type(result["value"]) is bool
    assert native.CFStringGetCString.calls
    native.assert_released()


@pytest.mark.parametrize("text,expected", [("0", 0), ("0005", 5), ("300", 300), ("2147483647", 2_147_483_647)])
def test_legacy_delay_integer_strings_remain_exact_known_numbers(text, expected, native):
    native.effective = ("string", text)
    result = probe.read_preferences("com.apple.screensaver", "askForPasswordDelay")
    assert result["available"] is True
    assert result["value"] == expected
    assert type(result["value"]) is int
    native.assert_released()


@pytest.mark.parametrize("text", [
    "", "0", "1", "2", " true", "true ", "TRUE\n", "on", "enabled",
    "private-user password=hidden", "true\0hidden", "true\u200b", "ＴＲＵＥ",
])
def test_boolean_string_recognition_never_uses_truthiness_or_trims_ambiguous_input(text, native):
    native.effective = ("string", text)
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    assert "private-user" not in json.dumps(result)
    assert "hidden" not in json.dumps(result)
    native.assert_released()


@pytest.mark.parametrize("text", [
    "", "true", "YES", "false", "NO", "-1", "+0", "0.0", "5.5", "1e2",
    " 0", "0 ", "０", "2147483648", "0" * 33, "0\0hidden",
])
def test_delay_strings_require_bounded_full_nonnegative_ascii_integers(text, native):
    native.effective = ("string", text)
    result = probe.read_preferences("com.apple.screensaver", "askForPasswordDelay")
    assert result["available"] is False
    assert result["value"] is None
    assert "hidden" not in json.dumps(result)
    native.assert_released()


def test_valid_string_scope_values_preserve_precedence_observations_without_raw_strings(native):
    native.effective = ("string", "YES")
    native.managed = True
    native.configured = {
        (1, 3): ("string", "NO"), (1, 4): ("string", "false"),
        (2, 3): ("string", "TrUe"), (2, 4): ("boolean", True),
    }
    result = observe()
    assert result["available"] is True
    assert result["value"] is True
    assert result["explicit_current_host"] is False
    assert result["explicit_any_host"] is False
    assert result["machine_current_host"] is True
    assert result["machine_any_host"] is True
    assert result["managed"] is True
    assert result["unreadable_scopes"] == []
    serialized = json.dumps(result)
    for text in ("YES", "NO", "TrUe"):
        assert text not in serialized
    native.assert_released()


def test_absent_effective_value_is_not_replaced_by_a_valid_explicit_string(native):
    native.effective = None
    native.configured = {(1, 4): ("string", "true")}
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    assert result["explicit_any_host"] is True
    assert result["unreadable_scopes"] == []
    native.assert_released()


@pytest.mark.parametrize("missing", ["CFStringGetTypeID", "CFStringGetLength", "CFStringGetCString"])
def test_optional_string_api_absence_does_not_break_typed_boolean_reads(missing, native):
    delattr(native, missing)
    assert observe()["value"] is True
    native.assert_released()


@pytest.mark.parametrize("missing", ["CFStringGetTypeID", "CFStringGetLength", "CFStringGetCString"])
def test_string_observation_remains_unknown_without_required_string_api(missing, native):
    delattr(native, missing)
    native.effective = ("string", "true")
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    native.assert_released()


def test_native_string_conversion_failure_is_not_an_empty_or_false_value(native):
    native.effective = ("string", "true")
    native.string_conversion_ok = False
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    native.assert_released()


@pytest.mark.parametrize("length", [-1, 0, 33, 2**63 - 1])
def test_native_string_lengths_are_bounded_before_copying(length, native):
    native.effective = ("string", "true")
    native.CFStringGetLength.callback = lambda reference: length
    result = observe()
    assert result["available"] is False
    assert not native.CFStringGetCString.calls
    native.assert_released()


def test_string_probe_exception_remains_unknown_and_sanitized(native):
    native.effective = ("string", "true")

    def denied(*arguments):
        raise PermissionError("private-user credential=hidden")

    native.CFStringGetCString.callback = denied
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    assert "private-user" not in json.dumps(result)
    assert "hidden" not in json.dumps(result)
    native.assert_released()


def test_string_interpretation_requires_an_explicit_allowlisted_kind(native):
    reference = native.copy(("string", "true"))
    with pytest.raises(probe._UnreadableValue):
        probe._copy_scalar(native, reference)
    native.assert_released()


def test_absence_is_never_false_or_zero(native):
    native.effective = None
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    assert result["reason"] == "missing-or-unreadable-effective-value"
    assert not native.CFBooleanGetValue.calls
    assert not native.CFNumberGetValue.calls
    assert not native.CFStringGetCString.calls
    native.assert_released()


def test_effective_byhost_and_configured_values_remain_distinct(native):
    native.effective = ("boolean", False)
    native.configured = {
        (1, 3): ("boolean", False),
        (1, 4): ("boolean", True),
        (2, 3): ("integer", 0),
        (2, 4): ("integer", 1),
    }
    native.managed = True
    result = observe()
    assert result["value"] is False
    assert result["explicit_current_host"] is False
    assert result["explicit_any_host"] is True
    assert result["machine_current_host"] == 0
    assert result["machine_any_host"] == 1
    assert result["managed"] is True
    assert result["managed_available"] is True
    native.assert_released()


def test_machine_time_observation_is_not_interpreted_as_enabled_or_disabled(native):
    native.effective = ("boolean", False)
    native.configured = {(2, 4): ("boolean", False)}
    result = probe.read_preferences("com.apple.timed", "TMAutomaticTimeOnlyEnabled")
    assert result["value"] is False
    assert result["machine_any_host"] is False
    assert "enabled" not in result
    native.assert_released()


def test_missing_resolved_value_can_still_report_explicit_observations(native):
    native.effective = None
    native.configured = {(1, 4): ("integer", 5)}
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    assert result["explicit_any_host"] == 5
    native.assert_released()


@pytest.mark.parametrize("observation", [
    ("string", "private credential=hidden"),
    ("dictionary", {"password": "hidden"}),
    ("real", float("nan")),
    ("real", float("inf")),
])
def test_unsupported_or_nonfinite_values_remain_unavailable_and_sanitized(observation, native):
    native.effective = observation
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    serialized = json.dumps(result, allow_nan=False)
    assert "private" not in serialized
    assert "hidden" not in serialized
    native.assert_released()


def test_numeric_conversion_failure_is_not_a_truncated_value(native):
    native.effective = ("integer", 42)
    native.conversion_ok = False
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    native.assert_released()


def test_invalid_higher_priority_configured_object_is_flagged_without_erasing_effective_value(native):
    native.configured = {(1, 3): ("string", "secret diagnostic")}
    result = observe()
    assert result["available"] is True
    assert result["value"] is True
    assert result["explicit_current_host"] is None
    assert result["unreadable_scopes"] == ["explicit_current_host"]
    assert "secret" not in json.dumps(result)
    native.assert_released()


@pytest.mark.parametrize("scope,user,host", [
    ("explicit_current_host", 1, 3),
    ("explicit_any_host", 1, 4),
    ("machine_current_host", 2, 3),
    ("machine_any_host", 2, 4),
])
@pytest.mark.parametrize("malformed", [
    ("string", "private-user credential=hidden"),
    ("dictionary", {"password": "hidden"}),
    ("real", float("nan")),
    ("real", float("inf")),
])
def test_each_unreadable_supplemental_scope_is_isolated_and_sanitized(scope, user, host, malformed, native):
    native.effective = ("boolean", False)
    native.configured = {(user, host): malformed}
    result = observe()
    assert result["available"] is True
    assert result["value"] is False
    assert result[scope] is None
    assert result["unreadable_scopes"] == [scope]
    assert "private-user" not in json.dumps(result, allow_nan=False)
    assert "hidden" not in json.dumps(result, allow_nan=False)
    native.assert_released()


def test_managed_effective_value_survives_unreadable_lower_priority_configuration(native):
    native.effective = ("boolean", True)
    native.managed = True
    native.configured = {
        (1, 4): ("string", "legacy-private-value"),
        (2, 4): ("dictionary", {"token": "hidden"}),
    }
    result = observe()
    assert result["available"] is True
    assert result["value"] is True
    assert result["managed_available"] is True
    assert result["managed"] is True
    assert result["unreadable_scopes"] == ["explicit_any_host", "machine_any_host"]
    assert "legacy-private-value" not in json.dumps(result)
    assert "hidden" not in json.dumps(result)
    native.assert_released()


def test_missing_effective_value_is_not_replaced_by_an_unreadable_configured_scope(native):
    native.effective = None
    native.configured = {(1, 4): ("string", "not-a-boolean")}
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    assert result["explicit_any_host"] is None
    assert result["unreadable_scopes"] == ["explicit_any_host"]
    assert result["reason"] == "missing-or-unreadable-effective-value"
    native.assert_released()


def test_missing_keys_are_distinct_from_unreadable_observations(native):
    native.effective = None
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    assert result["unreadable_scopes"] == []
    for field in ("explicit_current_host", "explicit_any_host", "machine_current_host", "machine_any_host"):
        assert result[field] is None
    native.assert_released()


def test_supplemental_numeric_conversion_failure_does_not_erase_boolean_effective_value(native):
    native.configured = {(2, 4): ("integer", 1)}
    native.conversion_ok = False
    result = observe()
    assert result["available"] is True
    assert result["value"] is True
    assert result["machine_any_host"] is None
    assert result["unreadable_scopes"] == ["machine_any_host"]
    native.assert_released()


def test_native_scope_read_exception_remains_conservative_and_does_not_leak_details(native):
    def denied(*arguments):
        raise PermissionError("private-user credential=hidden")
    native.CFPreferencesCopyValue.callback = denied
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    assert result["reason"] == "native-preference-read-unavailable"
    assert "private-user" not in json.dumps(result)
    assert "hidden" not in json.dumps(result)
    native.assert_released()


def test_optional_management_api_does_not_invent_management_status(native):
    del native.CFPreferencesAppValueIsForced
    result = observe()
    assert result["available"] is True
    assert result["managed"] is False
    assert result["managed_available"] is False
    native.assert_released()


def test_allocated_strings_are_released_when_second_allocation_fails(native):
    native.fail_string = "askForPassword"
    assert observe()["available"] is False
    assert len(native.created) == 1
    native.assert_released()


def test_ffi_definitions_preserve_64_bit_pointers_and_numeric_types(native):
    observe()
    assert native.CFPreferencesCopyAppValue.restype is ctypes.c_void_p
    assert native.CFPreferencesCopyValue.argtypes == (ctypes.c_void_p,) * 4
    assert native.CFGetTypeID.restype is ctypes.c_ulong
    assert native.CFBooleanGetValue.restype is ctypes.c_ubyte
    assert native.CFNumberGetValue.argtypes == (ctypes.c_void_p, ctypes.c_long, ctypes.c_void_p)
    assert native.CFRelease.restype is None
    assert native.CFStringGetTypeID.restype is ctypes.c_ulong
    assert native.CFStringGetLength.restype is ctypes.c_long
    assert native.CFStringGetCString.argtypes == (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long, ctypes.c_uint32)
    native.assert_released()


@pytest.mark.parametrize("domain,key", [
    ("com.apple.loginwindow", "Password"),
    ("com.apple.screensaver", "unrestricted-domain-dump"),
    ("/Users/a-user/Library/Preferences/com.apple.screensaver", "askForPassword"),
    ("com.apple.timed", "askForPassword"),
])
def test_unknown_queries_never_load_a_native_library(domain, key, monkeypatch):
    monkeypatch.setattr(probe.ctypes, "CDLL", lambda path: pytest.fail("Unallowlisted query must not access native APIs"))
    result = probe.read_preferences(domain, key)
    assert result["available"] is False
    assert result["reason"] == "unsupported-query"


def test_unsupported_platform_is_a_sanitized_unavailable_value(monkeypatch):
    monkeypatch.setattr(probe.platform, "system", lambda: "Windows")
    monkeypatch.setattr(probe.ctypes, "CDLL", lambda path: pytest.fail("Not a native Mac"))
    assert observe()["reason"] == "unsupported-platform"


def test_mixed_process_identity_is_not_replaced_with_another_account(native, monkeypatch):
    monkeypatch.setattr(probe.os, "geteuid", lambda: 0)
    result = observe()
    assert result["available"] is False
    assert result["reason"] == "ambiguous-user-context"
    assert not native.created


def test_hostname_and_sudo_environment_do_not_select_preferences(native, monkeypatch):
    monkeypatch.setenv("SUDO_USER", "another-user")
    monkeypatch.setattr(probe.platform, "node", lambda: pytest.fail("Hostname must not influence preference lookup"))
    assert observe()["available"] is True
    source_pairs = {(arguments[2], arguments[3]) for arguments in native.CFPreferencesCopyValue.calls}
    assert source_pairs == {(1, 3), (1, 4), (2, 3), (2, 4)}
    native.assert_released()


@pytest.mark.parametrize("variable", ["HOME", "CFFIXED_USER_HOME"])
def test_user_home_redirect_is_rejected_without_reading_other_preferences(variable, native, monkeypatch, tmp_path):
    monkeypatch.setenv(variable, str(tmp_path / "someone-else"))
    result = observe()
    assert result["available"] is False
    assert result["reason"] == "ambiguous-user-context"
    assert not native.created


def test_matching_fixed_home_is_allowed(native, monkeypatch):
    monkeypatch.setenv("CFFIXED_USER_HOME", probe.os.environ["HOME"])
    assert observe()["available"] is True
    native.assert_released()


def test_unresolvable_user_identity_does_not_trigger_native_reads(native, monkeypatch):
    def unknown(uid):
        raise KeyError("private account detail")
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwuid=unknown))
    result = observe()
    assert result["available"] is False
    assert result["reason"] == "ambiguous-user-context"
    assert "private" not in json.dumps(result)
    assert not native.created


def test_missing_or_denied_native_library_is_unavailable_without_exception_details(native, monkeypatch):
    def denied(path):
        raise PermissionError("/Users/private-person credential=hidden")
    monkeypatch.setattr(probe.ctypes, "CDLL", denied)
    result = observe()
    assert result["available"] is False
    assert "private-person" not in json.dumps(result)
    assert "hidden" not in json.dumps(result)


def test_missing_exported_api_is_unavailable(native):
    del native.CFPreferencesCopyValue
    result = observe()
    assert result["available"] is False
    assert result["reason"] == "native-preference-read-unavailable"


def test_missing_native_constant_is_unavailable(native, monkeypatch):
    def missing(library, name):
        raise ValueError("private native diagnostic")
    monkeypatch.setattr(probe, "_constant_pointer", missing)
    assert observe()["available"] is False
    assert not native.created


def test_main_emits_only_one_sanitized_json_object(native, capsys):
    assert probe.main(["com.apple.screensaver", "askForPassword"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert len(captured.out.splitlines()) == 1
    assert json.loads(captured.out)["value"] is True
    native.assert_released()


def test_standalone_helper_rejects_unknown_queries_before_any_native_read():
    result = subprocess.run(
        [sys.executable, str(Path(probe.__file__).resolve()), "not-an-allowed-domain", "arbitrary"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout)["reason"] == "unsupported-query"
