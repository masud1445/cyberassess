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
        self.fail_string = None
        self.CFStringCreateWithCString = Function(self.create_string)
        self.CFPreferencesCopyAppValue = Function(lambda key, app: self.copy(self.effective))
        self.CFPreferencesCopyValue = Function(lambda key, app, user, host: self.copy(self.configured.get((user, host))))
        self.CFPreferencesAppValueIsForced = Function(lambda key, app: int(self.managed))
        self.CFGetTypeID = Function(lambda reference: {"boolean": 10, "integer": 20, "real": 20}.get(self.objects[reference][0], 30))
        self.CFBooleanGetTypeID = Function(lambda: 10)
        self.CFNumberGetTypeID = Function(lambda: 20)
        self.CFBooleanGetValue = Function(lambda reference: int(self.objects[reference][1]))
        self.CFNumberIsFloatType = Function(lambda reference: int(self.objects[reference][0] == "real"))
        self.CFNumberGetValue = Function(self.get_number)
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


def test_absence_is_never_false_or_zero(native):
    native.effective = None
    result = observe()
    assert result["available"] is False
    assert result["value"] is None
    assert result["reason"] == "missing-or-unreadable-effective-value"
    assert not native.CFBooleanGetValue.calls
    assert not native.CFNumberGetValue.calls
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


def test_invalid_configured_object_does_not_become_effective_success(native):
    native.configured = {(1, 3): ("string", "secret diagnostic")}
    result = observe()
    assert result["available"] is False
    assert "secret" not in json.dumps(result)
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
