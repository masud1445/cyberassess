"""Internal, read-only CoreFoundation preference probe.

Run in a bounded subprocess as the assessment user. Only four allowlisted keys
are read; native preference resolution may include that user's ByHost and
managed settings. No preference is created, synchronized, or changed. Missing
objects are never converted to Boolean false or integer zero.
"""

from __future__ import annotations

import ctypes
import json
import math
import os
from pathlib import Path
import platform
import re
import sys
from typing import Any


_FRAMEWORK = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
_UTF8 = 0x08000100
_NUMBER_SINT64 = 4
_NUMBER_DOUBLE = 13
_ALLOWED = {
    "com.apple.SoftwareUpdate": frozenset({"AutomaticCheckEnabled"}),
    "com.apple.screensaver": frozenset({"askForPassword", "askForPasswordDelay"}),
    "com.apple.timed": frozenset({"TMAutomaticTimeOnlyEnabled"}),
}


class _UnreadableValue(ValueError):
    """The native object cannot establish an unambiguous typed scalar."""


def _unavailable(reason: str) -> dict[str, Any]:
    return {
        "available": False,
        "value": None,
        "managed": False,
        "managed_available": False,
        "explicit_current_host": None,
        "explicit_any_host": None,
        "machine_current_host": None,
        "machine_any_host": None,
        "unreadable_scopes": [],
        "reason": reason,
    }


def _configure(library: Any) -> None:
    pointer = ctypes.c_void_p
    definitions = {
        "CFStringCreateWithCString": (pointer, (pointer, ctypes.c_char_p, ctypes.c_uint32)),
        "CFPreferencesCopyAppValue": (pointer, (pointer, pointer)),
        "CFPreferencesCopyValue": (pointer, (pointer, pointer, pointer, pointer)),
        "CFGetTypeID": (ctypes.c_ulong, (pointer,)),
        "CFBooleanGetTypeID": (ctypes.c_ulong, ()),
        "CFBooleanGetValue": (ctypes.c_ubyte, (pointer,)),
        "CFNumberGetTypeID": (ctypes.c_ulong, ()),
        "CFNumberIsFloatType": (ctypes.c_ubyte, (pointer,)),
        "CFNumberGetValue": (ctypes.c_ubyte, (pointer, ctypes.c_long, pointer)),
        "CFRelease": (None, (pointer,)),
    }
    for name, (result_type, argument_types) in definitions.items():
        function = getattr(library, name)
        function.restype = result_type
        function.argtypes = argument_types
    # Optional only so an absent string API cannot break native Boolean/number
    # reads. String observations themselves remain unavailable without it.
    string_definitions = {
        "CFStringGetTypeID": (ctypes.c_ulong, ()),
        "CFStringGetLength": (ctypes.c_long, (pointer,)),
        "CFStringGetCString": (ctypes.c_ubyte, (pointer, pointer, ctypes.c_long, ctypes.c_uint32)),
    }
    for name, (result_type, argument_types) in string_definitions.items():
        function = getattr(library, name, None)
        if function is not None:
            function.restype = result_type
            function.argtypes = argument_types
    forced = getattr(library, "CFPreferencesAppValueIsForced", None)
    if forced is not None:
        forced.restype = ctypes.c_ubyte
        forced.argtypes = (pointer, pointer)


def _constant_pointer(library: Any, name: str) -> int:
    # These exported CFString references are borrowed, not owned copies.
    value = ctypes.c_void_p.in_dll(library, name).value
    if value is None:
        raise _UnreadableValue("Unavailable native constant")
    return value


def _string_scalar(library: Any, reference: Any, kind: str | None) -> bool | int:
    """Read only a bounded security scalar, never stringify an arbitrary object.

    Apple CFApplicationPreferences.c accepts case-insensitive true/YES and
    false/NO for Boolean preferences, and full integer strings for integer
    preferences. Keep a conservative, key-aware subset with no missing-value
    coercion: https://github.com/apple-oss-distributions/CF/blob/main/CFApplicationPreferences.c
    """
    if kind not in {"boolean", "delay"}:
        raise _UnreadableValue("Unknown string preference kind")
    length_function = getattr(library, "CFStringGetLength", None)
    copy_function = getattr(library, "CFStringGetCString", None)
    if length_function is None or copy_function is None:
        raise _UnreadableValue("Native string APIs unavailable")
    length = length_function(reference)
    if type(length) is not int or not 0 < length <= 32:
        raise _UnreadableValue("Unsupported native string length")
    buffer = ctypes.create_string_buffer(33)
    if not copy_function(reference, buffer, len(buffer), _UTF8):
        raise _UnreadableValue("Native string conversion unavailable")
    try:
        text = buffer.value.decode("ascii")
    except UnicodeDecodeError as error:
        raise _UnreadableValue("Non-ASCII native scalar") from error
    if len(text) != length:
        raise _UnreadableValue("Ambiguous native string content")
    if kind == "boolean":
        value = {"true": True, "yes": True, "false": False, "no": False}.get(text.lower())
        if value is None:
            raise _UnreadableValue("Unsupported Boolean string")
        return value
    if not re.fullmatch(r"[0-9]+", text):
        raise _UnreadableValue("Unsupported integer string")
    value = int(text)
    if value > 2_147_483_647:
        raise _UnreadableValue("Unsupported password delay")
    return value


def _copy_scalar(library: Any, reference: Any, kind: str | None = None) -> bool | int | float | None:
    if not reference:
        return None
    try:
        type_id = library.CFGetTypeID(reference)
        if type_id == library.CFBooleanGetTypeID():
            return bool(library.CFBooleanGetValue(reference))
        string_type = getattr(library, "CFStringGetTypeID", None)
        if string_type is not None and type_id == string_type():
            return _string_scalar(library, reference, kind)
        if type_id != library.CFNumberGetTypeID():
            # Do not stringify objects, dump collections, or coerce strings.
            raise _UnreadableValue("Unsupported native scalar type")
        if library.CFNumberIsFloatType(reference):
            number = ctypes.c_double()
            if not library.CFNumberGetValue(reference, _NUMBER_DOUBLE, ctypes.byref(number)):
                raise _UnreadableValue("Inexact native numeric conversion")
            if not math.isfinite(number.value):
                raise _UnreadableValue("Nonfinite native number")
            return number.value
        integer = ctypes.c_longlong()
        if not library.CFNumberGetValue(reference, _NUMBER_SINT64, ctypes.byref(integer)):
            raise _UnreadableValue("Inexact native numeric conversion")
        return integer.value
    finally:
        # Every Copy result is owned, including objects rejected above.
        library.CFRelease(reference)


def _read_with_library(domain: str, key: str, library: Any) -> dict[str, Any]:
    """The FFI boundary, separately exercisable with a fake native library."""
    _configure(library)
    kind = None
    if domain in _ALLOWED and key in _ALLOWED[domain]:
        kind = "delay" if key == "askForPasswordDelay" else "boolean"
    constants = {
        name: _constant_pointer(library, name)
        for name in (
            "kCFPreferencesCurrentUser", "kCFPreferencesAnyUser",
            "kCFPreferencesCurrentHost", "kCFPreferencesAnyHost",
        )
    }
    owned_strings = []
    try:
        for text in (domain, key):
            reference = library.CFStringCreateWithCString(None, text.encode("utf-8"), _UTF8)
            if not reference:
                raise _UnreadableValue("Native allocation unavailable")
            owned_strings.append(reference)
        application, preference_key = owned_strings
        result = _unavailable("missing-or-unreadable-effective-value")
        result["value"] = _copy_scalar(
            library, library.CFPreferencesCopyAppValue(preference_key, application), kind,
        )
        for field, user, host in (
            ("explicit_current_host", "kCFPreferencesCurrentUser", "kCFPreferencesCurrentHost"),
            ("explicit_any_host", "kCFPreferencesCurrentUser", "kCFPreferencesAnyHost"),
            ("machine_current_host", "kCFPreferencesAnyUser", "kCFPreferencesCurrentHost"),
            ("machine_any_host", "kCFPreferencesAnyUser", "kCFPreferencesAnyHost"),
        ):
            try:
                result[field] = _copy_scalar(
                    library,
                    library.CFPreferencesCopyValue(
                        preference_key, application, constants[user], constants[host]
                    ),
                    kind,
                )
            except _UnreadableValue:
                # A stale or malformed supplementary value must not erase a
                # separately resolved, typed effective value. Preserve the
                # distinction from a missing key so the parent can enforce
                # precedence and ambiguity checks without inventing a value.
                result[field] = None
                result["unreadable_scopes"].append(field)
        forced = getattr(library, "CFPreferencesAppValueIsForced", None)
        if forced is not None:
            result["managed"] = bool(forced(preference_key, application))
            result["managed_available"] = True
        if result["value"] is not None:
            result["available"] = True
            result["reason"] = "effective-preference-value"
        return result
    finally:
        for reference in reversed(owned_strings):
            library.CFRelease(reference)


def _safe_user_context() -> bool:
    """Reject preference-domain redirects instead of choosing another account."""
    try:
        import pwd

        if os.getuid() != os.geteuid():
            return False
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        if not home.is_absolute() or home == Path("/"):
            return False
        expected = os.path.realpath(home)
        for name in ("HOME", "CFFIXED_USER_HOME"):
            supplied = os.environ.get(name)
            if supplied is not None:
                candidate = Path(supplied)
                if not supplied or not candidate.is_absolute() or os.path.realpath(candidate) != expected:
                    return False
        return True
    except (ImportError, AttributeError, OSError, KeyError, TypeError, ValueError):
        return False


def read_preferences(domain: str, key: str) -> dict[str, Any]:
    """Read fixed observations; semantic interpretation belongs to the collector."""
    if domain not in _ALLOWED or key not in _ALLOWED[domain]:
        return _unavailable("unsupported-query")
    if platform.system() != "Darwin":
        return _unavailable("unsupported-platform")
    try:
        if not _safe_user_context():
            return _unavailable("ambiguous-user-context")
        library = ctypes.CDLL(_FRAMEWORK)
        return _read_with_library(domain, key, library)
    except (
        AttributeError, OSError, ValueError, TypeError, RuntimeError,
        OverflowError, ctypes.ArgumentError,
    ):
        # Missing and denied preference reads are indistinguishable when the
        # API returns NULL. Do not expose exceptions, paths, or native output.
        return _unavailable("native-preference-read-unavailable")


def main(arguments: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 2:
        observation = _unavailable("unsupported-query")
    else:
        observation = read_preferences(arguments[0], arguments[1])
    print(json.dumps(observation, allow_nan=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
