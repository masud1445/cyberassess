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


def _copy_scalar(library: Any, reference: Any) -> bool | int | float | None:
    if not reference:
        return None
    try:
        type_id = library.CFGetTypeID(reference)
        if type_id == library.CFBooleanGetTypeID():
            return bool(library.CFBooleanGetValue(reference))
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
            library, library.CFPreferencesCopyAppValue(preference_key, application)
        )
        for field, user, host in (
            ("explicit_current_host", "kCFPreferencesCurrentUser", "kCFPreferencesCurrentHost"),
            ("explicit_any_host", "kCFPreferencesCurrentUser", "kCFPreferencesAnyHost"),
            ("machine_current_host", "kCFPreferencesAnyUser", "kCFPreferencesCurrentHost"),
            ("machine_any_host", "kCFPreferencesAnyUser", "kCFPreferencesAnyHost"),
        ):
            result[field] = _copy_scalar(
                library,
                library.CFPreferencesCopyValue(
                    preference_key, application, constants[user], constants[host]
                ),
            )
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
