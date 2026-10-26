"""Narrow interpretation of read-only macOS status getters.

The native getter is ``/usr/sbin/sysadminctl -screenLock status``. Its help
grammar is captured at https://github.com/xfreebird/kcpassword/issues/5 and
current-Mac status examples are recorded at:
https://github.com/sametsazak/mergen/issues/39
https://github.com/lil-shimon/dotfiles/issues/199
https://github.com/iamivanhx/macos-setup/issues/30
https://github.com/openai/codex/issues/55615

These diagnostic strings are not a stable machine-readable API: new output
formats remain unknown. A timestamp/process label is discarded, never retained
as evidence. No native command executes in this module.

The command's process-versus-console selection is not a public API contract.
Only permit it when both identities demonstrably refer to the same non-root
user. This checks public device metadata, never another user's preferences.
Machine update/time getters are decoded independently and do not select a
user's screen-lock policy. Normal status on stderr is accepted only when the
complete output contains one explicit recognized state and no diagnostics.
"""

from __future__ import annotations

from datetime import datetime
import os
import platform
import re
import stat
from typing import Callable

from cyberassess.collectors._macos_preferences import _safe_user_context


_COCOA_PREFIX = re.compile(
    r"^(?P<timestamp>[0-9]{4}-[0-9]{2}-[0-9]{2} "
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?) "
    r"sysadminctl\[[0-9]+(?::[0-9]+)?\] "
)
_DELAY = re.compile(r"screenLock delay is (0|[1-9][0-9]{0,9}) seconds")
_DISABLED_SENTINEL = 2_147_483_647


def _single_status_message(stdout: str, stderr: str, returncode: int, process: str, banner: str | None = None) -> str | None:
    """Accept one explicit status, not a substring inside arbitrary output."""
    if type(returncode) is not int or returncode != 0:
        return None
    if not isinstance(stdout, str) or not isinstance(stderr, str) or len(stdout) + len(stderr) > 4096:
        return None
    prefix_pattern = re.compile(_COCOA_PREFIX.pattern.replace("sysadminctl", re.escape(process)))
    messages = []
    banners = 0
    for stream in (stdout, stderr):
        for line in stream.splitlines():
            line = line.strip()
            if not line:
                continue
            prefix = prefix_pattern.match(line)
            if prefix is not None:
                try:
                    datetime.fromisoformat(prefix["timestamp"])
                except ValueError:
                    return None
                line = line[prefix.end():]
            if banner is not None and line == banner:
                banners += 1
            else:
                messages.append(line)
    if len(messages) != 1 or banners > 1:
        return None
    return messages[0]


def software_update_status(stdout: str, stderr: str, returncode: int) -> bool | None:
    message = _single_status_message(stdout, stderr, returncode, "softwareupdate", "Software Update Tool")
    return {"Automatic check is on": True, "Automatic check is off": False}.get(message)


def network_time_status(stdout: str, stderr: str, returncode: int) -> bool | None:
    message = _single_status_message(stdout, stderr, returncode, "systemsetup")
    return {"Network Time: On": True, "Network Time: Off": False}.get(message)


def automatic_time_status(stdout: str, stderr: str, returncode: int) -> bool | None:
    """Interpret only an explicit property/status sentence from the getter.

    Native help documents -automaticTime status on older and recent macOS:
    https://github.com/microsoft/macos-cookbook/issues/32
    https://github.com/xfreebird/kcpassword/issues/5
    Complete output wording is not a stable documented API. These bounded
    whole-message forms express the property directly; other wording remains
    unknown rather than using an enabled/disabled substring in a diagnostic.
    """
    message = _single_status_message(stdout, stderr, returncode, "sysadminctl")
    if message is None:
        return None
    statuses = {
        f"{label} is {state}": value
        for label in ("automatic time", "automatictime")
        for state, value in (("enabled", True), ("disabled", False), ("on", True), ("off", False))
    }
    return statuses.get(message.removesuffix(".").casefold())


def screen_lock_status(
    stdout: str, stderr: str, returncode: int,
) -> tuple[bool, int | None] | None:
    """Return explicit password requirement and reported delay, or unknown.

    sysadminctl can log its normal status to stderr using a Cocoa prefix.
    Exactly one recognized status line across both streams is required. Off
    supplies no numeric delay; neither missing output nor the disabled
    sentinel becomes a zero delay.
    """
    if type(returncode) is not int or returncode != 0:
        return None
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        return None
    if len(stdout) + len(stderr) > 4096:
        return None
    lines = [line.strip() for text in (stdout, stderr) for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        return None
    line = lines[0]
    prefix = _COCOA_PREFIX.match(line)
    if prefix is not None:
        try:
            datetime.fromisoformat(prefix["timestamp"])
        except ValueError:
            return None
        line = line[prefix.end():]
    if line == "screenLock is off":
        return False, None
    if line == "screenLock delay is immediate":
        return True, 0
    delay = _DELAY.fullmatch(line)
    if delay is None:
        return None
    seconds = int(delay[1])
    if seconds >= _DISABLED_SENTINEL:
        # MobileKeyBag uses INT_MAX for disabled. An unexpected numeric form
        # cannot safely be interpreted as an enabled requirement or a delay.
        return None
    return True, seconds


def conflicting_status(
    stdout: str, stderr: str, returncode: int,
    parser: Callable[[str, str, int], object | None],
) -> bool:
    """Detect distinct recognized observations, without resolving a status.

    The full-output decoders deliberately reject multiple status lines. A
    caller must not then discard explicit conflicting native states and fall
    back to a reassuring stored preference. Reuse the same narrow decoder on
    each complete line; unknown text supplies no value or default. False only
    means no conflict was proven, never that the evidence is usable.
    """
    if type(returncode) is not int or returncode != 0:
        return False
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        return False
    if len(stdout) + len(stderr) > 4096:
        return False
    observations = []
    for stream in (stdout, stderr):
        for line in stream.splitlines():
            value = parser(line, "", 0)
            if value is not None:
                if observations and value != observations[0]:
                    return True
                observations.append(value)
    return False


def current_user_status_context_safe() -> bool:
    """Verify one unambiguous invoking/console user before the native getter."""
    try:
        if platform.system() != "Darwin":
            return False
        uid = os.getuid()
        if type(uid) is not int or uid <= 0 or os.geteuid() != uid:
            return False
        if not _safe_user_context():
            return False
        console = os.stat("/dev/console", follow_symlinks=False)
        return (
            stat.S_ISCHR(console.st_mode)
            and type(console.st_uid) is int
            and console.st_uid == uid
        )
    except (AttributeError, OSError, KeyError, TypeError, ValueError):
        return False
