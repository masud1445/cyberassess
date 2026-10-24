"""Read-only, local macOS evidence with deliberately narrow output parsing.

Only the fixed queries below run. No command changes settings or requests sudo.
Missing preferences, unsupported commands, and uncertain output stay unknown;
they must never stand in for a secure default. Raw evidence is an allowlisted
summary, not an unrestricted dump of native command output.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
import platform
import plistlib
import re
import subprocess
from typing import Any, Callable
from xml.etree import ElementTree
from xml.parsers.expat import ExpatError

from cyberassess.collector import CollectionError


class MacOSCollectionError(CollectionError):
    """Native macOS collection cannot run on this development host."""


Value = bool | int | float | None
Runner = Callable[..., subprocess.CompletedProcess[str]]


def _filevault(text: str) -> Value:
    return {"FileVault is On.": True, "FileVault is Off.": False}.get(text.strip())


def _firewall(text: str) -> Value:
    return {
        "Firewall is enabled. (State = 1)": True,
        "Firewall is disabled. (State = 0)": False,
        "Firewall is set to block all non-essential incoming connections. (State = 2)": True,
    }.get(text.strip())


def _sip(text: str) -> Value:
    return {
        "System Integrity Protection status: enabled.": True,
        "System Integrity Protection status: disabled.": False,
    }.get(text.strip())


def _gatekeeper(text: str) -> Value:
    return {"assessments enabled": True, "assessments disabled": False}.get(text.strip())


def _preference(text: str) -> Value:
    return {"1": True, "0": False, "true": True, "false": False}.get(text.strip().lower())


def _delay(text: str) -> Value:
    text = text.strip()
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", text):
        return None
    # Avoid interpreting huge or sentinel values as meaningful policy evidence.
    value = float(text)
    if value > 2_147_483_647:
        return None
    return int(value) if value.is_integer() else value


def _remote_login(text: str) -> Value:
    return {"Remote Login: On": True, "Remote Login: Off": False}.get(text.strip())


def _network_time(text: str) -> Value:
    return {"Network Time: On": True, "Network Time: Off": False}.get(text.strip())


def _plist_value(text: str) -> Any:
    """Parse only plutil's extracted XML scalar, never an entire preference dump."""
    if len(text) > 4096:
        return None
    try:
        value = plistlib.loads(text.encode("utf-8"), fmt=plistlib.FMT_XML)
        # plistlib alone accepts multiple top-level scalars and even nested
        # boolean elements, silently selecting a value. plutil must emit one
        # scalar; malformed structures cannot establish security evidence.
        root = ElementTree.fromstring(text)
        if root.tag != "plist" or len(root) != 1 or (root.text or "").strip():
            return None
        scalar = root[0]
        if scalar.tag not in {"true", "false", "integer", "real"} or len(scalar) or (scalar.tail or "").strip():
            return None
        if scalar.tag in {"true", "false"} and (scalar.text or "").strip():
            return None
        return value
    except (ValueError, TypeError, OverflowError, ExpatError, ElementTree.ParseError):
        return None


def _plist_preference(text: str) -> Value:
    value = _plist_value(text)
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    return None


def _plist_delay(text: str) -> Value:
    value = _plist_value(text)
    if type(value) not in (int, float):
        return None
    if not 0 <= value <= 2_147_483_647 or not math.isfinite(value):
        return None
    return int(value) if value == int(value) else value


def _launchd_remote_login(text: str) -> Value:
    """An explicit SSH enable/disable override, not daemon activity or absence."""
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    if len(lines) < 2 or lines[0] != "disabled services = {" or lines[-1] != "}":
        return None
    matches = []
    for line in lines[1:-1]:
        entry = re.fullmatch(r'"([^"\r\n]+)"\s*=>\s*(true|false|enabled|disabled)', line)
        if entry is None:
            return None
        if entry[1] == "com.openssh.sshd":
            matches.append(entry[2])
    if len(matches) != 1:
        return None
    return {"true": False, "disabled": False, "false": True, "enabled": True}[matches[0]]


def _invoking_user_home() -> Path | None:
    """Never substitute HOME, SUDO_USER, the console user, or another account."""
    try:
        import pwd  # POSIX only; importing the collector must remain portable.

        if os.getuid() != os.geteuid():
            return None
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, AttributeError, KeyError, OSError):
        return None
    return home if home.is_absolute() and home != Path("/") else None


@dataclass(frozen=True)
class _Query:
    source: str
    key: str
    command: tuple[str, ...]
    parser: Callable[[str], Value]
    scope: str = "local machine status"


_SOFTWARE_UPDATE = "/Library/Preferences/com.apple.SoftwareUpdate"
_SCREENSAVER = "com.apple.screensaver"
_MACHINE_PREFERENCE = "explicit machine preference; effective MDM policy is not verified"
_USER_PREFERENCE = "invoking user's explicit screen saver preference; effective/ByHost/MDM policy is not verified"

_QUERIES = (
    _Query("filevault", "enabled", ("/usr/bin/fdesetup", "status"), _filevault),
    _Query("application_firewall", "enabled", ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"), _firewall),
    _Query("system_integrity", "enabled", ("/usr/bin/csrutil", "status"), _sip),
    _Query("gatekeeper", "enabled", ("/usr/sbin/spctl", "--status"), _gatekeeper),
    _Query("update_check", "enabled", ("/usr/bin/defaults", "read", _SOFTWARE_UPDATE, "AutomaticCheckEnabled"), _preference, _MACHINE_PREFERENCE),
    _Query("update_download", "enabled", ("/usr/bin/defaults", "read", _SOFTWARE_UPDATE, "AutomaticDownload"), _preference, _MACHINE_PREFERENCE),
    _Query("security_updates", "enabled", ("/usr/bin/defaults", "read", _SOFTWARE_UPDATE, "CriticalUpdateInstall"), _preference, _MACHINE_PREFERENCE),
    _Query("system_data_updates", "enabled", ("/usr/bin/defaults", "read", _SOFTWARE_UPDATE, "ConfigDataInstall"), _preference, _MACHINE_PREFERENCE),
    _Query("remote_login", "enabled", ("/usr/sbin/systemsetup", "-getremotelogin"), _remote_login),
    _Query("screen_lock", "password_required", ("/usr/bin/defaults", "read", _SCREENSAVER, "askForPassword"), _preference, _USER_PREFERENCE),
    _Query("screen_lock_delay", "seconds", ("/usr/bin/defaults", "read", _SCREENSAVER, "askForPasswordDelay"), _delay, _USER_PREFERENCE),
    _Query("network_time", "enabled", ("/usr/sbin/systemsetup", "-getusingnetworktime"), _network_time),
)


def _plist_query(query: _Query, path: Path, key: str) -> _Query:
    return _Query(
        query.source, query.key,
        ("/usr/bin/plutil", "-extract", key, "xml1", "-o", "-", str(path)),
        _plist_delay if query.source == "screen_lock_delay" else _plist_preference,
        query.scope + "; exact plist key extracted with plutil",
    )


def _fallback_queries(query: _Query) -> tuple[_Query, ...]:
    if query.source == "update_check":
        # MAC-005 explicitly requires this key. softwareupdate --schedule may
        # resolve an OS default and cannot establish that the key was set.
        return (_plist_query(query, Path(_SOFTWARE_UPDATE + ".plist"), "AutomaticCheckEnabled"),)
    if query.source == "remote_login":
        return (_Query(
            query.source, query.key, ("/bin/launchctl", "print-disabled", "system"),
            _launchd_remote_login,
            "explicit com.openssh.sshd launchd enable/disable override; service activity is not assessed",
        ),)
    if query.source == "network_time":
        timed = _Query(
            query.source, query.key,
            ("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.timed", "TMAutomaticTimeOnlyEnabled"),
            _preference,
            "explicit machine automatic-time preference; successful synchronization and MDM enforcement are not verified",
        )
        return (timed, _plist_query(timed, Path("/Library/Preferences/com.apple.timed.plist"), "TMAutomaticTimeOnlyEnabled"))
    if query.source in {"screen_lock", "screen_lock_delay"}:
        home = _invoking_user_home()
        if home is not None:
            return (_plist_query(query, home / "Library/Preferences/com.apple.screensaver.plist", query.command[-1]),)
    return ()


_UNAVAILABLE_HINTS = {
    "update_check": "AutomaticCheckEnabled must be explicitly readable; an absent key is not an enabled default.",
    "remote_login": "Remote Login needs a readable systemsetup status or an explicit com.openssh.sshd override; a missing launchd entry is unknown.",
    "screen_lock": "askForPassword must be explicitly readable for the invoking user; other users, ByHost settings and effective lock policy are outside this control.",
    "screen_lock_delay": "askForPasswordDelay must be explicitly readable for the invoking user; an absent delay is not zero.",
    "network_time": "Network time needs a readable systemsetup status or explicit TMAutomaticTimeOnlyEnabled preference; a running timed service is insufficient.",
}


class MacOSCollector:
    """Collect fixed native queries on an authorized local Mac.

    ``runner`` is a subprocess.run-compatible callable for deterministic tests.
    Supplying it also permits fixture validation on a non-macOS development host;
    a real collection on another platform raises MacOSCollectionError.
    """

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner if runner is not None else subprocess.run
        self._native_platform = runner is not None or platform.system() == "Darwin"

    @staticmethod
    def _unknown(query: _Query, reason: str) -> dict[str, Any]:
        return {
            query.key: None,
            "_collection_ok": False,
            "_raw": reason,
            "_scope": query.scope,
        }

    def _run_query(self, query: _Query) -> dict[str, Any]:
        # Native tools emit stable English status text in the C locale. Preserve
        # the process environment without recording it or its values in reports.
        command_env = dict(os.environ, LC_ALL="C", LANG="C")
        try:
            result = self._runner(
                list(query.command),
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=10,
                check=False,
                shell=False,
                env=command_env,
            )
        except subprocess.TimeoutExpired:
            return self._unknown(query, "Unavailable: read-only command timed out after 10 seconds.")
        except PermissionError:
            return self._unknown(query, "Unavailable: native query requires additional local privileges.")
        except OSError:
            return self._unknown(query, "Unavailable: native command could not be executed.")

        combined = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
        privilege_markers = (
            "administrator access", "must be run as root", "requires root",
            "permission denied", "operation not permitted", "not authorized",
            "not privileged", "access denied", "requires administrator",
            "requires full disk access",
        )
        if any(marker in combined for marker in privilege_markers):
            return self._unknown(query, "Unavailable: native query requires additional local privileges.")

        if result.returncode != 0:
            if query.command[0] in {"/usr/bin/defaults", "/usr/bin/plutil"}:
                reason = "Unavailable: explicit preference could not be read; no default was inferred."
            else:
                reason = "Unavailable: native command returned a nonzero exit status."
            return self._unknown(query, reason)

        if result.stderr and str(result.stderr).strip():
            return self._unknown(query, "Unavailable: native command reported a diagnostic; status is inconclusive.")

        text = result.stdout if isinstance(result.stdout, str) else ""
        value = query.parser(text)
        if value is None:
            return self._unknown(query, "Unavailable: unrecognized or ambiguous command output; no value was inferred.")

        # Only a parsed scalar and a fixed label enter retained evidence. Native
        # stderr/stdout may include identifiers, paths, or unsupported diagnostics.
        summary = str(value).lower() if isinstance(value, bool) else str(value)
        return {
            query.key: value,
            "_collection_ok": True,
            "_raw": f"{query.source}.{query.key}={summary}; {query.scope}",
            "_scope": query.scope,
        }

    def _collect_query(self, query: _Query) -> dict[str, Any]:
        primary = self._run_query(query)
        if primary["_collection_ok"] or query.source not in _UNAVAILABLE_HINTS:
            return primary
        failures = [primary["_raw"]]
        fallbacks = _fallback_queries(query)
        for fallback in fallbacks:
            result = self._run_query(fallback)
            if result["_collection_ok"]:
                return result
            if result["_raw"] not in failures:
                failures.append(result["_raw"])
        if not fallbacks and query.source in {"screen_lock", "screen_lock_delay"}:
            failures.append("Unavailable: invoking user's home could not be resolved safely for an exact plist read.")
        return self._unknown(query, "Unavailable: " + _UNAVAILABLE_HINTS[query.source] + " " + " ".join(failures))

    def collect(self) -> dict[str, Any]:
        if not self._native_platform:
            raise MacOSCollectionError("Local macOS collection requires macOS; use --demo for sample evidence.")
        return {
            "target_name": platform.node() or "Unknown (local macOS host)",
            "platform": "macOS",
            "collector": {
                "method": "local / native commands",
                "mode": "local",
                "read_only": True,
                "profile": "macos",
                "scope": "Authorized local Mac; current-user preferences refer to the invoking user only.",
                "limitations": "Explicit preferences do not prove effective MDM policy. No automatic privilege elevation. Unknown values are ERROR.",
                "evidence_policy": "Allowlisted status summaries only; no unrestricted command output is retained.",
            },
            "evidence": {query.source: self._collect_query(query) for query in _QUERIES},
        }
