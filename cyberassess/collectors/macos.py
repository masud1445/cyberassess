"""Read-only, local macOS evidence with deliberately narrow output parsing.

Only the fixed queries below run. No command changes settings or requests sudo.
Missing preferences, unsupported commands, and uncertain output stay unknown;
they must never stand in for a secure default. Raw evidence is an allowlisted
summary, not an unrestricted dump of native command output.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import platform
import re
import subprocess
from typing import Any, Callable

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

    def _collect_query(self, query: _Query) -> dict[str, Any]:
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
        except OSError:
            return self._unknown(query, "Unavailable: native command could not be executed.")

        combined = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
        privilege_markers = (
            "administrator access", "must be run as root", "requires root",
            "permission denied", "operation not permitted", "not authorized",
        )
        if any(marker in combined for marker in privilege_markers):
            return self._unknown(query, "Unavailable: native query requires additional local privileges.")

        if result.returncode != 0:
            if query.command[0] == "/usr/bin/defaults":
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
