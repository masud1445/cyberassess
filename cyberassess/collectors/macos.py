"""Read-only, local macOS evidence with deliberately narrow output parsing.

Only the fixed queries below run. No command changes settings. Explicit opt-in
permits noninteractive sudo only for three allowlisted read-only status commands,
without using or updating cached credentials.
Missing preferences, unsupported commands, and uncertain output stay unknown;
they must never stand in for a secure default. Raw evidence is an allowlisted
summary, not an unrestricted dump of native command output.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import platform
import plistlib
import re
import subprocess
import sys
from typing import Any, Callable
from xml.etree import ElementTree
from xml.parsers.expat import ExpatError

from cyberassess.collector import CollectionError
from cyberassess.collectors._macos_remote_login import parse_override_map, parse_service, resolve_remote_login
from cyberassess.collectors._macos_status import (
    automatic_time_status, conflicting_status, current_user_status_context_safe,
    network_time_status, screen_lock_status, software_update_status,
)


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
        if scalar.tag not in {"true", "false", "integer", "real", "string"} or len(scalar) or (scalar.tail or "").strip():
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


def _managed_plist_preference(text: str) -> Value:
    """Match the native probe's legacy Boolean format, only for policy reads."""
    value = _plist_value(text)
    if type(value) is str:
        if not 0 < len(value) <= 32 or not value.isascii():
            return None
        return {"true": True, "yes": True, "false": False, "no": False}.get(value.lower())
    return _boolean(value)


def _plist_delay(text: str) -> Value:
    value = _plist_value(text)
    if type(value) not in (int, float):
        return None
    if not 0 <= value <= 2_147_483_647 or not math.isfinite(value):
        return None
    return int(value) if value == int(value) else value


def _update_schedule(text: str) -> Value:
    return {"Automatic check is on": True, "Automatic check is off": False}.get(text.strip())


def _boolean(value: Any) -> Value:
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    return None


def _numeric_delay(value: Any) -> Value:
    if type(value) not in (int, float) or not 0 <= value <= 2_147_483_647:
        return None
    if not math.isfinite(value):
        return None
    return int(value) if value == int(value) else value


def _preference_payload(text: str) -> dict[str, Any] | None:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate native observation")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("Nonfinite native observation")

    if len(text) > 8192:
        return None
    try:
        value = json.loads(text, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (TypeError, ValueError):
        return None
    if not isinstance(value, dict) or type(value.get("available")) is not bool:
        return None
    if type(value.get("managed")) is not bool or type(value.get("managed_available")) is not bool:
        return None
    scope_names = {"explicit_current_host", "explicit_any_host", "machine_current_host", "machine_any_host"}
    unreadable = value.get("unreadable_scopes", [])
    if not isinstance(unreadable, list) or any(type(scope) is not str or scope not in scope_names for scope in unreadable):
        return None
    if len(unreadable) != len(set(unreadable)) or any(value.get(scope) is not None for scope in unreadable):
        return None
    for key in ("value", "explicit_current_host", "explicit_any_host", "machine_current_host", "machine_any_host"):
        scalar = value.get(key)
        if scalar is not None:
            if type(scalar) not in (bool, int, float):
                return None
            if type(scalar) is int and not -(2**63) <= scalar < 2**63:
                return None
            if type(scalar) is float and not math.isfinite(scalar):
                return None
    return value


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
_MACHINE_PREFERENCE = "explicit configured machine preference; effective MDM policy is not verified"
_USER_PREFERENCE = "invoking user's explicit configured screen saver preference; effective/ByHost/MDM policy is not verified"
_PREFERENCE_HELPER = str(Path(__file__).with_name("_macos_preferences.py").resolve())
_PRIVILEGE_REQUIRED = "Unavailable: native query requires additional local privileges."
_ELEVATED_READ_COMMANDS = frozenset({
    ("/usr/sbin/systemsetup", "-getremotelogin"),
    ("/usr/sbin/systemsetup", "-getusingnetworktime"),
    ("/usr/sbin/softwareupdate", "--schedule"),
})
# With a command, sudo -k ignores cached credentials and does not update them.
# -n forbids authentication prompts. Only pre-approved passwordless policy can
# authorize these reads; never run a standalone cache/credential command.
_ELEVATED_READ_PREFIX = ("/usr/bin/sudo", "-n", "-k", "--")

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
        return (_plist_query(query, Path(_SOFTWARE_UPDATE + ".plist"), "AutomaticCheckEnabled"),)
    if query.source in {"screen_lock", "screen_lock_delay"}:
        home = _invoking_user_home()
        if home is not None:
            return (_plist_query(query, home / "Library/Preferences/com.apple.screensaver.plist", query.command[-1]),)
    return ()


_UNAVAILABLE_HINTS = {
    "update_check": "Automatic update checking needs a native schedule status or a resolved machine preference; absence is not an enabled default.",
    "remote_login": "Remote Login needs a native status or consistent launchd registration, override and service-definition evidence; absence alone is unknown.",
    "screen_lock": "The invoking user's password requirement could not be resolved through native preferences; no other user's settings were read.",
    "screen_lock_delay": "The invoking user's effective password delay could not be established; an absent delay is not zero.",
    "network_time": "Automatic network time needs a native status or verified enforced machine policy; a timed preference or running service alone is insufficient.",
}


class MacOSCollector:
    """Collect fixed native queries on an authorized local Mac.

    ``runner`` is a subprocess.run-compatible callable for deterministic tests.
    Supplying it also permits fixture validation on a non-macOS development host;
    a real collection on another platform raises MacOSCollectionError.
    """

    def __init__(self, runner: Runner | None = None, *, allow_elevated_read: bool = False) -> None:
        if type(allow_elevated_read) is not bool:
            raise TypeError("allow_elevated_read must be an explicit Boolean.")
        self._runner = runner if runner is not None else subprocess.run
        self._allow_elevated_read = allow_elevated_read
        self._native_platform = runner is not None or platform.system() == "Darwin"
        self._command_cache: dict[tuple[str, ...], tuple[Any, str | None]] = {}

    @staticmethod
    def _unknown(query: _Query, reason: str) -> dict[str, Any]:
        return {
            query.key: None,
            "_collection_ok": False,
            "_raw": reason,
            "_scope": query.scope,
        }

    def _invoke(self, command: tuple[str, ...]) -> tuple[Any, str | None]:
        if command in self._command_cache:
            return self._command_cache[command]
        # Native tools emit stable English status text in the C locale. Preserve
        # the process environment without recording it or its values in reports.
        command_env = dict(os.environ, LC_ALL="C", LANG="C")
        try:
            result = self._runner(
                list(command),
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=10,
                check=False,
                shell=False,
                env=command_env,
            )
        except subprocess.TimeoutExpired:
            answer = (None, "Unavailable: read-only command timed out after 10 seconds.")
        except PermissionError:
            answer = (None, _PRIVILEGE_REQUIRED)
        except OSError:
            answer = (None, "Unavailable: native command could not be executed.")
        else:
            combined = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
            privilege_markers = (
                "administrator access", "must be run as root", "requires root",
                "must be root", "must run as root", "must have root privileges",
                "permission denied", "operation not permitted", "not authorized",
                "not privileged", "access denied", "requires administrator",
                "requires full disk access", "authentication required",
            )
            sudo_denials = (
                "a password is required", "a terminal is required", "no tty present",
                "not in the sudoers", "not allowed to execute", "may not run sudo",
            )
            denied = any(marker in combined for marker in privilege_markers)
            denied = denied or (command[0] == "/usr/bin/sudo" and any(marker in combined for marker in sudo_denials))
            reason = _PRIVILEGE_REQUIRED if denied else None
            answer = (None, reason) if reason else (result, None)
        self._command_cache[command] = answer
        return answer

    def _run_query(self, query: _Query) -> dict[str, Any]:
        result, reason = self._invoke(query.command)
        if reason:
            return self._unknown(query, reason)

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

    def _collect_configured(self, query: _Query) -> dict[str, Any]:
        primary = self._remaining_query(query)
        if primary["_collection_ok"] or query.source not in _UNAVAILABLE_HINTS:
            return primary
        failures = [primary["_raw"]]
        fallbacks = _fallback_queries(query)
        for fallback in fallbacks:
            result = self._remaining_query(fallback)
            if result["_collection_ok"]:
                return result
            if result["_raw"] not in failures:
                failures.append(result["_raw"])
        if not fallbacks and query.source in {"screen_lock", "screen_lock_delay"}:
            failures.append("Unavailable: invoking user's home could not be resolved safely for an exact plist read.")
        return self._unknown(query, "Unavailable: " + _UNAVAILABLE_HINTS[query.source] + " " + " ".join(failures))

    def _preferences(self, domain: str, key: str, *, machine_observations: bool = False) -> tuple[dict[str, Any] | None, str]:
        command = (sys.executable, _PREFERENCE_HELPER, domain, key)
        result, reason = self._invoke_remaining(command)
        if reason:
            return None, reason
        if result.returncode != 0 or (result.stderr or "").strip():
            return None, "Unavailable: native preference probe failed or reported a diagnostic."
        payload = _preference_payload(result.stdout or "")
        reason = "Unavailable: native preference resolution returned no reliable scalar."
        if payload is not None and payload.get("available") is False:
            known_reasons = {
                "unsupported-query", "unsupported-platform", "ambiguous-user-context",
                "missing-or-unreadable-effective-value", "native-preference-read-unavailable",
            }
            native_reason = payload.get("reason")
            if type(native_reason) is str and native_reason in known_reasons:
                reason += " Probe reason: " + native_reason + "."
            # CopyAppValue describes this user's application search path, not
            # a system daemon's configuration. The helper can still have read
            # exact AnyUser machine domains when that composite value is NULL.
            # Only MAC-005 opts into those separately typed observations. An
            # unavailable probe/context or malformed effective value cannot be
            # reclassified as a successful machine read.
            if (machine_observations and native_reason == "missing-or-unreadable-effective-value"
                    and payload.get("value") is None):
                return payload, reason
            return None, reason
        return payload, reason

    @staticmethod
    def _effective(query: _Query, value: Value, scope: str, configured: dict | None = None) -> dict[str, Any]:
        summary = str(value).lower() if isinstance(value, bool) else str(value)
        if configured is not None:
            explicit = configured.get(query.key) if configured.get("_collection_ok") else None
            explicit_text = str(explicit).lower() if isinstance(explicit, bool) else str(explicit)
            scope += f"; explicit configured value={explicit_text}" if explicit is not None else "; explicit any-host value unavailable"
        return {query.key: value, "_collection_ok": True, "_raw": f"{query.source}.{query.key}={summary}; {scope}", "_scope": scope}

    def _unavailable_effective(self, query: _Query, reason: str) -> dict[str, Any]:
        result = self._unknown(query, "Unavailable: " + _UNAVAILABLE_HINTS[query.source] + " " + reason)
        result["_scope"] = "unavailable effective local state"
        return result

    def _optional_elevated_status(self, query: _Query, normal: dict[str, Any]) -> dict[str, Any] | None:
        """Retry only an opted-in, denied getter after normal sources fail.

        No caller-supplied command or preference probe can reach sudo. -n and
        closed stdin prohibit a password prompt; -k with the getter ignores
        cached credentials and does not update them. No credentials are collected.
        Once an elevated retry fails, that control stays ERROR.
        """
        if not self._allow_elevated_read or query.command not in _ELEVATED_READ_COMMANDS:
            return None
        if normal.get("_collection_ok") or normal.get("_raw") != _PRIVILEGE_REQUIRED:
            return None
        command = (*_ELEVATED_READ_PREFIX, *query.command)
        elevated = self._run_query(_Query(query.source, query.key, command, query.parser))
        if elevated["_collection_ok"]:
            return self._effective(
                query, elevated[query.key],
                "effective system state via explicit sudo -n read of " + " ".join(query.command)
                + "; -k ignores cached credentials and does not cache authentication"
                + "; only this status command is elevated; user preferences retain the invoking user",
            )
        failure = elevated["_raw"]
        if "timed out" in failure:
            detail = "the noninteractive status read timed out after 10 seconds"
        elif "could not be executed" in failure:
            detail = "sudo or the allowlisted status command is unavailable or could not be executed"
        elif "unrecognized or ambiguous" in failure:
            detail = "the elevated command returned unrecognized or ambiguous status output"
        elif "reported a diagnostic" in failure:
            detail = "the elevated command reported a diagnostic; its status is inconclusive"
        else:
            detail = "the noninteractive status read was denied or failed; approved passwordless sudo access may be unavailable or the native read may still require privileges; cached credentials are deliberately ignored"
        return self._unavailable_effective(
            query, "Explicit elevated read failed: " + detail + ". No password was requested and no setting was changed.",
        )

    def _machine_policy(self, query: _Query, domain: str, key: str, payload: dict | None) -> tuple[Value, bool]:
        if not payload or payload.get("managed_available") is not True or payload.get("managed") is not True:
            return None, False
        # A current-user suite value alone cannot establish a daemon's machine
        # policy. Require the matching managed machine key as independent scope.
        policy = _plist_query(query, Path("/Library/Managed Preferences") / (domain + ".plist"), key)
        policy = _Query(policy.source, policy.key, policy.command, _managed_plist_preference, policy.scope)
        observation = self._remaining_query(policy)
        value = _boolean(payload.get("value"))
        configured = observation[query.key] if observation["_collection_ok"] else None
        conflict = value is not None and configured is not None and configured is not value
        return (value if configured is value else None), conflict

    def _invoke_remaining(self, command: tuple[str, ...]) -> tuple[Any, str | None]:
        """Keep malformed byte output unavailable in the four scoped paths."""
        try:
            return self._invoke(command)
        except UnicodeError:
            answer = (None, "Unavailable: native evidence output could not be decoded reliably.")
            self._command_cache[command] = answer
            return answer

    def _remaining_query(self, query: _Query) -> dict[str, Any]:
        # Preload a bounded cached result without changing the shared decoder
        # or MAC-009's behavior. The configured/policy callers are scoped here.
        self._invoke_remaining(query.command)
        return self._run_query(query)

    @staticmethod
    def _status_failure(native: Any) -> str:
        if native.returncode != 0:
            detail = "native status command returned a nonzero exit status"
        elif all(stream is None or (isinstance(stream, str) and not stream.strip())
                 for stream in (native.stdout, native.stderr)):
            detail = "native status command returned no status output"
        else:
            detail = "native status output was unrecognized or ambiguous"
        return "Unavailable: " + detail + "; no state was inferred and raw diagnostics were omitted."

    def _native_status_conflicts(self, command: tuple[str, ...], parser: Callable) -> bool:
        native, reason = self._invoke_remaining(command)
        return not reason and conflicting_status(native.stdout or "", native.stderr or "", native.returncode, parser)

    def _read_status_streams(self, query: _Query, parser: Callable[..., Value]) -> dict[str, Any]:
        """Only the remaining update/time getters use stream-aware decoding."""
        native, reason = self._invoke_remaining(query.command)
        if reason:
            return self._unknown(query, reason)
        value = parser(native.stdout or "", native.stderr or "", native.returncode)
        if value is None:
            return self._unknown(query, self._status_failure(native))
        return self._effective(query, value, "effective native status; exactly one recognized status across output streams")

    def _stream_aware_elevated_status(self, query: _Query, normal: dict[str, Any], parser: Callable[..., Value]) -> dict[str, Any] | None:
        # Preserve the existing opt-in, retry policy and exact sudo allowlist.
        # Reinterpret only an already executed, clean status result; never
        # introduce another retry or change another control's decoder.
        try:
            result = self._optional_elevated_status(query, normal)
        except UnicodeError:
            reason = "Unavailable: opted-in native status output could not be decoded reliably; no value was inferred."
            self._command_cache[(*_ELEVATED_READ_PREFIX, *query.command)] = (None, reason)
            return self._unavailable_effective(query, reason)
        if result is None or result["_collection_ok"]:
            return result
        entry = self._command_cache.get((*_ELEVATED_READ_PREFIX, *query.command))
        if not entry or entry[1] or entry[0] is None:
            return result
        native = entry[0]
        value = parser(native.stdout or "", native.stderr or "", native.returncode)
        if value is None:
            return result
        return self._effective(query, value, "effective system state via explicit sudo -n read of " + " ".join(query.command) + "; -k ignores cached credentials and does not cache authentication; status stream decoded without retaining native logs")

    def _effective_update_check(self, query: _Query) -> dict[str, Any]:
        configured = self._collect_configured(query)
        status_query = _Query(query.source, query.key, ("/usr/sbin/softwareupdate", "--schedule"), _update_schedule)
        status = self._read_status_streams(status_query, software_update_status)
        if self._native_status_conflicts(status_query.command, software_update_status):
            return self._unavailable_effective(query, "Native schedule output contains contradictory known states; preference fallback cannot resolve that conflict.")
        payload, reason = self._preferences("com.apple.SoftwareUpdate", "AutomaticCheckEnabled", machine_observations=True)
        resolved, policy_conflict = self._machine_policy(query, "com.apple.SoftwareUpdate", "AutomaticCheckEnabled", payload)
        if policy_conflict:
            return self._unavailable_effective(query, "Forced native preference and independently read managed machine policy disagree.")
        scope = "effective enforced machine update-check policy verified with CoreFoundation and managed machine preference"
        if resolved is None and payload and payload.get("managed_available") is True and payload.get("managed") is False:
            unreadable = payload.get("unreadable_scopes", [])
            machine = payload.get("machine_current_host")
            selected_scope = "machine_current_host"
            if machine is None and selected_scope not in unreadable:
                machine = payload.get("machine_any_host")
                selected_scope = "machine_any_host"
            machine = None if selected_scope in unreadable else _boolean(machine)
            if machine is not None:
                resolved = machine
                # The native AnyUser domain is a machine setting; a different
                # current-user value does not configure the system daemon.
                # Do not promote this fallback to proof of effective runtime
                # state. Neither an absent key nor an unreadable higher scope
                # can reach here as a Boolean.
                scope = "explicit machine configuration via CoreFoundation " + selected_scope + "; invoking-user application preferences do not determine machine configuration"
        if status["_collection_ok"] and resolved is not None and status[query.key] is not resolved:
            return self._unavailable_effective(query, "Native schedule status and resolved machine configuration disagree.")
        if status["_collection_ok"]:
            return self._effective(query, status[query.key], "effective machine state via softwareupdate --schedule", configured)
        if resolved is not None:
            return self._effective(query, resolved, scope, configured)
        elevated = self._stream_aware_elevated_status(status_query, status, software_update_status)
        if elevated is not None:
            if elevated["_collection_ok"]:
                return self._effective(query, elevated[query.key], elevated["_scope"], configured)
            return elevated
        return self._unavailable_effective(query, status["_raw"] + " " + reason + " No reliable machine update-check scalar was established; other download/install settings do not establish this preference.")

    def _effective_screen_lock(self, query: _Query) -> dict[str, Any]:
        payload, reason = self._preferences(_SCREENSAVER, query.command[-1])
        parser = _numeric_delay if query.source == "screen_lock_delay" else _boolean
        value = None if payload is None else parser(payload.get("value"))
        # Modern native lock state can live outside the old screensaver domain.
        # Its process/console selection is not a public contract: require both
        # to name the same invoking user before this read-only fallback runs.
        native_detail = "Native screen-lock getter skipped: a safe matching invoking/console user context could not be verified; no user switch was performed."
        if current_user_status_context_safe():
            command = ("/usr/sbin/sysadminctl", "-screenLock", "status")
            native, native_reason = self._invoke_remaining(command)
            if self._native_status_conflicts(command, screen_lock_status):
                return self._unavailable_effective(query, "Native screen-lock output contains contradictory known states; preference fallback cannot resolve that conflict.")
            native_state = None if native_reason else screen_lock_status(native.stdout or "", native.stderr or "", native.returncode)
            if native_state is None:
                native_detail = "Native screen-lock getter: " + (native_reason or self._status_failure(native))
            if native_state is not None:
                if not current_user_status_context_safe():
                    return self._unavailable_effective(query, "Invoking/console identity changed during the native screen-lock query; the result was discarded.")
                current = native_state[1] if query.source == "screen_lock_delay" else native_state[0]
                managed = bool(payload and payload.get("managed_available") is True and payload.get("managed") is True)
                if current is not None and managed and value is not None and current != value:
                    return self._unavailable_effective(query, "Native screen-lock status contradicts the enforced managed preference.")
                if current is None:
                    return self._unavailable_effective(query, "Native screen lock is off and supplies no numeric password delay; no zero or sentinel was invented.")
                explicit = None if payload is None else parser(payload.get("explicit_any_host"))
                configured = {query.key: explicit, "_collection_ok": explicit is not None}
                return self._effective(query, current, "effective current-user screen-lock status via sysadminctl; invoking and console identities matched; preference migration does not imply a default", configured)
        if value is None:
            return self._unavailable_effective(query, reason + " " + native_detail)
        # Exact configured values come from the same guarded native helper.
        # Do not invoke user-domain defaults before its identity/home checks.
        explicit = parser(payload.get("explicit_any_host"))
        configured = {query.key: explicit, "_collection_ok": explicit is not None}
        highest = payload.get("explicit_current_host")
        highest_scope = "explicit_current_host"
        unreadable = payload.get("unreadable_scopes", [])
        if highest is None and highest_scope not in unreadable:
            highest = payload.get("explicit_any_host")
            highest_scope = "explicit_any_host"
        managed = payload.get("managed_available") is True and payload.get("managed") is True
        if not managed and highest_scope in unreadable:
            return self._unavailable_effective(query, "A higher-priority configured preference is unreadable; its absence was not assumed.")
        if highest is not None and not managed and (parser(highest) is None or parser(highest) != value):
            return self._unavailable_effective(query, "Resolved and highest-priority configured preferences disagree without a verified managed override.")
        # MAC-011 independently compares a known delay against zero. Password
        # enforcement is MAC-010; do not introduce an extra baseline condition.
        kind = "managed" if managed else "current-user/ByHost resolved"
        return self._effective(query, value, f"invoking user's effective {kind} preference via CoreFoundation; runtime lock/unlock is not exercised", configured)

    def _effective_remote_login(self, query: _Query) -> dict[str, Any]:
        status = self._run_query(query)
        if status["_collection_ok"]:
            return self._effective(query, status[query.key], "effective system state via systemsetup -getremotelogin")
        overrides, override_error = self._invoke(("/bin/launchctl", "print-disabled", "system"))
        service, service_error = self._invoke(("/bin/launchctl", "print", "system/com.openssh.sshd"))
        definition = Path("/System/Library/LaunchDaemons/ssh.plist")
        label = self._run_query(_Query(query.source, query.key, ("/usr/bin/plutil", "-extract", "Label", "xml1", "-o", "-", str(definition)), lambda text: True if _plist_value(text) == "com.openssh.sshd" else None))
        disabled = self._run_query(_plist_query(query, definition, "Disabled"))
        if override_error or service_error or overrides.returncode != 0 or (overrides.stderr or "").strip():
            elevated = self._optional_elevated_status(query, status)
            if elevated is not None:
                return elevated
            return self._unavailable_effective(query, override_error or service_error or status["_raw"])
        value = resolve_remote_login(overrides.stdout or "", service.stdout or "", service.stderr or "", service.returncode,
                                     "com.openssh.sshd" if label["_collection_ok"] else None,
                                     disabled[query.key] if disabled["_collection_ok"] else None)
        if value is None:
            valid_map, enabled_override = parse_override_map(overrides.stdout or "")
            service_state = parse_service(service.stdout or "", service.stderr or "", service.returncode)
            contradictory = valid_map and (
                (enabled_override is False and service_state == "registered")
                or (enabled_override is True and service_state == "absent")
            )
            # A stronger privilege level must not turn conflicting known SSH
            # state into a secure assumption. Retry only an unresolved read.
            if not contradictory:
                elevated = self._optional_elevated_status(query, status)
                if elevated is not None:
                    return elevated
            stages = f" Override map={'valid' if valid_map else 'unknown'}; service={service_state}; definition label={'matched' if label['_collection_ok'] else 'unavailable'}; disabled default={'known' if disabled['_collection_ok'] else 'unavailable'}."
            return self._unavailable_effective(query, status["_raw"] + " Launchd evidence is incomplete, unsupported or contradictory." + stages)
        return self._effective(query, value, "effective launchd service configuration; override map, registration and actual service definition checked")

    def _effective_network_time(self, query: _Query) -> dict[str, Any]:
        status = self._read_status_streams(query, network_time_status)
        automatic_query = _Query(query.source, query.key, ("/usr/sbin/sysadminctl", "-automaticTime", "status"), _network_time)
        automatic = self._read_status_streams(automatic_query, automatic_time_status)
        if (self._native_status_conflicts(query.command, network_time_status)
                or self._native_status_conflicts(automatic_query.command, automatic_time_status)):
            return self._unavailable_effective(query, "Native automatic-time output contains contradictory known states; other getters or preference fallback cannot resolve that conflict.")
        payload, reason = self._preferences("com.apple.timed", "TMAutomaticTimeOnlyEnabled")
        policy, policy_conflict = self._machine_policy(query, "com.apple.timed", "TMAutomaticTimeOnlyEnabled", payload)
        if policy_conflict:
            return self._unavailable_effective(query, "Forced native preference and independently read managed machine policy disagree.")
        if status["_collection_ok"] and automatic["_collection_ok"] and status[query.key] is not automatic[query.key]:
            return self._unavailable_effective(query, "Native systemsetup and sysadminctl automatic-time status disagree.")
        # This key enforces automatic time when true. False/unforced is not a
        # report that automatic time is off, so it cannot become FAIL or PASS.
        if policy is True and any(result["_collection_ok"] and result[query.key] is False for result in (status, automatic)):
            return self._unavailable_effective(query, "Native time status contradicts the enforced machine automatic-time policy.")
        if status["_collection_ok"]:
            return self._effective(query, status[query.key], "effective system state via systemsetup -getusingnetworktime; synchronization success is not verified")
        if automatic["_collection_ok"]:
            return self._effective(query, automatic[query.key], "effective machine automatic-time status via unelevated sysadminctl -automaticTime status; synchronization success is not verified")
        if policy is True:
            return self._effective(query, True, "effective enforced machine automatic-time policy verified with CoreFoundation and managed machine preference; synchronization success is not verified")
        elevated = self._stream_aware_elevated_status(query, status, network_time_status)
        if elevated is not None:
            return elevated
        return self._unavailable_effective(query, status["_raw"] + " " + reason + " Native automatic-time getter: " + automatic["_raw"] + " An unforced or false enforcement preference does not determine automatic-time state.")

    def _collect_query(self, query: _Query) -> dict[str, Any]:
        if query.source == "update_check":
            return self._effective_update_check(query)
        if query.source in {"screen_lock", "screen_lock_delay"}:
            return self._effective_screen_lock(query)
        if query.source == "remote_login":
            return self._effective_remote_login(query)
        if query.source == "network_time":
            return self._effective_network_time(query)
        return self._run_query(query)

    def collect(self) -> dict[str, Any]:
        if not self._native_platform:
            raise MacOSCollectionError("Local macOS collection requires macOS; use --demo for sample evidence.")
        self._command_cache.clear()
        return {
            "target_name": platform.node() or "Unknown (local macOS host)",
            "platform": "macOS",
            "collector": {
                "method": "local / native commands",
                "mode": "local",
                "read_only": True,
                "profile": "macos",
                "scope": "Authorized local Mac; effective current-user preference resolution refers to the invoking user only.",
                "limitations": "Effective configuration is distinguished from explicit stored values; runtime lock and time synchronization success are not verified. "
                + ("Explicit elevated-read opt-in permits sudo -n -k only for denied, otherwise unresolved allowlisted status reads; cached credentials are ignored and not updated; no password prompt. " if self._allow_elevated_read else "Elevated reads are disabled. ")
                + "Unknown or contradictory values are ERROR.",
                "evidence_policy": "Allowlisted status summaries only; no unrestricted command output is retained.",
            },
            "evidence": {query.source: self._collect_query(query) for query in _QUERIES},
        }
