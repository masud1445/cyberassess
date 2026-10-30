"""Bounded, non-elevated macOS diagnostics without native output dumps.

This is a troubleshooting companion, not an assessment or remediation mode.
It reads only the three selected collector sources and summarizes their cached
observations. No extra native command, password prompt or elevation is added.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import platform
import sys
from typing import Any


# Direct execution resolves the reviewed checkout, independent of cwd/PYTHONPATH.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyberassess.collectors import macos
from cyberassess.collectors._macos_status import (
    automatic_time_status, network_time_status, screen_lock_status,
)


_SOURCES = {
    "screen_lock": ("password_required", macos._boolean),
    "screen_lock_delay": ("seconds", macos._numeric_delay),
    "network_time": ("enabled", macos._boolean),
}
_NATIVE = {
    "screen_lock": (("/usr/sbin/sysadminctl", "-screenLock", "status"), screen_lock_status),
    "system_network_time": (("/usr/sbin/systemsetup", "-getusingnetworktime"), network_time_status),
    "automatic_time": (("/usr/sbin/sysadminctl", "-automaticTime", "status"), automatic_time_status),
}
_PREFERENCES = {
    "screen_lock": ("com.apple.screensaver", "askForPassword", macos._boolean),
    "screen_lock_delay": ("com.apple.screensaver", "askForPasswordDelay", macos._numeric_delay),
    "network_time_enforcement": ("com.apple.timed", "TMAutomaticTimeOnlyEnabled", macos._boolean),
}
_SCOPES = ("explicit_current_host", "explicit_any_host", "machine_current_host", "machine_any_host")
_PREFERENCE_REASONS = {
    "effective-preference-value", "unsupported-query", "unsupported-platform",
    "ambiguous-user-context", "missing-or-unreadable-effective-value",
    "native-preference-read-unavailable",
}


def _fingerprints() -> dict[str, str | None]:
    values = {}
    for name in ("macos.py", "_macos_status.py", "_macos_preferences.py"):
        try:
            values[name] = hashlib.sha256(Path(getattr(macos, "__file__", None)).with_name(name).read_bytes()).hexdigest()
        except (OSError, TypeError, ValueError):
            values[name] = None
    return values


def _failure_reason(native: Any, reason: str | None) -> str:
    # Only fixed classifications leave the process, never exceptions/diagnostics.
    if reason == macos._PRIVILEGE_REQUIRED:
        return "permission-denied"
    if reason == "Unavailable: read-only command timed out after 10 seconds.":
        return "timeout"
    if reason == "Unavailable: native command could not be executed.":
        return "command-unavailable"
    if reason == "Unavailable: native evidence output could not be decoded reliably.":
        return "undecodable-output"
    if reason or native is None:
        return "unavailable"
    if type(native.returncode) is not int or native.returncode != 0:
        return "nonzero-exit"
    if all(stream is None or (isinstance(stream, str) and not stream.strip())
           for stream in (native.stdout, native.stderr)):
        return "empty-output"
    return "unrecognized-output"


def _native_snapshot(command: tuple[str, ...], parser, cache: dict) -> dict:
    result = {
        "getter": " ".join(command), "status": "not-run", "exit_status": None,
        "stdout_present": None, "stderr_present": None, "state": None, "reason": "not-run",
    }
    entry = cache.get(command)
    if entry is None:
        return result
    native, reason = entry
    result["status"] = "unavailable"
    result["reason"] = _failure_reason(native, reason)
    if native is None:
        return result
    result["exit_status"] = native.returncode if type(native.returncode) is int else None
    for stream in ("stdout", "stderr"):
        value = getattr(native, stream)
        result[stream + "_present"] = bool(value) if isinstance(value, str) else None
    if reason:
        return result
    state = parser(native.stdout or "", native.stderr or "", native.returncode)
    if state is not None:
        result.update(status="known", reason="recognized")
        result["state"] = {"password_required": state[0], "seconds": state[1]} if parser is screen_lock_status else state
    return result


def _preference_snapshot(domain: str, key: str, parser, cache: dict) -> dict:
    result = {
        "status": "not-run", "available": False, "value": None,
        "managed": None, "managed_available": False,
        **{field: None for field in _SCOPES}, "unreadable_scopes": [], "reason": "not-run",
    }
    if domain == "com.apple.timed":
        result["interpretation"] = "enforcement-only-not-automatic-time-status"
    entry = cache.get((sys.executable, macos._PREFERENCE_HELPER, domain, key))
    if entry is None:
        return result
    native, reason = entry
    result.update(status="unavailable", reason=_failure_reason(native, reason))
    if native is None or reason or type(native.returncode) is not int or native.returncode != 0:
        return result
    if not isinstance(native.stderr, str) or native.stderr.strip():
        result["reason"] = "diagnostic-output"
        return result
    payload = macos._preference_payload(native.stdout) if isinstance(native.stdout, str) else None
    if (payload is None or type(payload.get("reason")) is not str
            or payload["reason"] not in _PREFERENCE_REASONS
            or (payload["available"] and payload["reason"] != "effective-preference-value")
            or (payload["available"] and parser(payload.get("value")) is None)
            or (not payload["available"] and payload.get("value") is not None)):
        result["reason"] = "invalid-payload"
        return result
    if not payload["available"] and payload["reason"] != "missing-or-unreadable-effective-value":
        # Failed identity/native probes cannot establish even configured values.
        result["reason"] = payload["reason"]
        return result
    result.update(
        status="known" if payload["available"] else "unavailable",
        available=payload["available"], value=parser(payload.get("value")),
        managed=payload["managed"] if payload["managed_available"] else None,
        managed_available=payload["managed_available"], reason=payload["reason"],
        unreadable_scopes=list(payload.get("unreadable_scopes", [])),
    )
    for field in _SCOPES:
        result[field] = parser(payload.get(field))
    return result


def _document(available: bool, reason: str) -> dict:
    return {
        "format": "cyberassess-macos-diagnostics-v1", "available": available,
        "reason": reason, "read_only": True, "elevated_reads": False,
        "console_context_safe_at_start": False, "source_fingerprints": _fingerprints(),
        "selected_evidence": {
            source: {"available": False, "value": None, "summary": "Unavailable: diagnostic collection was not run."}
            for source in _SOURCES
        },
        "native_probes": {name: _native_snapshot(command, parser, {}) for name, (command, parser) in _NATIVE.items()},
        "preferences": {
            name: _preference_snapshot(domain, key, parser, {})
            for name, (domain, key, parser) in _PREFERENCES.items()
        },
    }


def diagnose(runner: macos.Runner | None = None) -> dict:
    """Read selected sources, or inject native responses for offline tests."""
    if runner is None and platform.system() != "Darwin":
        return _document(False, "unsupported-platform")
    document = _document(True, "completed")
    document["console_context_safe_at_start"] = bool(macos.current_user_status_context_safe())
    collector = macos.MacOSCollector(runner=runner, allow_elevated_read=False)
    for query in macos._QUERIES:
        if query.source not in _SOURCES:
            continue
        selected = document["selected_evidence"][query.source]
        try:
            evidence = collector._collect_query(query)
        except (OSError, ValueError, TypeError, AttributeError):
            selected["summary"] = "Unavailable: diagnostic collection could not be completed reliably."
            continue
        key, parser = _SOURCES[query.source]
        value = parser(evidence.get(key))
        selected["available"] = evidence.get("_collection_ok") is True and value is not None
        selected["value"] = value if selected["available"] else None
        summary = evidence.get("_raw")
        selected["summary"] = summary if isinstance(summary, str) and len(summary) <= 4096 else "Unavailable: sanitized collection summary is unavailable."
    cache = collector._command_cache
    document["native_probes"] = {
        name: _native_snapshot(command, parser, cache)
        for name, (command, parser) in _NATIVE.items()
    }
    document["preferences"] = {
        name: _preference_snapshot(domain, key, parser, cache)
        for name, (domain, key, parser) in _PREFERENCES.items()
    }
    return document


def main(arguments: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    document = _document(False, "invalid-arguments") if arguments else diagnose()
    print(json.dumps(document, allow_nan=False, sort_keys=True, indent=2))
    return 0 if document["available"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
