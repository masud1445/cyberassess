"""Collect a small Windows baseline locally using read-only PowerShell queries.

Only allowlisted, typed values enter the evidence bundle. Unsupported features,
missing policy values, permissions failures and ambiguous output remain ERRORs;
the collector never changes policy or treats unavailable evidence as compliance.
"""
from __future__ import annotations

import json
import os
import platform
from pathlib import PureWindowsPath
import re
import subprocess
from typing import Any, Callable

from cyberassess.collector import CollectionError


class WindowsCollectionError(CollectionError):
    """The requested local Windows collection cannot start."""


# These are fixed read-only queries. Never interpolate CLI input into commands.
# ConvertTo-Json receives only the explicitly selected fields, not whole objects.
_QUERIES = {
    "defender": r"""
$status = Get-MpComputerStatus
@{ antivirus_enabled = $status.AntivirusEnabled;
   realtime_enabled = $status.RealTimeProtectionEnabled }
""",
    "firewall": r"""
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
@{ profiles = @($profiles | ForEach-Object {
    @{ name = $_.Name; enabled = $_.Enabled.ToString() }
}) }
""",
    "bitlocker": r"""
$volume = @(Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName 'Win32_EncryptableVolume' -Property 'DriveLetter' |
    Where-Object { $_.DriveLetter -eq $env:SystemDrive })
if ($volume.Count -ne 1) { throw 'Ambiguous operating system volume' }
$protection = Invoke-CimMethod -InputObject $volume[0] -MethodName 'GetProtectionStatus'
if ($null -eq $protection.ReturnValue -or $protection.ReturnValue -ne 0) {
    throw 'BitLocker protection status is unavailable'
}
$status = 'Unknown'
if ($null -ne $protection.ProtectionStatus) {
    if ($protection.ProtectionStatus -eq 0) { $status = 'Off' }
    elseif ($protection.ProtectionStatus -eq 1) { $status = 'On' }
}
@{ protection_status = $status }
""",
    "rdp": r"""
@{ deny_connections = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' }
""",
    "rdp_nla": r"""
@{ user_authentication = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' }
""",
    "guest": r"""
$guest = @(Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' })
if ($guest.Count -ne 1) { throw 'Ambiguous local Guest account' }
@{ enabled = $guest[0].Enabled }
""",
    "uac": r"""
@{ enable_lua = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' }
""",
    "smb": r"""
$configuration = Get-SmbServerConfiguration
@{ smb1_enabled = $configuration.EnableSMB1Protocol }
""",
    "inactivity": r"""
@{ timeout_seconds = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' }
""",
    "secure_boot": r"""
@{ enabled = Confirm-SecureBootUEFI }
""",
    "eventlog": r"""
$service = Get-Service -Name 'EventLog'
@{ status = $service.Status.ToString() }
""",
}

_EVIDENCE_KEYS = {
    "defender": ("antivirus_enabled", "realtime_enabled"),
    "firewall": ("all_profiles_enabled",),
    "bitlocker": ("protection_enabled",),
    "rdp": ("disabled",),
    "rdp_nla": ("required",),
    "guest": ("disabled",),
    "uac": ("enabled",),
    "smb": ("smb1_disabled",),
    "inactivity": ("timeout_seconds",),
    "secure_boot": ("enabled",),
    "eventlog": ("running",),
}

_MAX_OUTPUT_BYTES = 32768


def _bool(value: Any) -> bool:
    if type(value) is not bool:
        raise ValueError("A Boolean field is missing or invalid.")
    return value


def _int(value: Any, *, maximum: int = 4294967295) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("An integer field is missing or invalid.")
    return value


def _binary(value: Any) -> bool:
    return _int(value, maximum=1) == 1


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON fields are ambiguous.")
        result[key] = value
    return result


def _parse_json(stdout: bytes | str) -> dict:
    if isinstance(stdout, bytes):
        if len(stdout) > _MAX_OUTPUT_BYTES:
            raise ValueError("Output exceeds the collection limit.")
        text = stdout.decode("utf-8-sig")
    elif isinstance(stdout, str):
        if len(stdout.encode("utf-8")) > _MAX_OUTPUT_BYTES:
            raise ValueError("Output exceeds the collection limit.")
        text = stdout.lstrip("\ufeff")
    else:
        raise ValueError("No JSON output is available.")
    value = json.loads(text, object_pairs_hook=_object_pairs)
    if not isinstance(value, dict):
        raise ValueError("A single JSON object is required.")
    return value


def _normalize(source: str, value: dict) -> tuple[dict, dict]:
    """Return control values plus the safe, minimal fields shown as evidence."""
    if source == "defender":
        data = {key: _bool(value.get(key)) for key in _EVIDENCE_KEYS[source]}
        return data, data
    if source == "firewall":
        profiles = value.get("profiles")
        if not isinstance(profiles, list) or len(profiles) != 3:
            raise ValueError("All three firewall profiles are required.")
        states = {}
        for entry in profiles:
            if not isinstance(entry, dict):
                raise ValueError("Invalid firewall profile.")
            name, enabled = entry.get("name"), entry.get("enabled")
            if name not in ("Domain", "Private", "Public") or name in states:
                raise ValueError("Firewall profile names are ambiguous.")
            if enabled not in ("True", "False"):
                raise ValueError("Firewall profile state is unknown.")
            states[name] = enabled == "True"
        return {"all_profiles_enabled": all(states.values())}, states
    if source == "bitlocker":
        status = value.get("protection_status")
        if status not in ("On", "Off"):
            raise ValueError("BitLocker protection state is unknown.")
        return {"protection_enabled": status == "On"}, {"protection_status": status}
    if source in ("rdp", "rdp_nla", "uac"):
        raw_key = {"rdp": "deny_connections", "rdp_nla": "user_authentication", "uac": "enable_lua"}[source]
        normalized = _binary(value.get(raw_key))
        return {_EVIDENCE_KEYS[source][0]: normalized}, {raw_key: int(normalized)}
    if source in ("guest", "smb"):
        raw_key = "enabled" if source == "guest" else "smb1_enabled"
        enabled = _bool(value.get(raw_key))
        return {_EVIDENCE_KEYS[source][0]: not enabled}, {raw_key: enabled}
    if source == "inactivity":
        data = {"timeout_seconds": _int(value.get("timeout_seconds"))}
        return data, data
    if source == "secure_boot":
        data = {"enabled": _bool(value.get("enabled"))}
        return data, data
    if source == "eventlog":
        status = value.get("status")
        if status not in ("Running", "Stopped", "Paused", "StartPending", "StopPending", "ContinuePending", "PausePending"):
            raise ValueError("Event Log service state is unknown.")
        return {"running": status == "Running"}, {"status": status}
    raise ValueError("Unknown evidence source.")


class WindowsCollector:
    """Run the Windows v1 profile on the current, authorized Windows machine.

    ``runner`` accepts the ``subprocess.run`` interface for mocked validation.
    No remote execution or policy modification is supported.
    """

    def __init__(self, runner: Callable | None = None) -> None:
        self._runner = runner or subprocess.run
        self._injected_runner = runner is not None

    @staticmethod
    def _failure(source: str, reason: str) -> dict:
        return {**{key: None for key in _EVIDENCE_KEYS[source]},
                "_collection_ok": False, "_raw": reason}

    def _collect_source(self, executable: str, source: str, query: str) -> dict:
        # Windows PowerShell 5.1 otherwise uses an OEM code page for redirected
        # output. Force UTF-8 in the process; tolerate only an optional UTF-8 BOM.
        command = (
            "$ErrorActionPreference = 'Stop'; "
            "$ProgressPreference = 'SilentlyContinue'; "
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
            "$OutputEncoding = [Console]::OutputEncoding; "
            "& {\n" + query + "\n} | ConvertTo-Json -Compress -Depth 4"
        )
        try:
            result = self._runner(
                [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=20, check=False,
            )
        except subprocess.TimeoutExpired:
            return self._failure(source, "Read-only query timed out; evidence is unavailable.")
        except (OSError, subprocess.SubprocessError):
            return self._failure(source, "PowerShell could not run; verify Windows PowerShell availability and permissions.")
        if result.returncode != 0:
            return self._failure(source, "Read-only query failed; the feature, policy, or required permissions may be unavailable.")
        try:
            data, safe_raw = _normalize(source, _parse_json(result.stdout))
        except (ValueError, TypeError, UnicodeError):
            return self._failure(source, "Read-only query returned missing, invalid, or ambiguous evidence.")
        return {**data, "_collection_ok": True,
                "_raw": json.dumps(safe_raw, sort_keys=True, ensure_ascii=True)}

    def collect(self) -> dict[str, Any]:
        if not self._injected_runner and platform.system() != "Windows":
            raise WindowsCollectionError("Windows local collection requires a native Windows host; use Windows demo mode elsewhere.")
        # Use the OS-provided executable, rather than a program found on PATH.
        executable = str(PureWindowsPath(os.environ.get("SystemRoot", r"C:\Windows")) /
                         "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
        hostname = platform.node()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", hostname):
            hostname = "Unknown (local Windows host)"
        return {
            "target_name": hostname,
            "platform": "Windows",
            "collector": {
                "method": "local / PowerShell", "mode": "local", "read_only": True,
                "sample_data": False, "profile": "windows", "profile_version": "1",
                "scope": "Current local Windows machine; read-only configuration checks",
                "privileges": "Current process token; unavailable or denied checks remain ERROR",
            },
            "evidence": {source: self._collect_source(executable, source, query)
                         for source, query in _QUERIES.items()},
        }
