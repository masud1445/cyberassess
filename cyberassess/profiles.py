"""Versioned assessment profiles over the existing evaluator.

The Ubuntu definitions remain in their original file.  This adapter adds
descriptive metadata in memory; it does not alter their evaluation semantics.
Legacy CLI calls continue to use the original loading and reporting path.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Any

from cyberassess import __version__
from cyberassess.evaluator import evaluate_baseline


_ROOT = Path(__file__).resolve().parent.parent
_REQUIRED_CONTROL_STRINGS = ("id", "title", "source", "key", "operator", "severity", "nist", "remediation")
_OPERATORS = {"EQUALS", "GREATER_OR_EQUAL", "LESS_OR_EQUAL", "MODE_AT_MOST"}
_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}

_UBUNTU_CATEGORIES = {
    "sshd": "SSH hardening",
    "firewall": "Network",
    "files": "File permissions",
    "accounts": "Accounts",
    "password_policy": "Accounts",
    "auditd": "Logging",
    "updates": "Updates",
    "time_sync": "Time synchronization",
    "services": "Services",
}

_UBUNTU_DESCRIPTIONS = {
    "SSH-001": "Check the effective SSH policy for direct root login.",
    "SSH-002": "Check whether SSH requires key-based authentication.",
    "SSH-003": "Check the configured maximum SSH authentication attempts.",
    "SSH-004": "Check whether SSH X11 forwarding is disabled.",
    "SSH-005": "Check whether SSH has a non-zero client alive interval.",
    "NET-001": "Check the host firewall's reported activation state.",
    "FILE-001": "Compare /etc/shadow permissions with the baseline's allowed permission bits.",
    "FILE-002": "Compare /etc/passwd permissions with the baseline's allowed permission bits.",
    "AUTH-001": "Check for local accounts with an empty password field.",
    "AUTH-002": "Check for non-root accounts that also have UID 0.",
    "AUTH-003": "Check the explicitly configured password quality minimum length.",
    "LOG-001": "Check whether the audit service is active.",
    "UPD-001": "Check whether unattended automatic security updates are enabled.",
    "TIME-001": "Check the reported system time synchronization state.",
    "SVC-001": "Check whether a Telnet server package is installed.",
}


@dataclass(frozen=True)
class Profile:
    """A versioned baseline and its offline demonstration evidence."""

    id: str
    name: str
    version: str
    platform: str
    description: str
    controls_path: Path
    demo_path: Path

    def load_controls(self) -> list[dict]:
        """Validate definitions and add descriptive fields in memory only."""
        try:
            document = json.loads(self.controls_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Profile '{self.id}' control definitions are not valid JSON.") from exc
        controls = document.get("controls") if isinstance(document, dict) else document
        if not isinstance(controls, list) or not all(isinstance(c, dict) for c in controls):
            raise ValueError(f"Profile '{self.id}' must define a list of controls.")

        normalized = []
        seen_ids = set()
        for index, control in enumerate(controls, start=1):
            context = f"Profile '{self.id}' control #{index}"
            for field in _REQUIRED_CONTROL_STRINGS:
                if not isinstance(control.get(field), str) or not control[field].strip():
                    raise ValueError(f"{context}: field '{field}' must be a non-empty string.")
            context += f" ('{control['id']}')"
            if control["id"] in seen_ids:
                raise ValueError(f"{context}: duplicate control ID.")
            if control["operator"] not in _OPERATORS:
                raise ValueError(f"{context}: unsupported operator '{control['operator']}'.")
            if control["severity"] not in _SEVERITIES:
                raise ValueError(f"{context}: severity must be HIGH, MEDIUM or LOW.")
            if "expected" not in control:
                raise ValueError(f"{context}: required field 'expected' is missing.")
            if type(control["expected"]) not in (bool, int, float, str):
                raise ValueError(f"{context}: field 'expected' must be a Boolean, number or string.")

            item = dict(control)
            item.setdefault("profile", self.id)
            item.setdefault("category", _UBUNTU_CATEGORIES.get(item.get("source"), "Other"))
            item.setdefault("description", _UBUNTU_DESCRIPTIONS.get(item.get("id"), item.get("title", "")))
            if item["profile"] != self.id:
                raise ValueError(f"{context}: field 'profile' must match selected profile '{self.id}'.")
            for field in ("category", "description"):
                if not isinstance(item[field], str) or not item[field].strip():
                    raise ValueError(f"{context}: field '{field}' must be a non-empty string.")
            seen_ids.add(item["id"])
            normalized.append(item)
        return normalized

    def load_demo(self) -> dict:
        """Return sample evidence, which is never represented as a live scan."""
        bundle = json.loads(self.demo_path.read_text(encoding="utf-8"))
        if not isinstance(bundle, dict) or not isinstance(bundle.get("evidence"), dict):
            raise ValueError(f"Profile '{self.id}' demo must contain an evidence object.")
        return bundle


_PROFILES = (
    Profile(
        id="ubuntu",
        name="CyberAssess Ubuntu Baseline",
        version="1",
        platform="Ubuntu Linux",
        description="The existing validated 15-control Ubuntu/Linux core baseline.",
        controls_path=_ROOT / "config" / "controls.json",
        demo_path=_ROOT / "samples" / "demo_evidence.json",
    ),
    Profile(
        id="windows",
        name="CyberAssess Windows Baseline",
        version="1",
        platform="Windows",
        description="A read-only Windows security baseline mapped to relevant NIST SP 800-53 controls.",
        controls_path=_ROOT / "config" / "profiles" / "windows.json",
        demo_path=_ROOT / "samples" / "windows_demo_evidence.json",
    ),
    Profile(
        id="macos",
        name="CyberAssess macOS Baseline",
        version="1",
        platform="macOS",
        description="A read-only macOS security baseline mapped to relevant NIST SP 800-53 controls.",
        controls_path=_ROOT / "config" / "profiles" / "macos.json",
        demo_path=_ROOT / "samples" / "macos_demo_evidence.json",
    ),
)


def list_profiles() -> tuple[Profile, ...]:
    """Return available baseline identities in display order."""
    return _PROFILES


def get_profile(profile_id: str) -> Profile:
    """Resolve an explicit profile identity without guessing another baseline."""
    for profile in _PROFILES:
        if profile.id == profile_id:
            return profile
    choices = ", ".join(profile.id for profile in _PROFILES)
    raise ValueError(f"Unknown profile '{profile_id}'. Choose one of: {choices}.")


def _timestamp(value: str | datetime) -> str:
    return value.isoformat() if isinstance(value, datetime) else str(value)


def _infer_mode(bundle: dict) -> str:
    method = str(bundle.get("collector", {}).get("method", "")).lower()
    if "sample" in method or "demo" in method:
        return "demo"
    if "ssh" in method:
        return "ssh"
    if "local" in method:
        return "local"
    return "unknown"


def build_profile_report(
    profile: Profile | str,
    bundle: dict[str, Any],
    *,
    assessment_mode: str | None = None,
    started_at: str | datetime | None = None,
    completed_at: str | datetime | None = None,
) -> dict[str, Any]:
    """Evaluate a selected baseline and add metadata for the new profile flows.

    The unchanged evaluator remains authoritative for status, scoring and result
    values.  Existing CLI invocations bypass this function so their JSON shape
    remains unchanged.  No target OS build or version is inferred here.
    """
    if isinstance(profile, str):
        profile = get_profile(profile)
    evidence = bundle.get("evidence")
    if not isinstance(evidence, dict):
        raise ValueError("An assessment bundle must contain an evidence object.")
    controls = profile.load_controls()
    assessment = evaluate_baseline(controls, evidence)
    for control, result in zip(controls, assessment["results"]):
        result.update(
            profile=profile.id,
            category=control["category"],
            description=control["description"],
            evidence_source=f"{control['source']}.{control['key']}",
        )

    mode = assessment_mode or _infer_mode(bundle)
    report = {
        **bundle,
        "schema_version": "2.0",
        "application": {"name": "CyberAssess", "version": __version__},
        "profile": {
            "id": profile.id,
            "name": profile.name,
            "version": profile.version,
            "platform": profile.platform,
            "description": profile.description,
        },
        "assessment_mode": mode,
        "assessment": assessment,
    }
    if started_at is not None:
        report["assessment_started_at"] = _timestamp(started_at)
    if completed_at is not None:
        report["assessment_completed_at"] = _timestamp(completed_at)

    collected_at = bundle.get("collected_at") or bundle.get("collector", {}).get("collected_at")
    if collected_at is not None:
        report["collected_at"] = _timestamp(collected_at)
    elif completed_at is not None and mode in {"local", "ssh"}:
        report["collected_at"] = _timestamp(completed_at)
    return report
