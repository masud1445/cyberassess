"""Conservative, pure resolution of native macOS SSH launchd evidence.

``launchctl print`` is a diagnostic format, not a stable API. Only the known
complete service shape below is accepted; new formats must remain unknown.
Nothing here executes a command, selects a user, or retains a service dump.
"""

from __future__ import annotations

import re


_LABEL = "com.openssh.sshd"
_SERVICE_HEADER = "system/com.openssh.sshd = {"
_SERVICE_PATH = "/System/Library/LaunchDaemons/ssh.plist"
_ABSENT = 'Could not find service "com.openssh.sshd" in domain for system'
_STATES = {"running", "waiting", "not running"}


def parse_override_map(text: str) -> tuple[bool, bool | None]:
    """Return map validity and an explicit override's Remote Login value.

    A valid map without an SSH entry returns ``(True, None)``. That absence
    does not mean either enabled or disabled.
    """
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    if len(lines) < 2 or lines[0] != "disabled services = {" or lines[-1] != "}":
        return False, None
    labels = set()
    remote_enabled = None
    for line in lines[1:-1]:
        entry = re.fullmatch(r'"([^"\r\n]+)"\s*=>\s*(enabled|disabled|true|false)', line)
        if entry is None or entry[1] in labels:
            return False, None
        labels.add(entry[1])
        if entry[1] == _LABEL:
            remote_enabled = {"enabled": True, "false": True, "disabled": False, "true": False}[entry[2]]
    return True, remote_enabled


def _brace_delta(line: str) -> tuple[int, int] | None:
    """Count diagnostic block delimiters without counting quoted values."""
    depth = 0
    minimum = 0
    quoted = False
    escaped = False
    for character in line:
        if escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif not quoted and character == "{":
            depth += 1
        elif not quoted and character == "}":
            depth -= 1
            minimum = min(minimum, depth)
    return None if quoted else (depth, minimum)


def parse_service(stdout: str, stderr: str, returncode: int) -> str:
    """Return ``registered``, recognized ``absent``, or ``unknown``.

    A registered socket-activated service may be ``not running`` while still
    enabled. Conversely, an unsuccessful print command is not automatically
    evidence that SSH is disabled.
    """
    if returncode != 0:
        errors = tuple(line.strip() for line in (stdout + "\n" + stderr).splitlines() if line.strip())
        if returncode > 0 and errors in {(_ABSENT,), ("Bad request.", _ABSENT)}:
            return "absent"
        return "unknown"
    if stderr.strip():
        return "unknown"
    lines = [line.strip() for line in stdout.strip().splitlines() if line.strip()]
    if len(lines) < 5 or lines[0] != _SERVICE_HEADER:
        return "unknown"
    diagnostics = (
        "permission denied", "operation not permitted", "not authorized",
        "could not find service", "bad request", "warning:", "error:",
    )
    if any(marker in stdout.lower() for marker in diagnostics):
        return "unknown"
    required = {}
    depth = 1
    for number, line in enumerate(lines[1:], start=1):
        if depth == 1 and line != "}":
            field = re.fullmatch(r"([A-Za-z0-9_ .()/:-]+?)\s*=\s*(.+)", line)
            if field is None:
                return "unknown"
            name, value = field[1].strip(), field[2].strip()
            if name in {"path", "type", "state"}:
                if name in required:
                    return "unknown"
                required[name] = value
        balance = _brace_delta(line)
        if balance is None:
            return "unknown"
        delta, minimum = balance
        if depth + minimum <= 0 and (line != "}" or number != len(lines) - 1):
            return "unknown"
        depth += delta
        if depth < 0 or (depth == 0 and (line != "}" or number != len(lines) - 1)):
            return "unknown"
    if depth != 0:
        return "unknown"
    if required.get("path") != _SERVICE_PATH or required.get("type") != "LaunchDaemon":
        return "unknown"
    if required.get("state") not in _STATES:
        return "unknown"
    return "registered"


def resolve_remote_login(
    override_map_text: str,
    service_stdout: str,
    service_stderr: str,
    service_returncode: int,
    definition_label: str | None,
    definition_disabled: bool | None,
) -> bool | None:
    """Resolve effective SSH availability from independent native evidence.

    The service definition's Disabled key is a load default, not a runtime
    result. An explicit override takes precedence. Without an override, an
    explicit disabled default can establish Off only with recognized service
    absence; a registered service establishes On even if its default was Off.
    """
    valid_map, enabled_override = parse_override_map(override_map_text)
    if not valid_map:
        return None
    service = parse_service(service_stdout, service_stderr, service_returncode)
    if service == "registered":
        return None if enabled_override is False else True
    if service != "absent" or enabled_override is True:
        return None
    if enabled_override is False:
        return False
    if definition_label == _LABEL and definition_disabled is True:
        return False
    return None
