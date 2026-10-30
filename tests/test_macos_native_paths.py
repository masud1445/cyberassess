"""Native macOS command paths must not inherit the development host's syntax."""

from pathlib import PurePosixPath, PureWindowsPath
import plistlib
import subprocess

import pytest

from cyberassess.collectors import macos


@pytest.fixture(params=[PurePosixPath, PureWindowsPath], ids=["posix-host", "windows-host"])
def host_paths(request, monkeypatch):
    # Patch only the collector's host-path constructor. Real fixture paths and
    # the preference helper's local executable path keep their actual syntax.
    monkeypatch.setattr(macos, "Path", request.param)


def query_for(source):
    return next(query for query in macos._QUERIES if query.source == source)


def xml(value):
    return plistlib.dumps(value, fmt=plistlib.FMT_XML).decode("utf-8")


class NativeCommands:
    """Return only explicitly supplied evidence; never execute a command."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, command, **options):
        command = tuple(command)
        self.calls.append(command)
        assert options["shell"] is False
        assert options["stdin"] == subprocess.DEVNULL
        assert options["timeout"] == 10
        response = self.responses.get(command, (127, "", ""))
        code, stdout, stderr = response if isinstance(response, tuple) else (0, response, "")
        return subprocess.CompletedProcess(command, code, stdout, stderr)


def test_software_update_plist_fallback_uses_a_posix_native_path(host_paths):
    fallback, = macos._fallback_queries(query_for("update_check"))
    assert fallback.command == (
        "/usr/bin/plutil", "-extract", "AutomaticCheckEnabled", "xml1", "-o", "-",
        "/Library/Preferences/com.apple.SoftwareUpdate.plist",
    )


def test_managed_machine_policy_requires_the_exact_posix_native_path(host_paths):
    command = (
        "/usr/bin/plutil", "-extract", "AutomaticCheckEnabled", "xml1", "-o", "-",
        "/Library/Managed Preferences/com.apple.SoftwareUpdate.plist",
    )
    runner = NativeCommands({command: xml(True)})
    collector = macos.MacOSCollector(runner=runner)
    payload = {"managed_available": True, "managed": True, "value": True}
    value, conflict = collector._machine_policy(
        query_for("update_check"), "com.apple.SoftwareUpdate", "AutomaticCheckEnabled", payload,
    )
    assert value is True
    assert conflict is False
    assert runner.calls == [command]


def test_absent_ssh_service_requires_its_posix_native_definition(host_paths):
    definition = "/System/Library/LaunchDaemons/ssh.plist"
    label = ("/usr/bin/plutil", "-extract", "Label", "xml1", "-o", "-", definition)
    disabled = ("/usr/bin/plutil", "-extract", "Disabled", "xml1", "-o", "-", definition)
    runner = NativeCommands({
        ("/usr/sbin/systemsetup", "-getremotelogin"): (1, "", "Permission denied"),
        ("/bin/launchctl", "print-disabled", "system"): "disabled services = {\n}",
        ("/bin/launchctl", "print", "system/com.openssh.sshd"): (
            113, "", 'Could not find service "com.openssh.sshd" in domain for system',
        ),
        label: xml("com.openssh.sshd"),
        disabled: xml(True),
    })
    result = macos.MacOSCollector(runner=runner)._effective_remote_login(query_for("remote_login"))
    assert result["_collection_ok"] is True
    assert result["enabled"] is False
    assert label in runner.calls
    assert disabled in runner.calls
    assert not any(command[0] == "/usr/bin/sudo" for command in runner.calls)
