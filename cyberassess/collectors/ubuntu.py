"""Local execution adapter for the existing validated Ubuntu collector."""

from __future__ import annotations

import getpass
import socket
import subprocess
from typing import Any

from cyberassess.collector import SSHCollector
from cyberassess.timestamps import collection_clock


class _LocalSession:
    """Provide the lifecycle expected by SSHCollector without opening SSH."""

    @staticmethod
    def close() -> None:
        return None


class UbuntuLocalCollector(SSHCollector):
    """Run the original Ubuntu read-only command set on the local machine.

    Collection and normalization are inherited unchanged from SSHCollector.
    Its static commands already use ``sudo -n`` where elevated read access is
    needed; this adapter never prompts for a password or changes sudo policy.
    The caller must first establish that the local platform is Ubuntu.
    """

    def __init__(self, *, timeout: float = 20) -> None:
        if timeout <= 0:
            raise ValueError("Command timeout must be greater than zero.")
        self.timeout = timeout
        super().__init__(host=socket.gethostname(), username=getpass.getuser(), key_file="")

    def _connect(self) -> _LocalSession:
        return _LocalSession()

    def _run(self, client: _LocalSession, command: str) -> dict[str, Any]:
        # Only the existing collector's fixed commands reach this adapter.
        # An argv invocation avoids any extra shell interpolation by Python.
        try:
            result = subprocess.run(
                ["/bin/sh", "-c", command],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return {"exit_code": 124, "stdout": "", "stderr": f"Read-only command timed out after {self.timeout:g} seconds."}
        except OSError as exc:
            return {"exit_code": 127, "stdout": "", "stderr": f"Read-only command could not be started: {exc}"}
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        }

    def collect(self) -> dict[str, Any]:
        bundle = super().collect()
        bundle["collector"] = {
            **collection_clock(),
            "method": "Local / subprocess",
            "host": self.host,
            "username": self.username,
            "read_only": True,
        }
        bundle["collected_at"] = bundle["collector"]["collected_at"]
        return bundle
