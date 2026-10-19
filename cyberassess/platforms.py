"""Conservative local platform detection for the supported baselines."""

from __future__ import annotations

from collections.abc import Mapping
import platform


def detect_local_profile(
    *,
    system: str | None = None,
    os_release: Mapping[str, str] | None = None,
) -> str:
    """Return a supported local profile, rejecting unsupported Linux variants.

    ``system`` and ``os_release`` allow platform-independent validation.  A Linux
    kernel alone does not establish compatibility with Ubuntu's command set.
    """
    system = platform.system() if system is None else system
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "macos"
    if system == "Linux":
        if os_release is None:
            try:
                os_release = platform.freedesktop_os_release()
            except OSError as exc:
                raise ValueError("Cannot identify this Linux distribution; the local Linux baseline requires Ubuntu.") from exc
        if str(os_release.get("ID", "")).strip().lower() == "ubuntu":
            return "ubuntu"
        name = os_release.get("PRETTY_NAME") or os_release.get("ID") or "unknown Linux distribution"
        raise ValueError(f"Unsupported local Linux distribution: {name}. The local Linux baseline requires Ubuntu.")
    raise ValueError(f"Unsupported local operating system: {system or 'unknown'}.")
