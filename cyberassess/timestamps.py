"""Offset-aware clock metadata; never infer a remote target's timezone."""

from __future__ import annotations

from datetime import datetime, timezone


def aware_datetime(value: object) -> datetime | None:
    """Accept a bounded ISO timestamp only when its UTC offset is explicit."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and len(value) <= 80 and not any(c in value for c in "\r\n\x00"):
        try:
            parsed = datetime.fromisoformat(value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else ""))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    try:
        parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None
    return parsed


def canonical_timestamp(value: str | datetime) -> str:
    parsed = aware_datetime(value)
    if parsed is None:
        raise ValueError("Assessment timestamps must be ISO date/time values with an explicit UTC offset.")
    return parsed.astimezone(timezone.utc).isoformat()


def display_timestamp(value: object, *, utc: bool = False) -> str:
    """Format the recorded instant, never the report viewer's current timezone."""
    parsed = aware_datetime(value)
    if parsed is None:
        return "Not recorded with a timezone"
    if utc:
        parsed = parsed.astimezone(timezone.utc)
    seconds = int(parsed.utcoffset().total_seconds())
    sign = "+" if seconds >= 0 else "-"
    hours, remainder = divmod(abs(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    offset = f"{sign}{hours:02}:{minutes:02}" + (f":{seconds:02}" if seconds else "")
    zone = "UTC" if offset == "+00:00" else "UTC" + offset
    return parsed.strftime("%d %b %Y · %H:%M:%S") + " " + zone


def collection_clock(*, remote: bool = False, target_time: object = None) -> dict:
    """Record completion of fresh reads, with a separately identified target clock.

    A remote clock is an observation, not evidence that the target clock is
    accurate. Missing remote metadata never adopts the operator's timezone.
    """
    now = datetime.now(timezone.utc)
    local = aware_datetime(target_time) if remote else now.astimezone()
    return {
        "collected_at": now.isoformat(),
        "target_local_time": local.isoformat() if local is not None else None,
        "time_source": "Assessment host UTC clock; target clock queried over SSH" if remote else "Local target system clock",
        "time_limitations": (
            "Clock accuracy is not verified."
            if local is not None else
            "Target local time/UTC offset unavailable; assessment host UTC collection time is recorded. Clock accuracy is not verified."
        ),
    }
