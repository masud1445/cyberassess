from __future__ import annotations

from typing import Any


SEVERITY_WEIGHTS = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def _norm(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value).strip().lower()


def _mode_at_most(actual: Any, expected: Any) -> bool:
    try:
        a = int(str(actual), 8)
        e = int(str(expected), 8)
    except (TypeError, ValueError):
        raise ValueError("File mode comparison requires octal values.")
    return (a & ~e) == 0


def evaluate_control(control: dict, evidence: dict) -> dict:
    source_name = control["source"]
    key = control["key"]
    source = evidence.get(source_name)

    if not isinstance(source, dict):
        return _result(control, "ERROR", None, "Evidence source is unavailable.")

    if source.get("_collection_ok") is False:
        return _result(
            control,
            "ERROR",
            None,
            f"Collection failed for source '{source_name}'.",
            source.get("_raw"),
        )

    if key not in source:
        return _result(control, "ERROR", None, f"Evidence key '{key}' is unavailable.", source.get("_raw"))

    actual = source.get(key)

    if actual is None:
        if source.get("configured") is False:
            return _result(
                control,
                "FAIL",
                "Not configured",
                "Required security configuration is not explicitly configured.",
                source.get("_raw"),
            )
        return _result(control, "ERROR", "Unknown", "Evidence value could not be determined.", source.get("_raw"))

    op = control["operator"]
    expected = control["expected"]

    try:
        if op == "EQUALS":
            passed = _norm(actual) == _norm(expected)
        elif op == "GREATER_OR_EQUAL":
            passed = float(actual) >= float(expected)
        elif op == "LESS_OR_EQUAL":
            passed = float(actual) <= float(expected)
        elif op == "MODE_AT_MOST":
            passed = _mode_at_most(actual, expected)
        else:
            return _result(control, "ERROR", actual, f"Unsupported operator: {op}", source.get("_raw"))
    except (TypeError, ValueError) as exc:
        return _result(control, "ERROR", actual, str(exc), source.get("_raw"))

    return _result(control, "PASS" if passed else "FAIL", actual, None, source.get("_raw"))


def _result(control: dict, status: str, actual: Any, notes: str | None, raw: str | None = None) -> dict:
    return {
        "control_id": control["id"],
        "title": control["title"],
        "severity": control["severity"],
        "status": status,
        "expected": control["expected"],
        "actual": actual,
        "nist": control["nist"],
        "remediation": control["remediation"],
        "notes": notes,
        "raw_evidence": raw,
    }


def evaluate_baseline(controls: list[dict], evidence: dict) -> dict:
    results = [evaluate_control(control, evidence) for control in controls]

    passed = sum(r["status"] == "PASS" for r in results)
    failed = sum(r["status"] == "FAIL" for r in results)
    errors = sum(r["status"] == "ERROR" for r in results)

    weighted_total = 0
    weighted_passed = 0
    for control, result in zip(controls, results):
        weight = SEVERITY_WEIGHTS.get(control["severity"].upper(), 1)
        weighted_total += weight

        if result["status"] == "PASS":
            weighted_passed += weight

    score = round((weighted_passed / weighted_total) * 100, 1) if weighted_total else 0.0

    return {
        "total_controls": len(results),
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "compliance_score": score,
        "results": results,
    }
