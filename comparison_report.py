import json
import html
import math
from pathlib import Path

from cyberassess.evaluator import SEVERITY_WEIGHTS
from cyberassess.timestamps import aware_datetime, display_timestamp


BEFORE_FILE = Path("reports/BEFORE_54.3.json")
AFTER_FILE = Path("reports/AFTER_100.json")
OUTPUT_FILE = Path("reports/COMPARISON_54.3_TO_100.html")


def esc(value):
    if value is None:
        return "—"
    return html.escape(str(value))


def load_report(path):
    return json.loads(path.read_text(encoding="utf-8"))


def result_map(report):
    assessment = report.get("assessment")
    if not isinstance(assessment, dict):
        raise ValueError("Comparison requires an assessment object in each snapshot.")
    results = assessment.get("results", [])
    if not isinstance(results, list) or not results:
        raise ValueError("Comparison requires recorded control results in both snapshots.")
    mapped = {}
    for item in results:
        if not isinstance(item, dict) or not isinstance(item.get("control_id"), str) or not item["control_id"].strip():
            raise ValueError("Comparison requires an unambiguous control identifier for every result.")
        if item["control_id"] in mapped:
            raise ValueError("Duplicate control identifiers make the snapshot ambiguous.")
        if not isinstance(item.get("status"), str) or item["status"] not in {"PASS", "FAIL", "ERROR"}:
            raise ValueError("Comparison supports only recorded PASS, FAIL and ERROR results.")
        mapped[item["control_id"]] = item
    return mapped


def recorded(value):
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if value.lower() in {"unknown", "unknown target", "unknown platform", "not recorded", "not available"} or value.lower().startswith("unknown (local "):
        return None
    return value


def snapshot_mode(report):
    collector = report.get("collector") if isinstance(report.get("collector"), dict) else {}
    method = str(collector.get("method", "")).lower()
    modes = {value.lower() for value in (report.get("assessment_mode"), collector.get("mode"))
             if isinstance(value, str) and value.lower() in {"demo", "local", "ssh"}}
    if collector.get("sample_data") is True or "sample" in method or "demo" in method:
        modes.add("demo")
    elif method.startswith("ssh / "):
        modes.add("ssh")
    elif method.startswith("local / "):
        modes.add("local")
    if "demo" in modes:
        return "demo"
    return next(iter(modes)) if len(modes) == 1 else "unknown"


def profile_value(report, key):
    profile = report.get("profile")
    value = profile.get(key) if isinstance(profile, dict) else None
    return recorded(str(value)) if type(value) is int else recorded(value)


def validate_comparison(before, after):
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("Comparison inputs must be assessment objects.")
    notes = []
    for key in ("target_name", "platform"):
        values = [recorded(report.get(key)) for report in (before, after)]
        if all(values) and values[0].casefold() != values[1].casefold():
            raise ValueError(f"Snapshots have different recorded {key} values.")
        if not all(values):
            notes.append(f"{key} is not recorded in one or both snapshots; identity equivalence is unverified.")
    for key in ("id", "version"):
        values = [profile_value(report, key) for report in (before, after)]
        if all(values) and values[0].casefold() != values[1].casefold():
            raise ValueError(f"Snapshots have different recorded profile {key} values.")
        if not all(values):
            notes.append(f"Profile {key} is not recorded in one or both snapshots; it was not inferred.")
    modes = [snapshot_mode(report) for report in (before, after)]
    if "demo" in modes and any(mode in {"local", "ssh"} for mode in modes):
        raise ValueError("Demonstration and live snapshots cannot be compared as the same assessment source.")
    if "unknown" in modes:
        notes.append("Collection source is not recorded consistently in one or both snapshots.")
    mappings = [result_map(report) for report in (before, after)]
    if mappings[0].keys() != mappings[1].keys():
        raise ValueError("Snapshots use different control sets.")
    for control_id, first in mappings[0].items():
        second = mappings[1][control_id]
        for key in ("expected", "severity"):
            if key in first and key in second and (type(first[key]) is not type(second[key]) or first[key] != second[key]):
                raise ValueError("Snapshots have different recorded control conditions or scoring weights.")
    for label, report, results in zip(("Before", "After"), (before, after), mappings):
        assessment = report["assessment"]
        counts = {"passed": "PASS", "failed": "FAIL", "errors": "ERROR"}
        for key, status in counts.items():
            value = assessment.get(key)
            if type(value) is not int or value != sum(item["status"] == status for item in results.values()):
                raise ValueError("Snapshot counts disagree with the recorded control results.")
        if type(assessment.get("total_controls")) is not int or assessment["total_controls"] != len(results):
            raise ValueError("Snapshot control total disagrees with its results.")
        score = assessment.get("compliance_score")
        try:
            valid_score = type(score) in (int, float) and math.isfinite(float(score)) and 0 <= float(score) <= 100
        except (TypeError, ValueError, OverflowError):
            valid_score = False
        if not valid_score:
            raise ValueError("Snapshot score must be a finite percentage from 0 through 100.")
        weights = [SEVERITY_WEIGHTS.get(item["severity"].upper())
                   if isinstance(item.get("severity"), str) else None for item in results.values()]
        if any(weight is None for weight in weights):
            notes.append(f"{label} snapshot score basis is unverified: severity weights are absent or unsupported.")
        else:
            total_weight = sum(weights)
            passed_weight = sum(weight for item, weight in zip(results.values(), weights) if item["status"] == "PASS")
            expected_score = round((passed_weight / total_weight) * 100, 1) if total_weight else 0.0
            if score != expected_score:
                raise ValueError("Snapshot score disagrees with its recorded results and severity weights.")
    return mappings, notes


def snapshot_time(report):
    collector = report.get("collector") if isinstance(report.get("collector"), dict) else {}
    for label, value in (("Collection", report.get("collected_at") or collector.get("collected_at")),
                         ("Assessment completed", report.get("assessment_completed_at") or collector.get("assessment_completed_at"))):
        if aware_datetime(value) is not None:
            return label + ": " + display_timestamp(value, utc=True)
    return "Not recorded with a timezone"


before = load_report(BEFORE_FILE)
after = load_report(AFTER_FILE)
(before_results, after_results), comparison_notes = validate_comparison(before, after)

before_assessment = before["assessment"]
after_assessment = after["assessment"]

before_score = float(before_assessment["compliance_score"])
after_score = float(after_assessment["compliance_score"])
improvement = round(after_score - before_score, 1)

fixed_controls = []

for control_id, old_result in before_results.items():
    new_result = after_results.get(control_id)

    if (
        new_result
        and old_result.get("status") != "PASS"
        and new_result.get("status") == "PASS"
    ):
        fixed_controls.append({
            "control_id": control_id,
            "title": new_result.get("title", ""),
            "severity": old_result.get("severity", ""),
            "before_status": old_result.get("status", ""),
            "after_status": new_result.get("status", ""),
            "before_actual": old_result.get("actual"),
            "after_actual": new_result.get("actual"),
            "nist": new_result.get("nist", ""),
        })


severity_order = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
}

fixed_controls.sort(
    key=lambda item: (
        severity_order.get(str(item["severity"]).upper(), 99),
        item["control_id"],
    )
)


def status_badge(status):
    status = str(status).upper()

    css_class = {
        "PASS": "pass",
        "FAIL": "fail",
        "ERROR": "error",
    }.get(status, "neutral")

    return (
        f'<span class="badge {css_class}">'
        f'{esc(status)}'
        f'</span>'
    )


def severity_badge(severity):
    severity = str(severity).upper()

    css_class = {
        "HIGH": "sev-high",
        "MEDIUM": "sev-medium",
        "LOW": "sev-low",
    }.get(severity, "neutral")

    return (
        f'<span class="badge {css_class}">'
        f'{esc(severity)}'
        f'</span>'
    )


fixed_rows = []

for item in fixed_controls:
    fixed_rows.append(
        f"""
        <tr>
            <td>
                <strong>{esc(item["control_id"])}</strong>
                <div class="control-title">{esc(item["title"])}</div>
            </td>
            <td>{severity_badge(item["severity"])}</td>
            <td>
                {status_badge(item["before_status"])}
                <div class="actual">{esc(item["before_actual"])}</div>
            </td>
            <td>
                {status_badge(item["after_status"])}
                <div class="actual">{esc(item["after_actual"])}</div>
            </td>
            <td>{esc(item["nist"])}</td>
        </tr>
        """
    )

fixed_rows_html = "\n".join(fixed_rows)
if not fixed_rows_html:
    fixed_rows_html = '<tr><td colspan="5">No recorded FAIL or ERROR results changed to PASS.</td></tr>'

fail_to_pass = sum(item["before_status"] == "FAIL" for item in fixed_controls)
error_to_pass = sum(item["before_status"] == "ERROR" for item in fixed_controls)

target_name = recorded(after.get("target_name")) or "Not recorded"
platform = recorded(after.get("platform")) or "Not recorded"
mode_labels = {"demo": "Demonstration", "local": "Live local", "ssh": "Live SSH", "unknown": "Not recorded"}
source_summary = " / ".join(mode_labels[snapshot_mode(report)] for report in (before, after))
profile_summary = " / ".join(
    f"{profile_value(report, 'id') or 'Not recorded'} (version {profile_value(report, 'version') or 'not recorded'})"
    for report in (before, after)
)
comparison_limitations = " ".join(comparison_notes) or "Recorded identity, profile and control-set checks agree."
demonstration_note = "Demonstration snapshot comparison; illustrative results, not live validation." if any(snapshot_mode(report) == "demo" for report in (before, after)) else "Source labels reflect recorded metadata; authorization is not verified by this comparison."


html_output = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>CyberAssess — Before / After Comparison</title>

<style>
:root {{
    --navy: #0b1f4b;
    --blue: #2f6fed;
    --green: #0f7a55;
    --red: #b3261e;
    --amber: #a86a00;
    --page: #f6f7fa;
    --card: #ffffff;
    --text: #172033;
    --muted: #667085;
    --border: #dde3ec;
}}

* {{
    box-sizing: border-box;
}}

html {{
    background: var(--page);
}}

body {{
    margin: 0;
    background: var(--page);
    color: var(--text);
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Arial,
        sans-serif;
    line-height: 1.38;
}}

.page {{
    width: min(1120px, calc(100% - 32px));
    margin: 24px auto;
}}

.header {{
    background: var(--navy);
    color: white;
    border-radius: 18px;
    padding: 26px 30px;
    margin-bottom: 14px;
}}

.header h1 {{
    font-family: Georgia, serif;
    margin: 0 0 8px;
    font-size: 32px;
    letter-spacing: -0.5px;
}}

.header p {{
    margin: 4px 0;
    color: #dbe6ff;
}}

.summary-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 12px;
    margin-bottom: 14px;
}}

.card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px;
    break-inside: avoid;
}}

.score-label {{
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 700;
}}

.score {{
    font-family: Georgia, serif;
    font-size: 38px;
    margin-top: 6px;
    font-weight: 700;
    line-height: 1.1;
}}

.before-score {{
    color: var(--red);
}}

.after-score {{
    color: var(--green);
}}

.improvement {{
    color: var(--blue);
}}

.section-title {{
    font-family: Georgia, serif;
    color: var(--navy);
    font-size: 22px;
    margin: 18px 0 8px;
}}

.metrics {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
    margin-top: 12px;
}}

.metric {{
    background: #f8fafc;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 8px;
    text-align: left;
}}

.metric strong {{
    display: block;
    font-size: 20px;
    color: var(--navy);
    line-height: 1.1;
    margin-bottom: 3px;
}}

.improvement-text {{
    margin: 8px 0 0;
}}

.improvement-detail {{
    margin: 10px 0 0;
    font-size: 14px;
}}

.progress {{
    height: 12px;
    background: #e9edf4;
    border-radius: 999px;
    overflow: hidden;
    margin-top: 9px;
}}

.progress-before {{
    height: 100%;
    width: {before_score}%;
    background: var(--red);
}}

.progress-after {{
    height: 100%;
    width: {after_score}%;
    background: var(--green);
}}

.compare-bars {{
    display: grid;
    gap: 10px;
}}

.bar-label {{
    display: flex;
    justify-content: space-between;
    gap: 20px;
    font-weight: 700;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}

th {{
    background: #eef3fb;
    color: var(--navy);
    text-align: left;
    padding: 9px 10px;
    border-bottom: 1px solid var(--border);
}}

td {{
    padding: 9px 10px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}}

.control-title {{
    margin-top: 3px;
    color: var(--muted);
}}

.actual {{
    margin-top: 4px;
    color: var(--muted);
    word-break: break-word;
}}

.badge {{
    display: inline-block;
    padding: 3px 8px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 0.04em;
}}

.pass {{
    background: #e5f6ef;
    color: var(--green);
}}

.fail {{
    background: #fce9e7;
    color: var(--red);
}}

.error {{
    background: #fff1d6;
    color: var(--amber);
}}

.sev-high {{
    background: #fce9e7;
    color: var(--red);
}}

.sev-medium {{
    background: #fff1d6;
    color: var(--amber);
}}

.sev-low {{
    background: #e8eefc;
    color: var(--blue);
}}

.summary-text p {{
    margin: 0 0 8px;
}}

.summary-text p:last-child {{
    margin-bottom: 0;
}}

.footer {{
    color: var(--muted);
    text-align: center;
    padding: 14px 0 4px;
    font-size: 12px;
}}

@media (max-width: 760px) {{
    .summary-grid {{
        grid-template-columns: 1fr;
    }}

    .header {{
        padding: 22px;
    }}

    .header h1 {{
        font-size: 28px;
    }}

    table {{
        font-size: 12px;
    }}

    th,
    td {{
        padding: 8px 6px;
    }}
}}

@media print {{
    @page {{
        size: A4;
        margin: 12mm;
    }}

    html,
    body {{
        background: #ffffff !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}

    body {{
        font-size: 9.5px;
        line-height: 1.25;
    }}

    .page {{
        width: 100%;
        margin: 0;
    }}

    .header {{
        padding: 12px 15px;
        margin-bottom: 7px;
        border-radius: 8px;
    }}

    .header h1 {{
        font-size: 21px;
        margin-bottom: 4px;
    }}

    .header p {{
        margin: 2px 0;
    }}

    .summary-grid {{
        grid-template-columns: repeat(3, 1fr);
        gap: 6px;
        margin-bottom: 7px;
    }}

    .card {{
        padding: 8px;
        border-radius: 8px;
    }}

    .score-label {{
        font-size: 8px;
    }}

    .score {{
        font-size: 24px;
        margin-top: 3px;
    }}

    .metrics {{
        grid-template-columns: repeat(3, 1fr);
        gap: 4px;
        margin-top: 6px;
    }}

    .metric {{
        padding: 5px 4px;
        border-radius: 6px;
        font-size: 7.5px;
    }}

    .metric strong {{
        font-size: 13px;
        margin-bottom: 1px;
    }}

    .improvement-text {{
        margin-top: 4px;
    }}

    .improvement-detail {{
        margin-top: 5px;
        font-size: 8px;
    }}

    .section-title {{
        font-size: 15px;
        margin: 7px 0 4px;
    }}

    .compare-bars {{
        gap: 5px;
    }}

    .progress {{
        height: 7px;
        margin-top: 4px;
    }}

    table {{
        font-size: 7.6px;
    }}

    th {{
        padding: 4px 5px;
    }}

    td {{
        padding: 4px 5px;
    }}

    .control-title {{
        margin-top: 1px;
    }}

    .actual {{
        margin-top: 2px;
    }}

    .badge {{
        padding: 2px 4px;
        font-size: 6.8px;
    }}

    .summary-text p {{
        margin-bottom: 4px;
    }}

    .footer {{
        padding: 6px 0 0;
        font-size: 7px;
    }}

    .header,
    .card,
    table,
    tr {{
        break-inside: avoid;
        page-break-inside: avoid;
    }}
}}
</style>
</head>

<body>
<main class="page">

<section class="header">
    <h1>CyberAssess — Snapshot Comparison</h1>
    <p><strong>Target:</strong> {esc(target_name)}</p>
    <p><strong>Platform:</strong> {esc(platform)}</p>
    <p><strong>Profile, before / after:</strong> {esc(profile_summary)}</p>
    <p><strong>Source, before / after:</strong> {esc(source_summary)}</p>
    <p><strong>Before recorded time:</strong> {esc(snapshot_time(before))}</p>
    <p><strong>After recorded time:</strong> {esc(snapshot_time(after))}</p>
    <p>
        Comparison of two point-in-time assessment snapshots; this report does
        not refresh automatically or establish that remediation occurred.
    </p>
    <p>{esc(demonstration_note)}</p>
    <p><strong>Comparability:</strong> {esc(comparison_limitations)}</p>
</section>

<section class="summary-grid">

    <div class="card">
        <div class="score-label">Before snapshot</div>
        <div class="score before-score">{before_score:.1f}%</div>

        <div class="metrics">
            <div class="metric">
                <strong>{esc(before_assessment["passed"])}</strong>
                Passed
            </div>

            <div class="metric">
                <strong>{esc(before_assessment["failed"])}</strong>
                Failed
            </div>

            <div class="metric">
                <strong>{esc(before_assessment["errors"])}</strong>
                Errors
            </div>
        </div>
    </div>

    <div class="card">
        <div class="score-label">After snapshot</div>
        <div class="score after-score">{after_score:.1f}%</div>

        <div class="metrics">
            <div class="metric">
                <strong>{esc(after_assessment["passed"])}</strong>
                Passed
            </div>

            <div class="metric">
                <strong>{esc(after_assessment["failed"])}</strong>
                Failed
            </div>

            <div class="metric">
                <strong>{esc(after_assessment["errors"])}</strong>
                Errors
            </div>
        </div>
    </div>

    <div class="card">
        <div class="score-label">Recorded score change</div>
        <div class="score improvement">{improvement:+.1f}</div>

        <p class="improvement-text">
            percentage points
        </p>

        <p class="improvement-detail">
            <strong>{len(fixed_controls)}</strong>
            controls changed to PASS: {fail_to_pass} from FAIL and
            {error_to_pass} previously unassessed (ERROR).
        </p>
    </div>

</section>

<h2 class="section-title">Weighted Score Comparison</h2>

<section class="card compare-bars">

    <div>
        <div class="bar-label">
            <span>Before</span>
            <span>{before_score:.1f}%</span>
        </div>

        <div class="progress">
            <div class="progress-before"></div>
        </div>
    </div>

    <div>
        <div class="bar-label">
            <span>After</span>
            <span>{after_score:.1f}%</span>
        </div>

        <div class="progress">
            <div class="progress-after"></div>
        </div>
    </div>

</section>

<h2 class="section-title">Controls Transitioning to PASS</h2>

<section class="card">
<table>
<thead>
<tr>
    <th>Control</th>
    <th>Severity</th>
    <th>Before</th>
    <th>After</th>
    <th>NIST</th>
</tr>
</thead>

<tbody>
{fixed_rows_html}
</tbody>
</table>
</section>

<h2 class="section-title">Assessment Summary</h2>

<section class="card summary-text">

    <p>
        The initial assessment recorded
        <strong>{before_assessment["passed"]}</strong>
        controls recorded as PASS,
        <strong>{before_assessment["failed"]}</strong>
        as FAIL and <strong>{before_assessment["errors"]}</strong>
        as ERROR, producing a weighted score of
        <strong>{before_score:.1f}%</strong>.
    </p>

    <p>
        In the after snapshot,
        <strong>{after_assessment["passed"]}</strong>
        of
        <strong>{after_assessment["total_controls"]}</strong>
        controls passed with
        <strong>{after_assessment["failed"]}</strong>
        failures and
        <strong>{after_assessment["errors"]}</strong>
        collection errors.
    </p>

    <p>
        After snapshot weighted score:
        <strong>{after_score:.1f}%</strong>.
        Recorded score change:
        <strong>{improvement:+.1f} percentage points</strong>.
        ERROR means unavailable evidence, not a confirmed insecure setting.
    </p>

</section>

<footer class="footer">
    CyberAssess · Read-only snapshot comparison; not formal compliance certification.
    Snapshots do not prove remediation, authorization or the cause of a result change.
    No target setting or remediation command is executed by this helper.
</footer>

</main>
</body>
</html>
"""


OUTPUT_FILE.write_text(html_output, encoding="utf-8")

print(f"Comparison report created: {OUTPUT_FILE}")
print(f"Before: {before_score:.1f}%")
print(f"After: {after_score:.1f}%")
print(f"Score change: {improvement:+.1f} points")
print(f"Transitions to PASS: {len(fixed_controls)} ({fail_to_pass} from FAIL; {error_to_pass} from ERROR)")
