import json
import html
from pathlib import Path


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
    results = report.get("assessment", {}).get("results", [])
    return {
        item.get("control_id"): item
        for item in results
        if item.get("control_id")
    }


before = load_report(BEFORE_FILE)
after = load_report(AFTER_FILE)

before_assessment = before["assessment"]
after_assessment = after["assessment"]

before_score = float(before_assessment["compliance_score"])
after_score = float(after_assessment["compliance_score"])
improvement = round(after_score - before_score, 1)

before_results = result_map(before)
after_results = result_map(after)

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

target_name = after.get("target_name", "Unknown target")
platform = after.get("platform", "Unknown platform")


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
    <h1>CyberAssess — Remediation Comparison</h1>
    <p><strong>Target:</strong> {esc(target_name)}</p>
    <p><strong>Platform:</strong> {esc(platform)}</p>
    <p>
        Automated read-only compliance assessment comparing
        the baseline state with the post-remediation state.
    </p>
</section>

<section class="summary-grid">

    <div class="card">
        <div class="score-label">Before remediation</div>
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
        <div class="score-label">After remediation</div>
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
        <div class="score-label">Compliance improvement</div>
        <div class="score improvement">+{improvement:.1f}</div>

        <p class="improvement-text">
            percentage points
        </p>

        <p class="improvement-detail">
            <strong>{len(fixed_controls)}</strong>
            controls changed from non-compliant to compliant.
        </p>
    </div>

</section>

<h2 class="section-title">Compliance Progress</h2>

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

<h2 class="section-title">Controls Remediated</h2>

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
        compliant controls and
        <strong>{before_assessment["failed"]}</strong>
        failed controls, producing a compliance score of
        <strong>{before_score:.1f}%</strong>.
    </p>

    <p>
        After authorized remediation and reassessment,
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
        Final compliance score:
        <strong>{after_score:.1f}%</strong>.
        Overall improvement:
        <strong>+{improvement:.1f} percentage points</strong>.
    </p>

</section>

<footer class="footer">
    CyberAssess · Read-only assessment checks.
    Remediation was performed separately on the authorized lab target.
</footer>

</main>
</body>
</html>
"""


OUTPUT_FILE.write_text(html_output, encoding="utf-8")

print(f"Comparison report created: {OUTPUT_FILE}")
print(f"Before: {before_score:.1f}%")
print(f"After: {after_score:.1f}%")
print(f"Improvement: +{improvement:.1f} points")
print(f"Controls fixed: {len(fixed_controls)}")