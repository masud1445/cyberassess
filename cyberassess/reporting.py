from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any
import json


VERDICT_THRESHOLDS = {
    "COMPLIANT": 90.0,
    "PARTIAL": 70.0,
}


def save_json(report: dict, output_dir: str = "reports") -> Path:
    """Save the assessment as JSON without changing its content."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out / f"audit_{stamp}.json"
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path


def _safe(value: Any) -> str:
    if value is None:
        value = "Not available"
    return escape(str(value), quote=True)


def _category_for_result(result: dict) -> str:
    control_id = str(result.get("control_id", "")).upper()
    mapping = (
        ("SSH", "SSH hardening"),
        ("AUTH", "Accounts"),
        ("LOG", "Logging"),
        ("NET", "Network"),
        ("FILE", "File permissions"),
        ("UPD", "Updates"),
        ("TIME", "Time synchronization"),
        ("SVC", "Services"),
    )
    for prefix, category in mapping:
        if control_id.startswith(prefix):
            return category
    return "Other"


def _display_value(result: dict, value: Any, expected: bool = False) -> str:
    """Convert raw values into clearer security-language labels."""
    control_id = str(result.get("control_id", "")).upper()
    if control_id == "SSH-005":
        if expected:
            return "> 0 sec"
        if value is not None:
            return f"{value} sec"
    if control_id == "UPD-001" and isinstance(value, bool):
        return "Enabled" if value else "Disabled"
    if control_id == "SVC-001" and isinstance(value, bool):
        return "Installed" if value else "Not installed"
    return str(value if value is not None else "Not available")


def _evidence_for_result(result: dict) -> str:
    """Return only the evidence relevant to this control."""
    control_id = str(result.get("control_id", "")).upper()
    actual = _display_value(result, result.get("actual"))
    labels = {
        "SSH-001": "PermitRootLogin",
        "SSH-002": "PasswordAuthentication",
        "SSH-003": "MaxAuthTries",
        "SSH-004": "X11Forwarding",
        "SSH-005": "ClientAliveInterval",
        "NET-001": "UFW status",
        "FILE-001": "/etc/shadow mode",
        "FILE-002": "/etc/passwd mode",
        "AUTH-001": "Empty-password accounts",
        "AUTH-002": "Non-root UID 0 accounts",
        "AUTH-003": "Minimum password length",
        "LOG-001": "auditd status",
        "UPD-001": "Automatic security updates",
        "TIME-001": "Time synchronization",
        "SVC-001": "Telnet server",
    }
    label = labels.get(control_id)
    if label:
        return f"{label}={actual}"
    raw = str(result.get("raw_evidence") or actual).strip()
    return raw[:240] + ("…" if len(raw) > 240 else "")


def _fix_command(result: dict) -> str:
    """
    Return display-only remediation commands.

    CyberAssess never runs these commands automatically. Operators should
    review commands and preserve access before changing an SSH or firewall
    configuration.
    """
    control_id = str(result.get("control_id", "")).upper()
    commands = {
        "SSH-001": (
            "printf 'PermitRootLogin no\\n' | sudo tee "
            "/etc/ssh/sshd_config.d/99-cyberassess-root.conf >/dev/null\n"
            "sudo sshd -t && sudo systemctl reload ssh"
        ),
        "SSH-002": (
            "printf 'PasswordAuthentication no\\n' | sudo tee "
            "/etc/ssh/sshd_config.d/99-cyberassess-password-auth.conf >/dev/null\n"
            "sudo sshd -t && sudo systemctl reload ssh"
        ),
        "SSH-003": (
            "printf 'MaxAuthTries 4\\n' | sudo tee "
            "/etc/ssh/sshd_config.d/99-cyberassess-maxauthtries.conf >/dev/null\n"
            "sudo sshd -t && sudo systemctl reload ssh"
        ),
        "SSH-004": (
            "printf 'X11Forwarding no\\n' | sudo tee "
            "/etc/ssh/sshd_config.d/99-cyberassess-x11.conf >/dev/null\n"
            "sudo sshd -t && sudo systemctl reload ssh"
        ),
        "SSH-005": (
            "printf 'ClientAliveInterval 300\\nClientAliveCountMax 2\\n' | sudo tee "
            "/etc/ssh/sshd_config.d/99-cyberassess-timeout.conf >/dev/null\n"
            "sudo sshd -t && sudo systemctl reload ssh"
        ),
        "NET-001": "sudo ufw allow OpenSSH && sudo ufw --force enable && sudo ufw status",
        "FILE-001": "sudo chmod 640 /etc/shadow && stat -c '%a %n' /etc/shadow",
        "FILE-002": "sudo chmod 644 /etc/passwd && stat -c '%a %n' /etc/passwd",
        "AUTH-003": (
            "sudo apt-get install -y libpam-pwquality\n"
            "echo 'minlen = 14' | sudo tee /etc/security/pwquality.conf.d/99-cyberassess.conf >/dev/null"
        ),
        "LOG-001": "sudo apt-get install -y auditd && sudo systemctl enable --now auditd",
        "UPD-001": "sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
        "TIME-001": "sudo timedatectl set-ntp true && timedatectl status",
        "SVC-001": "sudo apt-get purge -y telnetd inetutils-telnetd",
    }
    return commands.get(control_id, str(result.get("remediation", "Review the finding before remediation.")))


def _verdict(score: float) -> tuple[str, str]:
    """
    Report-only verdict thresholds.

    90-100%  = Compliant
    70-89.9% = Partially compliant
    Below 70% = Non-compliant
    """
    if score >= VERDICT_THRESHOLDS["COMPLIANT"]:
        return "Compliant", "#0f7a55"
    if score >= VERDICT_THRESHOLDS["PARTIAL"]:
        return "Partially compliant", "#a86a00"
    return "Non-compliant", "#b3261e"


def _all_clear(total_controls: int, errors: int = 0) -> str:
    if not total_controls:
        heading = "No controls assessed"
        description = "No control results were supplied. Assessment coverage cannot be established."
        state = "neutral"
    elif errors:
        heading = "Assessment incomplete"
        description = (
            f"No failed controls were recorded, but {errors} control"
            f"{'s' if errors != 1 else ''} could not be assessed. "
            "Review the collection notes before concluding that the baseline is satisfied."
        )
        state = "incomplete"
    else:
        heading = "No remediation gaps identified"
        description = (
            f"All {total_controls} controls passed the configured baseline. "
            "Retain this report as a point-in-time record and reassess after configuration changes."
        )
        state = "complete"
    return (
        f'<div class="assessment-state {state}">'
        f'<h3>{heading}</h3><p>{description}</p></div>'
    )


def _category_bars(results: list[dict]) -> str:
    categories: dict[str, dict[str, int]] = {}
    for result in results:
        category = _category_for_result(result)
        data = categories.setdefault(category, {"passed": 0, "scoreable": 0})
        status = str(result.get("status", "")).upper()
        if status in {"PASS", "FAIL", "ERROR"}:
            data["scoreable"] += 1
        if status == "PASS":
            data["passed"] += 1
    rows = []
    for category, data in categories.items():
        total = data["scoreable"]
        rate = round(data["passed"] / total * 100) if total else 0
        rows.append(
            f'<div class="category-row"><div class="category-meta"><span>{_safe(category)}</span>'
            f'<span class="category-count">{data["passed"]}/{total} · {rate}%</span></div>'
            f'<div class="bar-track" aria-hidden="true"><div class="bar-fill" '
            f'style="width:{rate}%"></div></div></div>'
        )
    return "".join(rows) or '<p class="small">No category results available.</p>'


def _status_badge(status: str) -> str:
    value = str(status).upper()
    css = {"PASS": "pass", "FAIL": "fail", "ERROR": "error"}.get(value, "neutral")
    return f'<span class="status-badge {css}">{_safe(value)}</span>'


def _severity_badge(severity: str) -> str:
    value = str(severity).upper()
    css = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(value, "neutral")
    return f'<span class="severity-badge {css}">{_safe(value)}</span>'


def _evidence_details(result: dict) -> str:
    notes = result.get("notes")
    note_html = f'<p class="collection-note"><strong>Collection note:</strong> {_safe(notes)}</p>' if notes else ""
    return f"""
    <details class="evidence-details">
      <summary>Evidence<span class="sr-only"> for {_safe(result.get('control_id', 'control'))}</span></summary>
      <div class="details-body">
        <p class="evidence-value">{_safe(_evidence_for_result(result))}</p>
        {note_html}
      </div>
    </details>
    """


def _gap_card(result: dict) -> str:
    expected = _safe(_display_value(result, result.get("expected"), expected=True))
    actual = _safe(_display_value(result, result.get("actual")))
    evidence = _safe(_evidence_for_result(result))
    command = _safe(_fix_command(result))
    remediation = _safe(result.get("remediation", ""))
    control_id = _safe(result.get("control_id", ""))
    return f"""
    <article class="gap-card">
      <div class="gap-top">
        <div class="gap-heading"><span class="control-id">{control_id}</span>{_severity_badge(result.get('severity', 'LOW'))}</div>
        <span class="nist-reference">NIST {_safe(result.get('nist', ''))}</span>
      </div>
      <div class="gap-summary">
        <h3>{_safe(result.get('title', ''))}</h3>
        <dl class="comparison">
          <div><dt>Expected</dt><dd>{expected}</dd></div>
          <div><dt>Actual</dt><dd>{actual}</dd></div>
        </dl>
      </div>
      <details class="remediation-details">
        <summary>Evidence &amp; remediation<span class="sr-only"> for {control_id}</span></summary>
        <div class="details-body remediation-body">
          <div><h4>Observed evidence</h4><p class="evidence-value">{evidence}</p></div>
          <div><h4>Recommended remediation</h4><p>{remediation}</p></div>
          <div class="command-section"><h4>Suggested command · review before use</h4><pre class="command-block"><code>{command}</code></pre></div>
        </div>
      </details>
    </article>
    """


_REPORT_CSS = """
:root {
  color-scheme: light;
  --navy: #0b1f4b;
  --ink: #202b3b;
  --muted: #596574;
  --line: #dce1e6;
  --surface: #f4f6f8;
  --pass: #245f4b;
  --fail: #9b332c;
  --warn: #775c29;
}
* { box-sizing: border-box; }
html { background: #edf0f3; }
body {
  margin: 0;
  color: var(--ink);
  font: 13px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
  -webkit-text-size-adjust: 100%;
}
h1, h2, h3, h4, p, dl { margin: 0; }
h1, h2, h3 { color: var(--navy); }
h1 { font-size: 28px; font-weight: 600; line-height: 1.25; letter-spacing: -.025em; }
h2 { font-size: 17px; font-weight: 600; line-height: 1.35; }
h3 { font-size: 13px; font-weight: 600; }
h4, dt { color: var(--muted); font-size: 10px; font-weight: 600; }
dd { margin: 0; }
.report-shell { max-width: 1100px; margin: 36px auto 64px; padding: 30px 40px; background: #fff; border: 1px solid var(--line); }
.report-header { border-top: 3px solid var(--navy); padding-top: 16px; }
.masthead { display: flex; justify-content: space-between; gap: 16px; margin-bottom: 28px; }
.brand { color: var(--navy); font-size: 12px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
.document-label, .small { color: var(--muted); font-size: 11px; }
.subtitle { margin-top: 8px; color: var(--muted); font-size: 12px; }
.metadata { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px 22px; margin-top: 22px; padding: 17px 0; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
.metadata dt { margin-bottom: 4px; }
.metadata dd { font-size: 12px; overflow-wrap: anywhere; }
.section { margin-top: 28px; }
.section-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 14px; }
.section-head .small { text-align: right; }
.summary-content { display: grid; grid-template-columns: 180px minmax(0, 1fr); gap: 28px; align-items: center; padding: 3px 0 20px; }
.score-label { color: var(--muted); font-size: 10px; }
.score-value { color: var(--navy); font-size: 42px; font-weight: 600; line-height: 1.2; letter-spacing: -.04em; font-variant-numeric: tabular-nums; }
.score-value span { margin-left: 2px; font-size: 22px; }
.verdict { display: inline-block; margin-bottom: 8px; font-size: 16px; font-weight: 600; }
.summary-copy p { max-width: 65ch; font-size: 12px; color: var(--muted); }
.summary-copy p + p { margin-top: 6px; }
.metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border-block: 1px solid var(--line); padding: 14px 0; }
.metric { padding: 0 18px; border-left: 1px solid var(--line); }
.metric:first-child { padding-left: 0; border-left: 0; }
.metric dt { margin-bottom: 2px; }
.metric dd { font-size: 22px; line-height: 1.3; font-weight: 500; font-variant-numeric: tabular-nums; }
.methodology { margin-top: 10px; font-size: 11px; color: var(--muted); }
.methodology .details-body { padding-top: 8px; }
.methodology p + p { margin-top: 4px; }
.category-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 18px 28px; }
.category-meta { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; margin-bottom: 7px; font-size: 11px; }
.category-count { flex-shrink: 0; color: var(--muted); font-size: 10px; font-variant-numeric: tabular-nums; }
.bar-track { height: 3px; background: #e8ecf0; }
.bar-fill { height: 100%; background: var(--navy); }
.severity-summary { display: flex; flex-wrap: wrap; gap: 8px 22px; padding: 10px 0; border-block: 1px solid var(--line); font-size: 11px; color: var(--muted); }
.severity-summary strong { color: var(--ink); font-weight: 600; }
.gap-card { padding: 15px 0; border-bottom: 1px solid var(--line); }
.gap-top, .gap-heading { display: flex; align-items: center; gap: 10px; }
.gap-top { justify-content: space-between; flex-wrap: wrap; }
.control-id, .mono, .evidence-value, .command-block { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.control-id { font-size: 10px; font-weight: 600; color: var(--muted); }
.nist-reference { color: var(--muted); font-size: 10px; overflow-wrap: anywhere; }
.gap-summary { display: grid; grid-template-columns: minmax(0, 1fr) minmax(230px, .7fr); gap: 20px; align-items: start; margin: 6px 0 8px; }
.comparison { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.comparison dt { font-size: 9px; }
.comparison dd { font: 11px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
.severity-badge { color: var(--muted); font-size: 9px; font-weight: 600; letter-spacing: .025em; }
.status-badge { display: inline-block; padding: 2px 6px; border: 1px solid currentColor; border-radius: 2px; font-size: 9px; font-weight: 600; line-height: 1.4; white-space: nowrap; }
.status-badge.pass { color: var(--pass); background: #eef4f0; }
.status-badge.fail { color: var(--fail); background: #f8eeec; }
.status-badge.error { color: var(--warn); background: #f6f1e7; }
.status-badge.neutral { color: var(--muted); }
summary { width: fit-content; max-width: 100%; cursor: pointer; color: var(--muted); font-size: 10px; }
summary::marker { font-size: 8px; }
summary:hover { color: var(--navy); }
summary:focus-visible, .table-wrap:focus-visible { outline: 2px solid var(--navy); outline-offset: 4px; }
.details-body { padding-top: 8px; }
.remediation-body { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 24px; font-size: 11px; }
.remediation-body h4 { margin-bottom: 4px; }
.evidence-value { font-size: 10px; overflow-wrap: anywhere; white-space: pre-wrap; }
.command-section { grid-column: 1 / -1; }
.command-block { margin: 0; padding: 10px 12px; border: 1px solid var(--line); background: var(--surface); color: var(--ink); font-size: 10px; line-height: 1.6; white-space: pre-wrap; overflow-wrap: anywhere; }
.assessment-state { padding: 18px 20px; border: 1px solid var(--line); border-left: 3px solid var(--navy); background: #fafbfc; }
.assessment-state.complete h3 { color: var(--pass); }
.assessment-state p { margin-top: 5px; max-width: 85ch; font-size: 12px; color: var(--muted); }
.error-item { padding: 12px 0; border-top: 1px solid var(--line); }
.error-heading { display: flex; align-items: baseline; gap: 10px; margin-bottom: 5px; }
.error-item p { font-size: 11px; color: var(--muted); overflow-wrap: anywhere; }
.table-wrap { overflow-x: auto; }
.table-hint { display: none; }
table { width: 100%; min-width: 780px; table-layout: fixed; border-collapse: collapse; text-align: left; font-size: 11px; }
caption { padding: 0 0 10px; text-align: left; color: var(--muted); font-size: 10px; }
col.col-id { width: 10%; } col.col-control { width: 32%; } col.col-severity { width: 9%; }
col.col-status { width: 10%; } col.col-expected { width: 13%; } col.col-actual { width: 15%; } col.col-nist { width: 11%; }
thead { background: var(--surface); }
th, td { padding: 10px 8px; vertical-align: top; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
thead th { font-size: 9px; font-weight: 600; color: var(--muted); }
tbody th { font-size: 10px; font-weight: 500; }
.control-title { font-weight: 600; line-height: 1.45; }
.table-category { margin-top: 3px; color: var(--muted); font-size: 10px; }
.evidence-details { margin-top: 6px; }
.evidence-details .details-body { font-size: 10px; }
.collection-note { margin-top: 6px; color: var(--muted); }
.footer { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 6px 20px; margin-top: 28px; padding-top: 14px; border-top: 1px solid var(--line); font-size: 10px; color: var(--muted); }
.footer strong { color: var(--navy); font-weight: 600; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; border: 0; }
@media screen and (max-width: 1160px) {
  .report-shell { margin: 24px; }
}
@media screen and (max-width: 800px) {
  .report-shell { margin: 16px; padding: 24px; }
  .metadata { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .category-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .summary-content { grid-template-columns: 150px minmax(0, 1fr); gap: 20px; }
  .gap-summary { grid-template-columns: 1fr; gap: 8px; }
  .table-hint { display: block; margin-bottom: 8px; color: var(--muted); font-size: 10px; }
}
@media screen and (max-width: 480px) {
  .report-shell { margin: 0; padding: 20px 16px; border: 0; }
  h1 { font-size: 24px; }
  .masthead { flex-direction: column; gap: 4px; margin-bottom: 22px; }
  .section-head { align-items: start; flex-direction: column; gap: 4px; }
  .section-head .small { text-align: left; }
  .summary-content { grid-template-columns: 1fr; gap: 14px; }
  .score-value { font-size: 36px; }
  .metrics { gap: 14px 0; grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .metric:nth-child(3) { padding-left: 0; border-left: 0; }
  .category-grid, .remediation-body { grid-template-columns: 1fr; }
  .comparison { gap: 12px; }
}
@page { size: A4 portrait; margin: 14mm 12mm; }
@media print {
  html, body { background: #fff; }
  body { font-size: 9pt; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .report-shell { max-width: none; margin: 0; padding: 0; border: 0; }
  .report-header { padding-top: 10px; }
  .masthead { margin-bottom: 16px; }
  h1 { font-size: 21pt; } h2 { font-size: 12pt; } h3 { font-size: 10pt; }
  .metadata { gap: 10px 16px; margin-top: 14px; padding: 12px 0; }
  .metadata dt, h4 { font-size: 7pt; } .metadata dd { font-size: 8pt; }
  .section { margin-top: 18px; }
  .section-head { margin-bottom: 10px; break-after: avoid; }
  .summary-content { grid-template-columns: 140px minmax(0, 1fr); gap: 20px; padding-bottom: 12px; }
  .score-value { font-size: 30pt; } .verdict { font-size: 12pt; }
  .summary-copy p, .assessment-state p { font-size: 8pt; }
  .metrics { padding: 10px 0; } .metric dd { font-size: 16pt; }
  .category-grid { gap: 12px 20px; }
  .category-row, .assessment-state, .gap-card, .error-item { break-inside: avoid; page-break-inside: avoid; }
  .gap-card { padding: 12px 0; }
  .gap-summary { grid-template-columns: minmax(0, 1fr) minmax(180px, .7fr); gap: 16px; }
  .remediation-body { font-size: 8pt; }
  .command-block, .evidence-value { font-size: 7pt; }
  details > .details-body { display: block !important; }
  details.remediation-details > .details-body { display: grid !important; }
  details::details-content { content-visibility: visible !important; display: block !important; }
  summary { font-size: 7pt; cursor: default; } summary::marker { content: ""; }
  .table-wrap { overflow: visible; }
  .screen-only { display: none; }
  table { min-width: 0; font-size: 8pt; line-height: 1.4; }
  .evidence-details { margin-top: 4px; }
  .evidence-details > summary { display: none; }
  .evidence-details .details-body { padding-top: 0; }
  thead { display: table-header-group; }
  tr { break-inside: avoid; page-break-inside: avoid; }
  th, td { padding: 7px 5px; }
  thead th, tbody th, .severity-badge, .status-badge, .nist-reference, .table-category { font-size: 7pt; }
  .footer { margin-top: 16px; font-size: 7pt; }
}
"""


def render_html(report: dict) -> str:
    assessment = report.get("assessment", {})
    results = list(assessment.get("results", []))
    score = float(assessment.get("compliance_score", 0.0))
    passed = int(assessment.get("passed", 0))
    failed = int(assessment.get("failed", 0))
    errors = int(assessment.get("errors", 0))
    total = int(assessment.get("total_controls", len(results)))
    target = _safe(report.get("target_name", "Unknown"))
    platform = _safe(report.get("platform", "Unknown"))
    generated_at = datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M UTC")
    collector = report.get("collector") or {}
    method = _safe(collector.get("method", "Not provided"))
    verdict, _ = _verdict(score)

    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    failures = [r for r in results if str(r.get("status", "")).upper() == "FAIL"]
    failures.sort(key=lambda r: (severity_rank.get(str(r.get("severity", "LOW")).upper(), 99), str(r.get("control_id", ""))))
    high = sum(str(r.get("severity", "")).upper() == "HIGH" for r in failures)
    medium = sum(str(r.get("severity", "")).upper() == "MEDIUM" for r in failures)
    low = sum(str(r.get("severity", "")).upper() == "LOW" for r in failures)
    error_results = [r for r in results if str(r.get("status", "")).upper() == "ERROR"]

    metadata = [
        ("Target", target),
        ("Platform", platform),
        ("Collection method", method),
        ("Report generated", _safe(generated_at)),
    ]
    for key, label in (("host", "Connection host"), ("username", "Collection account")):
        if collector.get(key):
            metadata.append((label, _safe(collector[key])))
    metadata_html = "".join(f"<div><dt>{label}</dt><dd>{value}</dd></div>" for label, value in metadata)

    if not results:
        summary_text = "No control results were supplied. This report does not establish assessment coverage."
    elif failed:
        summary_text = (
            f"{failed} control{'s' if failed != 1 else ''} did not meet the configured baseline. "
            "Review the remediation findings below, ordered by severity."
        )
    elif errors:
        summary_text = "No failed controls were recorded. Collection errors prevent a complete baseline assessment."
    else:
        summary_text = f"All {passed} assessed controls met the configured baseline. No remediation gaps were identified."
    error_notice = (
        f'<p>{errors} control{"s" if errors != 1 else ""} could not be assessed. '
        'Review the assessment errors and collection notes.</p>' if errors and failed else ""
    )

    table_rows = []
    for r in results:
        table_rows.append(f"""
        <tr>
          <th scope="row" class="mono">{_safe(r.get('control_id', ''))}</th>
          <td><div class="control-title">{_safe(r.get('title', ''))}</div><div class="table-category">{_safe(_category_for_result(r))}</div>{_evidence_details(r)}</td>
          <td>{_severity_badge(r.get('severity', ''))}</td>
          <td>{_status_badge(r.get('status', ''))}</td>
          <td class="mono">{_safe(_display_value(r, r.get('expected'), expected=True))}</td>
          <td class="mono">{_safe(_display_value(r, r.get('actual')))}</td>
          <td class="nist-reference">{_safe(r.get('nist', ''))}</td>
        </tr>
        """)
    if not table_rows:
        table_rows.append('<tr><td colspan="7">No control results available.</td></tr>')

    if failures:
        findings_html = f"""
        <div class="severity-summary" aria-label="Failed controls by severity">
          <span><strong>{high}</strong> High severity</span>
          <span><strong>{medium}</strong> Medium severity</span>
          <span><strong>{low}</strong> Low severity</span>
        </div>
        <div class="findings-list">{''.join(_gap_card(r) for r in failures)}</div>
        """
    else:
        findings_html = _all_clear(total if results else 0, errors)

    errors_html = ""
    if errors:
        error_items = "".join(f"""
        <article class="error-item">
          <div class="error-heading"><span class="control-id">{_safe(r.get('control_id', ''))}</span><h3>{_safe(r.get('title', ''))}</h3></div>
          <p>{_safe(r.get('notes') or 'Evidence could not be reliably collected or interpreted.')}</p>
          {_evidence_details(r)}
        </article>
        """ for r in error_results)
        errors_html = f"""
        <section class="section errors-section" aria-labelledby="errors-title">
          <div class="section-head"><h2 id="errors-title">Assessment errors</h2><span class="small">{errors} control{'s' if errors != 1 else ''} require review</span></div>
          {error_items or '<p class="small">Collection details were not provided.</p>'}
        </section>
        """

    threshold_text = "90%+ Compliant · 70–89.9% Partially compliant · Below 70% Non-compliant"
    weighted_text = "Severity-weighted score: High ×3, Medium ×2, Low ×1; FAIL or ERROR earns 0 weight, and ERROR remains in the weighted score denominator."
    scope_note = "Read-only collection. No settings were changed on the target." if collector.get("read_only") is True else "Assessment against the configured baseline."

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberAssess Compliance Report · {target}</title>
<style>{_REPORT_CSS}</style>
</head>
<body>
<main class="report-shell">
  <header class="report-header">
    <div class="masthead"><div class="brand">CyberAssess</div><div class="document-label">Security &amp; compliance assessment</div></div>
    <h1>Compliance &amp; Baseline Report</h1>
    <p class="subtitle">{total}-control Ubuntu baseline · NIST SP 800-53 mapped</p>
    <dl class="metadata">{metadata_html}</dl>
  </header>

  <section class="section summary-section" aria-labelledby="summary-title">
    <div class="section-head"><h2 id="summary-title">Assessment summary</h2><span class="small">Point-in-time baseline review</span></div>
    <div class="summary-content">
      <div><div class="score-label">Weighted compliance score</div><div class="score-value">{score:.1f}<span>%</span></div></div>
      <div class="summary-copy"><div class="verdict">{escape(verdict) if results else 'Not assessed'}</div><p>{summary_text}</p>{error_notice}</div>
    </div>
    <dl class="metrics">
      <div class="metric"><dt>Passed</dt><dd>{passed}</dd></div>
      <div class="metric"><dt>Failed</dt><dd>{failed}</dd></div>
      <div class="metric"><dt>Assessment errors</dt><dd>{errors}</dd></div>
      <div class="metric"><dt>Total controls</dt><dd>{total}</dd></div>
    </dl>
    <details class="methodology">
      <summary>Scoring methodology &amp; verdict thresholds</summary>
      <div class="details-body"><p>{escape(threshold_text)}</p><p>{escape(weighted_text)}</p></div>
    </details>
  </section>

  <section class="section coverage-section" aria-labelledby="coverage-title">
    <div class="section-head"><h2 id="coverage-title">Pass rate by category</h2><span class="small">Passed / total controls · unweighted</span></div>
    <div class="category-grid">{_category_bars(results)}</div>
  </section>

  <section class="section gaps-section" aria-labelledby="findings-title">
    <div class="section-head"><h2 id="findings-title">Remediation findings</h2><span class="small">{'Highest severity first' if failures else 'Baseline review'}</span></div>
    {findings_html}
  </section>

  {errors_html}

  <section class="section controls-section" aria-labelledby="controls-title">
    <div class="section-head"><h2 id="controls-title">All controls</h2><span class="small">PASS / FAIL / ERROR</span></div>
    <p class="table-hint" id="table-hint">Scroll horizontally to view all columns.</p>
    <div class="table-wrap" role="region" aria-labelledby="controls-title" aria-describedby="table-hint" tabindex="0"><table>
      <caption>Control results and baseline comparison.<span class="screen-only"> Expand Evidence for supporting details.</span></caption>
      <colgroup><col class="col-id"><col class="col-control"><col class="col-severity"><col class="col-status"><col class="col-expected"><col class="col-actual"><col class="col-nist"></colgroup>
      <thead><tr><th scope="col">ID</th><th scope="col">Control</th><th scope="col">Severity</th><th scope="col">Result</th><th scope="col">Expected</th><th scope="col">Actual</th><th scope="col">NIST</th></tr></thead>
      <tbody>{''.join(table_rows)}</tbody>
    </table></div>
  </section>

  <footer class="footer"><div><strong>CyberAssess</strong> · Compliance &amp; baseline assessment</div><div>{scope_note}</div></footer>
</main>
</body>
</html>"""


def save_html(report: dict, output_dir: str = "reports") -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out / f"audit_{stamp}.html"
    path.write_text(render_html(report), encoding="utf-8")
    return path
