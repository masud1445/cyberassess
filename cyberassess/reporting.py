from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any
import json


VERDICT_THRESHOLDS = {
    "COMPLIANT": 90.0,
    "PARTIAL": 70.0,
}

SEVERITY_COLORS = {
    "HIGH": "#b3261e",
    "MEDIUM": "#a86a00",
    "LOW": "#2f6fed",
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


def _score_ring(score: float, color: str) -> str:
    score = max(0.0, min(100.0, float(score)))
    circumference = 326.73
    dash = circumference * score / 100.0
    gap = circumference - dash
    return f"""
    <svg class="score-ring" viewBox="0 0 140 140" role="img" aria-label="Compliance score {score:.1f} percent">
      <circle class="ring-track" cx="70" cy="70" r="52" />
      <circle class="ring-progress" cx="70" cy="70" r="52" stroke="{color}"
              stroke-dasharray="{dash:.2f} {gap:.2f}" />
      <text x="70" y="66" text-anchor="middle" class="ring-number">{score:.1f}%</text>
      <text x="70" y="86" text-anchor="middle" class="ring-label">SCORE</text>
    </svg>
    """


def _all_clear(total_controls: int, errors: int = 0) -> str:
    if errors:
        return (
            '<div class="all-clear assessment-warning" '
            'style="display:flex;align-items:center;gap:8px;'
            'color:#8a5a00;font-weight:700;'
            'border-color:#f0d28a;background:#fff8e8;">'
            '<span aria-hidden="true" style="font-size:1.2em;">!</span>'
            f'<span>No failed controls, but {errors} control'
            f'{"s" if errors != 1 else ""} could not be assessed.</span>'
            '</div>'
        )

    return (
        '<div class="all-clear" '
        'style="display:flex;align-items:center;gap:8px;'
        'color:#0f7a55;font-weight:700;">'
        '<span aria-hidden="true" style="font-size:1.2em;">✓</span>'
        f'<span>No gaps found. All {total_controls} controls passed.</span>'
        '</div>'
    )


def _severity_donut(
    high: int,
    medium: int,
    low: int,
    total_controls: int,
    errors: int = 0,
) -> str:
    total = high + medium + low

    if total == 0:
        return f"""
        <div class="severity-wrap">
            <svg
                class="severity-donut"
                viewBox="0 0 120 120"
                role="img"
                aria-label="Failed controls by severity: 0 gaps"
            >
                <circle
                    cx="60"
                    cy="60"
                    r="40"
                    class="donut-track"
                />
                <text
                    x="60"
                    y="57"
                    text-anchor="middle"
                    class="donut-number"
                >0</text>
                <text
                    x="60"
                    y="72"
                    text-anchor="middle"
                    class="donut-label"
                >GAPS</text>
            </svg>

            <div class="legend">
                {_all_clear(total_controls, errors)}
            </div>
        </div>
        """
    circumference = 251.33
    values = [
        (high, "#b3261e", 0.0),
        (medium, "#a86a00", high),
        (low, "#2f6fed", high + medium),
    ]
    segments = []
    for count, color, previous_count in values:
        length = circumference * count / total
        offset = -(circumference * previous_count / total)
        segments.append(
            f'<circle cx="60" cy="60" r="40" class="donut-segment" stroke="{color}" '
            f'stroke-dasharray="{length:.2f} {circumference - length:.2f}" '
            f'stroke-dashoffset="{offset:.2f}" />'
        )
    return f"""
    <div class="severity-wrap">
      <svg class="severity-donut" viewBox="0 0 120 120" role="img" aria-label="Failed controls by severity">
        <circle cx="60" cy="60" r="40" class="donut-track" />
        {''.join(segments)}
        <text x="60" y="57" text-anchor="middle" class="donut-number">{total}</text>
        <text x="60" y="72" text-anchor="middle" class="donut-label">GAPS</text>
      </svg>
      <div class="legend">
        <div><span class="dot high"></span><span>High</span><strong>{high}</strong></div>
        <div><span class="dot medium"></span><span>Medium</span><strong>{medium}</strong></div>
        <div><span class="dot low"></span><span>Low</span><strong>{low}</strong></div>
      </div>
    </div>
    """


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
            f'<strong>{rate}%</strong></div><div class="bar-track"><div class="bar-fill" '
            f'style="width:{rate}%"></div></div></div>'
        )
    return "".join(rows)


def _status_badge(status: str) -> str:
    value = str(status).upper()
    css = {"PASS": "pass", "FAIL": "fail", "ERROR": "error"}.get(value, "neutral")
    return f'<span class="status-badge {css}">{_safe(value)}</span>'


def _severity_badge(severity: str) -> str:
    value = str(severity).upper()
    return f'<span class="severity-badge {value.lower()}">{_safe(value)}</span>'


def _gap_card(result: dict) -> str:
    severity = str(result.get("severity", "LOW")).upper()
    accent = SEVERITY_COLORS.get(severity, "#667085")
    expected = _safe(_display_value(result, result.get("expected"), expected=True))
    actual = _safe(_display_value(result, result.get("actual")))
    evidence = _safe(_evidence_for_result(result))
    command = _safe(_fix_command(result))
    remediation = _safe(result.get("remediation", ""))
    return f"""
    <article class="gap-card" style="--gap-accent:{accent}">
      <div class="gap-top">
        <div class="gap-heading">{_severity_badge(severity)}<span class="control-id">{_safe(result.get('control_id',''))}</span></div>
        <span class="nist-pill">NIST {_safe(result.get('nist',''))}</span>
      </div>
      <h3>{_safe(result.get('title',''))}</h3>
      <div class="comparison-grid">
        <div class="comparison-box"><span>Expected</span><strong>{expected}</strong></div>
        <div class="comparison-box actual"><span>Found</span><strong>{actual}</strong></div>
      </div>
      <div class="finding-line"><strong>Evidence</strong><span>{evidence}</span></div>
      <div class="remediation-copy"><strong>Recommended remediation</strong><p>{remediation}</p></div>
      <div class="command-label">Suggested command</div>
      <pre class="command-block"><code>{command}</code></pre>
    </article>
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
    scan_date = datetime.now().strftime("%d %B %Y · %H:%M")
    verdict, verdict_color = _verdict(score)

    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    failures = [r for r in results if str(r.get("status", "")).upper() == "FAIL"]
    failures.sort(key=lambda r: (severity_rank.get(str(r.get("severity", "LOW")).upper(), 99), str(r.get("control_id", ""))))
    high = sum(str(r.get("severity", "")).upper() == "HIGH" for r in failures)
    medium = sum(str(r.get("severity", "")).upper() == "MEDIUM" for r in failures)
    low = sum(str(r.get("severity", "")).upper() == "LOW" for r in failures)

    table_rows = []
    for r in results:
        table_rows.append(f"""
        <tr class="row-{_safe(str(r.get('status','')).lower())}">
          <td class="mono">{_safe(r.get('control_id',''))}</td>
          <td><strong>{_safe(r.get('title',''))}</strong><div class="table-category">{_safe(_category_for_result(r))}</div></td>
          <td>{_severity_badge(r.get('severity',''))}</td>
          <td>{_status_badge(r.get('status',''))}</td>
          <td class="mono">{_safe(_display_value(r, r.get('expected'), expected=True))}</td>
          <td class="mono">{_safe(_display_value(r, r.get('actual')))}</td>
          <td><span class="nist-pill">{_safe(r.get('nist',''))}</span></td>
        </tr>
        """)

    threshold_text = "90%+ Compliant · 70–89.9% Partially compliant · Below 70% Non-compliant"
    weighted_text = "Severity-weighted score: High ×3, Medium ×2, Low ×1; FAIL or ERROR earns 0 weight, and ERROR remains in the weighted score denominator."

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberAssess Compliance Report</title>
<style>
:root{{--navy:#0b1f4b;--page:#f6f7fa;--card:#fff;--text:#172033;--muted:#667085;--line:#e2e6ed;--pass:#0f7a55;--pass-soft:#eaf7f1;--fail:#b3261e;--fail-soft:#fceceb;--warn:#a86a00;--warn-soft:#fff4df;--blue:#2f6fed;--blue-soft:#edf3ff;--shadow:0 10px 28px rgba(11,31,75,.07)}}
*{{box-sizing:border-box}} html{{background:var(--page)}} body{{margin:0;background:linear-gradient(180deg,#f3f5f9 0,var(--page) 420px);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;line-height:1.45}} h1,h2,h3{{font-family:Georgia,"Times New Roman",serif}}
.report-shell{{width:min(1180px,calc(100% - 36px));margin:34px auto 60px}} .report-header{{position:relative;overflow:hidden;background:linear-gradient(135deg,var(--navy),#123571);color:#fff;border-radius:22px;padding:34px 38px;box-shadow:0 20px 50px rgba(11,31,75,.18)}} .report-header:after{{content:"";position:absolute;width:280px;height:280px;top:-150px;right:-70px;border:1px solid rgba(255,255,255,.15);border-radius:50%}} .eyebrow{{color:#bcd0ff;font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}} h1{{position:relative;z-index:1;margin:8px 0 14px;font-size:clamp(30px,4vw,44px);line-height:1.08}} .header-meta{{position:relative;z-index:1;display:flex;flex-wrap:wrap;gap:8px}} .chip{{padding:7px 10px;border:1px solid rgba(255,255,255,.18);border-radius:999px;background:rgba(255,255,255,.08);font-size:12px;color:#eef3ff}}
.grid-2{{display:grid;grid-template-columns:minmax(280px,.85fr) minmax(420px,1.6fr);gap:20px;margin-top:20px}} .card{{background:var(--card);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow)}} .score-card{{display:flex;align-items:center;justify-content:center;gap:22px;padding:24px;min-height:225px}} .score-ring{{width:160px;height:160px;flex:0 0 auto}} .ring-track,.ring-progress{{fill:none;stroke-width:12}} .ring-track{{stroke:#e7ebf2}} .ring-progress{{stroke-linecap:round;transform:rotate(-90deg);transform-origin:70px 70px}} .ring-number{{fill:var(--text);font-size:21px;font-weight:800}} .ring-label{{fill:var(--muted);font-size:8px;font-weight:800;letter-spacing:.14em}} .verdict{{margin:4px 0 6px;font:700 24px Georgia,serif;white-space:nowrap}} .small{{color:var(--muted);font-size:12px}}
.metrics{{padding:20px}} .metrics-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}} .metric{{padding:17px;border:1px solid var(--line);border-radius:14px;background:#fbfcfe}} .metric strong{{display:block;font:700 29px Georgia,serif}} .metric.pass strong{{color:var(--pass)}} .metric.fail strong{{color:var(--fail)}} .metric span{{font-size:11px;font-weight:800;color:var(--muted);letter-spacing:.07em;text-transform:uppercase}} .method-note{{margin-top:14px;padding:11px 12px;background:#f7f9fc;border-radius:10px;color:var(--muted);font-size:11px}}
.analytics{{display:grid;grid-template-columns:minmax(260px,.8fr) minmax(360px,1.4fr);gap:20px;margin-top:20px}} .analytics .card{{padding:21px}} .kicker{{color:var(--blue);font-size:10px;font-weight:800;letter-spacing:.11em;text-transform:uppercase}} .section-title{{margin:4px 0 15px;font-size:24px}} .severity-wrap{{display:flex;align-items:center;gap:22px}} .severity-donut{{width:130px;height:130px}} .donut-track,.donut-segment{{fill:none;stroke-width:13}} .donut-track{{stroke:#edf0f5}} .donut-segment{{transform:rotate(-90deg);transform-origin:60px 60px}} .donut-number{{fill:var(--text);font-size:18px;font-weight:800}} .donut-label{{fill:var(--muted);font-size:7px;font-weight:800}} .legend{{display:grid;gap:9px;min-width:125px}} .legend div{{display:grid;grid-template-columns:auto 1fr auto;gap:8px;align-items:center;color:var(--muted);font-size:12px}} .dot{{width:9px;height:9px;border-radius:50%}} .dot.high{{background:var(--fail)}} .dot.medium{{background:var(--warn)}} .dot.low{{background:var(--blue)}} .category-row{{margin-bottom:13px}} .category-meta{{display:flex;justify-content:space-between;font-size:12px;margin-bottom:6px}} .bar-track{{height:8px;background:#e9edf4;border-radius:999px;overflow:hidden}} .bar-fill{{height:100%;background:linear-gradient(90deg,var(--blue),#4e89ff);border-radius:inherit}}
.section{{margin-top:28px}} .section-head{{display:flex;justify-content:space-between;gap:16px;align-items:end;margin-bottom:13px}} .section-head h2{{margin:0;font-size:27px}} .gaps-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}} .gap-card{{padding:18px;border:1px solid var(--line);border-left:5px solid var(--gap-accent);border-radius:15px;background:var(--card);box-shadow:0 7px 22px rgba(11,31,75,.05);break-inside:avoid}} .gap-top,.gap-heading{{display:flex;align-items:center;gap:8px}} .gap-top{{justify-content:space-between}} .control-id{{font:800 11px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted)}} .gap-card h3{{margin:12px 0;font-size:19px;line-height:1.2}} .severity-badge,.status-badge,.nist-pill{{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;font-size:9.5px;font-weight:800;letter-spacing:.05em;white-space:nowrap}} .severity-badge{{padding:5px 8px}} .severity-badge.high{{background:var(--fail-soft);color:var(--fail)}} .severity-badge.medium{{background:var(--warn-soft);color:var(--warn)}} .severity-badge.low{{background:var(--blue-soft);color:var(--blue)}} .status-badge{{min-width:52px;padding:5px 9px}} .status-badge.pass{{background:var(--pass-soft);color:var(--pass)}} .status-badge.fail{{background:var(--fail-soft);color:var(--fail)}} .status-badge.error{{background:var(--warn-soft);color:var(--warn)}} .nist-pill{{padding:5px 8px;border:1px solid #dbe3f2;background:#f7f9fc;color:#41506b}} .comparison-grid{{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin:12px 0}} .comparison-box{{padding:10px;border:1px solid var(--line);border-radius:10px;background:#fafbfc}} .comparison-box.actual{{background:var(--fail-soft);border-color:#f3d4d1}} .comparison-box span{{display:block;color:var(--muted);font-size:9px;font-weight:800;letter-spacing:.06em;text-transform:uppercase}} .comparison-box strong{{font:700 12px ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}} .finding-line,.remediation-copy{{font-size:11px;color:#455066;margin-top:9px}} .finding-line strong,.remediation-copy strong{{display:block;color:var(--text);margin-bottom:2px}} .remediation-copy p{{margin:0}} .command-label{{margin:10px 0 5px;color:var(--muted);font-size:9px;font-weight:800;letter-spacing:.06em;text-transform:uppercase}} .command-block{{margin:0;padding:11px 12px;background:#08152e;color:#dce8ff;border-radius:10px;font:10px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-word;overflow:auto}}
.controls-card{{overflow:hidden;background:var(--card);border:1px solid var(--line);border-radius:15px;box-shadow:var(--shadow)}} .table-wrap{{overflow-x:auto}} table{{width:100%;border-collapse:collapse;font-size:11px}} thead{{background:#f7f9fc}} th{{padding:11px 10px;text-align:left;color:#526079;font-size:9px;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--line)}} td{{padding:10px;vertical-align:top;border-bottom:1px solid #edf0f4}} tbody tr:last-child td{{border-bottom:none}} .row-pass{{background:linear-gradient(90deg,rgba(15,122,85,.035),transparent 35%)}} .row-fail{{background:linear-gradient(90deg,rgba(179,38,30,.035),transparent 35%)}} .row-error{{background:linear-gradient(90deg,rgba(168,106,0,.045),transparent 35%)}} .table-category{{margin-top:2px;color:var(--muted);font-size:9px}} .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}} .footer{{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:24px;padding-top:15px;border-top:1px solid var(--line);font-size:10px;color:var(--muted)}} .footer strong{{color:var(--navy)}} .all-clear{{padding:20px;text-align:center;border:1px solid #cae9dc;border-radius:12px;background:var(--pass-soft);color:var(--pass);font-weight:700}}
@media(max-width:820px){{.report-shell{{width:min(100% - 20px,760px);margin-top:10px}}.grid-2,.analytics,.gaps-grid{{grid-template-columns:1fr}}.report-header{{padding:26px 22px}}}} @media(max-width:560px){{.score-card{{flex-direction:column;text-align:center}}.metrics-grid,.comparison-grid{{grid-template-columns:1fr}}}}
@media(prefers-color-scheme:dark){{:root{{--page:#0a1020;--card:#10192c;--text:#eef3ff;--muted:#a7b2c7;--line:#26324a}} body{{background:#0a1020}} .metric,.comparison-box{{background:#10192c}} thead{{background:#162138}} .nist-pill{{border-color:#33415e;background:#18233a;color:#c6d4ef}}}}
@page{{size:A4;margin:12mm}} @media print{{*{{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}} html,body{{background:#fff!important}} .report-shell{{width:100%;margin:0}} .report-header{{padding:18px 22px;border-radius:10px;box-shadow:none}} .card,.controls-card{{box-shadow:none!important}} .score-card{{gap:12px}} .verdict{{font-size:15px}} h1{{font-size:25px}} .grid-2{{grid-template-columns:.8fr 1.4fr;gap:9px;margin-top:9px}} .score-card{{min-height:150px;padding:12px}} .score-ring{{width:100px;height:100px}} .metrics{{padding:11px}} .metric{{padding:9px}} .metric strong{{font-size:21px}} .method-note{{font-size:8px;padding:6px;margin-top:7px}} .analytics{{gap:9px;margin-top:9px}} .analytics .card{{padding:11px}} .severity-donut{{width:88px;height:88px}} .section{{margin-top:14px}} .section-head{{margin-bottom:7px}} .section-head h2{{font-size:19px}} .gaps-grid{{gap:6px}} .gap-card{{padding:9px;border-radius:9px;box-shadow:none;break-inside:avoid;page-break-inside:avoid}} .gap-card h3{{margin:5px 0;font-size:12px}} .comparison-grid{{margin:5px 0;gap:5px}} .comparison-box{{padding:5px}} .finding-line{{font-size:8px;margin-top:4px}} .remediation-copy{{display:none}} .command-label{{margin:5px 0 3px;font-size:7px}} .command-block{{padding:5px 6px;font-size:7px;line-height:1.35}} .controls-section{{break-before:page;page-break-before:always}} table{{font-size:7.6px}} th,td{{padding:5px}} tr,.controls-card,.gap-card{{break-inside:avoid;page-break-inside:avoid}} .footer{{margin-top:9px;padding-top:7px;font-size:7.5px}}}}
</style>
</head>
<body>
<main class="report-shell">
  <header class="report-header">
    <div class="eyebrow">CyberAssess · Live security assessment</div>
    <h1>Compliance &amp; Baseline Report</h1>
    <div class="header-meta">
      <span class="chip">Target: <strong>{target}</strong></span>
      <span class="chip">{platform}</span>
      <span class="chip">Scan: {scan_date}</span>
      <span class="chip">{total}-control Ubuntu baseline · NIST SP 800-53 mapped</span>
    </div>
  </header>

  <section class="grid-2">
    <div class="card score-card">
      {_score_ring(score, verdict_color)}
      <div><div class="kicker">Assessment verdict</div><p class="verdict" style="color:{verdict_color}">{escape(verdict)}</p><div class="small">Weighted compliance score</div></div>
    </div>
    <div class="card metrics">
      <div class="metrics-grid">
        <div class="metric pass"><strong>{passed}</strong><span>Passed</span></div>
        <div class="metric fail"><strong>{failed}</strong><span>Failed</span></div>
        <div class="metric"><strong>{total}</strong><span>Total controls</span></div>
      </div>
      <div class="method-note"><strong>Verdict thresholds:</strong> {escape(threshold_text)}<br><strong>Scoring:</strong> {escape(weighted_text)}<br><strong>Assessment errors:</strong> {errors}</div>
    </div>
  </section>

  <section class="analytics">
    <div class="card"><div class="kicker">Risk distribution</div><h2 class="section-title">Failed controls</h2>{_severity_donut(high, medium, low, total, errors)}</div>
    <div class="card"><div class="kicker">Coverage</div><h2 class="section-title">Pass rate by category</h2>{_category_bars(results)}</div>
  </section>

  <section class="section gaps-section" style="{'' if failures else 'display:none'}">
    <div class="section-head"><div><div class="kicker">Priority remediation</div><h2>Gaps to fix</h2></div><div class="small">Sorted highest risk first</div></div>
    <div class="gaps-grid">{''.join(_gap_card(r) for r in failures) if failures else _all_clear(total, errors)}</div>
  </section>

  <section class="section controls-section">
    <div class="section-head"><div><div class="kicker">Technical detail</div><h2>All controls</h2></div><div class="small">PASS / FAIL / ERROR</div></div>
    <div class="controls-card"><div class="table-wrap"><table>
      <thead><tr><th>ID</th><th>Control</th><th>Severity</th><th>Result</th><th>Expected</th><th>Actual</th><th>NIST</th></tr></thead>
      <tbody>{''.join(table_rows)}</tbody>
    </table></div></div>
  </section>

  <footer class="footer"><div><strong>CyberAssess</strong> · Automated compliance assessment</div><div>Read-only checks. No settings were changed on the target.</div></footer>
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
