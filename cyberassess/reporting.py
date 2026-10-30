from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any
import json
import re

from cyberassess.timestamps import aware_datetime, display_timestamp


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
    if result.get("category"):
        return str(result["category"])
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


def _display_value(result: dict, value: Any, expected: bool = False, ubuntu: bool = True) -> str:
    """Convert raw values into clearer security-language labels."""
    control_id = str(result.get("control_id", "")).upper()
    if ubuntu and control_id == "SSH-005":
        if expected:
            return "> 0 sec"
        if value is not None:
            return f"{_evidence_text(value)} sec"
    if ubuntu and control_id == "UPD-001" and isinstance(value, bool):
        return "Enabled" if value else "Disabled"
    if ubuntu and control_id == "SVC-001" and isinstance(value, bool):
        return "Installed" if value else "Not installed"
    if isinstance(value, bool):
        return "true" if value else "false"
    return _evidence_text(value if value is not None else "Not available")


def _evidence_text(value: Any, limit: int = 600) -> str:
    """Bound displayed evidence and redact recognizable credential material.

    Collectors are responsible for producing non-sensitive evidence. This extra
    display boundary never serializes arbitrary nested input or entire sources.
    """
    if isinstance(value, (dict, list, tuple)):
        return "Structured evidence omitted; review the normalized control value."
    text = str(value)
    text = re.sub(r"-----BEGIN [^-]*(?:PRIVATE KEY|OPENSSH)[^-]*-----.*?(?:-----END [^-]+-----|$)",
                  "[credential material redacted]", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"\bauthorization[\"']?\s*[:=]\s*[\"']?bearer\s+[^\s;,\"']+",
                  "[credential field redacted]", text, flags=re.IGNORECASE)
    credential_field = (
        r"\b(?:password|passwd|(?:access[_-]?|refresh[_-]?)?token|(?:client[_-]?)?secret|"
        r"api[_-]?key|authorization|private[_-]?key|"
        r"aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key|session[_-]?token))"
        r"\b[\"']?\s*[:=]\s*"
    )
    text = re.sub(credential_field + r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')''',
                  "[credential field redacted]", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(credential_field + r"[\"']?[^\s;,\"']+",
                  "[credential field redacted]", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16})\b",
                  "[credential redacted]", text)
    return text[:limit] + ("…" if len(text) > limit else "")


def _evidence_for_result(result: dict, ubuntu: bool = True) -> str:
    """Return only the evidence relevant to this control."""
    control_id = str(result.get("control_id", "")).upper()
    actual = _display_value(result, result.get("actual"), ubuntu=ubuntu)
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
    label = labels.get(control_id) if ubuntu else None
    if label:
        return f"{label}={actual}"
    return actual


_WINDOWS_RAW_FIELDS = {
    "defender": {"antivirus_enabled", "realtime_enabled"},
    "firewall": {"Domain", "Private", "Public"},
    "bitlocker": {"protection_status"},
    "rdp": {"deny_connections"},
    "rdp_nla": {"user_authentication"},
    "guest": {"enabled"},
    "uac": {"enable_lua"},
    "smb": {"smb1_enabled"},
    "inactivity": {"timeout_seconds"},
    "secure_boot": {"enabled"},
    "eventlog": {"status"},
}
_MACOS_EVIDENCE_SOURCES = {
    "filevault", "application_firewall", "system_integrity", "gatekeeper",
    "update_check", "update_download", "security_updates", "system_data_updates",
    "remote_login", "screen_lock", "screen_lock_delay", "network_time",
}


def _safe_raw_evidence(result: dict) -> str:
    """Expose only known, scalar collector status fields; never arbitrary raw data."""
    source = str(result.get("evidence_source", ""))
    source_name = source.partition(".")[0]
    raw = result.get("raw_evidence")
    if not isinstance(raw, str) or len(raw) > 4000:
        return ""
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        parsed = None
    if isinstance(parsed, dict):
        approved = {}
        for key in _WINDOWS_RAW_FIELDS.get(source_name, set()):
            value = parsed.get(key)
            if isinstance(value, (bool, int, float)) or (
                isinstance(value, str) and value in {"On", "Off", "Running", "Stopped", "Unknown"}
            ):
                approved[key] = value
        if approved:
            return _evidence_text(json.dumps(approved, sort_keys=True, ensure_ascii=False), 900)
    # macOS collectors synthesize this prefix from the normalized scalar only.
    prefix = raw.partition(";")[0]
    if source_name in _MACOS_EVIDENCE_SOURCES and re.fullmatch(
        re.escape(source) + r"=(?:true|false|[0-9]{1,10})", prefix
    ):
        return prefix
    return ""


def _collection_diagnostic(result: dict) -> str:
    """Show bounded diagnostics emitted by the new, sanitized local collectors."""
    if str(result.get("status", "")).upper() != "ERROR":
        return ""
    profile = result.get("profile")
    source = str(result.get("evidence_source", "")).partition(".")[0]
    raw = result.get("raw_evidence")
    if not isinstance(raw, str):
        return ""
    known_windows = profile == "windows" and source in _WINDOWS_RAW_FIELDS and raw.startswith(
        ("Read-only query ", "PowerShell could not run;")
    )
    known_macos = profile == "macos" and source in _MACOS_EVIDENCE_SOURCES and raw.startswith("Unavailable:")
    return _evidence_text(raw, 800) if known_windows or known_macos else ""


def _fix_command(result: dict, ubuntu: bool = True) -> str:
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
    return commands.get(control_id, "") if ubuntu else ""


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
        heading = "All assessed controls passed"
        description = (
            f"All {total_controls} controls passed the configured baseline. "
            "Retain this report as a point-in-time record and reassess after configuration changes."
        )
        state = "complete"
    return (
        f'<div class="assessment-state {state}">'
        '<span class="state-symbol" aria-hidden="true">'
        f'{"✓" if state == "complete" else "!" if state == "incomplete" else "—"}</span>'
        f'<div><h3>{heading}</h3><p>{description}</p></div></div>'
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
        tone = "complete" if rate == 100 else "partial" if rate else "unmet"
        rows.append(
            f'<div class="category-row {tone}"><div class="category-meta"><span>{_safe(category)}</span>'
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


def _evidence_details(result: dict, ubuntu: bool = True, printable: bool = False) -> str:
    notes = result.get("notes")
    note_html = f'<p class="collection-note"><strong>Collection note:</strong> {_safe(_evidence_text(notes))}</p>' if notes else ""
    description = result.get("description")
    description_html = f'<p class="control-description">{_safe(_evidence_text(description, 1200))}</p>' if description else ""
    source = _safe(_evidence_text(result.get("evidence_source") or "Not recorded"))
    raw = _safe_raw_evidence(result)
    raw_html = f'<div><h4>Supporting status</h4><pre class="raw-evidence">{_safe(raw)}</pre></div>' if raw else ""
    diagnostic = _collection_diagnostic(result)
    diagnostic_html = f'<div><h4>Collection diagnostic</h4><p class="evidence-value">{_safe(diagnostic)}</p></div>' if diagnostic else ""
    remediation = _safe(_evidence_text(result.get("remediation") or "Review the selected baseline and your organization’s security policy.", 1600))
    source_html = f'<div><h4>Evidence source</h4><p class="evidence-value">{source}</p></div>'
    observed_html = f'<div><h4>Observed state</h4><p class="evidence-value">{_safe(_evidence_for_result(result, ubuntu))}</p></div>'
    remediation_html = f'<div><h4>Remediation guidance</h4><p>{remediation}</p></div>'
    if printable:
        command = _fix_command(result, ubuntu) if str(result.get("status", "")).upper() == "FAIL" else ""
        command_html = (
            '<div class="print-command"><h4>Suggested command · review before use</h4>'
            f'<pre class="command-block"><code>{_safe(command)}</code></pre></div>' if command else ""
        )
        return f"""
        <article class="print-evidence-article">
          <div class="print-evidence-heading"><span class="control-id">{_safe(result.get('control_id', ''))}</span>{_status_badge(result.get('status', ''))}<h3>{_safe(result.get('title', ''))}</h3></div>
          <div class="print-evidence-grid">
            <div class="print-evidence-column">{source_html}{observed_html}{raw_html}{diagnostic_html}{note_html}</div>
            <div class="print-evidence-column">{description_html}{remediation_html}</div>
          </div>
          {command_html}
        </article>
        """
    return f"""
    <details class="evidence-details">
      <summary>Evidence &amp; guidance<span class="sr-only"> for {_safe(result.get('control_id', 'control'))}</span></summary>
      <div class="details-body">
        {description_html}
        {source_html}
        {observed_html}
        {raw_html}
        {diagnostic_html}
        {note_html}
        {remediation_html}
      </div>
    </details>
    """


def _gap_card(result: dict, ubuntu: bool = True) -> str:
    expected = _safe(_display_value(result, result.get("expected"), expected=True, ubuntu=ubuntu))
    actual = _safe(_display_value(result, result.get("actual"), ubuntu=ubuntu))
    evidence = _safe(_evidence_for_result(result, ubuntu))
    command = _fix_command(result, ubuntu)
    command_html = (
        '<div class="command-section"><h4>Suggested command · review before use</h4>'
        f'<pre class="command-block"><code>{_safe(command)}</code></pre></div>'
        if command else ""
    )
    remediation = _safe(_evidence_text(result.get("remediation") or "Review the selected baseline and your organization’s security policy.", 1600))
    source_html = f'<p class="collection-note">Source: {_safe(_evidence_text(result["evidence_source"]))}</p>' if result.get("evidence_source") else ""
    control_id = _safe(result.get("control_id", ""))
    severity_class = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(str(result.get("severity", "")).upper(), "neutral")
    return f"""
    <article class="gap-card severity-{severity_class}">
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
          <div><h4>Observed evidence</h4><p class="evidence-value">{evidence}</p>{source_html}</div>
          <div><h4>Recommended remediation</h4><p>{remediation}</p></div>
          {command_html}
        </div>
      </details>
    </article>
    """


_REPORT_CSS = """
:root {
  color-scheme: light;
  --navy: #122b48;
  --ink: #25384c;
  --muted: #576a7e;
  --line: #dce4ed;
  --surface: #f3f6fa;
  --pass: #16704f;
  --fail: #b1363e;
  --warn: #926017;
  --info: #28679b;
  --shadow: 0 5px 18px rgb(16 35 58 / 5%);
}
* { box-sizing: border-box; }
html { background: #e9eef4; scroll-padding-top: 90px; }
body {
  display: flow-root;
  margin: 0;
  min-height: 100vh;
  color: var(--ink);
  background: linear-gradient(180deg, #142a43 0, #233d57 230px, #dce5ee 500px, #edf1f6 850px);
  font: 13px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
  -webkit-text-size-adjust: 100%;
}
h1, h2, h3, h4, p, dl { margin: 0; }
h1, h2, h3 { color: var(--navy); }
h1 { font-size: 34px; font-weight: 650; line-height: 1.2; letter-spacing: -.035em; }
h2 { font-size: 22px; font-weight: 650; line-height: 1.3; letter-spacing: -.025em; }
h3 { font-size: 14px; font-weight: 650; }
h4, dt { color: var(--muted); font-size: 11.5px; font-weight: 600; }
dd { margin: 0; }
a { color: var(--info); }
.report-shell { width: calc(100% - 64px); max-width: 1320px; margin: 32px auto 48px; }
.report-header { padding: 26px 30px 0; overflow: hidden; border: 1px solid #3b526b; border-radius: 16px; background: linear-gradient(115deg, #173553, #0b1c33); box-shadow: 0 12px 28px rgb(5 17 34 / 15%); color: #e5edf5; }
.masthead { display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 24px; }
.brand { display: inline-flex; gap: 9px; align-items: center; color: #fff; font-size: 17px; font-weight: 650; letter-spacing: -.025em; }
.brand-mark { width: 23px; height: 25px; color: #b7cce0; }
.document-label { font-size: 11.5px; color: #b9cadd; }
.platform-badge { display: inline-flex; align-items: center; gap: 8px; padding: 7px 11px; border: 1px solid #526980; border-radius: 6px; background: #263f59; color: #edf4fc; font-size: 11.5px; font-weight: 600; }
.platform-badge svg { width: 16px; height: 16px; flex-shrink: 0; }
.header-title-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; }
.report-header h1 { color: #fff; }
.subtitle { margin-top: 9px; color: #bed0e2; font-size: 12px; }
.header-target { padding-top: 3px; min-width: 120px; max-width: 260px; text-align: right; }
.header-target span { display: block; color: #b9cadd; font-size: 11px; margin-bottom: 4px; }
.header-target strong { color: #fff; font: 600 14px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
.metadata { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 17px 24px; margin-top: 24px; padding: 20px 0 22px; border-top: 1px solid #3e556d; }
.metadata dt { color: #b9cadd; font-size: 10.5px; margin-bottom: 4px; }
.metadata dd { color: #f0f4f9; font-size: 11.5px; overflow-wrap: anywhere; }
.metadata .metadata-wide { grid-column: span 2; }
.sample-notice { display: flex; gap: 7px; align-items: baseline; margin-top: 15px; color: #e5d2ab; font-size: 11px; }
.sample-notice::before { content: "i"; display: inline-flex; justify-content: center; align-items: center; width: 13px; height: 13px; flex-shrink: 0; border: 1px solid #b9a583; border-radius: 50%; font-size: 9px; font-weight: 600; }
.report-nav { position: sticky; top: 12px; z-index: 5; display: flex; align-items: center; gap: 6px; margin: 16px 0 20px; padding: 8px; border: 1px solid #d5e0eb; border-radius: 10px; background: #f9fbfd; box-shadow: 0 4px 14px rgb(15 36 61 / 9%); }
.nav-label { padding: 0 12px; color: var(--muted); font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
.report-nav a { display: inline-flex; align-items: center; gap: 7px; padding: 7px 12px; border-radius: 6px; color: #425c76; font-size: 12px; font-weight: 600; text-decoration: none; }
.report-nav a:hover { color: var(--navy); background: #e9eff6; }
.report-nav a:first-of-type { color: #fff; background: var(--navy); }
.nav-count { min-width: 17px; padding: 0 4px; border: 1px solid #cbd8e5; border-radius: 4px; color: #536d86; font-size: 10px; line-height: 16px; text-align: center; font-variant-numeric: tabular-nums; }
.section { min-width: 0; margin-top: 20px; padding: 24px; border: 1px solid var(--line); border-radius: 13px; background: #fff; box-shadow: var(--shadow); }
.section-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 20px; }
.section-head .small { text-align: right; }
.small { color: var(--muted); font-size: 11.5px; }
.summary-cards { display: grid; grid-template-columns: 1.2fr 1.45fr repeat(4, minmax(0, 1fr)); gap: 12px; }
.summary-card { min-width: 0; min-height: 156px; padding: 16px; border: 1px solid var(--line); border-radius: 9px; background: #fff; box-shadow: 0 3px 9px rgb(20 44 71 / 3%); }
.score-card { background: #f1f5fa; border-color: #cfdae7; }
.score-label, .card-label { color: var(--muted); font-size: 11.5px; font-weight: 600; }
.score-ring { position: relative; display: grid; place-items: center; width: 106px; height: 106px; margin: 11px auto 0; border-radius: 50%; background: conic-gradient(var(--score-tone, var(--info)) var(--score-angle), #dce5ee 0); }
.score-ring::before { content: ""; position: absolute; inset: 8px; border-radius: 50%; background: #f1f5fa; }
.score-value { position: relative; color: var(--navy); font-size: 30px; font-weight: 650; line-height: 1.1; letter-spacing: -.05em; font-variant-numeric: tabular-nums; }
.score-value span { font-size: 14px; margin-left: 2px; letter-spacing: 0; }
.verdict-card { display: flex; flex-direction: column; align-items: flex-start; background: #f9fbfd; }
.verdict { display: block; margin-top: 23px; font-size: 20px; font-weight: 650; line-height: 1.25; letter-spacing: -.02em; }
.verdict-card .card-note { margin-top: auto; padding-top: 12px; }
.verdict-card.compliant .verdict { color: var(--pass); }
.verdict-card.partial .verdict { color: var(--warn); }
.verdict-card.non-compliant .verdict { color: var(--fail); }
.verdict-card.not-assessed .verdict { color: var(--muted); }
.metric { display: flex; flex-direction: column; }
.metric dt { display: flex; align-items: baseline; gap: 6px; }
.metric dt::before { content: ""; width: 6px; height: 6px; flex-shrink: 0; border-radius: 50%; background: var(--info); }
.metric dd { margin-top: 23px; color: var(--navy); font-size: 32px; font-weight: 600; line-height: 1.15; letter-spacing: -.03em; font-variant-numeric: tabular-nums; }
.metric-pass dt::before { background: var(--pass); }
.metric-fail dt::before { background: var(--fail); }
.metric-error dt::before { background: #b37b26; }
.metric-pass dd { color: var(--pass); }
.metric-fail dd { color: var(--fail); }
.metric-error dd { color: var(--warn); }
.card-note { margin-top: auto; padding-top: 12px; color: var(--muted); font-size: 10.5px; }
.summary-content { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; margin-top: 18px; padding: 16px 0 0; border-top: 1px solid var(--line); }
.summary-copy p { max-width: 82ch; color: var(--muted); font-size: 12px; }
.summary-copy p + p { margin-top: 5px; }
.assessed-count { flex-shrink: 0; color: var(--muted); font-size: 11px; text-align: right; }
.assessed-count strong { display: block; color: var(--navy); font-size: 17px; font-weight: 600; font-variant-numeric: tabular-nums; }
.methodology { position: relative; margin-top: 12px; font-size: 11px; color: var(--muted); }
.methodology .details-body { padding: 8px 0 0 18px; }
.methodology p + p { margin-top: 5px; }
.analytics-grid { display: grid; grid-template-columns: minmax(0, 1.9fr) minmax(0, 1fr); gap: 20px; }
.analytics-grid .section { height: auto; }
.analytics-grid .section-head { align-items: flex-start; gap: 8px; }
.analytics-grid .section-head h2 { font-size: 20px; }
.analytics-grid .section-head .small { max-width: 160px; font-size: 10.5px; }
.category-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 19px 24px; }
.category-meta { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; margin-bottom: 7px; font-size: 11.5px; font-weight: 500; overflow-wrap: anywhere; }
.category-count { flex-shrink: 0; color: var(--muted); font-size: 10.5px; font-weight: 400; font-variant-numeric: tabular-nums; }
.bar-track { height: 9px; border-radius: 4px; background: #e8edf3; overflow: hidden; }
.bar-fill { height: 100%; background: #437398; border-radius: 4px; box-shadow: inset 0 1px rgb(255 255 255 / 16%); }
.category-row.complete .bar-fill { background: #367e65; }
.category-row.unmet .bar-track { background: #eee5e7; }
.risk-intro { color: var(--muted); font-size: 11.5px; margin-bottom: 18px; }
.severity-summary { display: grid; gap: 13px; }
.severity-stat { display: grid; grid-template-columns: 58px minmax(0, 1fr) 26px; align-items: center; gap: 10px; font-size: 12px; }
.severity-label { color: var(--muted); font-weight: 500; }
.risk-track { height: 9px; background: #edf0f4; border-radius: 4px; overflow: hidden; }
.risk-fill { height: 100%; border-radius: 4px; min-width: 0; }
.severity-stat.high .risk-fill { background: #b34f55; }
.severity-stat.medium .risk-fill { background: #b58743; }
.severity-stat.low .risk-fill { background: #6489a7; }
.severity-stat strong { text-align: right; font-size: 17px; font-weight: 600; font-variant-numeric: tabular-nums; }
.severity-stat.high strong { color: var(--fail); }
.severity-stat.medium strong { color: var(--warn); }
.severity-stat.low strong { color: var(--info); }
.risk-note { margin-top: 19px; padding-top: 12px; border-top: 1px solid var(--line); color: var(--muted); font-size: 10.5px; }
.findings-list { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.gap-card { min-width: 0; padding: 17px; border: 1px solid var(--line); border-left: 3px solid #8294a7; border-radius: 8px; background: #fff; box-shadow: 0 2px 6px rgb(14 37 62 / 3%); }
.gap-card.severity-high { border-left-color: #b34f55; }
.gap-card.severity-medium { border-left-color: #b58743; }
.gap-card.severity-low { border-left-color: #6489a7; }
.gap-top, .gap-heading { display: flex; align-items: center; gap: 9px; }
.gap-top { justify-content: space-between; flex-wrap: wrap; }
.control-id, .mono, .evidence-value, .command-block { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.control-id { font-size: 11.5px; font-weight: 600; color: #425c76; }
.nist-reference { color: var(--muted); font-size: 11px; overflow-wrap: anywhere; }
.gap-summary { margin: 12px 0; }
.gap-summary h3 { font-size: 14px; line-height: 1.45; }
.comparison { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; margin-top: 12px; padding: 11px 12px; border: 1px solid #e6ebf1; border-radius: 6px; background: #f5f7fa; }
.comparison dt { margin-bottom: 4px; font-size: 10.5px; }
.comparison dd { font: 11.5px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
.severity-badge { display: inline-flex; align-items: center; padding: 2px 6px; border-radius: 4px; color: var(--muted); background: #eef2f6; font-size: 9.5px; font-weight: 650; line-height: 1.5; letter-spacing: .025em; }
.severity-badge.high { color: #9b3038; background: #f8eaec; }
.severity-badge.medium { color: #815619; background: #f7f0e4; }
.severity-badge.low { color: #35668b; background: #eaf1f7; }
.status-badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 6px; border: 1px solid transparent; border-radius: 4px; font-size: 9.5px; font-weight: 650; line-height: 1.4; white-space: nowrap; }
.status-badge::before { font-size: 10px; }
.status-badge.pass { color: #176547; background: #e9f4ee; border-color: #cfe5d9; }
.status-badge.pass::before { content: "✓"; }
.status-badge.fail { color: #a3313a; background: #faedef; border-color: #eed7da; }
.status-badge.fail::before { content: "×"; }
.status-badge.error { color: #885b17; background: #fbf2e1; border-color: #ecdec1; }
.status-badge.error::before { content: "!"; }
.status-badge.neutral { color: var(--muted); background: #eef2f6; }
summary { position: relative; display: flex; align-items: baseline; gap: 7px; width: fit-content; max-width: 100%; cursor: pointer; color: #43627f; font-size: 11.5px; font-weight: 500; list-style: none; }
summary::-webkit-details-marker { display: none; }
summary::marker { content: ""; }
summary::before { content: ""; display: inline-block; width: 5px; height: 5px; margin-right: 2px; flex-shrink: 0; border-right: 1.5px solid currentColor; border-bottom: 1.5px solid currentColor; transform: rotate(-45deg); }
details[open] > summary::before { transform: rotate(45deg); }
summary:hover { color: var(--navy); }
a:focus-visible, summary:focus-visible, .table-wrap:focus-visible { outline: 2px solid #286da5; outline-offset: 4px; border-radius: 3px; }
.details-body { padding-top: 9px; }
.remediation-details, .evidence-details { position: relative; border: 1px solid #dfe7ef; border-radius: 6px; background: #f5f8fb; }
.remediation-details > summary, .evidence-details > summary { width: 100%; padding: 8px 10px; font-size: 10.5px; }
.remediation-details[open] > summary, .evidence-details[open] > summary { border-bottom: 1px solid #dfe7ef; }
.remediation-body { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 18px; padding: 11px; font-size: 11px; }
.remediation-body h4 { margin-bottom: 4px; }
.evidence-value, .raw-evidence { font: 11px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; white-space: pre-wrap; margin: 0; }
.command-section { grid-column: 1 / -1; min-width: 0; }
.command-block { margin: 0; padding: 10px 12px; border: 1px solid var(--line); border-radius: 5px; background: #edf2f7; color: #2b465f; font-size: 10px; line-height: 1.6; white-space: pre-wrap; overflow-wrap: anywhere; }
.assessment-state { display: flex; align-items: center; gap: 15px; padding: 21px; border: 1px solid #d7e2ec; border-radius: 8px; background: #f3f7fb; }
.assessment-state.complete { border-color: #d0e5d9; background: #f1f8f4; }
.state-symbol { display: inline-grid; place-items: center; width: 37px; height: 37px; flex-shrink: 0; border: 1px solid #c6d6e4; border-radius: 50%; color: #4e6c86; font-size: 20px; font-weight: 500; }
.assessment-state.complete .state-symbol { color: var(--pass); border-color: #bcdac9; background: #e5f1e9; }
.assessment-state.complete h3 { color: var(--pass); }
.assessment-state.incomplete { border-color: #ead9b7; background: #fbf6ed; }
.assessment-state.incomplete .state-symbol { color: var(--warn); border-color: #e4ceaa; }
.assessment-state p { margin-top: 5px; max-width: 90ch; font-size: 12px; color: var(--muted); }
.errors-section { border-top: 3px solid #b9883c; }
.error-explainer { display: flex; align-items: flex-start; gap: 11px; margin-bottom: 16px; padding: 12px 14px; border: 1px solid #eadfc9; border-radius: 7px; background: #fbf6ec; color: #725222; font-size: 12px; }
.error-list { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.error-item { min-width: 0; padding: 15px; border: 1px solid #eadfc9; border-left: 3px solid #b9883c; border-radius: 7px; background: #fffdf8; }
.error-heading { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 7px; }
.error-heading h3 { flex-basis: 100%; margin-top: 2px; }
.error-item > p { font-size: 12px; color: #725b3b; overflow-wrap: anywhere; }
.error-item .evidence-details { margin-top: 12px; }
.table-wrap { overflow: auto; max-height: 780px; border: 1px solid var(--line); border-radius: 8px; }
.table-hint { margin-bottom: 10px; color: var(--muted); font-size: 10.5px; }
table { width: 100%; min-width: 1080px; table-layout: fixed; border-collapse: separate; border-spacing: 0; text-align: left; font-size: 12.5px; line-height: 1.5; }
caption { padding: 11px 13px; text-align: left; color: var(--muted); background: #f8fafc; font-size: 10.5px; border-bottom: 1px solid var(--line); }
col.col-id { width: 9%; } col.col-category { width: 11%; } col.col-control { width: 26%; } col.col-severity { width: 8%; }
col.col-status { width: 8%; } col.col-expected { width: 12%; } col.col-actual { width: 15%; } col.col-nist { width: 11%; }
thead { background: #eaf0f6; }
th, td { padding: 12px 9px; vertical-align: top; border-bottom: 1px solid #e1e7ef; overflow-wrap: anywhere; }
thead th { position: sticky; top: 0; z-index: 2; padding-top: 11px; padding-bottom: 11px; background: #eaf0f6; box-shadow: 0 1px #cad7e4; font-size: 10.5px; font-weight: 650; color: #3c5671; }
tbody tr:nth-child(even) { background: #f8fafd; }
tbody tr:hover { background: #f0f5fa; }
tbody tr:last-child > * { border-bottom: 0; }
tbody th { font-size: 11px; font-weight: 600; color: #425c76; }
.control-title { font-weight: 600; line-height: 1.45; color: #263d54; }
.table-category { color: #536b82; font-size: 11px; font-weight: 500; }
.category-tag { display: inline-block; padding: 2px 6px; border: 1px solid #dde5ed; border-radius: 4px; background: #f0f4f8; font-size: 10px; line-height: 1.5; }
.table-wrap td.mono { font-size: 11px; }
.evidence-details { margin-top: 9px; }
.evidence-details .details-body { display: grid; gap: 9px; padding: 10px; font-size: 11px; }
.evidence-details h4 { margin-bottom: 3px; font-size: 10.5px; }
.collection-note { margin-top: 6px; color: var(--muted); }
.footer { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 6px 20px; margin-top: 22px; padding: 0 3px; color: #566b80; font-size: 10.5px; }
.footer-statement { flex-basis: 100%; margin-top: 4px; }
.print-evidence-section { display: none; }
.footer strong { color: var(--navy); font-weight: 600; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; border: 0; }
@media screen and (max-width: 1160px) {
  .report-shell { width: calc(100% - 40px); margin-top: 20px; }
  .summary-cards { grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .score-card, .verdict-card { grid-column: span 2; min-height: 145px; }
  .score-card { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
  .score-ring { margin: 0; flex-shrink: 0; }
  .verdict-card .verdict { margin-top: 15px; }
  .metric { min-height: 134px; }
  .metric dd { margin-top: 14px; }
  .analytics-grid { grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr); }
  .analytics-grid .section-head { flex-direction: column; }
  .analytics-grid .section-head .small { text-align: left; max-width: none; }
  .findings-list, .error-list { grid-template-columns: 1fr; }
  .gap-summary { display: grid; grid-template-columns: minmax(0, 1fr) minmax(230px, .9fr); gap: 20px; align-items: center; }
  .comparison { margin-top: 0; }
}
@media screen and (max-width: 800px) {
  .report-header { padding: 23px 24px 0; }
  h1 { font-size: 30px; }
  .header-title-row { display: block; }
  .header-target { display: none; }
  .metadata { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 15px 22px; }
  .section { padding: 22px; }
  .summary-content { gap: 18px; }
  .analytics-grid { grid-template-columns: 1fr; gap: 0; }
  .analytics-grid .section-head { flex-direction: row; }
  .analytics-grid .section-head .small { max-width: 160px; text-align: right; }
  .severity-summary { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 18px; }
  .severity-stat { grid-template-columns: 1fr auto; gap: 8px; }
  .severity-stat .risk-track { order: 3; grid-column: 1 / -1; }
  .risk-intro { margin-bottom: 12px; }
  .risk-note { margin-top: 14px; }
  .gap-summary { grid-template-columns: 1fr; gap: 11px; }
  .report-nav { top: 8px; }
}
@media screen and (max-width: 480px) {
  html { scroll-padding-top: 78px; }
  .report-shell { width: calc(100% - 24px); margin: 12px auto 26px; }
  .report-header { padding: 19px 17px 0; border-radius: 12px; }
  .masthead { gap: 8px; margin-bottom: 21px; }
  .brand { font-size: 16px; gap: 7px; }
  .brand-mark { width: 20px; }
  .platform-badge { font-size: 10px; padding: 6px 8px; gap: 6px; }
  h1 { font-size: 28px; }
  h2 { font-size: 21px; }
  .subtitle { font-size: 11.5px; line-height: 1.6; }
  .metadata { gap: 15px 14px; margin-top: 19px; padding: 17px 0; }
  .metadata dt { font-size: 10px; }
  .metadata dd { font-size: 11px; }
  .sample-notice { align-items: baseline; font-size: 10.5px; line-height: 1.5; }
  .report-nav { gap: 3px; padding: 6px; margin: 12px 0 14px; border-radius: 8px; }
  .nav-label { display: none; }
  .report-nav a { justify-content: center; gap: 4px; padding: 7px; font-size: 10.5px; flex: 1; }
  .nav-count { display: none; }
  .section { padding: 18px 15px; margin-top: 14px; border-radius: 10px; }
  .section-head, .analytics-grid .section-head { align-items: flex-start; flex-direction: column; gap: 5px; margin-bottom: 16px; }
  .section-head .small, .analytics-grid .section-head .small { max-width: none; text-align: left; font-size: 10.5px; }
  .summary-cards { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; }
  .summary-card { padding: 13px; }
  .score-card, .verdict-card { grid-column: span 2; min-height: 126px; }
  .score-card { padding: 15px 19px; }
  .score-label { max-width: 90px; font-size: 13px; }
  .score-ring { width: 94px; height: 94px; }
  .score-value { font-size: 29px; }
  .verdict-card { min-height: 116px; }
  .verdict-card .verdict { margin-top: 9px; }
  .verdict-card .card-note { padding-top: 9px; }
  .metric { min-height: 128px; }
  .metric dd { font-size: 30px; }
  .card-note { font-size: 10px; }
  .summary-content { flex-direction: column; gap: 12px; margin-top: 15px; padding-top: 13px; }
  .assessed-count { display: flex; align-items: baseline; gap: 8px; text-align: left; }
  .assessed-count strong { display: inline; order: -1; }
  .category-grid, .remediation-body { grid-template-columns: 1fr; }
  .category-grid { gap: 17px; }
  .category-meta { font-size: 11.5px; }
  .severity-summary { gap: 12px; }
  .severity-stat { font-size: 11px; }
  .severity-stat strong { font-size: 16px; }
  .gap-card, .error-item { padding: 13px; }
  .gap-top { gap: 7px; }
  .gap-heading { gap: 7px; }
  .comparison { gap: 12px; padding: 10px; }
  .comparison dd { font-size: 11px; }
  .assessment-state { padding: 15px; align-items: flex-start; gap: 10px; }
  .state-symbol { width: 29px; height: 29px; font-size: 17px; }
  .error-explainer { gap: 8px; padding: 11px; font-size: 11px; }
  .error-explainer .status-badge { flex-shrink: 0; }
}
@page { size: A4 portrait; margin: 14mm 12mm; }
@media print {
  html, body { background: #fff; }
  body { font-size: 9pt; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .report-shell { width: auto; max-width: none; margin: 0; padding: 0; border: 0; }
  .report-header { padding: 10px 0 0; border: 0; border-top: 3px solid var(--navy); border-radius: 0; background: #fff; color: var(--ink); box-shadow: none; }
  .report-header h1, .brand { color: var(--navy); }
  .masthead { margin-bottom: 16px; }
  .brand { font-size: 11pt; }
  .brand-mark { width: 18px; height: 19px; color: var(--navy); }
  .platform-badge { color: var(--navy); border-color: var(--line); background: #f3f6fa; padding: 4px 7px; font-size: 7pt; }
  .header-target { display: none; }
  .report-nav { display: none; }
  h1 { font-size: 21pt; } h2 { font-size: 12pt; } h3 { font-size: 10pt; }
  .subtitle { color: var(--muted); font-size: 8pt; }
  .metadata { gap: 10px 16px; margin-top: 14px; padding: 12px 0; border-color: var(--line); border-bottom: 1px solid var(--line); }
  .metadata dt, h4 { color: var(--muted); font-size: 7pt; } .metadata dd { color: var(--ink); font-size: 8pt; }
  .sample-notice { color: #725222; font-size: 7pt; margin-top: 8px; }
  .section { margin-top: 18px; padding: 0; border: 0; border-radius: 0; background: #fff; box-shadow: none; }
  .section-head { margin-bottom: 10px; break-after: avoid; }
  .section-head .small { font-size: 7pt; }
  .summary-cards { grid-template-columns: 1.25fr 1.45fr repeat(4, minmax(0, 1fr)); gap: 6px; }
  .summary-card { padding: 8px; min-height: 100px; border-radius: 4px; box-shadow: none; }
  .score-label, .card-label, .metric dt { font-size: 7pt; }
  .score-ring { width: 67px; height: 67px; margin-top: 6px; border: 5px solid #d6e1ea; background: none; }
  .score-ring::before { display: none; }
  .score-value { font-size: 18pt; } .score-value span { font-size: 9pt; }
  .verdict { margin-top: 14px; font-size: 10pt; }
  .metric dd { margin-top: 14px; font-size: 20pt; }
  .card-note { font-size: 6pt; padding-top: 8px; }
  .summary-content { margin-top: 10px; padding-top: 9px; gap: 16px; }
  .summary-copy p, .assessment-state p { font-size: 8pt; }
  .assessed-count { font-size: 7pt; }
  .assessed-count strong { font-size: 11pt; }
  .methodology { margin-top: 8px; font-size: 7pt; }
  .analytics-grid { grid-template-columns: minmax(0, 1.9fr) minmax(0, 1fr); gap: 20px; }
  .analytics-grid .section-head h2 { font-size: 12pt; }
  .analytics-grid .section-head { display: block; }
  .analytics-grid .section-head .small { display: block; text-align: left; font-size: 6.5pt; max-width: none; }
  .category-grid { gap: 10px 16px; }
  .category-meta { font-size: 7pt; margin-bottom: 4px; }
  .category-count { font-size: 6.5pt; }
  .bar-track, .risk-track { height: 5px; }
  .bar-fill { box-shadow: none; }
  .risk-intro { margin-bottom: 10px; font-size: 7pt; }
  .severity-summary { gap: 8px; }
  .severity-stat { grid-template-columns: 36px minmax(0, 1fr) 18px; gap: 7px; font-size: 7pt; }
  .severity-stat strong { font-size: 10pt; }
  .risk-note { margin-top: 10px; padding-top: 7px; font-size: 6.5pt; }
  .no-results .risk-intro { margin-bottom: 6px; }
  .no-results .severity-summary { display: flex; gap: 14px; }
  .no-results .severity-stat { display: flex; flex: 1; justify-content: space-between; }
  .no-results .risk-track { display: none; }
  .no-results .risk-note { margin-top: 6px; padding-top: 6px; }
  .category-row, .assessment-state, .gap-card, .error-item { break-inside: avoid; page-break-inside: avoid; }
  .findings-list, .error-list { display: block; }
  .gap-card { margin-top: 8px; padding: 10px 12px; box-shadow: none; border-radius: 4px; }
  .gap-summary { display: grid; grid-template-columns: minmax(0, 1fr) minmax(180px, .8fr); gap: 16px; margin: 7px 0 0; align-items: center; }
  .gap-summary h3 { font-size: 9pt; }
  .comparison { margin-top: 0; padding: 7px 9px; gap: 12px; }
  .comparison dt { font-size: 6.5pt; }
  .comparison dd { font-size: 7pt; }
  .assessment-state { padding: 13px; border-radius: 4px; }
  .state-symbol { width: 29px; height: 29px; font-size: 16px; }
  .error-explainer { margin-bottom: 10px; padding: 9px 11px; font-size: 7.5pt; }
  .error-item { margin-top: 8px; padding: 9px 12px; }
  .error-item > p { font-size: 8pt; }
  .error-heading { margin-bottom: 4px; }
  .error-heading h3 { flex-basis: auto; font-size: 9pt; margin: 0; }
  .remediation-body { font-size: 8pt; }
  .command-block, .evidence-value, .raw-evidence { font-size: 7pt; }
  details > .details-body { display: block !important; }
  details::details-content { content-visibility: visible !important; display: block !important; }
  summary { font-size: 7pt; cursor: default; } summary::before { display: none; }
  .table-wrap { overflow: visible; max-height: none; border: 0; border-radius: 0; }
  .screen-only { display: none; }
  .table-hint { display: none; }
  table { min-width: 0; border-collapse: collapse; font-size: 7.5pt; line-height: 1.4; }
  col.col-id { width: 10.5%; } col.col-nist { width: 9.5%; }
  caption { padding: 0 0 8px; font-size: 7pt; background: none; border: 0; }
  .evidence-details, .remediation-details { display: none !important; }
  thead { display: table-header-group; }
  tr { break-inside: avoid; page-break-inside: avoid; }
  th, td { padding: 7px 5px; }
  thead th { position: static; box-shadow: none; }
  thead th, tbody th, .severity-badge, .status-badge, .nist-reference, .table-category { font-size: 6.5pt; }
  .status-badge { padding: 2px 4px; gap: 2px; }
  .status-badge::before { font-size: 7px; }
  .severity-badge { padding: 2px 4px; }
  .category-tag { font-size: 6pt; padding: 1px 3px; }
  .table-wrap td.mono { font-size: 7pt; }
  .control-title { font-size: 7.5pt; }
  .print-evidence-section { display: block; }
  .print-evidence-article { padding: 10px 0; border-top: 1px solid var(--line); break-inside: avoid; page-break-inside: avoid; font-size: 8pt; line-height: 1.4; }
  .print-evidence-heading { display: flex; align-items: baseline; gap: 8px; margin-bottom: 6px; }
  .print-evidence-heading h3 { flex: 1; font-size: 9pt; }
  .print-evidence-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 20px; }
  .print-evidence-column > * + * { margin-top: 5px; }
  .print-evidence-column h4 { display: inline; }
  .print-evidence-column h4::after { content: ": "; }
  .print-evidence-column > div > p, .print-evidence-column > div > pre { display: inline; }
  .print-command { margin-top: 8px; }
  .print-command h4 { margin-bottom: 4px; }
  .footer { margin-top: 16px; font-size: 7pt; }
}
"""


def _presentation_mode(report: dict, collector: dict) -> str:
    """Identify provenance for legacy and versioned reports without inventing it.

    Sample metadata always retains the demonstration warning. Conflicting live
    metadata cannot establish either local or SSH provenance. This affects only
    presentation; the assessment and its machine-readable values are unchanged.
    """
    modes = {
        value.lower() for value in (report.get("assessment_mode"), collector.get("mode"))
        if isinstance(value, str) and value.lower() in {"demo", "local", "ssh"}
    }
    if collector.get("sample_data") is True:
        modes.add("demo")
    method = collector.get("method")
    if isinstance(method, str):
        method = method.lower()
        if "sample" in method or "demo" in method:
            modes.add("demo")
        elif method.startswith("ssh / "):
            modes.add("ssh")
        elif method.startswith("local / "):
            modes.add("local")
    if "demo" in modes:
        return "demo"
    return next(iter(modes)) if len(modes) == 1 else "Not recorded"


def _report_time(value: Any) -> str:
    parsed = aware_datetime(value)
    if parsed is None:
        return "Not recorded with a timezone"
    return f'<time datetime="{_safe(parsed.isoformat())}">{_safe(display_timestamp(parsed, utc=True))}</time>'


def render_html(report: dict) -> str:
    assessment = report.get("assessment", {})
    results = list(assessment.get("results", []))
    score = float(assessment.get("compliance_score", 0.0))
    passed = int(assessment.get("passed", 0))
    failed = int(assessment.get("failed", 0))
    errors = int(assessment.get("errors", 0))
    total = int(assessment.get("total_controls", len(results)))
    profile = report.get("profile") if isinstance(report.get("profile"), dict) else {}
    application = report.get("application") if isinstance(report.get("application"), dict) else {}
    platform_name = report.get("platform") or profile.get("platform") or "Unknown"
    profile_id = str(profile.get("id", "")).lower()
    ubuntu = profile_id in {"ubuntu", "ubuntu-core"} if profile else "ubuntu" in str(platform_name).lower()
    profile_name = profile.get("name") or ("CyberAssess Ubuntu Baseline" if ubuntu else "Baseline not recorded")
    profile_version = profile.get("version") or ("1" if ubuntu else None)
    profile_label = str(profile_name) + (f" v{profile_version}" if profile_version else "")
    version = application.get("version")
    product_label = "CyberAssess" + (f" v{version}" if version else " · version not recorded")
    target = _safe(report.get("target_name", "Unknown"))
    platform = _safe(platform_name)
    generated_at = display_timestamp(datetime.now(timezone.utc), utc=True)
    collector = report.get("collector") if isinstance(report.get("collector"), dict) else {}
    method = _safe(collector.get("method", "Not provided"))
    mode = _presentation_mode(report, collector)
    timestamp_label = "Evidence collected"
    timestamp = report.get("collected_at") or collector.get("collected_at")
    if not timestamp:
        timestamp_label = "Assessment completed"
        timestamp = report.get("assessment_completed_at") or collector.get("assessment_completed_at")
    if not timestamp:
        timestamp_label = "Assessment time"
        timestamp = "Not recorded"
    elif aware_datetime(timestamp) is None:
        timestamp = "Not recorded with a timezone"
    verdict, _ = _verdict(score)
    verdict_class = {
        "Compliant": "compliant", "Partially compliant": "partial", "Non-compliant": "non-compliant"
    }.get(verdict, "not-assessed") if results else "not-assessed"
    score_tone = {"compliant": "var(--pass)", "partial": "var(--warn)", "non-compliant": "var(--fail)"}.get(verdict_class, "var(--muted)")
    score_angle = min(100.0, max(0.0, score)) * 3.6

    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    failures = [r for r in results if str(r.get("status", "")).upper() == "FAIL"]
    failures.sort(key=lambda r: (severity_rank.get(str(r.get("severity", "LOW")).upper(), 99), str(r.get("control_id", ""))))
    high = sum(str(r.get("severity", "")).upper() == "HIGH" for r in failures)
    medium = sum(str(r.get("severity", "")).upper() == "MEDIUM" for r in failures)
    low = sum(str(r.get("severity", "")).upper() == "LOW" for r in failures)
    error_results = [r for r in results if str(r.get("status", "")).upper() == "ERROR"]
    failure_count = len(failures)
    risk_bars = "".join(
        f'<div class="severity-stat {tone}"><span class="severity-label">{label}</span>'
        f'<div class="risk-track" aria-hidden="true"><div class="risk-fill" style="width:{count / failure_count * 100 if failure_count else 0:.1f}%"></div></div>'
        f'<strong>{count}</strong></div>'
        for tone, label, count in (("high", "High", high), ("medium", "Medium", medium), ("low", "Low", low))
    )

    metadata = [
        ("Target", target),
        ("Platform", platform),
        ("Baseline / profile", _safe(profile_label)),
        ("Assessment mode", _safe(mode.upper() if mode.lower() == "ssh" else mode.capitalize())),
        (timestamp_label, _safe(timestamp) if timestamp == "Not recorded" else _report_time(timestamp)),
        ("Collection method", method),
        ("Application", _safe(product_label)),
        ("Report generated", _safe(generated_at)),
    ]
    for key, label in (("assessment_started_at", "Assessment started"),
                       ("assessment_completed_at", "Assessment completed")):
        value = report.get(key) or collector.get(key)
        if value and label != timestamp_label:
            metadata.append((label, _report_time(value)))
    target_clock = aware_datetime(collector.get("target_local_time"))
    if mode == "demo":
        clock_text = "Not applicable · demonstration data"
    elif target_clock is None:
        clock_text = "Not recorded · target local timezone unavailable"
    else:
        clock_text = display_timestamp(target_clock) + " / " + display_timestamp(target_clock, utc=True)
    metadata.append(("Target clock (local / UTC)", _safe(clock_text)))
    if mode != "demo":
        for key, label in (("time_source", "Collection clock source"),
                           ("time_limitations", "Clock limitations"),
                           ("scope", "Collection scope"),
                           ("limitations", "Evidence limitations"),
                           ("privileges", "Read permissions")):
            if collector.get(key):
                metadata.append((label, _safe(_evidence_text(collector[key], 600))))
    for key, label in (("host", "Connection host"), ("username", "Collection account")):
        if collector.get(key):
            metadata.append((label, _safe(collector[key])))
    wide_fields = {"Target clock (local / UTC)", "Clock limitations", "Collection scope", "Evidence limitations"}
    metadata_html = "".join(
        f'<div class="metadata-wide"><dt>{label}</dt><dd>{value}</dd></div>'
        if label in wide_fields else f"<div><dt>{label}</dt><dd>{value}</dd></div>"
        for label, value in metadata
    )

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
          <td class="table-category"><span class="category-tag">{_safe(_category_for_result(r))}</span></td>
          <td><div class="control-title">{_safe(r.get('title', ''))}</div>{_evidence_details(r, ubuntu)}</td>
          <td>{_severity_badge(r.get('severity', ''))}</td>
          <td>{_status_badge(r.get('status', ''))}</td>
          <td class="mono">{_safe(_display_value(r, r.get('expected'), expected=True, ubuntu=ubuntu))}</td>
          <td class="mono">{_safe(_display_value(r, r.get('actual'), ubuntu=ubuntu))}</td>
          <td class="nist-reference">{_safe(r.get('nist', ''))}</td>
        </tr>
        """)
    if not table_rows:
        table_rows.append('<tr><td colspan="8">No control results available.</td></tr>')

    if failures:
        findings_html = f"""
        <div class="findings-list">{''.join(_gap_card(r, ubuntu) for r in failures)}</div>
        """
    else:
        findings_html = _all_clear(total if results else 0, errors)

    errors_html = ""
    if errors:
        error_items = "".join(f"""
        <article class="error-item">
          <div class="error-heading"><span class="control-id">{_safe(r.get('control_id', ''))}</span>{_status_badge('ERROR')}<h3>{_safe(r.get('title', ''))}</h3></div>
          <p>{_safe(_evidence_text(r.get('notes') or 'Evidence could not be reliably collected or interpreted.'))}</p>
          {_evidence_details(r, ubuntu)}
        </article>
        """ for r in error_results)
        errors_html = f"""
        <section class="section errors-section" aria-labelledby="errors-title">
          <div class="section-head"><h2 id="errors-title">Assessment errors</h2><span class="small">{errors} control{'s require' if errors != 1 else ' requires'} review</span></div>
          <div class="error-explainer">{_status_badge('ERROR')}<p>These controls were not assessed because evidence was unavailable or could not be reliably interpreted. ERROR indicates a collection or interpretation issue, not a confirmed insecure setting.</p></div>
          <div class="error-list">{error_items or '<p class="small">Collection details were not provided.</p>'}</div>
        </section>
        """

    threshold_text = "90%+ Compliant · 70–89.9% Partially compliant · Below 70% Non-compliant"
    weighted_text = "Severity-weighted score: High ×3, Medium ×2, Low ×1; FAIL or ERROR earns 0 weight, and ERROR remains in the weighted score denominator."
    scope_note = (
        "CyberAssess performs read-only baseline assessment and does not automatically modify target security settings. "
        "Remediation guidance and suggested commands require operator review and are never run automatically. "
        "Baseline outcomes are not formal compliance certification."
    )
    if mode == "demo":
        sample_notice = '<p class="sample-notice">Demonstration data · illustrative results, not a live device assessment.</p>'
    else:
        source_notice = {
            "local": "Live native assessment · read-only evidence from the local target.",
            "ssh": "Live Ubuntu SSH assessment · collect only from an authorized target.",
        }.get(mode, "Assessment source not verified · collection mode was not recorded consistently.")
        sample_notice = f'<p class="subtitle assessment-source">{source_notice}</p>'
    errors_nav = f'<a href="#errors-title">Errors<span class="nav-count">{errors}</span></a>' if errors else ""
    print_evidence = f"""
    <section class="section print-evidence-section" aria-labelledby="print-evidence-title">
      <div class="section-head"><h2 id="print-evidence-title">Control evidence &amp; guidance</h2><span class="small">Technical reference · commands are display-only</span></div>
      {''.join(_evidence_details(r, ubuntu, printable=True) for r in results)}
    </section>
    """ if results else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberAssess Compliance Report · {target}</title>
<style>{_REPORT_CSS}</style>
</head>
<body>
<main class="report-shell{' no-results' if not results else ''}">
  <header class="report-header">
    <div class="masthead">
      <div class="brand"><svg class="brand-mark" viewBox="0 0 24 27" fill="none" aria-hidden="true"><path d="M12 2 22 6v7c0 6-5 10-10 12C7 23 2 19 2 13V6l10-4Z" stroke="currentColor" stroke-width="1.7"/><path d="m7.5 13 3 3 6-6" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>CyberAssess</div>
      <span class="platform-badge"><svg viewBox="0 0 20 20" fill="none" aria-hidden="true"><rect x="2.5" y="3" width="15" height="10.5" rx="1.5" stroke="currentColor" stroke-width="1.3"/><path d="M7 17h6m-3-3v3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>{platform}</span>
    </div>
    <div class="header-title-row">
      <div><h1>Compliance &amp; Baseline Report</h1><p class="subtitle">{_safe(profile_label)} · mapped to relevant NIST SP 800-53 controls</p></div>
      <div class="header-target"><span>Assessment target</span><strong>{target}</strong></div>
    </div>
    {sample_notice}
    <dl class="metadata">{metadata_html}</dl>
  </header>

  <nav class="report-nav screen-only" aria-label="Report sections">
    <span class="nav-label">Report</span>
    <a href="#summary-title">Summary</a>
    <a href="#findings-title">Findings<span class="nav-count">{failed}</span></a>
    {errors_nav}
    <a href="#controls-title">All Controls<span class="nav-count">{total}</span></a>
  </nav>

  <section class="section summary-section" aria-labelledby="summary-title">
    <div class="section-head"><h2 id="summary-title">Assessment summary</h2><span class="small">Point-in-time baseline review</span></div>
    <div class="summary-cards">
      <div class="summary-card score-card">
        <div class="score-label">Weighted compliance score</div>
        <div class="score-ring" style="--score-angle:{score_angle:.1f}deg;--score-tone:{score_tone}" role="img" aria-label="Weighted compliance score: {score:.1f}%"><div class="score-value" aria-hidden="true">{score:.1f}<span>%</span></div></div>
      </div>
      <div class="summary-card verdict-card {verdict_class}"><div class="card-label">Baseline verdict</div><div class="verdict">{escape(verdict) if results else 'Not assessed'}</div><p class="card-note">Severity-weighted baseline result</p></div>
      <div class="summary-card metric metric-pass"><dl><dt>Passed</dt><dd>{passed}</dd></dl><p class="card-note">Baseline met</p></div>
      <div class="summary-card metric metric-fail"><dl><dt>Failed</dt><dd>{failed}</dd></dl><p class="card-note">Remediation needed</p></div>
      <div class="summary-card metric metric-error"><dl><dt>Errors / unavailable</dt><dd>{errors}</dd></dl><p class="card-note">Not assessed</p></div>
      <div class="summary-card metric"><dl><dt>Total controls</dt><dd>{total}</dd></dl><p class="card-note">Selected baseline</p></div>
    </div>
    <div class="summary-content">
      <div class="summary-copy"><p>{summary_text}</p>{error_notice}<p>This report is a point-in-time snapshot and does not refresh automatically. Re-run a live assessment for current evidence.</p><p>Baseline outcomes are not formal compliance certification.</p></div>
      <div class="assessed-count">Assessed (PASS + FAIL)<strong>{passed + failed} / {total}</strong></div>
    </div>
    <details class="methodology">
      <summary>Scoring methodology &amp; verdict thresholds</summary>
      <div class="details-body"><p>{escape(threshold_text)}</p><p>{escape(weighted_text)}</p></div>
    </details>
  </section>

  <div class="analytics-grid">
    <section class="section coverage-section" aria-labelledby="coverage-title">
      <div class="section-head"><h2 id="coverage-title">Pass rate by category</h2><span class="small">Passed / total controls · unweighted</span></div>
      <div class="category-grid">{_category_bars(results)}</div>
    </section>
    <section class="section risk-section" aria-labelledby="risk-title">
      <div class="section-head"><h2 id="risk-title">Risk summary</h2><span class="small">Failed controls only</span></div>
      <p class="risk-intro">Prioritize confirmed baseline gaps by severity.</p>
      <div class="severity-summary" aria-label="Failed controls by severity">{risk_bars}</div>
      <p class="risk-note">ERROR controls are shown separately as unavailable evidence.</p>
    </section>
  </div>

  <section class="section gaps-section" aria-labelledby="findings-title">
    <div class="section-head"><h2 id="findings-title">Remediation findings</h2><span class="small">{'Highest severity first' if failures else 'Baseline review'}</span></div>
    {findings_html}
  </section>

  {errors_html}

  <section class="section controls-section" aria-labelledby="controls-title">
    <div class="section-head"><h2 id="controls-title">All controls</h2><span class="small">PASS / FAIL / ERROR</span></div>
    <p class="table-hint" id="table-hint">Scroll horizontally to view all columns.</p>
    <div class="table-wrap" role="region" aria-labelledby="controls-title" aria-describedby="table-hint" tabindex="0"><table>
      <caption>Control results and baseline comparison.<span class="screen-only"> Expand Evidence &amp; guidance for supporting details.</span></caption>
      <colgroup><col class="col-id"><col class="col-category"><col class="col-control"><col class="col-severity"><col class="col-status"><col class="col-expected"><col class="col-actual"><col class="col-nist"></colgroup>
      <thead><tr><th scope="col">ID</th><th scope="col">Category</th><th scope="col">Control</th><th scope="col">Severity</th><th scope="col">Result</th><th scope="col">Expected</th><th scope="col">Actual</th><th scope="col">NIST</th></tr></thead>
      <tbody>{''.join(table_rows)}</tbody>
    </table></div>
  </section>

  {print_evidence}

  <footer class="footer"><div><strong>{_safe(product_label)}</strong> · Automated Baseline Assessment</div><div>{_safe(profile_label)}</div><div>Generated {_safe(generated_at)}</div><div class="footer-statement">{scope_note}</div></footer>
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
