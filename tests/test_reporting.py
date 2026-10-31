"""Presentation contract for portable, platform-aware assessment reports."""

from copy import deepcopy
from html.parser import HTMLParser
import json

import pytest

from cyberassess.reporting import render_html


def report_for(platform="Windows", profile="windows", status="FAIL"):
    return {
        "target_name": "workstation-01",
        "platform": platform,
        "application": {"name": "CyberAssess", "version": "2.0.0"},
        "profile": {"id": profile, "name": f"CyberAssess {platform} Baseline", "version": "1"},
        "assessment_mode": "local",
        "collected_at": "2026-01-02T03:04:05+00:00",
        "assessment": {
            "total_controls": 1,
            "passed": int(status == "PASS"),
            "failed": int(status == "FAIL"),
            "errors": int(status == "ERROR"),
            "compliance_score": 100.0 if status == "PASS" else 0.0,
            "results": [{
                "control_id": "WIN-001" if profile == "windows" else "MAC-001",
                "profile": profile,
                "category": "Encryption",
                "title": "Device encryption enabled",
                "description": "Check the selected device encryption state.",
                "severity": "HIGH",
                "status": status,
                "expected": True,
                "actual": None if status == "ERROR" else status == "PASS",
                "evidence_source": "bitlocker.protection_enabled",
                "raw_evidence": '{"protection_status":"On"}',
                "notes": "Evidence unavailable" if status == "ERROR" else None,
                "nist": "SC-28",
                "remediation": "Review encryption policy with the device owner.",
            }],
        },
    }


class Markup(HTMLParser):
    def __init__(self, document):
        super().__init__()
        self.tags = []
        self.feed(document)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


@pytest.mark.parametrize("platform,profile", [("Windows", "windows"), ("macOS", "macos")])
def test_platform_metadata_and_guidance_without_ubuntu_commands(platform, profile):
    document = render_html(report_for(platform, profile))
    assert f"CyberAssess {platform} Baseline v1" in document
    assert "CyberAssess v2.0.0" in document
    assert "<title>CyberAssess — Automated Security Baseline Assessment · workstation-01</title>" in document
    assert "<h1>Security Baseline Report</h1>" in document
    assert "Weighted baseline score: 0.0%" in document
    assert "· Automated Security Baseline Assessment</div>" in document
    assert "2026-01-02T03:04:05+00:00" in document
    assert "Evidence collected" in document
    assert "bitlocker.protection_enabled" in document
    assert "Check the selected device encryption state." in document
    assert "Review encryption policy with the device owner." in document
    assert "Remediation guidance" in document
    assert "Ubuntu" not in document
    assert "sudo " not in document
    assert "apt-get" not in document
    assert "Assessed (PASS + FAIL)" in document
    assert "<th scope=\"col\">Category</th>" in document


def test_generation_time_does_not_claim_to_be_collection_time():
    report = report_for()
    del report["collected_at"]
    document = render_html(report)
    assert "<dt>Assessment time</dt><dd>Not recorded</dd>" in document
    assert "Evidence collected" not in document
    report["assessment_completed_at"] = "2026-01-02T04:00:00+00:00"
    document = render_html(report)
    assert '<dt>Assessment completed</dt><dd><time datetime="2026-01-02T04:00:00+00:00">02 Jan 2026 · 04:00:00 UTC</time></dd>' in document


def test_demo_is_clearly_distinguished_from_live_assessment():
    report = report_for()
    report["assessment_mode"] = "demo"
    del report["collected_at"]
    document = render_html(report)
    assert "Demonstration data · illustrative results, not a live device assessment." in document
    assert "Evidence collected" not in document


def test_legacy_ubuntu_presentation_retains_known_evidence_and_commands():
    report = report_for("Ubuntu Linux", "ubuntu")
    del report["profile"]
    del report["application"]
    result = report["assessment"]["results"][0]
    result.update(control_id="SSH-001", actual="yes", expected="no")
    document = render_html(report)
    assert "CyberAssess Ubuntu Baseline v1" in document
    assert "PermitRootLogin=yes" in document
    assert "sudo sshd -t" in document
    assert "version not recorded" in document


def test_explicit_non_ubuntu_profile_never_uses_ubuntu_id_lookup():
    report = report_for()
    report["assessment"]["results"][0].update(control_id="SSH-001", actual="yes", expected="no")
    document = render_html(report)
    assert "PermitRootLogin" not in document
    assert "sudo " not in document


def test_html_escapes_metadata_evidence_and_guidance():
    report = report_for()
    injection = '<img src=x onerror="alert(1)">'
    report["target_name"] = injection
    report["platform"] = injection
    report["profile"]["name"] = injection
    result = report["assessment"]["results"][0]
    for field in ("title", "description", "actual", "expected", "notes", "remediation", "evidence_source", "category", "nist"):
        result[field] = injection
    result["raw_evidence"] = injection
    document = render_html(report)
    assert injection not in document
    assert "&lt;img" in document
    assert not any(tag in {"script", "img", "iframe"} for tag, _ in Markup(document).tags)


def test_only_allowlisted_scalar_raw_status_fields_are_displayed():
    report = report_for(status="PASS")
    result = report["assessment"]["results"][0]
    result["raw_evidence"] = json.dumps({
        "protection_status": "On", "password": "hidden-credential",
        "environment": {"TOKEN": "hidden-token"},
        "stdout": "hidden-arbitrary-output",
    })
    report["evidence"] = {"secret": "hidden-full-evidence"}
    report["collector"] = {"method": "local", "private_key": "hidden-key"}
    document = render_html(report)
    assert "protection_status&quot;: &quot;On" in document
    for value in ("hidden-credential", "hidden-token", "hidden-arbitrary-output", "hidden-full-evidence", "hidden-key"):
        assert value not in document


@pytest.mark.parametrize("raw", [
    "-----BEGIN OPENSSH PRIVATE KEY-----\nhidden-key\n-----END OPENSSH PRIVATE KEY-----",
    '{"password":"hidden-password"}',
    "arbitrary untrusted command output hidden-token",
])
def test_unknown_raw_evidence_is_not_serialized(raw):
    report = report_for()
    report["assessment"]["results"][0]["raw_evidence"] = raw
    document = render_html(report)
    assert "hidden-key" not in document
    assert "hidden-password" not in document
    assert "hidden-token" not in document


def test_sensitive_structured_values_and_recognizable_credentials_are_redacted():
    report = report_for()
    result = report["assessment"]["results"][0]
    result["actual"] = {"password": "hidden-dict-value"}
    result["notes"] = 'password=hidden-password; {"client_secret":"hidden-secret"}; Authorization: Bearer hidden-bearer'
    result["raw_evidence"] = ""
    document = render_html(report)
    for value in ("hidden-dict-value", "hidden-password", "hidden-secret", "hidden-bearer"):
        assert value not in document
    assert "credential field redacted" in document


def test_macos_synthesized_raw_prefix_is_safe_and_clipped_to_status():
    report = report_for("macOS", "macos")
    result = report["assessment"]["results"][0]
    result.update(evidence_source="filevault.enabled", raw_evidence="filevault.enabled=true; hidden-untrusted-suffix")
    document = render_html(report)
    assert "filevault.enabled=true" in document
    assert "hidden-untrusted-suffix" not in document


def test_evidence_clips_large_values_without_rendering_unknown_raw_output():
    report = report_for()
    result = report["assessment"]["results"][0]
    result["actual"] = "a" * 1000 + "hidden-trailing-value"
    result["raw_evidence"] = "b" * 5000 + "hidden-trailing-raw"
    document = render_html(report)
    assert "a" * 600 + "…" in document
    assert "hidden-trailing-value" not in document
    assert "hidden-trailing-raw" not in document


@pytest.mark.parametrize("platform,profile,source,diagnostic", [
    ("Windows", "windows", "bitlocker.protection_enabled", "Read-only query failed; the feature, policy, or required permissions may be unavailable."),
    ("macOS", "macos", "remote_login.enabled", "Unavailable: native query requires additional local privileges."),
])
def test_safe_collection_diagnostic_is_visible_for_new_profile_errors(platform, profile, source, diagnostic):
    report = report_for(platform, profile, status="ERROR")
    result = report["assessment"]["results"][0]
    result.update(evidence_source=source, raw_evidence=diagnostic)
    document = render_html(report)
    assert "Collection diagnostic" in document
    assert diagnostic in document


def test_collection_diagnostics_are_redacted_escaped_and_bounded():
    report = report_for(status="ERROR")
    result = report["assessment"]["results"][0]
    result["raw_evidence"] = (
        'Read-only query failed; password=hidden-password; Authorization: Bearer hidden-bearer; '
        '<img src=x onerror="alert(1)">; '
        '-----BEGIN OPENSSH PRIVATE KEY-----\nhidden-key\n-----END OPENSSH PRIVATE KEY-----; '
        + "x" * 1000 + "hidden-trailing-diagnostic"
    )
    document = render_html(report)
    assert "Collection diagnostic" in document
    assert "&lt;img" in document
    for value in ("hidden-password", "hidden-bearer", "hidden-key", "hidden-trailing-diagnostic"):
        assert value not in document
    assert not any(tag == "img" for tag, _ in Markup(document).tags)


def test_quoted_credentials_with_spaces_and_escapes_are_redacted_entirely():
    report = report_for(status="ERROR")
    result = report["assessment"]["results"][0]
    result["raw_evidence"] = (
        'Read-only query failed; password="hidden first and last"; '
        "client_secret='hidden quoted secret'; "
        r'api_key="hidden escaped \" quote"; AWS_SECRET_ACCESS_KEY=hidden-access-key'
    )
    document = render_html(report)
    for value in ("hidden first", "first and last", "quoted secret", "hidden escaped", "access-key"):
        assert value not in document
    assert "Collection diagnostic" in document


@pytest.mark.parametrize("status,profile,source", [
    ("PASS", "windows", "bitlocker.protection_enabled"),
    ("ERROR", "ubuntu", "sshd.PermitRootLogin"),
    ("ERROR", "windows", "unknown.value"),
])
def test_diagnostics_never_expose_legacy_unknown_or_successful_collection_output(status, profile, source):
    report = report_for(status=status)
    result = report["assessment"]["results"][0]
    result.update(profile=profile, evidence_source=source, raw_evidence="Read-only query hidden-diagnostic")
    document = render_html(report)
    assert "Collection diagnostic" not in document
    assert "hidden-diagnostic" not in document


def test_all_pass_and_unavailable_states_are_distinct():
    passed = render_html(report_for(status="PASS"))
    unavailable = render_html(report_for(status="ERROR"))
    assert "All assessed controls passed" in passed
    assert "No remediation gaps were identified" in passed
    assert "Assessment incomplete" in unavailable
    assert "All assessed controls passed" not in unavailable
    assert "Evidence unavailable" in unavailable
    assert "ERROR" in unavailable


def test_empty_report_is_not_presented_as_compliant():
    document = render_html({"assessment": {"results": []}})
    assert "Not assessed" in document
    assert "No controls assessed" in document
    assert "Baseline not recorded" in document
    assert "All assessed controls passed" not in document
    assert 'colspan="8"' in document


def test_print_appendix_retains_full_evidence_and_guidance_outside_narrow_table_cells():
    report = report_for(status="ERROR")
    result = report["assessment"]["results"][0]
    result["raw_evidence"] = "Read-only query failed; required permissions may be unavailable."
    document = render_html(report)
    appendix = document.partition('<section class="section print-evidence-section"')[2]
    assert appendix
    for value in ("WIN-001", "Device encryption enabled", "bitlocker.protection_enabled",
                  "Observed state", "Remediation guidance", "Evidence unavailable",
                  "required permissions may be unavailable", "Review encryption policy with the device owner."):
        assert value in appendix
    assert "<details" not in appendix
    articles = [attrs for tag, attrs in Markup(document).tags if tag == "article" and attrs.get("class") == "print-evidence-article"]
    assert len(articles) == 1
    assert ".print-evidence-section { display: none; }" in document
    assert ".print-evidence-section { display: block; }" in document
    assert ".evidence-details, .remediation-details { display: none !important; }" in document


def test_assessment_error_review_message_uses_singular_grammar():
    assert "1 control requires review" in render_html(report_for(status="ERROR"))


def test_render_is_offline_accessible_and_does_not_mutate_input():
    report = report_for()
    original = deepcopy(report)
    document = render_html(report)
    assert report == original
    assert "@page { size: A4 portrait" in document
    assert "@media print" in document
    assert "@media screen and (max-width: 480px)" in document
    assert "table-header-group" in document
    assert "content-visibility: visible" in document
    assert "focus-visible" in document
    assert "<details" in document
    tags = Markup(document).tags
    assert not any(tag in {"script", "link", "img", "iframe"} for tag, _ in tags)
    assert any(tag == "div" and attrs.get("role") == "region" and attrs.get("tabindex") == "0" for tag, attrs in tags)
    assert "does not automatically modify target security settings" in document
