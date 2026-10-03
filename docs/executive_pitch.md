# CyberAssess — Executive Pitch

## Automated Security Baseline Assessment for SMEs and Training Environments

**CyberAssess** is a lightweight Python-based cybersecurity compliance and baseline assessment tool designed for SMEs, internal IT teams, training providers and students.

It performs **read-only live evidence collection** from authorized Ubuntu Linux systems over SSH, evaluates **15 selected security controls**, maps findings to **NIST SP 800-53 references**, calculates automated PASS / FAIL / ERROR results, and generates machine-readable JSON plus client-ready HTML reports.

---

## SME Audit Capability

CyberAssess provides a repeatable first-line security baseline assessment for small organizations that may not have a dedicated security audit team.

Current assessment areas include:

- SSH hardening;
- host firewall status;
- sensitive file permissions;
- local account security;
- password policy;
- audit logging;
- automatic security updates;
- time synchronization;
- insecure Telnet service detection.

Each control includes the expected state, observed state, severity, evidence, framework reference and remediation guidance.

---

## Time Savings

Traditional baseline reviews require an administrator to manually inspect multiple configuration files, services and security settings.

CyberAssess automates this repetitive evidence-gathering process into a single assessment workflow:

**Connect → Collect → Evaluate → Score → Report**

The same controls and evaluation logic are applied consistently on every run, reducing repetitive manual checking and making reassessment faster after remediation.

---

## Compliance and Operational ROI

CyberAssess creates value by helping SMEs and IT teams:

- identify configuration gaps earlier;
- prioritize remediation by severity;
- reduce repetitive manual assessment work;
- retain structured assessment evidence;
- compare security posture before and after remediation;
- demonstrate measurable compliance improvement;
- support internal audit preparation and security awareness training.

The tool can therefore reduce administrative effort while improving consistency, repeatability and visibility of baseline security controls.

---

## Demonstrated Technical Capability

The current validated implementation includes:

**15 security controls**
**Live SSH / Paramiko evidence collection**
**Severity-weighted compliance scoring**
**PASS / FAIL / ERROR evaluation**
**Automated gap reporting**
**NIST SP 800-53 mappings**
**JSON and HTML reporting**
**Automated evaluator tests**
**Read-only assessment design**

A validated live assessment demonstrated that the tool can collect the current state of an Ubuntu lab, evaluate all configured controls and generate a complete compliance report.

---

## Business Positioning

CyberAssess is suitable as an:

**Entry-level SME security baseline checker**
**Internal IT compliance-readiness tool**
**Cybersecurity teaching and lab assessment platform**

It does not replace a formal certified audit, full CIS Benchmark assessment, vulnerability assessment or penetration test.

Its purpose is to provide a practical, repeatable and evidence-based first layer of cybersecurity assessment.

---

**CyberAssess**
*Automated Compliance & Baseline Assessment Tool*
**Target Platform:** Ubuntu Linux
**Assessment Mode:** Read-only
**Framework Mapping:** Selected NIST SP 800-53 controls