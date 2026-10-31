# CyberAssess — Automated Security Baseline Assessment

## Product overview

**CyberAssess** is a Python-based security baseline assessment application for IT administrators, cybersecurity analysts, small and medium-sized organizations, authorized assessment operators, and training or lab environments.

It performs **read-only live evidence collection** from authorized Ubuntu, Windows and macOS systems, maps selected baseline checks to **NIST SP 800-53 references**, calculates automated PASS / FAIL / ERROR results, and generates machine-readable JSON plus self-contained HTML reports.

| Target profile | Controls | Collection |
| --- | ---: | --- |
| Ubuntu | 15 | Authorized SSH workflow or matching native local execution |
| Windows | 13 | Native local PowerShell queries |
| macOS | 12 | Native local status and safely scoped preference queries |

Windows/macOS run on the machine being assessed. The profiles contain different
control sets and their percentages are not cross-platform rankings. Offline
fixtures remain available for training without reading live security settings.

---

## SME Audit Capability

CyberAssess provides a repeatable first-line security baseline assessment for small organizations that may not have a dedicated security audit team.

The Ubuntu baseline covers:

- SSH hardening;
- host firewall status;
- sensitive file permissions;
- local account security;
- password policy;
- audit logging;
- automatic security updates;
- time synchronization;
- insecure Telnet service detection.

Windows adds checks for selected endpoint protection, encryption, remote access,
machine policy and logging settings. macOS covers FileVault, Application Firewall,
SIP, Gatekeeper, selected update preferences, Remote Login, safely scoped
screen-lock policy and automatic network time. Unsupported or unavailable native
evidence remains ERROR, including macOS update/time settings when the operating
system or allowed permissions expose no reliable state.

Each control includes the expected state, observed state, severity, evidence, framework reference and remediation guidance.

---

## Time Savings

Traditional baseline reviews require an administrator to manually inspect multiple configuration files, services and security settings.

CyberAssess automates this repetitive evidence-gathering process into a single assessment workflow:

**Connect → Collect → Evaluate → Score → Report**

The same controls and evaluation logic are applied consistently on every run, reducing repetitive manual checking and making reassessment faster after remediation.

---

## Operational value

CyberAssess creates value by helping SMEs and IT teams:

- identify configuration gaps earlier;
- prioritize remediation by severity;
- reduce repetitive manual assessment work;
- retain structured assessment evidence;
- compare compatible baseline snapshots before and after separately approved changes;
- track baseline findings across authorized reassessments;
- support internal audit preparation and security awareness training.

The tool can therefore reduce administrative effort while improving consistency, repeatability and visibility of baseline security controls.

---

## Demonstrated Technical Capability

The implementation includes:

**Versioned 15-control Ubuntu, 13-control Windows and 12-control macOS baselines**
**Ubuntu SSH / Paramiko and matching native local evidence collection**
**Severity-weighted baseline scoring**
**PASS / FAIL / ERROR evaluation**
**Automated gap reporting**
**NIST SP 800-53 mappings**
**JSON and HTML reporting**
**Automated evaluator, collector, CLI, report and portability regressions**
**Read-only assessment design**

The repository preserves a historical authorized Ubuntu-lab report. It records
one earlier target state under the then-current collector, not acceptance of
every current platform or receiving machine. Current testing evidence and
native/live acceptance limits are recorded in the
[validation record](portability-validation.md); mocked tests and hosted CI do
not establish effective security correctness on a real deployment target.

Reports identify live native, Ubuntu SSH or demonstration provenance and are
point-in-time snapshots. They show available collection and assessment timing,
target-local offsets and UTC without inventing missing historical timestamps.

---

## Business Positioning

CyberAssess is suitable as an:

**Entry-level SME security baseline checker**
**Internal IT compliance-readiness tool**
**Cybersecurity training and lab assessment application**

It does not replace a formal certified audit, full CIS Benchmark assessment, vulnerability assessment or penetration test.

Its purpose is to provide a practical, repeatable and evidence-based first layer of cybersecurity assessment.

---

**CyberAssess — Automated Security Baseline Assessment**
**Target Platforms:** Ubuntu Linux, native Windows and native macOS
**Assessment Mode:** Read-only
**Framework Mapping:** Selected NIST SP 800-53 controls

For deployment, see the [operator handover](HANDOVER.md),
[control coverage](control_master_table.md) and [training lab](student_lab_manual.md).
The scope is selected operating-system baseline assessment. CyberAssess does not
perform cloud assessment, vulnerability scanning, penetration testing, continuous
monitoring, automatic remediation or compliance certification.
