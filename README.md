# CyberAssess

CyberAssess is a read-only automated cybersecurity compliance and baseline assessment tool for authorized Ubuntu/Linux systems. It uses Python and Paramiko to collect live evidence over SSH, evaluates 15 security controls, produces PASS / FAIL / ERROR results, calculates a severity-weighted compliance score, and generates JSON plus premium self-contained HTML reports.

## Internship alignment — Pillar 2 / Sub-Track 2.1

This project addresses automated compliance and baseline assessment by:

- collecting live OS security configuration evidence over SSH;
- comparing evidence against a defined Ubuntu security baseline;
- mapping controls to NIST SP 800-53 references;
- automatically generating PASS / FAIL / ERROR results and a gap report;
- providing remediation guidance for lab and SME readiness use;
- supporting a repeatable **assess → fix → reassess** workflow.

## Current baseline

CyberAssess evaluates 15 controls across:

- SSH hardening
- host firewall
- sensitive file permissions
- local account security
- password policy
- audit logging
- automatic security updates
- time synchronization
- insecure Telnet service exposure

The active baseline is stored in `config/controls.json`.

## Result semantics

- **PASS** — evidence was collected and satisfies the baseline.
- **FAIL** — evidence was collected and does not satisfy the baseline.
- **ERROR** — CyberAssess could not reliably collect or interpret the evidence.

## Scoring

CyberAssess uses severity weights:

- HIGH = 3
- MEDIUM = 2
- LOW = 1

The compliance score is the weighted percentage of passing scoreable controls. ERROR controls are excluded from the score denominator because they represent an assessment failure rather than confirmed compliance or non-compliance.

### Report verdict thresholds

- **90–100%** — Compliant
- **70–89.9%** — Partially compliant
- **Below 70%** — Non-compliant

These labels are report classifications; the underlying numeric score is not changed by the classification.

## Setup on macOS

```bash
cd ~/Projects/cyberassess
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=.
```

## Run automated tests

```bash
pytest -q
```

## Demo mode

```bash
python main.py --demo
```

Demo mode uses `samples/demo_evidence.json`; it does not connect to a live host.

## Live audit

Use CyberAssess only against systems you own or are explicitly authorized to assess.

```bash
python main.py \
  --host 192.168.252.2 \
  --user ubuntu \
  --key ~/.ssh/cyberassess_lab
```

If the host key has not yet been trusted in the lab:

```bash
python main.py \
  --host 192.168.252.2 \
  --user ubuntu \
  --key ~/.ssh/cyberassess_lab \
  --accept-new-host
```

## Reports

Each assessment produces:

- JSON — machine-readable evidence and results
- HTML — self-contained client/supervisor-ready report with score, risk distribution, category coverage, gap cards, remediation guidance and full control table

The collector is read-only. Remediation commands shown in the report are guidance only and are never executed automatically.

## Project structure

```text
cyberassess/
├── main.py
├── requirements.txt
├── config/
│   └── controls.json
├── cyberassess/
│   ├── collector.py
│   ├── evaluator.py
│   └── reporting.py
├── samples/
│   └── demo_evidence.json
├── tests/
│   └── test_evaluator.py
├── docs/
│   ├── student_lab_manual.md
│   ├── executive_pitch.md
│   └── work_log_template.md
└── reports/
```

## Safety and scope

CyberAssess is a baseline assessment and teaching/readiness tool. It is not a replacement for a formal compliance audit or penetration test. Always preserve administrative access and validate configuration changes before reloading SSH or enabling firewall rules.
