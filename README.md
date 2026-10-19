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

The compliance score is the severity-weighted percentage of passing controls:

```text
score = round(100 × sum(weights of PASS controls) / sum(weights of all controls), 1)
```

Both FAIL and ERROR controls contribute their severity weight to the denominator and earn zero passing weight. ERROR still means unavailable or unreliable evidence, rather than confirmed non-compliance. With no controls, the score is 0.0.

For example, this baseline has total weight 35. If 14 controls pass and the weight-1 TIME-001 control has an ERROR, the score is `34 / 35 × 100 = 97.1%`. Review assessment errors even when the numerical verdict is Compliant.

### Report verdict thresholds

- **90–100%** — Compliant
- **70–89.9%** — Partially compliant
- **Below 70%** — Non-compliant

These labels are report classifications; the underlying numeric score is not changed by the classification.

## Fresh-machine setup

Use Python **3.10–3.13** (3.12 recommended), Git, and a local virtual environment. The laptop can run macOS, Linux, or Windows; live assessment targets must provide the Ubuntu/Linux tools described in the SSH guide. No server, database, or application secrets are required for the demo.

Follow [Fresh-machine setup](docs/setup.md) for OS-specific installation, PowerShell commands, validation, and troubleshooting. Obtain the approved handover commit/branch first; a fresh clone of `main` may not contain this work until it is merged.

From the repository root on macOS/Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -c constraints.txt
.venv/bin/python -m pip check
.venv/bin/python -m pytest -q
.venv/bin/python scripts/check_portability.py
.venv/bin/python main.py --demo
```

On Windows (PowerShell, Python 3.12 installed with the launcher):

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -c constraints.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/check_portability.py
.\.venv\Scripts\python.exe main.py --demo
```

`requirements.txt` declares the supported dependency ranges; `constraints.txt` selects tested versions for repeatable installation, including the Windows-only test dependency. Recreate the virtual environment on each machine rather than copying it. All application commands must run from the repository root so relative config, sample, and report paths resolve correctly.

## Demo mode

```bash
python main.py --demo
```

After activating the virtual environment (or using its Python executable as above), demo mode uses `samples/demo_evidence.json`; it does not connect to a live host. Expected result: **15 controls, 7 PASS, 8 FAIL, 0 ERROR, 54.3%**. Findings in the sample are intentional.

## Live audit

Use CyberAssess only against systems you own or are explicitly authorized to assess. Before running, complete [SSH key, host trust, authorized-target and passwordless sudo prerequisites](docs/ssh-target-setup.md). The current collector needs an explicitly supplied key file; it does not use an SSH agent or prompt for a key passphrase or sudo password.

```bash
python main.py \
  --host 192.168.252.2 \
  --user ubuntu \
  --key ~/.ssh/cyberassess_lab
```

The example host is a placeholder for your authorized target. Prefer a verified entry in `~/.ssh/known_hosts`. `--accept-new-host` accepts an unknown host for that connection without establishing its authenticity or persisting trust in this collector; see the SSH guide before using it.

## Reports

Each assessment produces:

- JSON — machine-readable evidence and results
- HTML — self-contained report with assessment metadata, summary, category coverage, remediation findings, evidence details and full control table

The collector is read-only. Remediation commands shown in the report are guidance only and are never executed automatically.

## Handover and portability

- [Fresh-machine setup](docs/setup.md) — macOS, Linux, Windows and dependency maintenance.
- [SSH target setup](docs/ssh-target-setup.md) — keys, host verification, target tools and privileged reads.
- [Handover runbook](docs/handover-runbook.md) — transfer checklist, operating procedure, report retention and troubleshooting.
- [Validation record](docs/portability-validation.md) — executed Linux checks and pending hosted-platform coverage.
- `python scripts/check_portability.py` — dependency check and isolated demo under a path containing spaces and Unicode, with JSON/HTML validation. It makes no SSH connections and cleans up its temporary reports.
- [Portability workflow](.github/workflows/portability.yml) — automated Ubuntu Python 3.10/3.12/3.13 and macOS/Windows Python 3.12 jobs. Local Linux validation does not establish that the hosted macOS/Windows jobs have run.

## Project structure

```text
cyberassess/
├── main.py
├── requirements.txt
├── constraints.txt
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
├── scripts/
│   └── check_portability.py
├── docs/
│   ├── setup.md
│   ├── ssh-target-setup.md
│   ├── handover-runbook.md
│   ├── portability-validation.md
│   ├── student_lab_manual.md
│   ├── executive_pitch.md
│   └── work_log_template.md
└── reports/
```

## Safety and scope

CyberAssess is a baseline assessment and teaching/readiness tool. It is not a replacement for a formal compliance audit or penetration test. Always preserve administrative access and validate configuration changes before reloading SSH or enabling firewall rules.
