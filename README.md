# CyberAssess

CyberAssess is a read-only cybersecurity baseline assessment CLI for authorized Ubuntu, Windows and macOS systems. It collects configuration evidence, evaluates platform-specific controls and produces self-contained HTML and machine-readable JSON reports. It supports a repeatable **assess → review → approve changes → reassess** workflow; it never applies remediation.

The project remains aligned with **Internship Pillar 2 / Sub-Track 2.1: Automated Compliance / Baseline Assessment Scripts**, supporting supervised labs, SME administration and compliance-readiness reviews.

For supervisor review, use the [official requirement traceability and Final Acceptance Checklist](docs/HANDOVER.md#supervisor-requirement-traceability). This is an OS/NIST assessment project: boto3 and cloud scanning are examples of possible tooling, not unimplemented mandatory requirements.

## Platform profiles and scope

| Profile | Controls | Live collection | Scope |
| --- | ---: | --- | --- |
| `ubuntu` | 15 | Existing SSH collector, or local Ubuntu collector | Original Ubuntu baseline: SSH, firewall, permissions, accounts, password policy, logging, updates, time and Telnet |
| `windows` | 13 | Native local Windows only | Defender, firewall profiles, BitLocker, RDP/NLA, Guest, UAC, SMBv1 server, inactivity policy, Secure Boot and Event Log |
| `macos` | 12 | Native local macOS only | FileVault, firewall, SIP, Gatekeeper, native update-check state, remaining explicit update preferences, Remote Login, network time and resolved current-user screen-lock preferences |

Each profile maps checks to NIST SP 800-53 references. A profile is a limited baseline, not evidence of certification, a complete audit, or an effective-policy guarantee. Scores describe different control sets and must not be used as an OS ranking.

**Windows and macOS run on the machine being assessed.** An operator may first open an authorized remote terminal and then launch the local CLI on that target, with Python and CyberAssess installed there. CyberAssess does not provide WinRM, remote PowerShell or remote macOS SSH collection. Ubuntu local collection requires Ubuntu; another Linux distribution, WSL or a container is not automatically an equivalent target.

## Fresh-machine setup

Use Python **3.10–3.13** (3.12 recommended), Git and a new machine-local virtual environment. No database, web server, Docker or application secrets are required. Clone and check out the reviewed handover revision; this work is on `feature/multiplatform-cyberassess` and is not automatically merged into `main`.

```text
git clone https://github.com/masud1445/cyberassess.git
cd cyberassess
git fetch origin
git switch --detach HANDOVER_REF
```

Replace `HANDOVER_REF` with the maintainer's approved commit or fetched branch. An unpublished branch needs the Git bundle procedure in the [runbook](docs/handover-runbook.md).

macOS/Linux:

```sh
sh install.sh
# If needed: PYTHON=python3.12 sh install.sh
.venv/bin/python -m pytest -q
.venv/bin/python scripts/check_portability.py
.venv/bin/python main.py --list-profiles
.venv/bin/python main.py --profile ubuntu --demo
```

Windows PowerShell:

```powershell
.\install.ps1
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/check_portability.py
.\.venv\Scripts\python.exe main.py --list-profiles
.\.venv\Scripts\python.exe main.py --profile windows --demo
```

The Windows helper defaults to `py -3.12`; use `-Python "C:\Path\python.exe"` for another supported interpreter. If your execution policy blocks the helper, use the explicit Python commands in [fresh-machine setup](docs/setup.md); no policy change or activation is necessary. Helpers install constrained dependencies, preserve existing `.venv`, fail on an incompatible environment and run `pip check`. They do not start an assessment, elevate privileges or change security settings. Recreate `.venv` on a new machine rather than copying it.

## Demo and live commands

Run from the repository root, using that machine's virtual-environment Python. In the commands below, `python` means `.venv/bin/python` on macOS/Linux or `.\.venv\Scripts\python.exe` on Windows.

```text
python main.py --version
python main.py --list-profiles
python main.py --profile ubuntu --demo --output reports/demo-ubuntu
python main.py --profile windows --demo --output reports/demo-windows
python main.py --profile macos --demo --output reports/demo-macos
```

Every profile's demo is an offline fixture, runnable on any supported development OS; it makes no SSH connection and reads no live security configuration. Windows/macOS fixtures and injected command tests are **mocked evidence**, not validation on native systems. The original `python main.py --demo` remains available with its unchanged Ubuntu sample and legacy JSON format: **15 controls, 7 PASS, 8 FAIL, 0 ERROR, 54.3%**.

After the owner authorizes the target and the [platform prerequisites](docs/setup.md#live-platform-prerequisites) are satisfied:

```text
# On an Ubuntu target
python main.py --profile ubuntu --local --output reports/ubuntu-local

# On a native Windows target
python main.py --profile windows --local --output reports/windows-local

# On a native macOS target
python main.py --profile macos --local --output reports/macos-read-only

# Optional macOS-only noninteractive elevated status reads
python main.py --profile macos --local --allow-elevated-read --output reports/macos-elevated-read

# Select the current supported OS explicitly through detection
python main.py --auto-detect --local --output reports/local
```

`--local` also detects the current supported OS; `--auto-detect` implies local collection. Detection rejects unsupported operating systems. No collection occurs merely by listing profiles or requesting the version. Missing tools, permissions, unavailable settings and uninterpretable evidence must be reviewed as collection limitations; the tool does not automatically grant privileges, install assessment services, or fix the target.

On macOS, normal mode never invokes sudo. Passing `--allow-elevated-read` is explicit operator consent for that run; before collection, the CLI lists the three fixed read-only getters it authorizes. Reliable unprivileged evidence is tried first; only a recognized permission denial with unresolved status permits `sudo -n -k --` for `systemsetup -getremotelogin`, `systemsetup -getusingnetworktime` or `softwareupdate --schedule` without an `on`/`off` argument. Existing administrator-approved passwordless authorization for the exact getter is required: existing sudo credentials are ignored and are not updated. CyberAssess never requests or collects passwords, changes privilege configuration, elevates user-preference reads, changes settings or runs remediation. An authorized network-time getter can establish MAC-012 On/Off; MAC-005 still needs a reliable check-specific scalar, which some macOS versions may not expose. Missing, denied, unsupported or ambiguous evidence remains ERROR. See [macOS collection and validation](docs/macos-live-collection.md) for exact commands and scope.

The existing Ubuntu SSH workflow remains available from macOS, Linux or Windows:

```text
python main.py --host TARGET_ADDRESS --user ASSESSMENT_USER --key "PATH_TO_PRIVATE_KEY"
```

An explicit `--profile ubuntu` may also be used with the SSH arguments. Follow the [SSH authorization, keys, host trust and passwordless sudo guide](docs/ssh-target-setup.md). The collector requires a supplied key file, does not use an SSH agent and does not prompt for a key passphrase or sudo password. `--accept-new-host` accepts an unknown key for that connection without persisting verified trust. Prefer a trusted `known_hosts` entry.

## Results and scoring

- **PASS** — collected evidence satisfies the control.
- **FAIL** — collected evidence does not satisfy the control.
- **ERROR** — evidence is unavailable, ambiguous, unsupported or cannot be reliably interpreted. An ERROR does not prove noncompliance.

All profiles retain the original severity weights: **HIGH = 3, MEDIUM = 2, LOW = 1**.

```text
score = round(100 × sum(weights of PASS controls) / sum(weights of all controls), 1)
```

FAIL and ERROR both retain their weight in the denominator and earn zero passing weight. With no controls the score is 0.0. For the unchanged Ubuntu baseline, total weight is 35: 14 passing controls plus an ERROR on the weight-1 TIME-001 check gives `34 / 35 × 100 = 97.1%`. Review errors even when a report's numerical verdict is Compliant.

Report classifications remain **90–100% Compliant**, **70–89.9% Partially compliant**, and **below 70% Non-compliant**. A successful process exit does not mean all controls passed: completed assessments with FAIL/ERROR results still return 0. Inspect the findings and evidence.

## Reports

Both JSON and HTML are written to `reports/`, or the directory selected by `--output`. Use the exact two paths printed by the CLI. HTML remains self-contained, responsive, printable on A4 and suitable for direct browser/file preview; no application server is needed. Reports identify the assessment profile/OS for the new explicit-profile workflow and present counts, findings, remediation guidance and compact evidence details. Explicit profiles use a shared versioned JSON report envelope; the original unqualified Ubuntu commands retain their original JSON field structure.

Open the printed HTML path with `open "REPORT.html"` on macOS, `xdg-open "REPORT.html"` on a desktop Linux session, or `Invoke-Item "REPORT.html"` in Windows PowerShell. Replace the placeholder with the real path. On a headless host, transfer the paired reports through an approved secure channel to a browser-equipped machine. Evidence can contain sensitive target identifiers and configuration: apply access and retention rules before sharing. Remediation is guidance and is never executed automatically. HTML evidence is compacted and selected recognizable secrets are redacted; this is not a complete data-loss prevention filter, and JSON/raw evidence still requires review before sharing.

## Architecture and adding a profile

```text
main.py                          CLI and workflow selection
cyberassess/profiles.py           Profile registry and common report construction
cyberassess/platforms.py          Supported local platform detection
cyberassess/collector.py          Original Ubuntu SSH collector
cyberassess/collectors/           Ubuntu, Windows and macOS local collectors
cyberassess/evaluator.py          Shared unchanged evaluation and weighted scoring
cyberassess/reporting.py          Shared JSON/HTML rendering
cyberassess/timestamps.py         Explicit local-offset/UTC clock provenance
comparison_report.py             Historical reviewed snapshot comparison (no collection)
config/controls.json             Original 15 Ubuntu controls, unchanged
config/profiles/                 Windows and macOS control definitions
samples/                         Offline evidence fixtures
tests/                           Regression, profile, parser and CLI checks
scripts/check_portability.py     Dependency and isolated-demo validation
install.sh / install.ps1         Machine-local dependency setup
```

To add a future platform, first document the exact configuration scope, native read-only commands, permissions, expected values and unsupported states. Add a collector returning the shared evidence structure, control definitions using the existing evaluator operators, an offline fixture and a registry entry. Parse structured output where available; do not infer PASS from empty output or a failed command. Missing/denied/unsupported or ambiguous evidence must remain unavailable rather than receive an invented default. Keep execution noninteractive, bounded by timeouts and free of automatic remediation/elevation. Add injected command/parser tests for success, fail, denied, missing-tool, malformed and timeout cases, CLI/profile validation and both report formats. Re-run the original Ubuntu regression tests and demos to protect compatibility. A mocked fixture is not native validation: record real-platform acceptance separately before production use.

## Handover and validation

- [Concise handover](docs/HANDOVER.md) — first-run checklist and acceptance gates.
- [Control coverage](docs/control_master_table.md) — all 40 profile checks, selected NIST references and interpretation limits.
- [Fresh-machine setup](docs/setup.md) — macOS, Linux, Windows, dependencies and local privilege limitations.
- [SSH target guide](docs/ssh-target-setup.md) — Ubuntu remote authorization, key/trust and exact sudo requirements.
- [Operator runbook](docs/handover-runbook.md) — transfers, live assessment, evidence review and report retention.
- [Validation record](docs/portability-validation.md) — what was exercised and which native/live checks remain pending.
- [Portability workflow](.github/workflows/portability.yml) — hosted runtime matrix; inspect actual job outcomes rather than assuming a push or test pass.

CyberAssess supports baseline assessment, teaching and readiness. It is not a replacement for a formal compliance audit or penetration test. Any change to the assessed host belongs to the owner's separate change process.
