# CyberAssess v2 handover

Start here when moving to another laptop or handing the tool to another operator.
The reviewed work is on **`feature/multiplatform-cyberassess`**; obtain the exact
commit from the maintainer. Do not assume `main` contains it or merge it as part
of setup. [Full operator runbook](handover-runbook.md).

## First run on a fresh machine

1. Clone/check out the approved revision, or restore its Git bundle using the
   runbook. Record `git rev-parse HEAD` and the receiving operator's identity.
2. Install Python **3.10–3.13** (3.12 recommended) and Git from approved sources.
   From the repository root, use `sh install.sh` on macOS/Linux or
   `.\install.ps1` on Windows. The helper prepares only local dependencies;
   neither starts collection nor changes security policy. See [setup](setup.md)
   for explicit interpreter/manual installation commands.
3. Use the virtual-environment Python for `-m pip check`, `-m pytest -q`,
   `scripts/check_portability.py`, `main.py --version` and
   `main.py --list-profiles`. Recreate `.venv`; never copy it between machines.
4. Generate the three offline demos below. Confirm both printed report paths
   exist, open HTML in a browser, and compare counts/profile labels with JSON.
5. Review the [validation record](portability-validation.md). Mocked fixtures and
   Linux tests do not establish native Windows/macOS or live SSH validation.

`python` below means `.venv/bin/python` on macOS/Linux or
`.\.venv\Scripts\python.exe` on Windows:

```text
python main.py --demo
python main.py --profile ubuntu --demo --output reports/demo-ubuntu
python main.py --profile windows --demo --output reports/demo-windows
python main.py --profile macos --demo --output reports/demo-macos
```

| Fixture | Controls | PASS / FAIL / ERROR | Score |
| --- | ---: | --- | ---: |
| Original/explicit Ubuntu | 15 | 7 / 8 / 0 | 54.3% |
| Windows | 13 | 9 / 3 / 1 | 70.6% |
| macOS | 12 | 7 / 3 / 2 | 64.3% |

Fixtures are demonstration data. Their findings do not describe the current
machine, and percentages across different profiles are not comparable rankings.

## Before any live collection

- Record the owner's explicit authorization, target, profile/version, operator,
  account context and access window. Installation does not grant permission.
- Ubuntu SSH: complete the [key, host trust and exact passwordless sudo
  preflight](ssh-target-setup.md). No agent, key-passphrase or sudo-password prompt
  is supported. Do not copy private keys into source or handover archives.
- Local profiles: run on the matching authorized native OS. Review [permissions
  and feature limitations](setup.md#live-platform-prerequisites). There is no
  automatic elevation, WinRM or remote macOS collector. In a remote session,
  Python/source/dependencies must be installed on the target and the CLI launched
  there. macOS screen-saver evidence concerns the invoking user's explicit
  preferences; blanket root execution changes that scope.
- Preserve prior reports. Use a separate `--output` directory per run to avoid
  timestamp collisions, and review every ERROR as unavailable evidence.

```text
python main.py --host TARGET --user AUDITOR --key "PRIVATE_KEY_PATH"
python main.py --profile ubuntu --local --output reports/ubuntu-local
python main.py --profile windows --local --output reports/windows-local
python main.py --profile macos --local --output reports/macos-local
```

Choose the one command matching the approved workflow. `--auto-detect --local`
selects the supported current OS; unsupported distributions fail rather than
being assessed under another baseline. A completed assessment returns 0 even
with FAIL/ERROR findings. Scoring counts every control weight in the denominator;
only PASS earns numerator weight. ERROR is not confirmed noncompliance.

## Review, preview and retain

Keep the exact JSON/HTML paths printed by the CLI together with authorization,
source commit, platform/profile, invoking account, runtime versions and review
outcome. Open HTML directly with `open "REPORT.html"` on macOS,
`xdg-open "REPORT.html"` on a Linux desktop or `Invoke-Item "REPORT.html"` in
Windows PowerShell. No web server is required; transfer files securely from a
headless target. Reports carry sensitive operational evidence and need access
control, review before sharing, retention and backups; HTML filtering is not
complete sanitization. Remediation belongs to a separate approved change,
followed by reassessment.

Acceptance requires passing local dependency/tests/demos and either an approved,
reviewed native/live run or an explicit record that native/live validation is
pending. Escalate unsupported/denied evidence to the owner; do not widen sudo or
weaken host security just to increase the score.
