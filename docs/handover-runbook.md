# CyberAssess — Automated Security Baseline Assessment

## Handover and operator runbook

Use this runbook after completing [fresh-machine setup](setup.md). Run every
command below from the repository root with the local virtual environment
activated, or substitute its explicit Python path. The operator laptop may run
macOS, Linux, or Windows. Ubuntu supports the SSH workflow and a
native local mode; Windows/macOS profiles run only on their matching native
target. Check [platform prerequisites](setup.md#live-platform-prerequisites)
before collecting; the [SSH prerequisites](ssh-target-setup.md) apply to Ubuntu
remote collection.

## Handover to another laptop

1. Record the repository URL, branch and exact commit (`git rev-parse HEAD`),
   Python version (`python --version`) and dependency versions
   (`python -m pip freeze`). Also retain `requirements.txt`, `constraints.txt`,
   the setup instructions, target inventory and the written assessment scope.
2. Clone the repository on the receiving laptop and check out that reviewed
   commit. Recreate `.venv` using the setup instructions; virtual environments
   contain machine-specific paths and must not be copied between laptops.
3. Install and verify dependencies, then run the offline checks below before
   attempting a live assessment. Keep a new version record if the Python or
   dependency versions change.
4. For Ubuntu SSH, provision the receiving operator's approved SSH key and verify
   the target's host-key fingerprint through a trusted channel. Transfer keys only through
   the organization's approved secure process; never put private keys in the
   repository, reports, tickets or a handover archive. Revoke obsolete access.
5. Have the target administrator confirm authorized scope and profile. For
   Ubuntu SSH, verify network access, key-based login and passwordless sudo for
   the exact reads in the [SSH guide](ssh-target-setup.md). For Windows/macOS,
   install the reviewed application on the target itself and verify native tools
   and read permissions. Record unsupported/inaccessible checks rather than
   granting broad privileges or changing policy to make a report pass.

If the reviewed branch has not been pushed, transfer its **committed source**
as a Git bundle. On the sending laptop, from the repository root:

```text
git bundle create ../cyberassess-handover.bundle feature/multiplatform-cyberassess
git bundle verify ../cyberassess-handover.bundle
```

Transfer the bundle through an approved channel. On the receiving laptop, from
the directory containing it:

```text
git clone -b feature/multiplatform-cyberassess cyberassess-handover.bundle cyberassess
cd cyberassess
git rev-parse HEAD
```

Compare the full commit hash with the sender's handover record. A bundle includes
tracked history, not uncommitted edits, ignored reports, virtual environments or
external SSH keys. Keep the original repository URL in the run record; the cloned
bundle's `origin` points to the bundle file rather than GitHub.

## Before each assessment

- Confirm profile, target hostname/address, account, authorization window and
  scope with the owner. Confirm that the approved target baseline is applicable.
- Verify the repository commit and a clean working tree (`git status --short`),
  the intended interpreter and sufficient disk space for reports.
- For Ubuntu SSH, confirm the port, private-key path, trusted host key and required
  `sudo -n` permissions. The collector uses the supplied key file, disables SSH-agent/key
  discovery and has no password or key-passphrase prompt option. Do not assume
  that a successful interactive SSH session proves CyberAssess can authenticate.
- For native local profiles, confirm the actual OS and account context. Windows
  needs approved elevated reads for some cmdlets; macOS screen-saver preferences
  require a safely matching, non-root invoking and console user. Run from that
  user's Terminal; root, headless and different-user sessions cannot establish
  the console user's screen-lock policy. Do not change user scope to hide errors.
- Archive previous reports before running concurrent jobs or repeated runs within
  one second. Existing report filenames use local time with one-second precision;
  another run in that second can overwrite them. JSON and HTML are named by
  separate save calls and can have different timestamps across a second boundary.

## Offline acceptance and demonstration

```text
python -m pip check
python -m pytest -q
python scripts/check_portability.py
python main.py --demo
python main.py --profile ubuntu --demo --output reports/demo-ubuntu
python main.py --profile windows --demo --output reports/demo-windows
python main.py --profile macos --demo --output reports/demo-macos
```

The legacy and explicit Ubuntu fixtures show **15 controls, 7 PASS, 8 FAIL,
0 ERROR and 54.3%**. Windows shows **13 controls, 9 PASS, 3 FAIL, 1 ERROR and
70.6%**; macOS shows **12 controls, 7 PASS, 3 FAIL, 2 ERROR and 64.3%**.
All are offline sample data and run on any supported development platform.
Confirm that both output paths printed by the CLI exist, open the HTML in a
browser, and check that its target and counts
match the JSON. The demo proves the local workflow; it does not verify live SSH
access, sudo permissions or the target's security configuration.

## Live Ubuntu SSH assessment

Replace all placeholders below; quote paths containing spaces. The command fits
on one line in POSIX shells and PowerShell. Add `--port PORT` for a nondefault
SSH port.

```text
python main.py --host TARGET_ADDRESS --user ASSESSMENT_USER --key "PATH_TO_PRIVATE_KEY"
```

Use the host-key verification procedure in the SSH setup guide. The existing
`--accept-new-host` option accepts an unknown key for the connection and should
only be used after the administrator confirms the fingerprint; do not treat it
as durable host-key enrollment or as protection against an impostor host.

A completed assessment returns exit status **0 even when controls FAIL or
ERROR**. Inspect the reported counts and individual results; exit status alone
does not establish compliance or complete evidence. Connection failures return
**2**; missing required CLI arguments also cause an argument error with status
**2**. Other uncaught failures can return a different nonzero status.

Review ERROR results and collection prerequisites before interpreting a low
score. All control weights remain in the denominator, while only PASS weights
contribute to the numerator; ERROR therefore reduces the score without proving
noncompliance. Remediation text is guidance only. Any target changes require the
owner's separate change process, followed by a new authorized assessment.

## Live native local assessment

Run the matching command **on the authorized target**, with its fresh local
environment and native tools. Windows and macOS do not accept SSH target flags.

```text
python main.py --profile ubuntu --local --output reports/ubuntu-local
python main.py --profile windows --local --output reports/windows-local
python main.py --profile macos --local --output reports/macos-local
```

Use only the line matching the actual OS. `python main.py --auto-detect --local`
or `python main.py --local` selects a supported local profile; unsupported OS
detection fails before collection. Windows/macOS cannot be emulated by selecting
their profile on Linux; use `--demo` for cross-platform presentation/testing.
Only actual Ubuntu is selected as Linux's supported target profile.

For an authorized remote terminal session, install and run the CLI on the target;
CyberAssess supplies no WinRM, remote PowerShell or macOS SSH transport. Preserve
the invocation's account context in the run record. Missing commands, registry
keys/preferences, denied reads and unsupported OS features require evidence
review. Native collection does not remediate, install security services, request
elevation or weaken policy. See the [setup guide](setup.md#live-platform-prerequisites)
for Windows feature/firmware limits and macOS explicit-preference/user scope.

Completed local assessments also return 0 despite control FAIL/ERROR results.
Review counts and findings, not just process status. Profiles assess different
controls, so compare a host's repeated runs under the same profile/version rather
than ranking different operating systems by their percentage.

## Retain the assessment record

Use the **two paths printed by the CLI** to identify the matching JSON and HTML;
do not rely solely on identical filename timestamps. Move or copy both into a
restricted, access-controlled case folder before the next run. Keep an external
run record with the target, authorization/reference, operator, UTC run time and
local timezone, profile/version, collection mode, invoking account, source commit,
Python/dependency versions, printed paths, counts and review outcome. Filenames
use local time and do not encode a timezone; use the recorded metadata, rather
than a filename, to identify the assessment instant.

## Understand assessment times and report provenance

Every new live run performs new native reads. The macOS command cache is scoped
to one collection and cleared on the next; no collector uses demonstration
evidence as a live fallback. A failed live connection produces an error rather
than a sample report. Individual unavailable or ambiguous reads retain ERROR.

Reports are **point-in-time snapshots**, not continuously updating dashboards.
Reopening an HTML file does not collect anything. Run another authorized live
assessment to obtain current evidence. Demo reports are labelled demonstration,
including the legacy `--demo` output; they do not describe the current machine.
The `--demo` CLI heading also identifies the run as a demonstration assessment.

The JSON records offset-aware UTC collection and assessment timestamps. In the
legacy Ubuntu SSH envelope, the clock/assessment fields are nested under
`collector`; the five original top-level fields and security evidence stay intact.
Versioned reports also expose the canonical collection/start/completion times
at the top level. Completion is recorded after baseline evaluation. Collection
time marks completion of the read attempts, not an atomic measurement of every
control at one instant. Existing imported reports may lack these fields.

HTML displays readable UTC start/completion/collection times and the separately
observed **target clock (local / UTC)** with an explicit UTC offset. For example,
`2026-10-31T03:28:00+08:00` is 31 October at 03:28 local and 30 October at 19:28
UTC. Offsets are captured for the observed instant; an offset from completion
is never applied to a different event across a daylight-saving transition.
Naive historical timestamps remain unavailable rather than adopting the viewer's
timezone. Report generation is separately labelled UTC in metadata and footer;
printing the HTML retains the same recorded assessment metadata.

Local targets use their native process clock. Ubuntu SSH adds only the fixed,
unprivileged read `LC_ALL=C /bin/date --iso-8601=seconds` on the established
connection. Missing, denied, malformed or unavailable target clock output leaves
local time unknown; the operator host's UTC collection time remains explicitly
identified. No operator timezone is substituted for the target's. The remote
clock is sampled separately and can differ from the operator clock; clock
accuracy is not proven by displaying either timestamp.

Review collection scope, limitations and ERROR details before acting on a score.
The baseline verdict is not formal compliance certification. Remediation text
and commands are display-only guidance, require separate authorization/review,
and are never executed by report generation.

Reports contain target identifiers, configuration and evidence. Apply the
organization's retention and sharing policy, encrypt backups when required and
check recipients before sharing. Generated `audit_*` reports are ignored by Git;
a Git push is not a report backup. Protect existing tracked sample/validation
reports from accidental replacement. Restore-test backups as part of handover.

Open the printed HTML path directly; replace `REPORT.html` below:

```text
macOS:              open "REPORT.html"
Linux desktop:      xdg-open "REPORT.html"
Windows PowerShell: Invoke-Item "REPORT.html"
```

There is no web service or listening port. On a headless host, transfer the files
through an approved channel. HTML truncates raw details and filters recognized
secret patterns, but that is not complete sanitization. JSON retains evidence;
review both files before sharing. Do not publish real evidence as demo content.

## Troubleshooting

| Symptom | Operator action |
| --- | --- |
| `config/controls.json` or sample file cannot be found | Change to the cloned repository root; resource paths are relative to the current directory. |
| Missing module or dependency conflict | Activate that laptop's `.venv`; reinstall from the documented requirements/constraints and run `python -m pip check`. |
| SSH authentication fails | Check account, port, explicit key path and supported noninteractive key authentication; ask the administrator to verify access. Do not post key contents. |
| Unknown or changed host key | Verify the fingerprint with the owner and follow the SSH setup guide. Investigate a changed key before updating trust. |
| Timeout or connection refused | Check target address, approved route/VPN, firewall and SSH service with the owner. |
| ERROR results or unexpected empty evidence | Verify target compatibility, installed tools and exact passwordless `sudo -n` checks. Some remote checks suppress stderr; inspect the affected result and prerequisites. |
| Windows cmdlet or macOS native read unavailable | Confirm matching native OS, feature/edition support and approved read permissions. Missing preferences, unsupported Secure Boot/BitLocker, denied access or malformed output remain ERROR; do not alter policy solely to pass the assessment. |
| Local profile does not match this machine | Run on the matching authorized target or select `--demo`; another OS cannot supply native live evidence. |
| FAIL results with exit status 0 | This is expected behavior. Review findings; make approved changes separately and reassess. |
| Cannot write reports or reports appear missing | Check working directory, write permissions, available space, printed output paths and possible same-second overwrites. |

## Handover acceptance checklist

Use the single [Final Acceptance Checklist](HANDOVER.md#final-acceptance-checklist)
for deployment scope, runtime/CI evidence, authorized native
validation and secure report retention. The procedures above provide the
operational detail; record unperformed live checks as unverified.
