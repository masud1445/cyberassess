# CyberAssess handover and operator runbook

Use this runbook after completing [fresh-machine setup](setup.md). Run every
command below from the repository root with the local virtual environment
activated. The operator laptop may run macOS, Linux, or Windows; the live target
must match the Ubuntu/Linux baseline and tools described in
[SSH and target prerequisites](ssh-target-setup.md).

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
4. Provision the receiving operator's approved SSH key and verify the target's
   host-key fingerprint through a trusted channel. Transfer keys only through
   the organization's approved secure process; never put private keys in the
   repository, reports, tickets or a handover archive. Revoke obsolete access.
5. Have the target administrator confirm authorized scope, network access,
   key-based login and passwordless sudo for the exact read-only checks in the
   [SSH setup guide](ssh-target-setup.md). Laptop setup alone does not prepare
   the target or grant assessment permission.

If the reviewed branch has not been pushed, transfer its **committed source**
as a Git bundle. On the sending laptop, from the repository root:

```text
git bundle create ../cyberassess-handover.bundle feature/deployment-handover
git bundle verify ../cyberassess-handover.bundle
```

Transfer the bundle through an approved channel. On the receiving laptop, from
the directory containing it:

```text
git clone -b feature/deployment-handover cyberassess-handover.bundle cyberassess
cd cyberassess
git rev-parse HEAD
```

Compare the full commit hash with the sender's handover record. A bundle includes
tracked history, not uncommitted edits, ignored reports, virtual environments or
external SSH keys. Keep the original repository URL in the run record; the cloned
bundle's `origin` points to the bundle file rather than GitHub.

## Before each assessment

- Confirm target hostname/address, SSH port, account, authorization window and
  scope with the owner. Confirm that the approved target baseline is applicable.
- Verify the repository commit and a clean working tree (`git status --short`),
  the intended interpreter and sufficient disk space for reports.
- Confirm the correct private-key path, trusted host key and required `sudo -n`
  permissions. The collector uses the supplied key file, disables SSH-agent/key
  discovery and has no password or key-passphrase prompt option. Do not assume
  that a successful interactive SSH session proves CyberAssess can authenticate.
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
```

The bundled demo must show **15 controls, 7 PASS, 8 FAIL, 0 ERROR and 54.3%**.
It requires no target or SSH credentials. Confirm that both output paths printed
by the CLI exist, open the HTML in a browser, and check that its target and counts
match the JSON. The demo proves the local workflow; it does not verify live SSH
access, sudo permissions or the target's security configuration.

## Live assessment

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

## Retain the assessment record

Use the **two paths printed by the CLI** to identify the matching JSON and HTML;
do not rely solely on identical filename timestamps. Move or copy both into a
restricted, access-controlled case folder before the next run. Keep an external
run record with the target, authorization/reference, operator, UTC run time and
local timezone, source commit, Python/dependency versions, printed paths, counts
and review outcome. HTML records its generation time in UTC; filenames use local
time and do not encode a timezone.

Reports contain target identifiers, configuration and evidence. Apply the
organization's retention and sharing policy, encrypt backups when required and
check recipients before sharing. Generated `audit_*` reports are ignored by Git;
a Git push is not a report backup. Protect existing tracked sample/validation
reports from accidental replacement. Restore-test backups as part of handover.

## Troubleshooting

| Symptom | Operator action |
| --- | --- |
| `config/controls.json` or sample file cannot be found | Change to the cloned repository root; resource paths are relative to the current directory. |
| Missing module or dependency conflict | Activate that laptop's `.venv`; reinstall from the documented requirements/constraints and run `python -m pip check`. |
| SSH authentication fails | Check account, port, explicit key path and supported noninteractive key authentication; ask the administrator to verify access. Do not post key contents. |
| Unknown or changed host key | Verify the fingerprint with the owner and follow the SSH setup guide. Investigate a changed key before updating trust. |
| Timeout or connection refused | Check target address, approved route/VPN, firewall and SSH service with the owner. |
| ERROR results or unexpected empty evidence | Verify target compatibility, installed tools and exact passwordless `sudo -n` checks. Some remote checks suppress stderr; inspect the affected result and prerequisites. |
| FAIL results with exit status 0 | This is expected behavior. Review findings; make approved changes separately and reassess. |
| Cannot write reports or reports appear missing | Check working directory, write permissions, available space, printed output paths and possible same-second overwrites. |

## Handover acceptance checklist

- [ ] Receiving operator has the reviewed source commit and fresh local `.venv`.
- [ ] Dependency check, test suite and portability check pass on the new laptop.
- [ ] Demo JSON/HTML open and show the expected counts and score.
- [ ] Target inventory, scope, owner and authorization are recorded.
- [ ] Approved key, host-key trust and exact noninteractive sudo checks are verified.
- [ ] An authorized live run is reviewed, or live validation is explicitly pending.
- [ ] Paired reports and run records are stored securely with a working backup.
- [ ] Operator knows how to escalate access/evidence errors and arrange reassessment.
