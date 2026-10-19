# Handover validation record

These results cover the development/demo workflow with the committed
`requirements.txt` and `constraints.txt`. They do not establish live access to
an assessment target or hosted macOS/Windows execution.

## Executed on the Linux handover runner

Each row used its own newly created virtual environment and constrained
dependency installation, rather than the previously prepared project `.venv`.

| Python | Dependency consistency | Existing tests | Portable demo |
| --- | --- | --- | --- |
| 3.10.22 | `pip check` passed | 7 passed | Passed |
| 3.12.14 | `pip check` passed | 7 passed | Passed |
| 3.13.5 | `pip check` passed | 7 passed | Passed |

Commands, using each environment's interpreter from the repository root:

```text
python -m pip install -r requirements.txt -c constraints.txt
python -m pip check
python -m pytest -q
python scripts/check_portability.py
```

The checker was also invoked from outside the repository. It created a fresh
temporary project whose path contains spaces and `café`, copied the application
and required config/sample assets, and executed the unchanged demo CLI there.
It checked installed package versions against the active requirements and
platform/Python constraints, then verified the exact JSON field sets, evidence
and evaluation data, control
coverage/order, UTF-8 JSON/HTML and the expected **15 controls, 7 PASS, 8 FAIL,
0 ERROR, 54.3%**. Generated reports stayed in the temporary project and the
original checkout's reports were unchanged.

Five failure cases were exercised in disposable environments/copies: missing
dependencies, missing control assets, changed sample results, an incompatible
requirement range and a mismatched version constraint. Each returned status 1
with an actionable `FAIL` message. No SSH connection was made.

## Automated checks to run on publication

[The portability workflow](../.github/workflows/portability.yml) defines five
jobs: Ubuntu Python 3.10/3.12/3.13, macOS Python 3.12, and Windows Python 3.12.
Each installs constrained dependencies, checks consistency, runs the existing
suite and invokes the checker from outside the checkout. The actions are pinned
to upstream v6 commits.

The workflow has been added locally; hosted results are **pending a push and
GitHub Actions execution**. Check those job outcomes before recording macOS or
Windows as tested. Python 3.11, other CPU architectures, and other operating
system versions have not been directly exercised here.

## Receiving-laptop acceptance

Re-run the [setup checks](setup.md#verify-the-installation) on the actual receiving
laptop. Verify its SSH identity, host-key trust, authorized target and exact
noninteractive sudo prerequisites separately using the
[SSH guide](ssh-target-setup.md). Record any pending live validation in the
[handover checklist](handover-runbook.md#handover-acceptance-checklist).

Application source, control definitions, existing tests, dependency declarations
and sample evidence are unchanged by this handover change. The README scoring
description now matches the existing implementation; no score or result
semantics were changed.
