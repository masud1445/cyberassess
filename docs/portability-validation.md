# Portability and validation record

Separate offline/runtime validation from native security collection. A mocked
fixture, a passing dependency installation or an HTML preview does not establish
live access, correct target permissions or effective host security configuration.

## v2 scope and compatibility

- The original `config/controls.json`, `cyberassess/collector.py` and
  `cyberassess/evaluator.py` remain the compatibility baseline: 15 Ubuntu
  controls, original SSH evidence collection, PASS/FAIL/ERROR semantics and the
  same severity-weighted formula. The original unqualified Ubuntu CLI workflow
  retains its JSON field structure. A committed golden fixture checks its exact
  evidence, assessment fields, ordering and **54.3%** score.
- Explicit profiles share a version **2.0** JSON envelope with application,
  profile/version/platform, mode and assessment timing metadata. Ubuntu v1 adds
  descriptive metadata in memory; Windows v1 defines 13 controls and macOS v1
  defines 12. Windows/macOS evidence fixtures are synthetic and labelled demo.
- New local collection runs only on a matching native platform; unsupported
  Linux distributions are rejected rather than treated as Ubuntu. Native
  Windows/macOS collection and authorized Ubuntu local/SSH validation remain
  separate acceptance work on suitable targets.

## Current Linux development checks

Before changes, all **7 existing tests passed**, and the legacy demo was recorded.
The final v2 suite passes on the following Linux runtimes; this runner is not an
Ubuntu assessment target:

| Runtime | Full suite | Requirements/constraints and portable demos |
| --- | --- | --- |
| Python 3.10.22 | 263 passed | Passed |
| Python 3.12.14 | 263 passed | Passed |
| Python 3.13.5 | 263 passed | Passed |

The suite includes the original regressions plus profile, collector, CLI and
report checks. Injected command results and fixtures exercise Windows/macOS
success, denial, malformed output, unsupported features and timeouts without
making native execution claims. Golden fixtures verify the complete legacy
Ubuntu JSON and console output (apart from generated paths). The original SSH
collector, evaluator, Ubuntu definitions and demo evidence remain unchanged.

```text
python -m pip check
python -m pytest -q
python scripts/check_portability.py
python main.py --version
python main.py --list-profiles
python main.py --demo
python main.py --profile ubuntu --demo --output reports/demo-ubuntu
python main.py --profile windows --demo --output reports/demo-windows
python main.py --profile macos --demo --output reports/demo-macos
```

| Offline fixture | Controls | PASS | FAIL | ERROR | Score |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original/explicit Ubuntu | 15 | 7 | 8 | 0 | 54.3% |
| Windows | 13 | 9 | 3 | 1 | 70.6% |
| macOS | 12 | 7 | 3 | 2 | 64.3% |

Demo JSON and HTML are inspected for profile identity, counts, metadata, fixture
labels, details and escaped evidence. The intended sample paths are
`reports/audit_v2_ubuntu.html`, `reports/audit_v2_windows.html` and
`reports/audit_v2_macos.html`, paired with JSON files of the same base names.
These are local generated artifacts, not live assessment evidence.

Chromium checks passed for the three profile demos at 320, 390, 768, 1024 and
1440 pixels, with no document overflow, keyboard-accessible disclosures and
self-contained output. A4 exports repeat table headers and print full-width
evidence/guidance reference sections: Ubuntu 5 pages, Windows 4 and macOS 4 for
the current demo fixtures. Screenshots and final printed pages were visually
reviewed. All-pass and unavailable-evidence examples are also synthetic.

The portability checker validates installed active requirements/constraints and
runs offline CLI/report checks in a temporary project path containing spaces and
`café`; it is also runnable from outside the source checkout. It must not make
SSH connections. This checks source transfer, resource inclusion, UTF-8 paths
and report generation, rather than platform security privileges.

`install.sh` is syntax-checked and exercised on Linux: a fresh install under a
path containing spaces and Unicode, a repeat install preserving a sentinel file
inside `.venv`, reuse of the project environment, and rejection of an unusable
existing `.venv` without deleting its user file all passed. `install.ps1` is
ASCII-only and reviewed for Windows PowerShell
5.1-compatible syntax and argument quoting; native execution is pending on
Windows. Neither helper changes OS policy or launches assessments.

## Earlier handover baseline

The previous handover used newly created Linux virtual environments with the
same `requirements.txt` and `constraints.txt`:

| Python | `pip check` | Original suite | Original portable demo |
| --- | --- | --- | --- |
| 3.10.22 | Passed | 7 passed | Passed |
| 3.12.14 | Passed | 7 passed | Passed |
| 3.13.5 | Passed | 7 passed | Passed |

That earlier checker also exercised missing dependencies, missing assets,
changed fixtures, incompatible requirement ranges and mismatched constraints;
failures produced actionable diagnostics. Those historical results do not claim
that the complete v2 suite has run under every interpreter or native OS.

## Hosted and live checks still required

[The portability workflow](../.github/workflows/portability.yml) defines Ubuntu
Python 3.10/3.12/3.13 and macOS/Windows Python 3.12 jobs. Inspect actual GitHub
Actions outcomes after a maintainer publishes the branch; defining a job does
not mean it ran. Hosted tests/demos do not prove native elevated security reads
or the applicability of this baseline to every OS release/edition. Windows jobs
also parse installer and collector scripts under Windows PowerShell without
executing security queries; that hosted parsing remains pending here.

Before accepting live use on a receiving machine:

1. Follow [fresh-machine setup](setup.md) and re-run dependency checks, the full
   test suite, the portability checker and all three fixture demos.
2. On an authorized Ubuntu target, validate the original SSH key/host trust and
   exact passwordless sudo checks separately; on an actual Ubuntu local target,
   validate the equivalent read permissions and platform tooling.
3. On native Windows, record OS release/edition, Windows PowerShell version,
   firmware/feature support and permitted elevation. Run the Windows local
   profile, compare evidence to administrator-observed native state, and record
   unsupported or denied cmdlets as collection limitations.
4. On native macOS, record release/architecture and invoking user. Validate the
   exact native query outputs and explicit preference scope. Record privileged
   `systemsetup` errors and missing keys; do not conflate defaults with effective
   managed policy or change user scope silently.
5. Retain the source commit, runtime versions, authorization and paired reports;
   complete the [handover acceptance checklist](handover-runbook.md#handover-acceptance-checklist).

No native Windows/macOS live assessment was performed on this Linux runner.
No new authorized SSH/local assessment target or credentials were supplied for
v2. Earlier committed Ubuntu live-validation artifacts are historical evidence,
not proof that the new receiving machine or a new profile has been validated.
