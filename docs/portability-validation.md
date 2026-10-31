# Portability and validation record

Separate offline/runtime validation from native security collection. A mocked
fixture, a passing dependency installation or an HTML preview does not establish
live access, correct target permissions or effective host security configuration.

## Final professional QA and requirement audit

Audited baseline: `5e898bd329d92b49baf37fecc9a1de521e40eb97`, **1,328 passing
tests**, with all five hosted jobs successful in
[Portability run 41121239929](https://github.com/masud1445/cyberassess/actions/runs/41121239929).
The earlier review sections below are historical records; this audit supersedes
claims there that Ubuntu command failure handling is unchanged.

| Audit classification | Finding and disposition | Evidence |
| --- | --- | --- |
| Already correct | Native 15/13/12 profile selection, unsupported-OS rejection, separate Ubuntu SSH mode, fresh per-run reads, control definitions/NIST IDs, severity formula, read-only native queries, explicit macOS privileged-read consent and current dashboard design. | Existing platform/CLI/collector/scoring/report suites; baseline CI; unchanged control/evaluator files. |
| Genuine defect corrected | Ubuntu shell pipelines/wrappers could hide failed upstream reads, including a false Telnet PASS; malformed numeric/Chrony evidence and unreadable password settings could be misclassified. Capture status before filtering, require bounded whole scalar values, distinguish readable absence from unavailable evidence, and retain ERROR for contradictory password sources. | `test_ubuntu_safe_failure.py`, strengthened Ubuntu compatibility failures, manual fixed-command stubs and POSIX syntax checks. |
| Genuine boundary defect corrected | Deeply nested JSON could raise an uncaught recursion error and abort collection/reporting. Unexpected output now follows the existing unavailable/ERROR path without retaining the raw payload. | `test_json_depth_failures.py`; other controls continue to evaluate. |
| Genuine provenance defect corrected | The profile adapter could label known samples live and substitute completion time for an absent collection clock. All live CLI entry points reject known sample markers; missing collection time remains absent. | `test_report_provenance_guard.py`; existing fixture data/assertions retained with accurately labelled injected-source metadata. |
| Genuine comparison defect corrected | Historical comparison output inferred remediation/authorization and could compare incompatible snapshots. Reject known mismatches and describe recorded transitions, separating ERROR-to-PASS from FAIL-to-PASS. | `test_comparison_report.py`; fixed paths/CSS and valid 54.3-to-100 comparison preserved; source reports unchanged. |
| Minor improvements | Completed the truncated lab manual; corrected stale platform/console-user descriptions and historical test-count labels; added official traceability, all-profile coverage and one canonical supervisor checklist. Ignore the documented diagnostic output and generated audit PDFs. | [Supervisor handover](HANDOVER.md), [control coverage](control_master_table.md), setup/pitch/lab/diagnostic docs; Markdown/link and ignore checks. |
| Unverified/native acceptance | Receiving-machine security state, exact read privileges, firmware/edition support, modern macOS unavailable state and owner approval for report distribution require separate acceptance. | [Final Acceptance Checklist](HANDOVER.md#final-acceptance-checklist); no new live SSH credentials or authorized native Windows/macOS target supplied. |

### Verification for this audit

The reviewed suite has **1,493 passing tests** on both Python **3.12.14** and
**3.13.5** on this Linux runner, compared with 1,328 at the audited baseline.
The 165 additions cover Ubuntu safe failures (99), deeply nested JSON (7),
sample/live provenance and collection-clock absence (32), and historical
comparison integrity (27). No test was skipped or weakened. Dependency checks,
constrained-version portability checks and POSIX installer syntax pass. All
1,493 test identifiers remain below Windows' environment-value length limit
(maximum 4,235 characters); large JSON payloads are constructed inside tests.

Ubuntu, Windows, macOS and legacy demos retain their recorded scores and counts.
Chromium checks of these four reports plus synthetic all-pass and unavailable
states pass at 320, 390, 768, 1024 and 1440 pixels, with no document overflow or
external requests. Navigation targets, keyboard evidence disclosures, JSON/HTML
counts and scores, and A4 exports containing every control ID pass. Desktop,
mobile and printed pages were visually reviewed; the existing report CSS is
unchanged. These preview artifacts are local ignored outputs, not live evidence.

The exact pushed commit and new five-job hosted workflow outcome are recorded
in the final delivery after CI completes. Verify that revision through the
[feature-branch workflow history](https://github.com/masud1445/cyberassess/actions/workflows/portability.yml?query=branch%3Afeature%2Fmultiplatform-cyberassess).
Run `python -m pip check`, `python -m pytest -q`,
`python scripts/check_portability.py` and the three profile demos from the
reviewed checkout. The existing requirements/constraints and supported Python
3.10–3.13 installation approach remain unchanged. No boto3/cloud dependency was
added; cloud scanning was not an established mandatory requirement.

Injected tests and controlled shell stubs do not establish actual host security
correctness. In particular, re-run the strengthened Ubuntu collector on the
approved real target before relying on a new score. Successful readable absence
of an explicit password minimum remains the existing Not configured FAIL;
unreadable, malformed or conflicting evidence is ERROR. The check is limited
to explicit password-quality configuration, not complete effective PAM policy.
SSH channel reads retain Paramiko's 20-second I/O timeout; the subsequent
exit-status wait has its own 20-second deadline. These are separate bounds,
not an overall assessment or command wall-clock deadline. See the
[SSH preflight and limitations](ssh-target-setup.md).

MAC-005 and MAC-012 source selection and conditions remain unchanged. Recent
macOS can expose no reliable automatic-check scalar; network time can require
additional privileges. Neither missing preferences nor a running service becomes
PASS, and no new automatic sudo, setting change or remediation is introduced.
Existing one-second report filename/cross-save naming limitations remain; retain
the two printed paths and use a distinct output directory for each assessment.

### Privacy and historical evidence

The intentionally tracked `FINAL_LIVE_VALIDATION_100.json`, its HTML companion
and `CyberAssess_Final_Live_Assessment_Report.pdf` are historical Ubuntu lab
artifacts. They contain target/account identifiers and private-network addressing;
they are not anonymized examples or evidence of this revision's native accuracy.
Their bytes/history are preserved. Pattern checks found no private keys or
recognized credential/token material in them, but that is not complete sanitization.
Owner review is required before further distribution, including supervisor packs.

No new raw live report, diagnostic document, credential or private key is staged
for publication. The default `macos-diagnostics.json` and generated `audit_*.pdf`
outputs are ignored; renamed/manual outputs still need explicit review. Retain
useful fixtures, prior validation records and investigations with their historical
scope rather than deleting evidence or rewriting Git history.

## Earlier production-readiness review (5e898bd)

Review baseline: `f11662e9fe1421ac91ae1182326e16230e5d235a`, **1,266 passing tests**.
The updated suite has **1,328 tests**. The 62 additions cover actual collector
dispatch for macOS (12), Windows (13) and Ubuntu (15), unsupported-platform
rejection, unavailable live collection without demo fallback, repeated fresh
reads, clock provenance, timezone-aware UTC normalization, midnight/year changes,
DST gaps/folds, HTML/JSON agreement and explicit live/demo/source warnings.
Timezone fixtures carry explicit offsets and need no platform-specific zone
database or Windows-incompatible environment variables.

Python 3.12/3.13 dependency checks, the full suite, POSIX installer syntax and the
portability checker pass on this Linux development runner. The three profile
demos retain their original counts and scores. Chromium rendering is reviewed
at 320, 390, 768, 1024 and 1440 pixels, with no document overflow or external
requests. A4 exports include all control IDs, the snapshot/source warning and
the evidence/guidance appendix; all-pass and unavailable states are synthetic.

The baseline's native [Portability run 41114154791](https://github.com/masud1445/cyberassess/actions/runs/41114154791)
passed Ubuntu Python 3.10/3.12/3.13 and macOS/Windows Python 3.12. For the updated
revision, verify all five jobs in the
[feature-branch workflow history](https://github.com/masud1445/cyberassess/actions/workflows/portability.yml?query=branch%3Afeature%2Fmultiplatform-cyberassess)
against the exact pushed commit; its outcome is also recorded in the final
delivery. A passing native hosted test job verifies the regression suite and
portable demos, not effective security state or privileged reads on a receiving
machine. No live Windows/macOS target or new SSH credentials were supplied.

The current layout, CSS identity, control definitions/conditions, NIST mappings,
weighted scoring, JSON assessment fields and CLI options are preserved. Only
clock metadata is added to live collector envelopes. Ubuntu security commands
and normalization remain unchanged; one optional unprivileged target-clock
getter supplies SSH metadata. No settings, remediation or privilege changes run.
See [timestamp/provenance guidance](handover-runbook.md#understand-assessment-times-and-report-provenance)
for clock limitations, historical reports and operator acceptance.

## v2 scope and compatibility

- The original `config/controls.json` and `cyberassess/evaluator.py` remain
  unchanged: 15 Ubuntu
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

## Earlier v2 Linux development checks

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
security evidence, evaluator, Ubuntu definitions and demo evidence remain
unchanged. The current review adds clock metadata only.

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

## Hosted checks and live acceptance

[The portability workflow](../.github/workflows/portability.yml) defines Ubuntu
Python 3.10/3.12/3.13 and macOS/Windows Python 3.12 jobs. Inspect actual GitHub
Actions outcomes for the exact pushed revision; the verified baseline run is
linked above. Hosted tests/demos do not prove native elevated security reads
or the applicability of this baseline to every OS release/edition. Windows jobs
also parse installer and collector scripts under Windows PowerShell without
executing security queries. These checks passed for the published baseline;
the updated revision requires its own successful run.

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
