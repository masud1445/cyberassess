# Archived development context and requirement mapping

This record preserves CyberAssess's original academic context for development
history and later internship reporting. It is **not** a product operating
requirement, release gate or dependency on academic approval. Use the
[product overview](../README.md), [operational handover](HANDOVER.md) and
[technical validation record](portability-validation.md) for current operation.

## Original scope

The project originated under **Internship Pillar 2 / Sub-Track 2.1: Compliance
& Baseline Check Scripts**. Its official technical requirements were:

- Develop automated Python audit scripts using appropriate tools such as
  Paramiko, boto3, os and json.
- Parse OS/cloud configuration evidence against CIS Benchmarks or NIST SP 800-53.
- Generate automated Pass/Fail scoring.
- Produce gap reports suitable for SME security reviews and IT class grading.

The established implementation scope was authorized OS assessment using selected
NIST SP 800-53 references. The example library boto3 did not make AWS/cloud
scanning mandatory. The development brief included supervisor review, student
submission and academic acceptance; these belong to that historical process,
not to the independent application's operating requirements.

## Historical requirement audit

The following table is preserved from the handover at
[`04e7cd2a3edbc30a22bab0c75d7c0eccb44990a2`](https://github.com/masud1445/cyberassess/blob/04e7cd2a3edbc30a22bab0c75d7c0eccb44990a2/docs/HANDOVER.md).
Its academic wording and acceptance references describe that review. They do
not impose current product requirements or imply formal NIST certification.

| Official requirement | Existing implementation | Relevant source | Successful verification evidence | Fulfilment | Genuine remaining gap |
| --- | --- | --- | --- | --- | --- |
| Automated Python audit scripts using appropriate tools | Python CLI; Paramiko Ubuntu SSH; native Ubuntu, Windows and macOS reads; stdlib os/json/subprocess/ctypes | `main.py`, `cyberassess/collector.py`, `cyberassess/collectors/` | CLI/collector/platform suites; three runnable demos; [hosted and local verification](portability-validation.md) | Met for the OS scope | Receiving-machine permissions and authorized native acceptance remain separate. No cloud-scanning requirement established. |
| Parse OS/cloud evidence against CIS or NIST | 15 Ubuntu, 13 Windows and 12 macOS configuration checks with explicit values, operators and selected NIST references | `config/controls.json`, `config/profiles/`, `cyberassess/profiles.py` | Profile validation, parser/denial/malformed-output tests; [all control mappings and scope](control_master_table.md) | Met for selected OS/NIST checks | Limited configuration coverage; not a full NIST/CIS assessment or certification. Unknown native state remains ERROR. |
| Automated Pass/Fail scoring | Shared evaluator produces PASS/FAIL/ERROR; High=3, Medium=2, Low=1; only PASS earns numerator weight | `cyberassess/evaluator.py` | Evaluator and Ubuntu golden regressions; 54.3% reference demo; ERROR denominator tests | Met | ERROR is unavailable evidence, not a confirmed insecure state. Resolve evidence limitations before interpreting a grade. |
| Gap reports suitable for SME reviews and IT grading | Self-contained JSON/HTML, expected/actual values, severity, NIST references, evidence, findings, display-only guidance and A4 output | `cyberassess/reporting.py`, `samples/`, `scripts/check_portability.py` | Report/provenance/timestamp suites, JSON/HTML comparison, browser/A4 review and portable demos | Met with documented limitations | Supervisor must approve scope and grading policy; snapshots and weighted baseline verdicts do not certify compliance. |

## Verification milestones

| Revision | Recorded verification | Scope |
| --- | --- | --- |
| `f11662e9fe1421ac91ae1182326e16230e5d235a` | 1,266 tests; [five-job CI](https://github.com/masud1445/cyberassess/actions/runs/41114154791) | Earlier native collector and portability baseline |
| `5e898bd329d92b49baf37fecc9a1de521e40eb97` | 1,328 tests; [five-job CI](https://github.com/masud1445/cyberassess/actions/runs/41121239929) | Platform dispatch, clock provenance and report readiness |
| `04e7cd2a3edbc30a22bab0c75d7c0eccb44990a2` | 1,493 tests; [five-job CI](https://github.com/masud1445/cyberassess/actions/runs/41154107906) | Ubuntu safe failures, JSON depth, live/demo provenance and snapshot comparison integrity |

The subsequent product presentation review removed academic requirements from
product guidance, corrected the legacy demo's misleading Live Assessment banner,
and standardized report wording. It preserved controls, collection, evaluation,
JSON contracts, scoring and report CSS. The old demo banner and prior product
wording remain inspectable at the source revision above; the console test fixture
was updated to match the truthful demonstration label.

Hosted tests and simulated fixtures establish the recorded software paths, not
the security correctness of an untested native target. Authorized receiving-host
validation and reliable evidence remain operational requirements.

## Retained records

Technical investigations, the engineering [work-log template](work_log_template.md),
training documentation and historical validation reports remain in the repository.
Tracked historical live reports contain target/account identifiers and private
network addressing; their bytes and history are preserved. Review them before
sharing in any operational, academic or external report. Pattern checks are not
complete sanitization. Do not include credentials or private keys in a handover.
