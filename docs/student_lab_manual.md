# CyberAssess — Student Lab Manual
## Automated Ubuntu Security Baseline Assessment

### 1. Lab Objective

The purpose of this lab is to use **CyberAssess** to perform an automated, read-only cybersecurity baseline assessment against an authorized Ubuntu Linux system. This exercise uses the original 15-control Ubuntu SSH workflow. The application also offers a 13-control native Windows profile and a 12-control native macOS profile; they assess different baselines and are not interchangeable lab targets.

CyberAssess collects live system evidence over SSH, compares the evidence with configured security controls, calculates PASS / FAIL / ERROR results, produces a compliance score, and generates a gap report.

The complete workflow is:

**Live evidence collection → baseline evaluation → PASS / FAIL / ERROR scoring → gap review → authorized manual remediation → reassessment**

CyberAssess does not automatically modify the target system.

---

### 2. Learning Outcomes

After completing this lab, the student should be able to:

- run a Python-based automated security assessment;
- collect live Ubuntu configuration evidence through SSH;
- interpret PASS, FAIL and ERROR results;
- compare expected and actual security values;
- identify security gaps and remediation guidance;
- understand selected NIST SP 800-53 mappings;
- manually remediate an approved lab issue;
- rerun the assessment and verify measurable improvement.

---

### 3. Prerequisites

Required environment:

- macOS, Windows or Linux operator workstation;
- supported Python 3.10–3.13 (3.12 recommended), Git and machine-local dependencies;
- CyberAssess project and dependencies;
- authorized Ubuntu Linux VM/server;
- SSH connectivity;
- authorized SSH private key;
- Python virtual environment.

Complete [fresh-machine setup](setup.md) and the [Ubuntu SSH authorization, key,
host-trust and read-permission preflight](ssh-target-setup.md). Do not transfer
private keys or an existing virtual environment in a project submission.

Example lab environment:

```text
Target: cyberlab
Platform: Ubuntu Linux
Connection: SSH / Paramiko
Assessment mode: Read-only
```

`cyberlab` is an illustrative lab name, not a required hostname. Replace every
placeholder below with the approved target/account/path. Run from the repository
root. `python` means `.venv/bin/python` on macOS/Linux or
`.\.venv\Scripts\python.exe` on Windows.

### 4. Offline workflow check

```text
python -m pip check
python -m pytest -q
python scripts/check_portability.py
python main.py --demo --output reports/lab-demo
```

The Ubuntu demonstration intentionally records **15 controls, 7 PASS, 8 FAIL,
0 ERROR and 54.3%**. Open the two printed JSON/HTML paths and compare the target,
profile, counts and score. Demo data does not describe the operator workstation
or prove live SSH access. The legacy console heading is retained for
compatibility; use the explicit demo invocation and report source warning.

### 5. Authorized live Ubuntu assessment

Obtain owner approval and complete the SSH preflight before running:

```text
python main.py --host TARGET_ADDRESS --user ASSESSMENT_USER --key "PATH_TO_PRIVATE_KEY" --output reports/lab-before
```

The target must meet the Ubuntu baseline prerequisites. If running directly on
the authorized Ubuntu target, `--profile ubuntu --local` is an alternative to
SSH. Native Windows/macOS assessment runs on its matching target with `--local`;
see the [operator runbook](handover-runbook.md#live-native-local-assessment).
Never select another OS profile to obtain a different result.

### 6. Interpret evidence and findings

- PASS means available evidence satisfies the configured rule.
- FAIL means available evidence does not satisfy the rule.
- ERROR means the state is unavailable or cannot be reliably interpreted; it is
  not a confirmed insecure setting. Investigate the recorded collection reason.

Weights remain High = 3, Medium = 2 and Low = 1. Only passing weights contribute
to the numerator; every control, including ERROR, remains in the denominator.
A completed process can return zero while controls FAIL or ERROR. A 100% score
describes only the selected baseline, not certification or complete security.

For selected findings, explain the expected value, actual value, evidence source,
NIST reference, severity and proposed owner-reviewed action. If evidence is
missing, record the limitation rather than inventing a value or forcing PASS.
Check the assessment window, collection clock and target-local/UTC offset;
historical reports may not contain those fields. HTML is a point-in-time
snapshot and never updates the target's evidence when reopened.

### 7. Approved change and reassessment

CyberAssess never applies remediation. Any lab change requires separate owner
approval, a recovery/access plan and the normal change process. After an approved
change, run the same authorized workflow/profile/version into a new output
directory, such as `reports/lab-after`. Compare matched controls and evidence;
do not rank different OS profiles by percentage or assume every ERROR-to-PASS
transition proves a security setting changed.

### 8. Supervisor submission

Submit the source revision, runtime/dependency check results, assessment scope,
paired JSON/HTML paths, selected evidence explanations, remaining ERROR reasons
and reassessment outcome. Use the [handover acceptance checklist](HANDOVER.md)
and [validation record](portability-validation.md). Distinguish fixture tests,
hosted native CI and independently reviewed live target evidence.

Share reports only through the owner's approved process. Review target/account
identifiers and raw evidence; HTML filtering is not complete sanitization.
Never include credentials, private keys or unrestricted configuration dumps in
public submissions. Grading should assess correct scope, reproducible evidence
and sound interpretation, not require every machine to achieve 100%.
