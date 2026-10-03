# CyberAssess — Student / User Lab Manual

## 1. Objective
Use CyberAssess to run a read-only baseline assessment against an authorized Ubuntu lab, interpret the findings, manually remediate one or more approved gaps, and rerun the assessment to prove measurable improvement.

## 2. Prerequisites
- macOS/Linux workstation with Python 3
- CyberAssess project and dependencies installed
- authorized Ubuntu VM reachable over SSH
- SSH key access to the lab

## 3. Run the assessment
Activate the environment and run:

```bash
cd ~/Projects/cyberassess
source .venv/bin/activate
export PYTHONPATH=.
python main.py --host 192.168.252.2 --user ubuntu --key ~/.ssh/cyberassess_lab
```

CyberAssess produces a JSON file and an HTML report in `reports/`.

## 4. Interpret the result
- PASS: collected evidence satisfies the control.
- FAIL: evidence was collected, but the control is non-compliant.
- ERROR: the tool could not reliably assess the control.

The score is severity weighted: HIGH ×3, MEDIUM ×2, LOW ×1. Report verdicts are 90%+ Compliant, 70–89.9% Partially compliant, and below 70% Non-compliant.

## 5. Review a gap
For each failed control, review:
- severity;
- expected value;
- actual value;
- control-specific evidence;
- NIST mapping;
- remediation guidance and suggested command.

Do not copy remediation commands blindly. Preserve SSH access, validate configuration syntax, and change only systems you are authorized to administer.

## 6. Reassess
After an approved manual change, rerun the same live command. Compare the earlier report with the new report and record which controls changed from FAIL to PASS and how the weighted score changed.

## 7. Evidence for the internship log
Record the date/time, target, controls tested, result summary, blocker/edge case, test evidence and Git commit hash. Keep a before/after report pair for the final demonstration.
