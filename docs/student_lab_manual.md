# CyberAssess — Student Lab Manual
## Automated Ubuntu Security Baseline Assessment

### 1. Lab Objective

The purpose of this lab is to use **CyberAssess** to perform an automated, read-only cybersecurity baseline assessment against an authorized Ubuntu Linux system.

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

- macOS or Linux workstation;
- Python 3;
- CyberAssess project and dependencies;
- authorized Ubuntu Linux VM/server;
- SSH connectivity;
- authorized SSH private key;
- Python virtual environment.

Example lab environment:

```text
Target: cyberlab
Platform: Ubuntu Linux
Connection: SSH / Paramiko
Assessment mode: Read-only