# Fresh-machine setup

CyberAssess runs as a Python command-line tool. Prepare the laptop with the steps below, then use the [handover runbook](handover-runbook.md). All profile demos and portability checks need no target or credentials. Live Ubuntu SSH collection additionally needs the [SSH target prerequisites](ssh-target-setup.md); Windows/macOS live profiles run locally on the authorized native target.

## Runtime and project requirements

| Item | Requirement |
| --- | --- |
| Laptop | macOS, Linux, or Windows; writable local project directory |
| Python | 3.10–3.13; 64-bit Python 3.12 is the recommended handover version |
| Dependencies | Install `requirements.txt` with `constraints.txt` into a new virtual environment |
| Git | Needed for cloning and recording the approved source revision; a complete source archive also works |
| Network | HTTPS to PyPI/package file hosts during installation; SSH to the explicitly authorized Ubuntu target for remote live runs |
| Application services | None: no database, web server, Node.js or Docker required |

The reviewed dependency constraints require Python 3.10 or later; the supported handover range is 3.10–3.13. Earlier Linux handover validation covered fresh environments on Python 3.10, 3.12 and 3.13. See the current [validation record](portability-validation.md) for the v2 checks actually executed. The repository workflow also defines Python 3.12 macOS/Windows checks; inspect its actual job results after pushing before claiming those platforms were validated. A hosted demo/test job still does not validate privileged native security collection. Other Python versions and target distributions are not covered by that matrix.

Do not transfer `.venv`, Python caches, private keys, or local trust files as part of the source checkout. Virtual environments contain platform-specific executables and paths. Recreate them even when moving between two laptops with the same OS.

## Obtain the approved source

Get the exact handover commit or approved tag from the maintainer. If the handover branch is available on GitHub:

```text
git clone https://github.com/masud1445/cyberassess.git
cd cyberassess
git fetch origin
git switch --detach HANDOVER_REF
git log -1 --oneline
```

Replace `HANDOVER_REF` with the approved commit/tag or fetched remote branch, such as `origin/feature/multiplatform-cyberassess` once published. An unpushed local branch cannot be fetched on another laptop; use the runbook's Git bundle transfer in that case. Do not silently substitute `main` for the handover revision. A supplied archive must contain `main.py`, `cyberassess/`, `config/`, `samples/`, `requirements.txt`, `constraints.txt`, `scripts/`, both installer helpers and `tests/`.

All commands below assume the shell is in the **repository root**, the directory containing `main.py`. The original unqualified Ubuntu workflow uses relative config/sample paths; output paths are also relative unless absolute. The explicit interpreter paths avoid shell activation and PowerShell execution-policy issues.

## macOS

Install Git and a supported Python from trusted installers. With Homebrew already installed:

```bash
brew install python@3.12 git
python3.12 --version
git --version
ssh -V
```

Alternatively use the Python 3.12 installer from python.org and Git's macOS installation instructions. Select that interpreter explicitly if multiple Python versions exist; do not rely on the OS-managed Python.

After obtaining the source and entering the repository root:

```bash
PYTHON=python3.12 sh install.sh
.venv/bin/python -m pytest -q
.venv/bin/python scripts/check_portability.py
.venv/bin/python main.py --profile macos --demo
```

The helper installs dependencies only. Equivalent manual setup, useful if shell scripts are restricted:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -c constraints.txt
.venv/bin/python -m pip check
.venv/bin/python -m pytest -q
.venv/bin/python scripts/check_portability.py
.venv/bin/python main.py --demo
```

For convenient later commands, `source .venv/bin/activate` lets you use `python` instead of `.venv/bin/python`. Run `deactivate` when finished.

## Linux

On Ubuntu/Debian, install Git, a Python 3.10–3.13 interpreter, its virtual-environment support, and an SSH client. Review the OS package versions before proceeding:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv python3-pip openssh-client
python3 --version
git --version
ssh -V
```

On Fedora-family systems the corresponding packages are `git python3 python3-pip openssh-clients`; use the supported package manager and ensure `python3 -m venv` is available. If the distro Python is outside the supported range, install a supported interpreter alongside it through your approved distribution/tooling. Do not replace the system Python.

From the repository root:

```bash
sh install.sh
.venv/bin/python -m pytest -q
.venv/bin/python scripts/check_portability.py
.venv/bin/python main.py --profile ubuntu --demo
```

Set `PYTHON=/approved/path/to/python3.12` when the default `python3` is outside the supported range. Equivalent manual setup:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -c constraints.txt
.venv/bin/python -m pip check
.venv/bin/python -m pytest -q
.venv/bin/python scripts/check_portability.py
.venv/bin/python main.py --demo
```

For convenient later commands, `source .venv/bin/activate` lets you use `python`. Install application packages into the virtual environment; no `sudo pip` or root application execution is needed.

## Windows (PowerShell)

Install 64-bit Python 3.12 from python.org with the Python launcher, and Git for Windows. Reopen PowerShell after installation and verify:

```powershell
py -3.12 --version
git --version
ssh -V
```

For Ubuntu SSH preflight, enable the Windows OpenSSH Client optional feature if `ssh` is unavailable. The Ubuntu remote collector uses Paramiko, not the external SSH executable. For the native Windows local profile, use ordinary Windows PowerShell and Windows Python, not WSL; the profile calls the OS's Windows PowerShell 5.1 executable. WSL does not collect the Windows host's security configuration through this profile.

Obtain the source and enter its root directory, then run:

```powershell
.\install.ps1
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/check_portability.py
.\.venv\Scripts\python.exe main.py --profile windows --demo
```

The helper defaults to `py -3.12`; use `.\install.ps1 -Python "C:\Approved\Python312\python.exe"` for an explicit interpreter. It installs no OS components, does not change the execution policy and does not start an assessment. If scripts are restricted, use the equivalent manual commands:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -c constraints.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/check_portability.py
.\.venv\Scripts\python.exe main.py --demo
```

No activation or execution-policy change is required. If the launcher is unavailable, use the full path to the approved Python 3.12 executable to create `.venv`. Quote paths that contain spaces; PowerShell executes a quoted executable path with the call operator, for example `& "C:\Path With Spaces\Python312\python.exe" -m venv .venv`.

To use the short `python` commands in the runbook, optional activation is `.\.venv\Scripts\Activate.ps1` if your policy permits it. Otherwise substitute `.\.venv\Scripts\python.exe` throughout.

## Verify the installation

The commands above must complete with:

- `pip check`: **No broken requirements found**.
- Test suite: all tests pass, including the original seven regression checks and new profile/collector/report/CLI coverage. Compare the actual total with the current validation record.
- Portability checker: a success message after importing dependencies, checking installed versions against requirements/constraints and dependency consistency, and exercising the offline report workflow in a temporary path containing spaces and Unicode. It does not establish live collection access.
- Original `--demo`: **15 controls, 7 PASS, 8 FAIL, 0 ERROR, 54.3%**, followed by newly created JSON and HTML report paths. Explicit-profile demos cover all 15 Ubuntu, 13 Windows and 12 macOS controls. Fixture findings are intentional, not a statement about the laptop. Open the printed HTML path in a browser and verify the matching JSON; tracked historical reports are not current-run evidence.

`python -m pytest` adds the current project directory to the import path; no permanent `PYTHONPATH` setting is necessary for this workflow. Dependency download requires Internet access the first time; after installation the demo runs offline. Live SSH connectivity and sudo must be verified separately against an authorized target.

The portability checker intentionally uses temporary output rather than changing tracked reports or relying on a writable source checkout. Application demo/live runs write into `reports/`, which must be writable. Each report is saved as UTF-8; use a browser for HTML and a UTF-8-aware editor for JSON.

See the [validation record](portability-validation.md) for the interpreter versions actually exercised and the hosted-platform checks still pending.

## Live platform prerequisites

Run only against an owned or explicitly authorized system. Record the target, profile, operator, access level and permitted time window before live collection. The CLI never elevates privileges or changes policy; denied/unsupported/ambiguous evidence is not a passing result. Demos are the safe acceptance path before authorization and target preparation.

### Ubuntu

The original SSH workflow requires the approved key, trusted host key and narrowly scoped passwordless `sudo -n` permissions in the [SSH guide](ssh-target-setup.md). The native local Ubuntu profile uses the same baseline and read-only command purposes on the actual Ubuntu host. It is not a portable Linux baseline; missing systemd/GNU/APT tooling in a container or incompatible environment limits evidence. Arrange the approved exact privileged reads with the administrator rather than granting unrestricted sudo or automatically installing assessment subjects. Some inherited commands suppress stderr or use pipelines whose final stage can succeed after a failed read; verify the exact privileged checks in preflight and review actual evidence even when a result says PASS.

```bash
.venv/bin/python main.py --profile ubuntu --local --output reports/ubuntu-local
```

### Windows

Use a native Windows installation with Windows PowerShell 5.1 and the platform's security cmdlets. Collection is local: there is no WinRM or remote PowerShell transport in CyberAssess. Use an administrator-approved elevated terminal when the necessary read permissions require it; elevation is a deliberate operator action, not an installer/collector feature. BitLocker, Defender, Secure Boot, SMB and local-account cmdlets depend on OS edition, firmware, installed modules and permissions. Unsupported features or denied reads remain ERROR; a legacy-BIOS or unsupported-edition system does not automatically pass Secure Boot/BitLocker.

```powershell
.\.venv\Scripts\python.exe main.py --profile windows --local --output reports/windows-local
```

The profile covers all Domain/Private/Public firewall profiles, the OS volume's BitLocker protection and the built-in Guest account by SID/RID rather than localized account name. Its inactivity checks concern the configured machine policy, not every user's effective screen lock. UAC checks configuration and do not prove a pending setting has taken effect after restart. SMBv1 checks the server protocol, not the client component. Windows Update policy is outside this initial profile.

### macOS

Use native macOS and its installed `fdesetup`, Application Firewall `socketfilterfw`, `csrutil`, `spctl`, `defaults`, `plutil`, `launchctl` and `systemsetup` tools. Collection is local and read-only, with no automatic `sudo` or privilege prompt. `systemsetup` Remote Login and network-time queries commonly require administrator/root access. The collector tries an explicit launchd SSH override and explicit automatic-time preferences when those reads fail; unavailable evidence still remains ERROR.

```bash
.venv/bin/python main.py --profile macos --local --output reports/macos-local
```

The screen-saver checks read the **invoking user's explicit preferences**. They do not resolve ByHost, effective runtime or MDM policy; update checks similarly inspect explicit machine preferences rather than asserting effective managed policy. Exact-key plist extraction provides a second read path, without inventing missing values. Missing preference keys are unavailable evidence. Running the entire application as root changes the user scope and is not a general fix for errors. Agree on the user scope with the owner, record inaccessible privileged checks, and avoid blanket elevation just to improve coverage. See [macOS live collection troubleshooting](macos-live-collection.md) for the five affected controls and Tahoe acceptance checks. Native release/architecture compatibility remains subject to acceptance on the receiving machine.

### Remote operator sessions

For Windows/macOS, first obtain an authorized terminal session using the organization's tooling, install the reviewed source and dependencies **on the target**, then run its matching `--profile ... --local` command there. CyberAssess does not connect to that target itself. `--host/--user/--key` select only the Ubuntu SSH workflow; combining them with Windows/macOS is rejected. Transfer the paired output files securely for viewing when the target has no desktop browser.

## Dependency refresh and reproducibility

`requirements.txt` keeps the project's supported Paramiko and pytest ranges. `constraints.txt` selects the direct and transitive package versions validated for this handover, with `colorama` constrained only on Windows and additional Python 3.10 dependencies constrained only below Python 3.11. It is a version-constraint set, not an artifact-hash lockfile: the package index selects the appropriate platform wheels or source archives over verified HTTPS, with pip checking index-provided artifact hashes when available. Keep TLS and package verification enabled. Python, OS and architecture still affect which artifacts are installed.

For a future dependency update, use a separate branch and a new virtual environment, review available versions and advisories, deliberately update the constraints, then run `pip check`, the existing tests, the portability checker, and the hosted OS matrix. Keep the known-good environment until acceptance; do not combine an unreviewed upgrade with an operational audit.

Record provenance for a handover without recording credentials:

```text
git rev-parse HEAD
python --version
python -m pip freeze
```

Use the virtual environment's interpreter. Store this output with the handover record, outside tracked application files. An Internet-restricted deployment can use an approved wheelhouse prepared for the **same OS, architecture and Python version**, with checksums retained by the maintainer; do not copy wheels or virtual environments blindly across platforms.

## Setup troubleshooting

| Symptom | Action |
| --- | --- |
| `python`/`py` not found or wrong version | Reopen the shell; use the installed interpreter's explicit path and confirm its version. |
| `ensurepip`/`venv` unavailable on Linux | Install the matching distro `python3-venv` package, then recreate the incomplete `.venv` you just made. |
| Import failure or externally managed environment error | Check you are invoking `.venv`'s Python; install the requirements there. |
| `config/controls.json` not found | Change to the repository root; retain `config/` and `samples/` during transfer. |
| PowerShell blocks activation | Use `.\.venv\Scripts\python.exe` directly, without changing machine policy. |
| TLS/certificate or proxy error | Configure the organization's supported proxy/CA trust; for python.org macOS Python, complete its certificate installation step. Do not use `--trusted-host` or disable TLS validation. |
| Native dependency cannot install | Use a supported 64-bit Python/platform and current compatible pip. If a source build is unavoidable, follow the dependency's official compiler/OpenSSL/libffi prerequisites or use an approved wheelhouse. |
| Tests pass but live collection fails | Continue with the SSH/sudo preflight in the target guide; local tests do not validate a remote host. |

The original Ubuntu controls, SSH collection, evaluator/scoring and unqualified command workflows remain available. New platform profiles add separate native read-only collectors; their operational and validation limits are documented in the [runbook](handover-runbook.md).
