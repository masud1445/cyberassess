# Fresh-machine setup

CyberAssess runs locally as a Python command-line tool. Prepare the laptop with the steps below, then use the [handover runbook](handover-runbook.md). Live collection additionally needs the [SSH target prerequisites](ssh-target-setup.md); the demo and portability checks need no target or credentials.

## Runtime and project requirements

| Item | Requirement |
| --- | --- |
| Laptop | macOS, Linux, or Windows; writable local project directory |
| Python | 3.10–3.13; 64-bit Python 3.12 is the recommended handover version |
| Dependencies | Install `requirements.txt` with `constraints.txt` into a new virtual environment |
| Git | Needed for cloning and recording the approved source revision; a complete source archive also works |
| Network | HTTPS to PyPI/package file hosts during installation; SSH to the explicitly authorized target for live runs |
| Application services | None: no database, web server, Node.js or Docker required |

The reviewed dependency constraints require Python 3.10 or later; the supported handover range is 3.10–3.13. Linux handover validation covers fresh environments on Python 3.10, 3.12 and 3.13. The repository workflow also defines Python 3.12 macOS/Windows checks; inspect its actual job results after pushing before claiming those platforms were validated. Other Python versions and target distributions are not covered by that matrix.

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

Replace `HANDOVER_REF` with the approved commit/tag or fetched remote branch, such as `origin/feature/deployment-handover` once published. An unpushed local branch cannot be fetched on another laptop; use the runbook's Git bundle transfer in that case. Do not silently substitute `main` for the handover revision. A supplied archive must contain `main.py`, `cyberassess/`, `config/`, `samples/`, `requirements.txt`, `constraints.txt`, `scripts/` and `tests/`.

All commands below assume the shell is in the **repository root**, the directory containing `main.py`. The application currently uses relative paths for configuration, sample evidence and reports. The explicit interpreter paths avoid shell activation and PowerShell execution-policy issues.

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

For live-audit preflight, enable the Windows OpenSSH Client optional feature if `ssh` is unavailable. The application itself uses Paramiko, not the external SSH executable. A Windows laptop is supported as a client; the assessed target still needs the Ubuntu/Linux services and tools. WSL is not required for the native client workflow.

Obtain the source and enter its root directory, then run:

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
- Existing evaluation/report suite: **7 tests passed**.
- Portability checker: a success message after importing dependencies, checking installed versions against requirements/constraints and dependency consistency, and running the real demo in a temporary project path containing spaces and Unicode. The JSON fields, result data and generated HTML are checked; no live audit is performed.
- Demo: **15 controls, 7 PASS, 8 FAIL, 0 ERROR, 54.3%**, followed by newly created JSON and HTML report paths. The FAIL results are intentional sample findings. Open the printed HTML path in a browser and verify the matching JSON; tracked historical reports are not current-run evidence.

`python -m pytest` adds the current project directory to the import path; no permanent `PYTHONPATH` setting is necessary for this workflow. Dependency download requires Internet access the first time; after installation the demo runs offline. Live SSH connectivity and sudo must be verified separately against an authorized target.

The portability checker intentionally uses temporary output rather than changing tracked reports or relying on a writable source checkout. Application demo/live runs write into `reports/`, which must be writable. Each report is saved as UTF-8; use a browser for HTML and a UTF-8-aware editor for JSON.

See the [validation record](portability-validation.md) for the interpreter versions actually exercised and the hosted-platform checks still pending.

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

The collector and CLI are unchanged by this handover work. Restrictions and existing failure modes are documented in the [runbook](handover-runbook.md), rather than hidden by setup changes.
