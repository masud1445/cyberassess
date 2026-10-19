# Prepare local dependencies only; never assess or change the machine baseline.
[CmdletBinding()]
param([string]$Python = "py")

$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") {
    throw "Use install.sh on macOS/Linux. This helper prepares a native Windows environment."
}

$PythonArguments = @()
if ((Split-Path -Leaf $Python) -in @("py", "py.exe")) {
    $PythonArguments = @("-3.12")
}

Push-Location $PSScriptRoot
try {
    $VersionCheck = "import sys; v=sys.version_info; print(str(v.major) + '.' + str(v.minor)); sys.exit(0 if (3,10) <= v[:2] < (3,14) else 'Python 3.10-3.13 is required.')"
    $PythonVersion = & $Python @PythonArguments -c $VersionCheck
    if ($LASTEXITCODE -ne 0) { throw "Select an installed Python 3.10-3.13 executable with -Python. The py launcher defaults to Python 3.12." }
    $VenvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath ".venv") {
        if (!(Test-Path -LiteralPath ".venv\pyvenv.cfg") -or !(Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
            throw "Existing .venv is not a usable Windows virtual environment. Inspect it; move it aside before retrying."
        }
        $IsolationCheck = "import sys; print(str(sys.version_info.major) + '.' + str(sys.version_info.minor)); sys.exit(0 if sys.prefix != sys.base_prefix else 'Existing .venv is not isolated.')"
        $VenvVersion = & $VenvPython -c $IsolationCheck
        if ($LASTEXITCODE -ne 0) { throw "Existing .venv could not be validated. Inspect it before retrying." }
        if ($VenvVersion -ne $PythonVersion) {
            throw "Existing .venv uses Python $VenvVersion; selected Python is $PythonVersion. Select the matching interpreter or move .venv aside."
        }
        Write-Output "Reusing existing .venv (Python $VenvVersion)."
    } else {
        & $Python @PythonArguments -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw "Could not create .venv. Check Python's venv support and directory permissions." }
    }
    & $VenvPython -m pip install --no-input -r requirements.txt -c constraints.txt
    if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed. Resolve the pip error and retry; keep TLS verification enabled." }
    & $VenvPython -m pip check
    if ($LASTEXITCODE -ne 0) { throw "Installed dependencies are inconsistent. Review pip check output." }
    Write-Output @'
Dependencies ready. Next, from the repository root:
  .\.venv\Scripts\python.exe -m pytest -q
  .\.venv\Scripts\python.exe scripts/check_portability.py
  .\.venv\Scripts\python.exe main.py --list-profiles
  .\.venv\Scripts\python.exe main.py --profile windows --demo
Read docs/HANDOVER.md before an authorized live assessment.
'@
} finally {
    Pop-Location
}
