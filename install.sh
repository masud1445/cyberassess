#!/bin/sh
# Prepare local dependencies only; never assess or change the machine baseline.
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"
python_bin=${PYTHON:-python3}

if ! command -v "$python_bin" >/dev/null 2>&1; then
    printf '%s\n' "Python not found: $python_bin. Install Python 3.10–3.13; set PYTHON to its executable."
    exit 1
fi

python_version=$("$python_bin" -c 'import sys; v=sys.version_info; print(f"{v.major}.{v.minor}"); sys.exit(0 if (3,10) <= v[:2] < (3,14) else "Python 3.10–3.13 is required.")')
venv_python="$project_dir/.venv/bin/python"
if [ -e .venv ] || [ -L .venv ]; then
    if [ ! -f .venv/pyvenv.cfg ] || [ ! -x "$venv_python" ]; then
        printf '%s\n' "Existing .venv is not a usable POSIX virtual environment. Inspect it; move it aside before retrying."
        exit 1
    fi
    venv_version=$("$venv_python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}"); sys.exit(0 if sys.prefix != sys.base_prefix else "Existing .venv is not isolated.")')
    if [ "$venv_version" != "$python_version" ]; then
        printf '%s\n' "Existing .venv uses Python $venv_version; selected Python is $python_version. Select the matching interpreter or move .venv aside."
        exit 1
    fi
    printf '%s\n' "Reusing existing .venv (Python $venv_version)."
else
    "$python_bin" -m venv .venv
fi

"$venv_python" -m pip install --no-input -r requirements.txt -c constraints.txt
"$venv_python" -m pip check
printf '%s\n' 'Dependencies ready. Next, from the repository root:' \
    '  .venv/bin/python -m pytest -q' \
    '  .venv/bin/python scripts/check_portability.py' \
    '  .venv/bin/python main.py --list-profiles' \
    '  .venv/bin/python main.py --profile ubuntu --demo' \
    'Read docs/HANDOVER.md before an authorized live assessment.'
