"""Check installed dependencies and an isolated demo; never contact an SSH target.

Run with the project's virtual-environment Python from any working directory.
Uses installed project dependencies; no extra packages are required.
"""

from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import importlib
from importlib import metadata
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile


REPORT_KEYS = {"target_name", "platform", "collector", "evidence", "assessment"}
ASSESSMENT_KEYS = {
    "total_controls", "passed", "failed", "errors", "compliance_score", "results"
}
RESULT_KEYS = {
    "control_id", "title", "severity", "status", "expected", "actual", "nist",
    "remediation", "notes", "raw_evidence",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(command: list[str], cwd: Path) -> None:
    result = subprocess.run(
        command, cwd=cwd, capture_output=True, timeout=60,
    )
    if result.returncode:
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        raise RuntimeError(f"{command[1:]} exited {result.returncode}:\n{output.strip()}")


def check_dependency_versions(repo: Path) -> None:
    # packaging is already installed by pytest; markers select this OS/Python.
    from packaging.requirements import Requirement

    launcher = "& " if sys.platform == "win32" else ""
    install = (
        f'From the repository root, run {launcher}"{sys.executable}" -m pip install '
        "-r requirements.txt -c constraints.txt."
    )
    for filename in ("requirements.txt", "constraints.txt"):
        for number, line in enumerate((repo / filename).read_text(encoding="utf-8").splitlines(), 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            requirement = Requirement(line)
            if requirement.marker and not requirement.marker.evaluate():
                continue
            try:
                installed = metadata.version(requirement.name)
            except metadata.PackageNotFoundError:
                raise RuntimeError(
                    f"{requirement.name} is not installed; expected {requirement} "
                    f"({filename}:{number}). {install}"
                ) from None
            require(
                installed in requirement.specifier,
                f"{requirement.name} {installed} does not match {requirement} "
                f"({filename}:{number}). {install}",
            )


def report_snapshot(repo: Path) -> dict[str, str]:
    """Detect accidental writes to the actual checkout's reports directory."""
    return {
        str(path.relative_to(repo)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (repo / "reports").rglob("*") if path.is_file()
    }


class ReportText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def check_demo(repo: Path) -> None:
    controls = json.loads((repo / "config/controls.json").read_text(encoding="utf-8"))
    sample = json.loads((repo / "samples/demo_evidence.json").read_text(encoding="utf-8"))
    evaluator = runpy.run_path(str(repo / "cyberassess/evaluator.py"))["evaluate_baseline"]
    expected = {**sample, "assessment": evaluator(controls, sample["evidence"])}
    original_reports = report_snapshot(repo)

    # Exercise Windows/macOS/Linux paths without depending on the calling cwd.
    with tempfile.TemporaryDirectory(prefix="cyberassess portable café ") as temporary:
        project = Path(temporary)
        shutil.copy2(repo / "main.py", project / "main.py")
        shutil.copytree(
            repo / "cyberassess", project / "cyberassess",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        for relative in ("config/controls.json", "samples/demo_evidence.json"):
            destination = project / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(repo / relative, destination)

        output_dir = project / "reports"
        require(not output_dir.exists(), "Isolated demo must start without reports.")
        run([sys.executable, "-B", "main.py", "--demo"], cwd=project)
        outputs = sorted(output_dir.iterdir())
        require(
            len(outputs) == 2 and {path.suffix for path in outputs} == {".json", ".html"},
            "Demo must create exactly one JSON and one HTML report in its copied project.",
        )
        for path in outputs:
            require(path.is_file() and path.stat().st_size > 0, f"Empty report: {path.name}")
            require(path.resolve().is_relative_to(project.resolve()), "Report escaped temporary project.")
        contents = {path.suffix: path.read_text(encoding="utf-8") for path in outputs}
        report = json.loads(contents[".json"])
        require(set(report) == REPORT_KEYS, "JSON top-level keys changed.")
        assessment = report["assessment"]
        require(set(assessment) == ASSESSMENT_KEYS, "JSON assessment keys changed.")
        require(
            all(set(result) == RESULT_KEYS for result in assessment["results"]),
            "JSON control-result keys changed.",
        )
        require(report == expected, "Demo JSON differs from sample evidence and evaluate_baseline output.")
        require(
            {key: assessment[key] for key in ASSESSMENT_KEYS - {"results"}} == {
                "total_controls": 15, "passed": 7, "failed": 8, "errors": 0,
                "compliance_score": 54.3,
            },
            "Demo baseline changed: expected 15 controls, 7 PASS, 8 FAIL, 0 ERROR, 54.3%.",
        )
        require(
            [result["control_id"] for result in assessment["results"]]
            == [control["id"] for control in controls],
            "Demo control order or coverage changed.",
        )
        parser = ReportText()
        parser.feed(contents[".html"])
        text = " ".join(parser.parts)
        labels = (
            "CyberAssess", "Compliance & Baseline Report", "Assessment summary",
            "Remediation findings", "All controls", "54.3",
        )
        for label in (*labels, *(control["id"] for control in controls)):
            require(label in text, f"HTML report is missing {label!r}.")

    require(report_snapshot(repo) == original_reports, "Demo changed reports in the original checkout.")


def main() -> int:
    try:
        require(sys.version_info >= (3, 10), "Python 3.10 or newer is required.")
        sys.dont_write_bytecode = True
        repo = Path(__file__).resolve().parent.parent
        for module in ("paramiko", "pytest"):
            importlib.import_module(module)
        check_dependency_versions(repo)
        run([sys.executable, "-m", "pip", "check"], cwd=repo)
        check_demo(repo)
    except (ImportError, OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: Python {sys.version.split()[0]} requirements/constraints and isolated portable demo.")
    print("Validated UTF-8 JSON/HTML, unchanged JSON data, 15 controls and 54.3%; no SSH used.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
