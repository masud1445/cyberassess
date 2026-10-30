"""Check installed dependencies and isolated demos; never assess a live target.

Run with the project's virtual-environment Python from any working directory.
Uses installed project dependencies; no extra packages are required.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
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
PROFILE_REPORT_KEYS = REPORT_KEYS | {
    "schema_version", "application", "profile", "assessment_mode",
    "assessment_started_at", "assessment_completed_at",
}
PROFILE_RESULT_KEYS = RESULT_KEYS | {
    "profile", "category", "description", "evidence_source",
}
PROFILE_CONTROL_COUNTS = {"ubuntu": 15, "windows": 13, "macos": 12}


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


def read_outputs(output_dir: Path, project: Path) -> tuple[dict, str]:
    require(output_dir.is_dir(), f"Demo did not create {output_dir.name}.")
    outputs = sorted(output_dir.iterdir())
    require(
        len(outputs) == 2 and {path.suffix for path in outputs} == {".json", ".html"},
        "Each demo must create exactly one JSON and one HTML report in its output directory.",
    )
    for path in outputs:
        require(path.is_file() and path.stat().st_size > 0, f"Empty report: {path.name}")
        require(path.resolve().is_relative_to(project.resolve()), "Report escaped temporary project.")
    contents = {path.suffix: path.read_text(encoding="utf-8") for path in outputs}
    return json.loads(contents[".json"]), contents[".html"]


def check_html(html: str, controls: list[dict], *extra_labels: str) -> None:
    parser = ReportText()
    parser.feed(html)
    text = " ".join(parser.parts)
    labels = (
        "CyberAssess", "Compliance & Baseline Report", "Assessment summary",
        "Remediation findings", "All controls", "point-in-time snapshot",
        "not formal compliance certification", "Demonstration data", *extra_labels,
    )
    for label in (*labels, *(control["id"] for control in controls)):
        require(label in text, f"HTML report is missing {label!r}.")


def check_legacy_demo(repo: Path, project: Path) -> None:
    """Keep the original unversioned Ubuntu report contract unchanged."""
    controls = json.loads((repo / "config/controls.json").read_text(encoding="utf-8"))
    sample = json.loads((repo / "samples/demo_evidence.json").read_text(encoding="utf-8"))
    evaluator = runpy.run_path(str(repo / "cyberassess/evaluator.py"))["evaluate_baseline"]
    expected = {**sample, "assessment": evaluator(controls, sample["evidence"])}
    output_dir = project / "reports"
    require(not output_dir.exists(), "Isolated legacy demo must start without reports.")
    run([sys.executable, "-B", "main.py", "--demo"], cwd=project)
    report, html = read_outputs(output_dir, project)
    require(set(report) == REPORT_KEYS, "Legacy JSON top-level keys changed.")
    assessment = report["assessment"]
    require(set(assessment) == ASSESSMENT_KEYS, "Legacy JSON assessment keys changed.")
    require(
        all(set(result) == RESULT_KEYS for result in assessment["results"]),
        "Legacy JSON control-result keys changed.",
    )
    require(report == expected, "Legacy demo JSON differs from sample evidence and evaluate_baseline output.")
    require(
        {key: assessment[key] for key in ASSESSMENT_KEYS - {"results"}} == {
            "total_controls": 15, "passed": 7, "failed": 8, "errors": 0,
            "compliance_score": 54.3,
        },
        "Legacy baseline changed: expected 15 controls, 7 PASS, 8 FAIL, 0 ERROR, 54.3%.",
    )
    require(
        [result["control_id"] for result in assessment["results"]]
        == [control["id"] for control in controls],
        "Legacy demo control order or coverage changed.",
    )
    check_html(html, controls, "54.3")


def check_profile_demos(repo: Path, project: Path) -> None:
    # Add only the known checkout so this script also works from another cwd.
    sys.path.insert(0, str(repo))
    try:
        from cyberassess import __version__
        from cyberassess.profiles import build_profile_report, list_profiles
    finally:
        sys.path.pop(0)

    profiles = list_profiles()
    require(
        [profile.id for profile in profiles] == list(PROFILE_CONTROL_COUNTS),
        "Available profiles changed; update the portability coverage explicitly.",
    )
    require(__version__ == "2.0.0", "Expected CyberAssess application version 2.0.0.")
    for profile in profiles:
        output_dir = project / f"profile {profile.id} café"
        require(not output_dir.exists(), "Each profile demo must use a fresh output directory.")
        run([
            sys.executable, "-B", "main.py", "--profile", profile.id, "--demo",
            "--output", str(output_dir),
        ], cwd=project)
        report, html = read_outputs(output_dir, project)
        require(set(report) == PROFILE_REPORT_KEYS, f"{profile.id}: versioned JSON top-level keys changed.")
        require(report["schema_version"] == "2.0", f"{profile.id}: expected JSON schema 2.0.")
        require(
            report["application"] == {"name": "CyberAssess", "version": __version__},
            f"{profile.id}: incorrect application metadata.",
        )
        require(
            profile.version == "1" and report["profile"] == {
                "id": profile.id, "name": profile.name, "version": profile.version,
                "platform": profile.platform, "description": profile.description,
            },
            f"{profile.id}: incorrect baseline identity/version metadata.",
        )
        require(report["assessment_mode"] == "demo", f"{profile.id}: sample data must be identified as demo.")
        sample = profile.load_demo()
        require(
            "sample" in str(sample.get("collector", {}).get("method", "")).lower(),
            f"{profile.id}: fixture must identify its collection method as sample data.",
        )
        started = datetime.fromisoformat(report["assessment_started_at"])
        completed = datetime.fromisoformat(report["assessment_completed_at"])
        require(
            started.tzinfo is not None and completed.tzinfo is not None and started <= completed,
            f"{profile.id}: assessment timestamps must be ordered and timezone-aware.",
        )
        expected = build_profile_report(
            profile, sample, assessment_mode="demo",
            started_at=report["assessment_started_at"],
            completed_at=report["assessment_completed_at"],
        )
        require(report == expected, f"{profile.id}: demo JSON differs from sample data and profile evaluation.")
        controls = profile.load_controls()
        assessment = report["assessment"]
        require(set(assessment) == ASSESSMENT_KEYS, f"{profile.id}: JSON assessment keys changed.")
        require(
            all(set(result) == PROFILE_RESULT_KEYS for result in assessment["results"]),
            f"{profile.id}: versioned JSON control-result keys changed.",
        )
        require(
            assessment["total_controls"] == len(controls) == PROFILE_CONTROL_COUNTS[profile.id],
            f"{profile.id}: incorrect control count.",
        )
        require(
            [result["control_id"] for result in assessment["results"]]
            == [control["id"] for control in controls],
            f"{profile.id}: demo control order or coverage changed.",
        )
        require(
            all(result["status"] in {"PASS", "FAIL", "ERROR"} for result in assessment["results"]),
            f"{profile.id}: unsupported assessment status.",
        )
        check_html(html, controls, profile.name, f"v{profile.version}", "Demonstration data", "Demo")


def check_demos(repo: Path) -> None:
    original_reports = report_snapshot(repo)

    # Exercise Windows/macOS/Linux paths without depending on the calling cwd.
    with tempfile.TemporaryDirectory(prefix="cyberassess portable café ") as temporary:
        project = Path(temporary)
        shutil.copy2(repo / "main.py", project / "main.py")
        shutil.copytree(
            repo / "cyberassess", project / "cyberassess",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        # Keep the fixture copy complete without copying keys or local settings.
        for directory in ("config", "samples"):
            for source in (repo / directory).rglob("*.json"):
                destination = project / source.relative_to(repo)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)

        check_legacy_demo(repo, project)
        check_profile_demos(repo, project)

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
        check_demos(repo)
    except (ImportError, OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: Python {sys.version.split()[0]} requirements/constraints and isolated portable demos.")
    print("Legacy Ubuntu JSON unchanged: 15 controls and 54.3%.")
    print("Validated v2 UTF-8 JSON/HTML demos: Ubuntu 15, Windows 13, macOS 12 controls; no live collection.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
