from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform

from cyberassess import __version__
from cyberassess.evaluator import evaluate_baseline
from cyberassess.platforms import detect_local_profile
from cyberassess.profiles import build_profile_report, get_profile, list_profiles, validate_live_evidence
from cyberassess.reporting import save_html, save_json


def load_controls() -> list[dict]:
    path = Path("config/controls.json")
    return json.loads(path.read_text(encoding="utf-8"))


def load_demo() -> dict:
    path = Path("samples/demo_evidence.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _print_results(report: dict) -> None:
    assessment = report["assessment"]
    print(f"Score:  {assessment['compliance_score']}%")
    print(f"Passed: {assessment['passed']}")
    print(f"Failed: {assessment['failed']}")
    print(f"Errors: {assessment['errors']}")
    print()
    for result in assessment["results"]:
        print(f"[{result['status']:<5}] {result['control_id']}  {result['title']}")


def _save_reports(report: dict, output: Path | None) -> None:
    # Keep the existing writer and naming behavior, including the default path.
    if output is None:
        json_path = save_json(report)
        html_path = save_html(report)
    else:
        json_path = save_json(report, output_dir=str(output))
        html_path = save_html(report, output_dir=str(output))
    print()
    print(f"JSON report: {json_path}")
    print(f"HTML report: {html_path}")


def _run_legacy(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Preserve the validated default Ubuntu CLI, assessment and JSON shape."""
    controls = load_controls()
    started_at = datetime.now(timezone.utc)
    if args.demo:
        evidence_bundle = load_demo()
    else:
        if not all([args.host, args.user, args.key]):
            parser.error("Live mode requires --host, --user and --key.")
        from cyberassess.collector import SSHCollector, CollectionError
        try:
            evidence_bundle = SSHCollector(
                host=args.host,
                username=args.user,
                key_file=args.key,
                port=args.port,
                accept_new_host=args.accept_new_host,
            ).collect()
            validate_live_evidence(evidence_bundle)
        except (CollectionError, ValueError) as exc:
            print(f"ERROR: {exc}")
            return 2

    assessment = evaluate_baseline(controls, evidence_bundle["evidence"])
    report = {**evidence_bundle, "assessment": assessment}
    if not args.demo and report.get("collector", {}).get("collected_at"):
        report["collector"] = {
            **report["collector"],
            "assessment_started_at": started_at.isoformat(),
            "assessment_completed_at": datetime.now(timezone.utc).isoformat(),
        }
    print()
    print("CyberAssess Live Assessment")
    print("===========================")
    print(f"Target: {report['target_name']}")
    _print_results(report)
    _save_reports(report, args.output)
    return 0


def _collect_profile(profile_id: str, args: argparse.Namespace, mode: str) -> dict:
    if mode == "ssh":
        from cyberassess.collector import SSHCollector
        return SSHCollector(
            host=args.host, username=args.user, key_file=args.key,
            port=args.port, accept_new_host=args.accept_new_host,
        ).collect()
    if profile_id == "ubuntu":
        from cyberassess.collectors.ubuntu import UbuntuLocalCollector
        return UbuntuLocalCollector().collect()
    if profile_id == "windows":
        from cyberassess.collectors.windows import WindowsCollector
        return WindowsCollector().collect()
    if profile_id == "macos":
        from cyberassess.collectors.macos import MacOSCollector
        if getattr(args, "allow_elevated_read", False):
            return MacOSCollector(allow_elevated_read=True).collect()
        return MacOSCollector().collect()
    from cyberassess.collector import CollectionError
    raise CollectionError(f"No local collector is registered for profile '{profile_id}'.")


def _run_profile(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.auto_detect and args.profile:
        parser.error("Choose either --auto-detect or --profile.")
    local_mode = args.local or args.auto_detect
    if args.demo and local_mode:
        parser.error("Choose either --demo or a local assessment.")
    remote_options = any((args.host, args.user, args.key, args.accept_new_host, args.port != 22))
    if (local_mode or args.demo) and remote_options:
        parser.error("SSH options cannot be combined with --local, --auto-detect or profile demo mode.")

    try:
        profile_id = args.profile or detect_local_profile()
        profile = get_profile(profile_id)
        if local_mode and detect_local_profile() != profile_id:
            parser.error("The selected profile does not match this local platform.")
    except ValueError as exc:
        parser.error(str(exc))

    if args.allow_elevated_read and (not local_mode or profile_id != "macos"):
        parser.error("--allow-elevated-read is available only for a local macOS assessment.")

    if args.demo:
        mode = "demo"
    elif local_mode:
        mode = "local"
    elif profile_id == "ubuntu":
        if not all((args.host, args.user, args.key)):
            parser.error("Ubuntu SSH mode requires --host, --user and --key; use --local for a local Ubuntu target.")
        mode = "ssh"
    else:
        parser.error("Windows and macOS support --local or --demo. Run CyberAssess on the authorized target for local collection.")

    try:
        control_count = len(profile.load_controls())
    except (OSError, ValueError) as exc:
        print(f"ERROR: Could not load the selected baseline: {exc}")
        return 2
    started_at = datetime.now(timezone.utc)
    target = "sample evidence" if mode == "demo" else (args.host if mode == "ssh" else platform.node())
    print(f"CyberAssess {__version__}")
    print("Automated Security Baseline Assessment")
    print()
    print(f"Target:   {target}")
    print(f"Platform: {profile.platform}")
    print(f"Profile:  {profile.name} v{profile.version}")
    print(f"Mode:     {mode}")
    if args.allow_elevated_read:
        print("Elevated reads: enabled (noninteractive sudo -n; read-only status queries)")
        from cyberassess.collectors.macos import _ELEVATED_READ_COMMANDS
        print("Authorization: --allow-elevated-read explicitly authorizes only these fixed read-only macOS status commands:")
        for command in sorted(_ELEVATED_READ_COMMANDS):
            print("  " + " ".join(command))
        print("Reliable unprivileged evidence is tried first; only unresolved permission-denied getters may be retried.")
        print("Credential policy: sudo -n -k ignores cached credentials and does not cache authentication; approved passwordless authorization is required.")
        print("No passwords are requested; user preferences remain unelevated; denied or unavailable evidence remains ERROR.", flush=True)
    print(f"Controls: {control_count}")
    print()
    print("Assessment in progress...")

    from cyberassess.collector import CollectionError
    try:
        bundle = profile.load_demo() if mode == "demo" else _collect_profile(profile_id, args, mode)
        report = build_profile_report(
            profile, bundle, assessment_mode=mode,
            started_at=started_at,
        )
        # Completion follows evaluation, rather than merely the final read.
        report["assessment_completed_at"] = datetime.now(timezone.utc).isoformat()
        print()
        print(f"Target: {report['target_name']}")
        _print_results(report)
        _save_reports(report, args.output)
    except (CollectionError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CyberAssess live cybersecurity baseline assessment")
    parser.add_argument("--demo", action="store_true", help="Use sample evidence instead of live collection")
    parser.add_argument("--host")
    parser.add_argument("--user")
    parser.add_argument("--key")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--accept-new-host", action="store_true")
    parser.add_argument("--profile", choices=[profile.id for profile in list_profiles()], help="Select a versioned baseline")
    parser.add_argument("--local", action="store_true", help="Read the matching local platform; no implicit elevation")
    parser.add_argument(
        "--allow-elevated-read", action="store_true",
        help="Explicitly authorize noninteractive sudo -n -k for allowlisted read-only macOS status queries; requires approved passwordless sudo; never prompts for passwords or changes settings",
    )
    parser.add_argument("--auto-detect", action="store_true", help="Detect and assess the supported local platform")
    parser.add_argument("--list-profiles", action="store_true", help="List baselines without collecting evidence")
    parser.add_argument("--version", action="version", version=f"CyberAssess {__version__}")
    parser.add_argument("--output", type=Path, metavar="DIRECTORY", help="Write JSON and self-contained HTML to this directory")
    args = parser.parse_args(argv)
    if args.allow_elevated_read and (args.list_profiles or args.demo or not (args.local or args.auto_detect)):
        parser.error("--allow-elevated-read requires a local macOS assessment; it cannot be used with demo, listing or SSH modes.")
    if args.list_profiles:
        print(f"CyberAssess {__version__} · Assessment profiles")
        try:
            for profile in list_profiles():
                print(f"{profile.id:<8} {profile.name} v{profile.version} · {len(profile.load_controls())} controls")
        except (OSError, ValueError) as exc:
            print(f"ERROR: Could not load the baseline registry: {exc}")
            return 2
        return 0
    if args.profile or args.local or args.auto_detect:
        return _run_profile(args, parser)
    return _run_legacy(args, parser)


if __name__ == "__main__":
    raise SystemExit(main())
