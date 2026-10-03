from __future__ import annotations

import argparse
import json
from pathlib import Path

from cyberassess.evaluator import evaluate_baseline
from cyberassess.reporting import save_html, save_json


def load_controls() -> list[dict]:
    path = Path("config/controls.json")
    return json.loads(path.read_text(encoding="utf-8"))


def load_demo() -> dict:
    path = Path("samples/demo_evidence.json")
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CyberAssess live cybersecurity baseline assessment"
    )
    parser.add_argument("--demo", action="store_true", help="Use sample evidence instead of SSH")
    parser.add_argument("--host")
    parser.add_argument("--user")
    parser.add_argument("--key")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--accept-new-host", action="store_true")

    args = parser.parse_args()
    controls = load_controls()

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
        except CollectionError as exc:
            print(f"ERROR: {exc}")
            return 2

    assessment = evaluate_baseline(controls, evidence_bundle["evidence"])
    report = {**evidence_bundle, "assessment": assessment}

    print()
    print("CyberAssess Live Assessment")
    print("===========================")
    print(f"Target: {report['target_name']}")
    print(f"Score:  {assessment['compliance_score']}%")
    print(f"Passed: {assessment['passed']}")
    print(f"Failed: {assessment['failed']}")
    print(f"Errors: {assessment['errors']}")
    print()

    for r in assessment["results"]:
        print(f"[{r['status']:<5}] {r['control_id']}  {r['title']}")

    json_path = save_json(report)
    html_path = save_html(report)

    print()
    print(f"JSON report: {json_path}")
    print(f"HTML report: {html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
