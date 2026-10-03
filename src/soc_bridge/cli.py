"""Command-line entry point for synthetic and live investigations."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from .core import investigate, render_json, render_markdown
from .demo import DemoQRadar, DemoVision
from .alert_investigation import render_alert_markdown


def main() -> None:
    parser = argparse.ArgumentParser(prog="soc-bridge", description="Read-only QRadar + Vision One evidence bridge")
    sub = parser.add_subparsers(dest="mode", required=True)
    demo = sub.add_parser("demo", help="Run with synthetic data, no account or dependencies")
    demo.add_argument("--output", type=Path, default=Path("reports/demo"))
    live = sub.add_parser("investigate", help="Connect to two local MCP transports")
    live.add_argument("--offense", type=int, required=True)
    live.add_argument("--output", type=Path, required=True)
    alert = sub.add_parser("alert", help="Start from a Vision One Workbench alert ID")
    alert.add_argument("--alert-id", required=True)
    alert.add_argument("--output", type=Path, required=True)
    doctor = sub.add_parser("doctor", help="Diagnose the bridge, connections and capabilities (no secrets shown)")
    doctor.add_argument("--trend", action="store_true", help="also start the local Vision One container and list its tools")
    doctor.add_argument("--json", action="store_true", help="print the full JSON report")
    cases = sub.add_parser("cases", help="List, show, delete or purge local investigation cases")
    cases.add_argument("action", choices=["list", "show", "delete", "purge"])
    cases.add_argument("case_id", nargs="?")
    args = parser.parse_args()
    if args.mode == "doctor":
        raise SystemExit(_doctor(args))
    if args.mode == "cases":
        raise SystemExit(_cases(args))
    try:
        if args.mode == "demo":
            report = asyncio.run(investigate(DemoQRadar(), DemoVision(), 1842))
        else:
            from .transports import live_investigation, live_alert_investigation
            runner = live_investigation if args.mode == "investigate" else live_alert_investigation
            report = asyncio.run(runner(
                args.offense if args.mode == "investigate" else args.alert_id,
                os.environ.get("QRADAR_MCP_URL", "http://127.0.0.1:5001/mcp"),
                os.environ.get("QRADAR_MCP_TOKEN"),
                os.environ.get("TREND_VISION_ONE_API_KEY", ""),
                os.environ.get("TREND_VISION_ONE_REGION", "us")))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.with_suffix(".json").write_text(render_json(report), encoding="utf-8")
        args.output.with_suffix(".md").write_text(
            render_alert_markdown(report) if args.mode == "alert" else render_markdown(report), encoding="utf-8")
        print(f"Saved {args.output.with_suffix('.md')} and {args.output.with_suffix('.json')}")
    except (RuntimeError, ValueError, OSError, ImportError) as exc:
        # Avoid printing raw exception text from network clients, which may contain URLs or headers.
        print(f"Investigation failed ({type(exc).__name__}). Check configuration and local MCP logs.", file=sys.stderr)
        raise SystemExit(1) from None


def _doctor(args: argparse.Namespace) -> int:
    import json
    from .diagnose import diagnose, render
    report = asyncio.run(diagnose(check_trend=args.trend))
    print(json.dumps(report, indent=1, default=str) if args.json else render(report))
    failed = any(s["state"] == "failed" for s in report["qradar"]["stages"] + report["trend"]["stages"])
    return 1 if failed or report["pack"]["problems"] else 0


def _cases(args: argparse.Namespace) -> int:
    import json
    from .case_store import CaseStore
    store = CaseStore()
    if args.action == "list":
        print(json.dumps(store.list(), indent=1, default=str))
    elif args.action == "purge":
        print(json.dumps({"removed": store.purge(), "retention_days": store.retention_days}))
    elif not args.case_id:
        print("case_id is required", file=sys.stderr)
        return 2
    elif args.action == "show":
        from .case_investigation import case_summary
        case = store.load(args.case_id)
        if case is None:
            print("unknown case", file=sys.stderr)
            return 1
        print(json.dumps(case_summary(case), indent=1, default=str))
    else:
        print(json.dumps({"deleted": store.delete(args.case_id)}))
    return 0


if __name__ == "__main__":
    main()
