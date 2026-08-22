#!/usr/bin/env python3
"""
nomad CLI — Catch autonomous agents that spawn ephemeral infrastructure
and migrate fluidly between services.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone

from nomad import NomadEngine, Scanner, Fingerprinter, Tracker


def cmd_scan(args):
    if args.block:
        print("\n  ⚠  BLOCK MODE: High-confidence drifters will be killed.")
        print("  ⚠  Use at your own risk. See LICENSE for terms.\n")

    engine = NomadEngine(dry_run=not args.block)
    result = engine.run_once()

    if args.json:
        print(json.dumps(result, indent=2))
        return

    ts = datetime.fromtimestamp(result["timestamp"], tz=timezone.utc).strftime("%H:%M:%S")
    print(f"\n  nomad scan — {ts}")
    print(f"  {'─' * 50}")
    print(f"  Containers: {result['containers']}")
    print(f"  Services:   {result['services']}")
    print(f"  Processes:  {result['processes']}")
    print()

    if result["new_containers"]:
        print(f"  🟢 New containers: {', '.join(result['new_containers'])}")
    if result["gone_containers"]:
        print(f"  🔴 Gone containers: {', '.join(result['gone_containers'])}")
    if result["new_services"]:
        print(f"  🟢 New services: {', '.join(result['new_services'])}")
    if result["gone_services"]:
        print(f"  🔴 Gone services: {', '.join(result['gone_services'])}")
    if result["new_processes"]:
        print(f"  🟢 New processes: {result['new_processes']}")
    if result["gone_processes"]:
        print(f"  🔴 Gone processes: {result['gone_processes']}")

    print()
    if result["migrations"]:
        print(f"  🔄 MIGRATIONS: {len(result['migrations'])}")
        for m in result["migrations"]:
            print(f"    {m['source']} → {m['target']}  ({m['kind']}, sim={m['similarity']:.2f})")
        print()

    if result.get("credential_findings"):
        print(f"  🔐 CREDENTIAL ACCESS: {len(result['credential_findings'])}")
        for c in result["credential_findings"]:
            emoji = "🔴" if c["risk_level"] == "critical" else "🟠" if c["risk_level"] == "high" else "🟡"
            print(f"    {emoji} {c['process_name']} (PID {c['pid']}) → {c['file_path']} [{c['risk_level']}]")
        print()

    if result.get("network_anomalies"):
        print(f"  🌐 NETWORK ANOMALIES: {len(result['network_anomalies'])}")
        for n in result["network_anomalies"]:
            emoji = "🔴" if n["risk_level"] == "critical" else "🟠" if n["risk_level"] == "high" else "🟡"
            remote = n["remote_addr"] or "N/A"
            print(f"    {emoji} {n['process_name']} (PID {n['pid']}) — {n['anomaly_type']} → {remote} [{n['risk_level']}]")
        print()

    disk = result.get("disk", {})
    if disk:
        icon = "🔴" if disk["level"] == "crit" else "🟡" if disk["level"] == "warn" else "✅"
        print(f"  {icon} Disk: {disk['free_gb']}G free / {disk['total_gb']}G ({disk['pct']}%) — {disk['level']}")
        print()

    mode = "BLOCKING" if args.block else "monitoring (dry-run)"
    print(f"  Mode: {mode}")


def cmd_watch(args):
    if args.block:
        print("\n  ⚠  BLOCK MODE: High-confidence drifters will be killed.")
        print("  ⚠  Use at your own risk. See LICENSE for terms.\n")

    engine = NomadEngine(dry_run=not args.block)
    print(f"\n  nomad watch — scanning every {args.interval}s (Ctrl+C to stop)")
    print(f"  Self-heal: scan >4s for 2+ scans → skip connections, >8s or 5+ slow → throttle, >15s or 10+ slow → critical\n")
    engine.run_loop(interval=args.interval)


def cmd_alerts(args):
    engine = NomadEngine()
    alerts = engine.get_alerts(limit=args.limit)
    if not alerts:
        print("  No alerts recorded.")
        return
    for a in alerts[-args.limit:]:
        ts = a.get("timestamp", "?")
        kind = a.get("type", "unknown")
        name = a.get("name", "")
        score = a.get("score", "")
        print(f"  [{ts}] {kind} — {name} (score={score})")


def cmd_fingerprint(args):
    scanner = Scanner()
    snapshot = scanner.scan()
    fp = Fingerprinter()
    drifters = fp.analyze(snapshot, {})

    if args.json:
        from dataclasses import asdict
        print(json.dumps([asdict(d) for d in drifters], indent=2))
        return

    if not drifters:
        print("  No drifters found in current scan.")
        return

    print(f"\n  Drifters found: {len(drifters)}")
    for d in drifters:
        emoji = "🔴" if d.score > 0.8 else "🟡"
        print(f"  {emoji} [{d.kind}] {d.name} — score={d.score:.2f}")
        print(f"     reason: {d.reason}")
        for ev in d.evidence:
            print(f"     evidence: {ev}")
    print()


def cmd_state(args):
    engine = NomadEngine()
    history = engine.get_state()
    if args.json:
        print(json.dumps(history, indent=2))
        return
    print(f"  State history entries: {len(history)}")


def cmd_security(args):
    from security import run_check, run_verify, get_security_summary

    if args.verify:
        result = run_verify()
        if args.json:
            print(json.dumps(result, indent=2))
            return

        print(f"\n  nomad security verify")
        print(f"  {'─' * 50}")
        if not result.get("available"):
            print(f"  ❌ {result.get('error', 'sec-toolkit.sh not found')}")
            return

        checks = result.get("checks", {})
        passed = result.get("passed", 0)
        total = result.get("total", 0)
        score = result.get("score", 0)

        for key, status in checks.items():
            if status == "ok":
                print(f"  ✅ {key}")
            elif status == "warn":
                print(f"  ⚠️  {key}")
            elif status == "critical":
                print(f"  🔴 {key}")

        print(f"\n  Score: {score}% ({passed}/{total} passed)")
        return

    result = run_check()
    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"\n  nomad security check")
    print(f"  {'─' * 50}")
    if not result.get("available"):
        print(f"  ❌ {result.get('error', 'sec-toolkit.sh not found')}")
        return

    sections = result.get("sections", {})
    score = result.get("score", 0)

    print(f"  Posture score: {score}/100\n")
    for name, content in sections.items():
        preview = content[:200].replace("\n", "\n    ")
        print(f"  [{name}]")
        print(f"    {preview}")
        if len(content) > 200:
            print(f"    ... ({len(content)} chars total)")
        print()


def main():
    parser = argparse.ArgumentParser(
        prog="nomad",
        description="Catch autonomous agents that spawn ephemeral infrastructure. "
                    "Monitors processes, containers, and services. Use --block with caution.\n"
                    "Free core: scan, fingerprint, state. Pro: dashboard, Telegram, blocking.",
    )
    parser.add_argument("--version", action="store_true", help="Show version")
    sub = parser.add_subparsers(dest="command", help="Command")

    p_scan = sub.add_parser("scan", help="Run a single scan")
    p_scan.add_argument("--block", action="store_true", help="[Pro] Enable blocking mode")
    p_scan.add_argument("--json", action="store_true", help="JSON output")
    p_scan.set_defaults(func=cmd_scan)

    p_watch = sub.add_parser("watch", help="Continuous monitoring")
    p_watch.add_argument("--interval", type=int, default=30, help="Scan interval (seconds)")
    p_watch.add_argument("--block", action="store_true", help="[Pro] Enable blocking mode")
    p_watch.set_defaults(func=cmd_watch)

    p_alerts = sub.add_parser("alerts", help="View alert history")
    p_alerts.add_argument("--limit", type=int, default=20, help="Number of alerts")
    p_alerts.add_argument("--json", action="store_true", help="JSON output")
    p_alerts.set_defaults(func=cmd_alerts)

    p_fp = sub.add_parser("fingerprint", help="Fingerprint current processes")
    p_fp.add_argument("--json", action="store_true", help="JSON output")
    p_fp.set_defaults(func=cmd_fingerprint)

    p_state = sub.add_parser("state", help="View tracked state")
    p_state.add_argument("--json", action="store_true", help="JSON output")
    p_state.set_defaults(func=cmd_state)

    p_sec = sub.add_parser("security", help="[Pro] System security check (requires sec-toolkit.sh)")
    p_sec.add_argument("--verify", action="store_true", help="Run verification instead of check")
    p_sec.add_argument("--json", action="store_true", help="JSON output")
    p_sec.set_defaults(func=cmd_security)

    args = parser.parse_args()
    if args.version:
        try:
            ver = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()
            print(f"nomad {ver}")
        except Exception:
            print("nomad unknown")
        return
    if not args.command:
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
