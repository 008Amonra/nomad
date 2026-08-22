#!/usr/bin/env python3
"""
nomad security — Bridge to sec-toolkit.sh for system security posture.

Runs sec-toolkit.sh check/verify, parses output into structured JSON,
and integrates with nomad's dashboard and alerting.
"""

import json
import re
import subprocess
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

SECTOOLKIT_PATHS = [
    Path.home() / "sec-toolkit" / "sec-toolkit.sh",
    Path.home() / "Downloads" / "sec" / "sec-toolkit.sh",
    Path.home() / "45dgof8" / "sec-toolkit.sh",
    Path.home() / "sec-toolkit.sh",
]

SECTOOLKIT_SCRIPT = None
for p in SECTOOLKIT_PATHS:
    if p.exists():
        SECTOOLKIT_SCRIPT = p
        break


def find_sectoolkit() -> Optional[Path]:
    """Find sec-toolkit.sh on the system."""
    global SECTOOLKIT_SCRIPT
    if SECTOOLKIT_SCRIPT and SECTOOLKIT_SCRIPT.exists():
        return SECTOOLKIT_SCRIPT
    path = shutil.which("sec-toolkit.sh")
    if path:
        SECTOOLKIT_SCRIPT = Path(path)
        return SECTOOLKIT_SCRIPT
    return None


def run_check() -> dict:
    """Run sec-toolkit.sh check and parse into structured JSON.
    
    Reads from the latest report file if available, otherwise runs the check.
    sec-toolkit.sh writes reports to ~/sec-check-reports/.
    """
    kit = find_sectoolkit()
    if not kit:
        return {
            "available": False,
            "error": "sec-toolkit.sh not found. Install it: place sec-toolkit.sh in ~/sec-toolkit/ or ~/Downloads/sec/",
            "sections": {},
            "score": 0,
        }

    output = _read_latest_report()
    
    if not output:
        try:
            result = subprocess.run(
                ["bash", str(kit), "check"],
                capture_output=True, text=True, timeout=30,
                stdin=subprocess.DEVNULL,
            )
            output = result.stdout
        except (subprocess.TimeoutExpired, Exception):
            pass

    if not output:
        return {"available": True, "error": "No report data available. Run: bash sec-toolkit.sh check", "sections": {}, "score": 0}

    sections = _parse_check_output(output)
    score = _calculate_posture_score(sections)

    return {
        "available": True,
        "sections": sections,
        "score": score,
        "raw_lines": len(output.splitlines()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def run_verify() -> dict:
    """Run sec-toolkit.sh verify and parse into structured JSON."""
    kit = find_sectoolkit()
    if not kit:
        return {"available": False, "error": "sec-toolkit.sh not found", "checks": {}, "score": 0}

    try:
        result = subprocess.run(
            ["bash", str(kit), "verify"],
            capture_output=True, text=True, timeout=120,
            stdin=subprocess.DEVNULL,
        )
        output = result.stdout
    except subprocess.TimeoutExpired:
        return {"available": True, "error": "verify timed out", "checks": {}, "score": 0}
    except Exception as e:
        return {"available": True, "error": str(e), "checks": {}, "score": 0}

    checks = _parse_verify_output(output)
    passed = sum(1 for v in checks.values() if v == "ok")
    total = len(checks)
    score = round(passed / total * 100) if total else 0

    return {
        "available": True,
        "checks": checks,
        "passed": passed,
        "total": total,
        "score": score,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _read_latest_report() -> str:
    """Read the latest sec-toolkit.sh report file."""
    report_dir = Path.home() / "sec-check-reports"
    if not report_dir.exists():
        return ""
    reports = sorted(report_dir.glob("sec-check_*.log"), reverse=True)
    if not reports:
        return ""
    try:
        return reports[0].read_text()
    except Exception:
        return ""


def _parse_check_output(output: str) -> dict:
    """Parse sec-toolkit.sh check output into sections."""
    sections = {}
    current_section = None
    current_lines = []

    for line in output.splitlines():
        if line.startswith("============================================================"):
            if current_section and current_lines:
                sections[current_section] = "\n".join(current_lines).strip()
            current_lines = []
            current_section = None
            continue

        if current_section is None and line.strip():
            current_section = line.strip()
            continue

        if current_section:
            current_lines.append(line)

    if current_section and current_lines:
        sections[current_section] = "\n".join(current_lines).strip()

    return sections


def _parse_verify_output(output: str) -> dict:
    """Parse sec-toolkit.sh verify output into check results."""
    import re
    checks = {}
    for line in output.splitlines():
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
        if "[OK]" in clean:
            key = clean.split("[OK]")[-1].strip()
            checks[key] = "ok"
        elif "[WARN]" in clean:
            key = clean.split("[WARN]")[-1].strip()
            checks[key] = "warn"
        elif "[CRITICAL]" in clean:
            key = clean.split("[CRITICAL]")[-1].strip()
            checks[key] = "critical"
    return checks


def _calculate_posture_score(sections: dict) -> int:
    """Calculate a 0-100 security posture score from check sections."""
    score = 50  # baseline

    ufw = sections.get("UFW STATUS", "").lower()
    if "status: active" in ufw:
        score += 15
    if "deny (incoming)" in ufw:
        score += 10

    apparmor = sections.get("APPARMOR", "").lower()
    if "active" in apparmor:
        score += 10

    updates = sections.get("AUTO-UPDATES", "").lower()
    if "update-package-lists" in updates:
        score += 5
    if "unattended-upgrade" in updates:
        score += 5

    failed = sections.get("FAILED SERVICES", "").lower()
    if "0 loaded units listed" in failed or "no failed" in failed:
        score += 5

    return min(100, max(0, score))


def get_security_summary() -> dict:
    """Get a compact security summary for the dashboard."""
    check = run_check()
    verify = run_verify()

    return {
        "available": check.get("available", False),
        "posture_score": check.get("score", 0),
        "verify_score": verify.get("score", 0),
        "verify_passed": verify.get("passed", 0),
        "verify_total": verify.get("total", 0),
        "sections": list(check.get("sections", {}).keys()),
        "critical_issues": [
            k for k, v in verify.get("checks", {}).items() if v == "critical"
        ],
        "warnings": [
            k for k, v in verify.get("checks", {}).items() if v == "warn"
        ],
        "timestamp": check.get("timestamp"),
    }
