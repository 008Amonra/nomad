#!/usr/bin/env python3
"""
nomad — Catch autonomous agents that spawn ephemeral infrastructure
and migrate fluidly between services.

Core engine: scanner, tracker, fingerprinter, alerter.
"""

import json
import os
import re
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from config import (
    STATE_DIR, SNAPSHOT_FILE, HISTORY_DIR, ALERT_LOG, EVENT_LOG,
    EPHEMERAL_THRESHOLD_SEC, MIGRATION_WINDOW_SEC,
    HIGH_CHURN_THRESHOLD, FINGERPRINT_TRIGGER,
    AGENT_NAME_PATTERNS, AGENT_ENV_PATTERNS,
    KNOWN_INFRASTRUCTURE, KNOWN_AGENTS,
    TELEGRAM_TOKEN, TELEGRAM_CHAT_ID,
    CREDENTIAL_FILE_PATTERNS, CREDENTIAL_ALERT_THRESHOLD,
    KNOWN_OUTBOUND_PORTS, SUSPICIOUS_PORTS, NETWORK_ALERT_THRESHOLD,
)


# ─── Data Models ─────────────────────────────────────────────

@dataclass
class ContainerSnapshot:
    id: str
    name: str
    image: str
    status: str
    state: str
    ports: str
    created: float
    started: Optional[float] = None
    networks: list = field(default_factory=list)
    env_keys: list = field(default_factory=list)
    labels: dict = field(default_factory=dict)
    mounts: list = field(default_factory=list)


@dataclass
class ServiceSnapshot:
    name: str
    state: str
    sub_state: str
    pid: Optional[int] = None
    memory: Optional[float] = None
    cpu: Optional[float] = None


@dataclass
class ProcessSnapshot:
    pid: int
    name: str
    cmdline: list
    username: Optional[str] = None
    cpu: float = 0.0
    memory: float = 0.0
    connections: list = field(default_factory=list)
    create_time: float = 0.0
    age_sec: float = 0.0
    ports_open: list = field(default_factory=list)


@dataclass
class FullSnapshot:
    timestamp: float
    containers: list
    services: list
    processes: list


@dataclass
class Drifter:
    kind: str
    name: str
    score: float
    reason: str
    evidence: list = field(default_factory=list)
    first_seen: float = 0
    last_seen: float = 0
    alive: bool = True


@dataclass
class Migration:
    source: str
    target: str
    kind: str
    time_gap: float
    similarity: float
    evidence: list = field(default_factory=list)


@dataclass
class CredentialAccess:
    pid: int
    process_name: str
    file_path: str
    access_time: float
    risk_level: str  # low, medium, high, critical
    evidence: list = field(default_factory=list)


@dataclass
class NetworkAnomaly:
    pid: int
    process_name: str
    local_addr: str
    remote_addr: str
    remote_port: int
    anomaly_type: str  # new_destination, suspicious_port, high_connection_count
    risk_level: str
    evidence: list = field(default_factory=list)


# ─── Scanner ─────────────────────────────────────────────────

class Scanner:
    def scan(self, degraded: int = 0) -> FullSnapshot:
        return FullSnapshot(
            timestamp=time.time(),
            containers=self._scan_containers(),
            services=self._scan_services(),
            processes=self._scan_processes(skip_connections=degraded >= 1),
        )

    def _scan_containers(self) -> list:
        containers = []
        try:
            raw = subprocess.check_output(
                ["docker", "ps", "-a", "--format", "{{json .}}"],
                timeout=10, stderr=subprocess.DEVNULL
            ).decode().strip()
            for line in raw.split("\n"):
                if not line:
                    continue
                c = json.loads(line)
                created_ts = self._parse_docker_time(c.get("CreatedAt", ""))
                containers.append(ContainerSnapshot(
                    id=c.get("ID", "")[:12],
                    name=c.get("Names", "unknown"),
                    image=c.get("Image", "unknown"),
                    status=c.get("Status", ""),
                    state=c.get("State", ""),
                    ports=c.get("Ports", ""),
                    created=created_ts,
                ))
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        return containers

    def _scan_services(self) -> list:
        services = []
        try:
            raw = subprocess.check_output(
                ["systemctl", "list-units", "--type=service",
                 "--state=running", "--no-pager", "--plain", "--no-legend"],
                timeout=10, stderr=subprocess.DEVNULL
            ).decode().strip()
            for line in raw.split("\n"):
                parts = line.split()
                if len(parts) >= 4:
                    name = parts[0].replace(".service", "")
                    state = parts[2]
                    sub_state = parts[3]
                    pid = self._get_service_pid(name)
                    mem, cpu = (None, None)
                    if pid and HAS_PSUTIL:
                        try:
                            p = psutil.Process(pid)
                            mem = p.memory_percent()
                            cpu = p.cpu_percent(interval=0.1)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    services.append(ServiceSnapshot(
                        name=name, state=state, sub_state=sub_state,
                        pid=pid, memory=mem, cpu=cpu,
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return services

    def _get_service_pid(self, name: str) -> Optional[int]:
        try:
            raw = subprocess.check_output(
                ["systemctl", "show", name, "--property=MainPID", "--value"],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode().strip()
            pid = int(raw)
            return pid if pid > 0 else None
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            return None

    def _scan_processes(self, skip_connections: bool = False) -> list:
        processes = []
        if not HAS_PSUTIL:
            return processes
        now = time.time()
        for p in psutil.process_iter(['pid', 'name', 'cmdline', 'username',
                                       'cpu_percent', 'memory_percent', 'create_time']):
            try:
                info = info = p.info
                connections = []
                ports = []
                if not skip_connections:
                    try:
                        for conn in p.connections():
                            if conn.status == 'ESTABLISHED':
                                connections.append(f"{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else f"{conn.laddr.ip}:{conn.laddr.port}->?")
                            if conn.laddr:
                                ports.append(conn.laddr.port)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                ct = info.get('create_time', 0)
                age = now - ct if ct else 0
                processes.append(ProcessSnapshot(
                    pid=info.get('pid', 0),
                    name=info.get('name', ''),
                    cmdline=info.get('cmdline') or [],
                    username=info.get('username'),
                    cpu=info.get('cpu_percent', 0) or 0,
                    memory=info.get('memory_percent', 0) or 0,
                    connections=connections,
                    create_time=ct,
                    age_sec=age,
                    ports_open=list(set(ports)),
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return processes

    @staticmethod
    def _parse_docker_time(s: str) -> float:
        try:
            from dateutil.parser import parse
            return parse(s).timestamp()
        except Exception:
            return 0


# ─── Tracker ─────────────────────────────────────────────────

class Tracker:
    def __init__(self):
        self.history = self._load_history()
        self.previous: Optional[FullSnapshot] = None
        self._load_previous()

    def _load_history(self) -> list:
        hist_file = HISTORY_DIR / "events.jsonl"
        events = []
        if hist_file.exists():
            for line in hist_file.read_text().splitlines():
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return events

    def _load_previous(self):
        if SNAPSHOT_FILE.exists():
            try:
                data = json.loads(SNAPSHOT_FILE.read_text())
                self.previous = self._dict_to_snapshot(data)
            except (json.JSONDecodeError, KeyError):
                self.previous = None

    def diff(self, current: FullSnapshot) -> dict:
        changes = {
            "containers_new": [],
            "containers_gone": [],
            "services_new": [],
            "services_gone": [],
            "processes_new": [],
            "processes_gone": [],
            "churn_events": [],
        }

        if not self.previous:
            return changes

        prev_c = {c.name: c for c in self.previous.containers}
        curr_c = {c.name: c for c in current.containers}
        for name in curr_c:
            if name not in prev_c:
                changes["containers_new"].append(curr_c[name])
        for name in prev_c:
            if name not in curr_c:
                changes["containers_gone"].append(prev_c[name])

        prev_s = {s.name: s for s in self.previous.services}
        curr_s = {s.name: s for s in current.services}
        for name in curr_s:
            if name not in prev_s:
                changes["services_new"].append(curr_s[name])
        for name in prev_s:
            if name not in curr_s:
                changes["services_gone"].append(prev_s[name])

        prev_p = {p.pid: p for p in self.previous.processes}
        curr_p = {p.pid: p for p in current.processes}
        for pid in curr_p:
            if pid not in prev_p:
                changes["processes_new"].append(curr_p[pid])
        for pid in prev_p:
            if pid not in curr_p:
                changes["processes_gone"].append(prev_p[pid])

        changes["churn_events"] = self._detect_churn(changes, current.timestamp)
        return changes

    def _detect_churn(self, changes: dict, now: float) -> list:
        churns = []
        gone_then_back = []

        for gone in changes["containers_gone"]:
            for new in changes["containers_new"]:
                if gone.image == new.image and gone.name != new.name:
                    gap = now - self.previous.timestamp if self.previous else 0
                    churns.append(Migration(
                        source=gone.name, target=new.name,
                        kind="container",
                        time_gap=gap,
                        similarity=0.9,
                        evidence=[f"Same image: {gone.image}"],
                    ))

        for gone in changes["processes_gone"]:
            for new in changes["processes_new"]:
                sim = self._process_similarity(gone, new)
                if sim > 0.5:
                    gap = new.age_sec - gone.age_sec if gone.age_sec else 0
                    churns.append(Migration(
                        source=f"pid:{gone.pid}({gone.name})",
                        target=f"pid:{new.pid}({new.name})",
                        kind="process",
                        time_gap=max(0, gap),
                        similarity=sim,
                        evidence=[f"Similar cmdline: {new.cmdline[:3]}"],
                    ))

        return churns

    def _process_similarity(self, a: ProcessSnapshot, b: ProcessSnapshot) -> float:
        score = 0.0
        if a.name == b.name:
            score += 0.3
        if a.username == b.username:
            score += 0.1
        if set(a.ports_open) & set(b.ports_open):
            score += 0.3
        if a.cmdline and b.cmdline:
            common = len(set(a.cmdline) & set(b.cmdline))
            total = max(len(set(a.cmdline) | set(b.cmdline)), 1)
            score += 0.3 * (common / total)
        return min(score, 1.0)

    def save(self, snapshot: FullSnapshot):
        SNAPSHOT_FILE.write_text(json.dumps(asdict(snapshot), indent=2))
        hist_file = HISTORY_DIR / f"snap_{int(snapshot.timestamp)}.json"
        hist_file.write_text(json.dumps(asdict(snapshot), indent=2))
        self.previous = snapshot

        cutoff = time.time() - 86400
        for f in sorted(HISTORY_DIR.glob("snap_*.json")):
            try:
                ts = int(f.stem.split("_")[1])
                if ts < cutoff:
                    f.unlink()
            except (ValueError, IndexError):
                pass

    @staticmethod
    def _dict_to_snapshot(d: dict) -> FullSnapshot:
        containers = [ContainerSnapshot(**c) for c in d.get("containers", [])]
        services = [ServiceSnapshot(**s) for s in d.get("services", [])]
        processes = [ProcessSnapshot(**p) for p in d.get("processes", [])]
        return FullSnapshot(
            timestamp=d.get("timestamp", 0),
            containers=containers,
            services=services,
            processes=processes,
        )


# ─── Fingerprinter ───────────────────────────────────────────

class Fingerprinter:
    def analyze(self, snapshot: FullSnapshot, changes: dict) -> list:
        drifters = []
        for c in snapshot.containers:
            d = self._fingerprint_container(c)
            if d:
                drifters.append(d)
        for s in snapshot.services:
            d = self._fingerprint_service(s)
            if d:
                drifters.append(d)
        for p in snapshot.processes:
            d = self._fingerprint_process(p)
            if d:
                drifters.append(d)
        return drifters

    def _fingerprint_container(self, c: ContainerSnapshot) -> Optional[Drifter]:
        score = 0.0
        reasons = []
        evidence = []

        name_lower = c.name.lower()
        name_matches = []
        for pattern in AGENT_NAME_PATTERNS:
            if pattern in name_lower:
                name_matches.append(pattern)
        if name_matches:
            score += 0.30
            if len(name_matches) > 1:
                score += 0.10
            reasons.append(f"agent name patterns: {', '.join(name_matches)}")
            evidence.append(f"Container name '{c.name}' matches: {', '.join(name_matches)}")

        if c.state == "created" and c.ports:
            score += 0.15
            reasons.append("created state with exposed ports")
            evidence.append(f"State={c.state}, Ports={c.ports}")

        if c.image:
            for pattern in AGENT_NAME_PATTERNS:
                if pattern in c.image.lower():
                    score += 0.15
                    reasons.append(f"agent image pattern: {pattern}")
                    evidence.append(f"Image '{c.image}' matches agent pattern")
                    break

        if c.state in ("created", "restarting"):
            score += 0.1
            reasons.append(f"volatile state: {c.state}")

        if c.state == "exited" and name_matches:
            score += 0.2
            reasons.append("agent-named container has exited (ephemeral behavior)")
            evidence.append(f"Container '{c.name}' matched agent patterns and exited — classic ephemeral agent")

        if c.ports:
            score += 0.05
            reasons.append(f"has exposed ports")
            evidence.append(f"Ports: {c.ports}")

        if c.state == "running" and name_matches:
            score += 0.15
            reasons.append("agent-named container is running")
            evidence.append(f"Running agent container on host")

        for pattern in KNOWN_INFRASTRUCTURE:
            if pattern in name_lower:
                score -= 0.3
                break

        score = max(0, min(1, score))
        if score >= FINGERPRINT_TRIGGER:
            return Drifter(
                kind="container",
                name=c.name,
                score=score,
                reason="; ".join(reasons),
                evidence=evidence,
                first_seen=c.created,
                last_seen=time.time(),
                alive=c.state in ("running", "restarting"),
            )
        return None

    def _fingerprint_service(self, s: ServiceSnapshot) -> Optional[Drifter]:
        score = 0.0
        reasons = []
        evidence = []

        name_lower = s.name.lower()
        for pattern in AGENT_NAME_PATTERNS:
            if pattern in name_lower:
                score += 0.25
                reasons.append(f"agent name pattern: {pattern}")
                evidence.append(f"Service '{s.name}' matches agent pattern")
                break

        for pattern in KNOWN_INFRASTRUCTURE:
            if pattern in name_lower:
                score -= 0.4
                break
        for pattern in KNOWN_AGENTS:
            if pattern in name_lower:
                score += 0.15
                reasons.append(f"known agent: {pattern}")
                evidence.append(f"Service '{s.name}' is a known agent")
                break

        score = max(0, min(1, score))
        if score >= FINGERPRINT_TRIGGER:
            return Drifter(
                kind="service",
                name=s.name,
                score=score,
                reason="; ".join(reasons),
                evidence=evidence,
                alive=s.state == "active",
            )
        return None

    def _fingerprint_process(self, p: ProcessSnapshot) -> Optional[Drifter]:
        score = 0.0
        reasons = []
        evidence = []

        name_lower = p.name.lower()
        cmdline_str = " ".join(p.cmdline).lower() if p.cmdline else ""

        for pattern in AGENT_NAME_PATTERNS:
            if pattern in name_lower or pattern in cmdline_str:
                score += 0.15
                reasons.append(f"agent pattern: {pattern}")
                evidence.append(f"Process matches agent pattern '{pattern}'")
                break

        for pattern in AGENT_ENV_PATTERNS:
            if pattern.lower() in cmdline_str:
                score += 0.2
                reasons.append(f"API key/token in cmdline: {pattern}")
                evidence.append(f"Process has {pattern} visible in command")
                break

        if p.age_sec < EPHEMERAL_THRESHOLD_SEC and p.age_sec > 0:
            score += 0.2
            reasons.append(f"ephemeral ({int(p.age_sec)}s old)")
            evidence.append(f"Process age: {int(p.age_sec)}s < {EPHEMERAL_THRESHOLD_SEC}s threshold")

        if p.ports_open and len(p.ports_open) > 0:
            ephemeral_ports = [port for port in p.ports_open if port > 1024]
            if ephemeral_ports:
                score += 0.1
                reasons.append(f"listening on ports: {ephemeral_ports}")
                evidence.append(f"Open ports: {ephemeral_ports}")

        if p.cpu > 50 or p.memory > 10:
            score += 0.1
            reasons.append(f"high resource usage (CPU={p.cpu:.1f}%, MEM={p.memory:.1f}%)")
            evidence.append(f"CPU: {p.cpu:.1f}%, Memory: {p.memory:.1f}%")

        for pattern in KNOWN_INFRASTRUCTURE:
            if pattern in name_lower:
                score -= 0.4
                break
        for pattern in KNOWN_AGENTS:
            if pattern in name_lower:
                score += 0.15
                reasons.append(f"known agent: {pattern}")
                break

        score = max(0, min(1, score))
        if score >= FINGERPRINT_TRIGGER:
            return Drifter(
                kind="process",
                name=p.name,
                score=score,
                reason="; ".join(reasons),
                evidence=evidence,
                first_seen=p.create_time,
                last_seen=time.time(),
                alive=True,
            )
        return None


# ─── Credential Monitor ──────────────────────────────────────

class CredentialMonitor:
    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self):
        self.patterns = []
        for p in CREDENTIAL_FILE_PATTERNS:
            try:
                self.patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                pass

    def scan(self, processes: list) -> list:
        if not HAS_PSUTIL:
            return []

        findings = []
        for p in processes:
            try:
                proc = psutil.Process(p.pid)
                open_files = proc.open_files()
                for f in open_files:
                    path = f.path
                    for pattern in self.patterns:
                        if pattern.search(path):
                            risk = self._assess_risk(path, p)
                            findings.append(CredentialAccess(
                                pid=p.pid,
                                process_name=p.name,
                                file_path=path,
                                access_time=time.time(),
                                risk_level=risk,
                                evidence=[f"Process {p.name} (PID {p.pid}) has {path} open"],
                            ))
                            break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _assess_risk(self, path: str, process: ProcessSnapshot) -> str:
        critical_paths = ["/etc/shadow", "/etc/passwd"]
        high_paths = [r"\.ssh/", r"id_rsa", r"id_ed25519"]
        medium_paths = [r"\.env", r"credentials", r"token", r"secret"]

        path_lower = path.lower()
        for p in critical_paths:
            if p in path_lower:
                return "critical"

        for p in high_paths:
            if re.search(p, path_lower):
                return "high"

        for p in medium_paths:
            if re.search(p, path_lower):
                return "medium"

        name_lower = process.name.lower()
        for pattern in AGENT_NAME_PATTERNS:
            if pattern in name_lower:
                return "high"

        return "low"


# ─── Network Monitor ─────────────────────────────────────────

class NetworkMonitor:
    def __init__(self):
        self.known_destinations = {}  # {(ip, port): first_seen}
        self.connection_counts = {}  # {pid: count}
        self._load_state()

    def _load_state(self):
        state_file = STATE_DIR / "network_state.json"
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text())
                # Convert string keys back to tuples
                self.known_destinations = {
                    tuple(k.split(",")): v
                    for k, v in data.get("known_destinations", {}).items()
                }
            except (json.JSONDecodeError, KeyError):
                pass

    def _save_state(self):
        state_file = STATE_DIR / "network_state.json"
        # Convert tuple keys to strings for JSON
        data = {
            "known_destinations": {
                f"{k[0]},{k[1]}": v
                for k, v in self.known_destinations.items()
            }
        }
        state_file.write_text(json.dumps(data))

    def scan(self, processes: list) -> list:
        if not HAS_PSUTIL:
            return []

        anomalies = []
        current_connections = {}

        for p in processes:
            # Skip known infrastructure
            name_lower = p.name.lower()
            skip = False
            for pattern in KNOWN_INFRASTRUCTURE:
                if pattern in name_lower:
                    skip = True
                    break
            if skip:
                continue

            try:
                proc = psutil.Process(p.pid)
                connections = proc.connections(kind='inet')
                est_count = 0

                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                        remote_addr = f"{remote_ip}:{remote_port}"
                        key = (remote_ip, remote_port)

                        est_count += 1

                        # Check for suspicious ports
                        if remote_port in SUSPICIOUS_PORTS:
                            anomalies.append(NetworkAnomaly(
                                pid=p.pid,
                                process_name=p.name,
                                local_addr=local_addr,
                                remote_addr=remote_addr,
                                remote_port=remote_port,
                                anomaly_type="suspicious_port",
                                risk_level="high",
                                evidence=[f"Connection to suspicious port {remote_port}"],
                            ))

                        # Check for new destinations
                        if key not in self.known_destinations:
                            self.known_destinations[key] = time.time()
                        else:
                            current_connections[p.pid] = current_connections.get(p.pid, 0) + 1

                # Check for high connection count per process (skip known agents)
                is_known_agent = False
                for pattern in KNOWN_AGENTS:
                    if pattern in name_lower:
                        is_known_agent = True
                        break

                if est_count > 10 and not is_known_agent:
                    anomalies.append(NetworkAnomaly(
                        pid=p.pid,
                        process_name=p.name,
                        local_addr="",
                        remote_addr="",
                        remote_port=0,
                        anomaly_type="high_connection_count",
                        risk_level="medium",
                        evidence=[f"Process has {est_count} established connections"],
                    ))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Prune old destinations (keep last hour) and save state
        cutoff = time.time() - 3600
        self.known_destinations = {
            k: v for k, v in self.known_destinations.items()
            if v > cutoff
        }
        self._save_state()

        return anomalies


# ─── Alerter ─────────────────────────────────────────────────

class Alerter:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._last_alert_time = {}  # {alert_key: timestamp}
        self._alert_cooldown = 300  # 5 minutes between same alerts

    def alert_drifters(self, drifters: list, migrations: list):
        if not drifters and not migrations:
            return

        now = datetime.now(timezone.utc).isoformat()

        for d in drifters:
            event = {
                "type": "drifter_detected",
                "timestamp": now,
                "kind": d.kind,
                "name": d.name,
                "score": d.score,
                "reason": d.reason,
                "evidence": d.evidence,
                "alive": d.alive,
            }
            self._log_event(event)
            self._log_alert(event)
            self._telegram_alert(d)

        for m in migrations:
            event = {
                "type": "migration_detected",
                "timestamp": now,
                "source": m.source,
                "target": m.target,
                "kind": m.kind,
                "time_gap": m.time_gap,
                "similarity": m.similarity,
                "evidence": m.evidence,
            }
            self._log_event(event)
            self._log_alert(event)
            self._telegram_migration(m)

    def _log_event(self, event: dict):
        with open(EVENT_LOG, "a") as f:
            f.write(json.dumps(event) + "\n")

    def _log_alert(self, alert: dict):
        with open(ALERT_LOG, "a") as f:
            f.write(json.dumps(alert) + "\n")

    def _telegram_alert(self, d: Drifter):
        if self.dry_run or not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
            return

        # Rate limit: same drifter name within cooldown period
        alert_key = f"drifter:{d.name}"
        now = time.time()
        if alert_key in self._last_alert_time:
            if now - self._last_alert_time[alert_key] < self._alert_cooldown:
                return
        self._last_alert_time[alert_key] = now

        try:
            import requests
            emoji = "🔴" if d.score > 0.8 else "🟡"
            msg = (
                f"{emoji} *nomad alert*\n"
                f"Kind: `{d.kind}`\n"
                f"Name: `{d.name}`\n"
                f"Score: `{d.score:.2f}`\n"
                f"Reason: {d.reason}\n"
                f"Alive: {'yes' if d.alive else 'no'}"
            )
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
                timeout=10,
            )
        except Exception:
            pass

    def _telegram_migration(self, m: Migration):
        if self.dry_run or not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
            return

        # Rate limit: same source->target within cooldown period
        alert_key = f"migration:{m.source}->{m.target}"
        now = time.time()
        if alert_key in self._last_alert_time:
            if now - self._last_alert_time[alert_key] < self._alert_cooldown:
                return
        self._last_alert_time[alert_key] = now

        try:
            import requests
            msg = (
                f"🔄 *nomad migration*\n"
                f"Source: `{m.source}`\n"
                f"Target: `{m.target}`\n"
                f"Kind: `{m.kind}`\n"
                f"Similarity: `{m.similarity:.2f}`\n"
                f"Gap: `{m.time_gap:.1f}s`"
            )
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
                timeout=10,
            )
        except Exception:
            pass

    def alert_credentials(self, findings: list):
        if not findings:
            return

        now = datetime.now(timezone.utc).isoformat()
        for c in findings:
            event = {
                "type": "credential_access",
                "timestamp": now,
                "pid": c.pid,
                "process_name": c.process_name,
                "file_path": c.file_path,
                "risk_level": c.risk_level,
                "evidence": c.evidence,
            }
            self._log_event(event)
            if c.risk_level in ("high", "critical"):
                self._log_alert(event)
                self._telegram_credential(c)

    def _telegram_credential(self, c: CredentialAccess):
        if self.dry_run or not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
            return

        # Rate limit: same process+file within cooldown period
        alert_key = f"cred:{c.process_name}:{c.file_path}"
        now = time.time()
        if alert_key in self._last_alert_time:
            if now - self._last_alert_time[alert_key] < self._alert_cooldown:
                return
        self._last_alert_time[alert_key] = now

        try:
            import requests
            emoji = "🔴" if c.risk_level == "critical" else "🟠"
            msg = (
                f"{emoji} *nomad credential alert*\n"
                f"Process: `{c.process_name}` (PID {c.pid})\n"
                f"File: `{c.file_path}`\n"
                f"Risk: `{c.risk_level}`"
            )
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
                timeout=10,
            )
        except Exception:
            pass

    def alert_disk(self, info: dict):
        """Send desktop notification on disk threshold crossing."""
        level = info["level"]
        pct = info["pct"]
        free = info["free_gb"]
        total = info["total_gb"]

        event = {
            "type": f"disk_{level}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pct": pct,
            "free_gb": free,
            "total_gb": total,
        }
        self._log_event(event)
        self._log_alert(event)

        if level == "crit":
            title = " DISK CRITICAL"
            body = f"Root at {pct}% — only {free}G free of {total}G"
        else:
            title = " DISK WARNING"
            body = f"Root at {pct}% — {free}G free of {total}G"

        try:
            subprocess.run(
                ["notify-send", "-u", "critical", title, body],
                timeout=5, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

        self._telegram_disk(info)

    def _telegram_disk(self, info: dict):
        if self.dry_run or not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
            return

        alert_key = f"disk:{info['level']}"
        now = time.time()
        if alert_key in self._last_alert_time:
            if now - self._last_alert_time[alert_key] < self._alert_cooldown:
                return
        self._last_alert_time[alert_key] = now

        try:
            import requests
            emoji = "🔴" if info["level"] == "crit" else "🟡"
            msg = (
                f"{emoji} *nomad disk alert*\n"
                f"Root: `{info['pct']}%`\n"
                f"Free: `{info['free_gb']}G` / `{info['total_gb']}G`\n"
                f"Level: `{info['level']}`"
            )
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
                timeout=10,
            )
        except Exception:
            pass

    def alert_disk_recovered(self, info: dict):
        """Send recovery notification when disk drops below warn threshold."""
        event = {
            "type": "disk_recovered",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pct": info["pct"],
            "free_gb": info["free_gb"],
        }
        self._log_event(event)

        title = " DISK OK"
        body = f"Root back to {info['pct']}% — {info['free_gb']}G free"

        try:
            subprocess.run(
                ["notify-send", "-u", "normal", title, body],
                timeout=5, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    def alert_network_anomalies(self, anomalies: list):
        if not anomalies:
            return

        now = datetime.now(timezone.utc).isoformat()
        for n in anomalies:
            event = {
                "type": "network_anomaly",
                "timestamp": now,
                "pid": n.pid,
                "process_name": n.process_name,
                "remote_addr": n.remote_addr,
                "remote_port": n.remote_port,
                "anomaly_type": n.anomaly_type,
                "risk_level": n.risk_level,
                "evidence": n.evidence,
            }
            self._log_event(event)
            if n.risk_level in ("high", "critical"):
                self._log_alert(event)
                self._telegram_network(n)

    def _telegram_network(self, n: NetworkAnomaly):
        if self.dry_run or not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
            return

        # Rate limit: same process+anomaly_type within cooldown period
        alert_key = f"net:{n.process_name}:{n.anomaly_type}"
        now = time.time()
        if alert_key in self._last_alert_time:
            if now - self._last_alert_time[alert_key] < self._alert_cooldown:
                return
        self._last_alert_time[alert_key] = now

        try:
            import requests
            emoji = "🔴" if n.risk_level == "critical" else "🟠"
            msg = (
                f"{emoji} *nomad network alert*\n"
                f"Process: `{n.process_name}` (PID {n.pid})\n"
                f"Type: `{n.anomaly_type}`\n"
                f"Remote: `{n.remote_addr}`\n"
                f"Risk: `{n.risk_level}`"
            )
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
                timeout=10,
            )
        except Exception:
            pass


# ─── Blocker (Optional) ─────────────────────────────────────

class Blocker:
    def kill_container(self, name: str, dry_run: bool = True) -> bool:
        if dry_run:
            return True
        try:
            subprocess.run(
                ["docker", "kill", name],
                timeout=10, capture_output=True,
            )
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return False

    def kill_process(self, pid: int, dry_run: bool = True) -> bool:
        if dry_run:
            return True
        try:
            if HAS_PSUTIL:
                p = psutil.Process(pid)
                p.terminate()
                return True
            else:
                os.kill(pid, 15)
                return True
        except (psutil.NoSuchProcess, ProcessLookupError, PermissionError):
            return False

    def stop_service(self, name: str, dry_run: bool = True) -> bool:
        if dry_run:
            return True
        try:
            subprocess.run(
                ["systemctl", "stop", f"{name}.service"],
                timeout=15, capture_output=True,
            )
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            return False


# ─── Disk Monitor ────────────────────────────────────────────

class DiskMonitor:
    """Monitors root disk free space and alerts on threshold crossings.
    Uses absolute free space (not percentage) to avoid ext4 reserved-block confusion.
    Tracks state so it only fires once per crossing, not every scan."""

    def __init__(self, warn_gb: int = 15, crit_gb: int = 5):
        self.warn_gb = warn_gb
        self.crit_gb = crit_gb
        self.state = "ok"  # ok, warn, crit
        self._last_free_gb = 0.0

    def check(self) -> dict:
        """Returns {'level': 'ok'|'warn'|'crit', 'free_gb': N, 'total_gb': N,
        'triggered': True} if this scan just crossed a threshold."""
        import shutil
        usage = shutil.disk_usage("/")
        free_gb = usage.free / (1024 ** 3)
        pct = usage.used / usage.total * 100

        old_state = self.state
        new_state = "ok"
        if free_gb <= self.crit_gb:
            new_state = "crit"
        elif free_gb <= self.warn_gb:
            new_state = "warn"

        self.state = new_state
        self._last_free_gb = round(free_gb, 1)

        triggered = (new_state != old_state and new_state != "ok")

        return {
            "level": new_state,
            "free_gb": round(free_gb, 1),
            "total_gb": round(usage.total / (1024 ** 3), 1),
            "pct": round(pct, 1),
            "triggered": triggered,
        }

    def get_status(self) -> dict:
        return {"state": self.state, "pct": 0, "free_gb": self._last_free_gb, "total_gb": 0}


# ─── Self-Heal ───────────────────────────────────────────────

class SelfHeal:
    """Monitors nomad's own resource usage and degrades scanning to prevent
    the watchdog from becoming the problem it was sent to catch."""

    SLOW_SCAN_S = 4.0
    BUSY_SCAN_S = 8.0
    CRITICAL_SCAN_S = 15.0
    BUSY_TRIGGER = 2
    THROTTLE_TRIGGER = 5
    CRITICAL_TRIGGER = 10
    RECOVER_OK = 3
    RECOVER_FULL = 6

    def __init__(self):
        self.own_process = psutil.Process() if HAS_PSUTIL else None
        self.consecutive_slow = 0
        self.consecutive_fast = 0
        self.scan_times = []
        self.state = "nominal"

    def check(self, scan_duration: float) -> int:
        """Run after each scan, returns degradation level 0–3.
        Uses scan duration as primary signal (catches p.connections()
        bottleneck). Falls back to own CPU for secondary signal."""
        if not HAS_PSUTIL:
            return 0

        self.scan_times.append(scan_duration)
        if len(self.scan_times) > 20:
            self.scan_times.pop(0)

        is_slow = scan_duration > self.SLOW_SCAN_S
        if is_slow:
            self.consecutive_slow += 1
            self.consecutive_fast = 0
        else:
            self.consecutive_fast += 1
            self.consecutive_slow = 0

        if self.consecutive_slow >= self.CRITICAL_TRIGGER or scan_duration > self.CRITICAL_SCAN_S:
            self.state = "critical"
            return 3
        if self.consecutive_slow >= self.THROTTLE_TRIGGER or scan_duration > self.BUSY_SCAN_S:
            self.state = "throttled"
            return 2
        if self.consecutive_slow >= self.BUSY_TRIGGER:
            self.state = "busy"
            return 1

        if self.consecutive_fast >= self.RECOVER_FULL:
            self.state = "nominal"
            return 0
        if self.consecutive_fast >= self.RECOVER_OK:
            if self.state == "critical":
                self.state = "throttled"
                return 2
            if self.state == "throttled":
                self.state = "busy"
                return 1
            self.state = "nominal"
            return 0

        return 0

    def get_status(self) -> dict:
        avg_scan = sum(self.scan_times[-5:]) / max(len(self.scan_times[-5:]), 1)
        cpu = 0.0
        if HAS_PSUTIL and self.own_process:
            try:
                cpu = self.own_process.cpu_percent(interval=0)
            except Exception:
                pass
        return {
            "state": self.state,
            "cpu_percent": round(cpu, 1),
            "consecutive_slow": self.consecutive_slow,
            "avg_scan_time_s": round(avg_scan, 2),
        }


# ─── Engine ──────────────────────────────────────────────────

class NomadEngine:
    def __init__(self, dry_run: bool = True, auto_block: bool = False):
        self.scanner = Scanner()
        self.tracker = Tracker()
        self.fingerprinter = Fingerprinter()
        self.credential_monitor = CredentialMonitor()
        self.network_monitor = NetworkMonitor()
        self.disk_monitor = DiskMonitor()
        self.alerter = Alerter(dry_run=dry_run)
        self.blocker = Blocker()
        self.self_heal = SelfHeal()
        self.dry_run = dry_run
        self.auto_block = auto_block
        self._disk_was_alerted = False

    def run_once(self) -> dict:
        degraded = self.self_heal.get_status()["state"] if HAS_PSUTIL else "nominal"
        degraded_level = {"nominal": 0, "busy": 1, "throttled": 2, "critical": 3}.get(degraded, 0)

        t0 = time.time()
        snapshot = self.scanner.scan(degraded=degraded_level)
        scan_time = time.time() - t0

        changes = self.tracker.diff(snapshot)
        drifters = self.fingerprinter.analyze(snapshot, changes)
        migrations = changes.get("churn_events", [])

        # Skip credential/network monitoring when throttled or critical
        if degraded_level >= 2:
            credential_findings = []
            network_anomalies = []
        else:
            credential_findings = self.credential_monitor.scan(snapshot.processes)
            network_anomalies = self.network_monitor.scan(snapshot.processes)

        # Alert on all findings
        self.alerter.alert_drifters(drifters, migrations)
        self.alerter.alert_credentials(credential_findings)
        self.alerter.alert_network_anomalies(network_anomalies)

        if self.auto_block and not self.dry_run:
            for d in drifters:
                if d.score > 0.85:
                    if d.kind == "container":
                        self.blocker.kill_container(d.name, dry_run=False)
                    elif d.kind == "process":
                        self.blocker.kill_process(d.pid, dry_run=False)
                    elif d.kind == "service":
                        self.blocker.stop_service(d.name, dry_run=False)

        self.tracker.save(snapshot)

        # Disk check after scan
        disk_info = self.disk_monitor.check()
        if disk_info["triggered"]:
            self.alerter.alert_disk(disk_info)
            self._disk_was_alerted = True
        elif disk_info["level"] == "ok" and self._disk_was_alerted:
            self.alerter.alert_disk_recovered(disk_info)
            self._disk_was_alerted = False

        # Self-heal check after scan
        self.self_heal.check(scan_time)
        health = self.self_heal.get_status()

        return {
            "timestamp": snapshot.timestamp,
            "containers": len(snapshot.containers),
            "services": len(snapshot.services),
            "processes": len(snapshot.processes),
            "drifters": [asdict(d) for d in drifters],
            "migrations": [asdict(m) for m in migrations],
            "credential_findings": [asdict(c) for c in credential_findings],
            "network_anomalies": [asdict(n) for n in network_anomalies],
            "new_containers": [c.name for c in changes["containers_new"]],
            "gone_containers": [c.name for c in changes["containers_gone"]],
            "new_services": [s.name for s in changes["services_new"]],
            "gone_services": [s.name for s in changes["services_gone"]],
            "new_processes": len(changes["processes_new"]),
            "gone_processes": len(changes["processes_gone"]),
            "scan_time_s": round(scan_time, 2),
            "disk": disk_info,
            "health": health,
        }

    def run_loop(self, interval: int = 30):
        import signal
        running = True
        def stop(sig, frame):
            nonlocal running
            running = False
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)

        while running:
            result = self.run_once()
            health = result.get("health", {})
            state = health.get("state", "nominal")

            # Print compact one-line status
            ts = datetime.fromtimestamp(result["timestamp"], tz=timezone.utc).strftime("%H:%M:%S")
            cpu = health.get("cpu_percent", "?")
            scan_t = result.get("scan_time_s", "?")
            status_icon = {"nominal": "✓", "busy": "⚡", "throttled": "🔻", "critical": "🔴"}.get(state, "?")
            disk = result.get("disk", {})
            disk_pct = disk.get("pct", "?")
            disk_free = disk.get("free_gb", "?")
            disk_icon = "🔴" if disk.get("level") == "crit" else "🟡" if disk.get("level") == "warn" else ""
            print(f"  [{ts}] {status_icon} {result['processes']}p {result['containers']}c {result['services']}s "
                  f"| scan={scan_t}s cpu={cpu}% state={state}"
                  f"{disk_icon} disk={disk_pct}%/{disk_free}G", flush=True)

            # Dynamic interval: back off when degraded
            effective_interval = interval
            if state == "busy":
                effective_interval = min(interval * 2, 120)
            elif state == "throttled":
                effective_interval = min(interval * 4, 300)
            elif state == "critical":
                effective_interval = min(interval * 8, 600)

            if effective_interval != interval:
                print(f"  ⚠ self-heal: degrading scan interval {interval}s → {effective_interval}s", flush=True)

            time.sleep(effective_interval)

    def get_state(self) -> dict:
        return self.tracker._load_history()[-100:]

    def get_alerts(self, limit: int = 50) -> list:
        alerts = []
        if ALERT_LOG.exists():
            for line in ALERT_LOG.read_text().splitlines()[-limit:]:
                if line.strip():
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return alerts
