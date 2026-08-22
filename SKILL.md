# nomad — Ephemeral Infrastructure Drift Detector

Catch autonomous agents that spawn ephemeral infrastructure and migrate fluidly between services.

## What it does
Scans Docker containers, systemd services, and running processes on the local machine. Fingerprints each entity for agent-like behavior (ephemeral lifetimes, API keys in cmdline, agent naming patterns, volatile state transitions). Detects "migrations" when an entity dies and a similar one appears elsewhere. Alerts via Telegram.

## When to use
- "Check for drifters" / "run nomad" / "catch agents"
- After installing new software or noticing unexplained resource usage
- When you suspect an autonomous process is spinning up and tearing down infrastructure
- Periodic health/security checks

## Usage

### CLI
```bash
# Single scan
python3 ~/45dgof8/nomad/cli.py scan

# JSON output
python3 ~/45dgof8/nomad/cli.py scan --json

# Continuous monitoring (30s interval)
python3 ~/45dgof8/nomad/cli.py watch

# Custom interval
python3 ~/45dgof8/nomad/cli.py watch --interval 10

# Fingerprint only (no tracking, no alerts)
python3 ~/45dgof8/nomad/cli.py fingerprint

# View alert history
python3 ~/45dgof8/nomad/cli.py alerts --limit 30

# View tracked state
python3 ~/45dgof8/nomad/cli.py state
```

### Dashboard
```bash
python3 ~/45dgof8/nomad/dashboard.py --port 5010
# Open http://localhost:5010
```

### API
```bash
# Trigger manual scan
curl -X POST http://localhost:5010/api/scan

# Get last scan results
curl http://localhost:5010/api/last

# Get alerts
curl http://localhost:5010/api/alerts?limit=20
```

## Blocking mode
```bash
# Dry-run (default) — only detects, never kills
python3 ~/45dgof8/nomad/cli.py scan

# Block mode — kills high-confidence drifters (>0.85 score)
python3 ~/45dgof8/nomad/cli.py scan --block
```

## Environment variables
- `NOMAD_TELEGRAM_TOKEN` — Telegram bot token for alerts
- `NOMAD_TELEGRAM_CHAT_ID` — Telegram chat ID for alerts
- `NOMAD_SCAN_INTERVAL` — Background scan interval in seconds (default: 30)

## Scoring
Each entity gets a drift score from 0 to 1:
- **0.0–0.4**: Known infrastructure (n8n, docker, systemd, etc.)
- **0.4–0.6**: Unlikely agent
- **0.6–0.8**: Suspicious — possible agent activity
- **0.8–1.0**: High confidence drifter — alert/block

## Architecture
- `nomad.py` — Core engine (Scanner, Tracker, Fingerprinter, Alerter, Blocker)
- `cli.py` — Command-line interface
- `dashboard.py` — Flask web dashboard on port 5010
- `config.py` — Configuration and thresholds
- `state/` — Runtime snapshots and history
- `logs/` — Alert and event logs (JSONL)
