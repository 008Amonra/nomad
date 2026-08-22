# nomad

**Catch autonomous agents that spawn ephemeral infrastructure and migrate fluidly between services.**

nomad is a local drift detector that scans your machine for agent-like processes — things that spin up Docker containers, fire up systemd services, listen on ports, then disappear and reappear somewhere else. It fingerprints each entity, scores it for "drifter" behavior, detects migrations, and alerts you.

## Why

Autonomous AI agents (AutoGPT, CrewAI, LangChain agents, custom bots) can:
- Spawn Docker containers that live for minutes then vanish
- Start HTTP servers on random ports, serve a task, then die
- Fork processes with API keys baked into command lines
- Migrate between services — container A dies, process B appears with the same image/port/pattern

nomad catches them. Every scan diffs against the previous state. Every entity gets a drift score. High-confidence drifters get alerted. Optionally blocked.

## Free vs Pro

| Feature | Free (MIT) | Pro ($19/mo) | Team ($49/mo) |
|---------|-----------|-------------|---------------|
| CLI scan + fingerprint | ✓ | ✓ | ✓ |
| Docker + systemd + process scanning | ✓ | ✓ | ✓ |
| Migration detection | ✓ | ✓ | ✓ |
| File-based alert logs | ✓ | ✓ | ✓ |
| Security posture check (read-only) | ✓ | ✓ | ✓ |
| Optional blocking (`--block`) | ✓ | ✓ | ✓ |
| Telegram alerts | — | ✓ | ✓ |
| Web dashboard | — | ✓ | ✓ |
| Credential monitoring | — | ✓ | ✓ |
| Network anomaly detection | — | ✓ | ✓ |
| Systemd auto-start services | — | ✓ | ✓ |
| sec-toolkit harden/verify/scan/fw | — | ✓ | ✓ |
| Multi-machine dashboard | — | — | ✓ |
| Custom agent patterns | — | — | ✓ |
| Webhook integrations | — | — | ✓ |
| Priority support | — | — | ✓ |

## Install (Free)

```bash
git clone https://github.com/45dgof8/nomad.git
cd nomad
bash install.sh
```

Or manual:
```bash
pip install -r requirements.txt
python3 setup.py    # interactive config wizard
```

## Quick Start

```bash
# One-shot scan
python3 cli.py scan

# Continuous monitoring (30s interval)
python3 cli.py watch

# Fingerprint only (no state tracking)
python3 cli.py fingerprint

# View alert history
python3 cli.py alerts
```

## Pro Features

### Telegram Alerts

1. Create a bot via [@BotFather](https://t.me/BotFather)
2. Run `python3 setup.py` and enter the token + your chat ID
3. Or manually create `.env`:
```
NOMAD_TELEGRAM_TOKEN=123456:ABC-DEF...
NOMAD_TELEGRAM_CHAT_ID=your_chat_id
```

Alerts include:
- 🔴 High-confidence drifter detected (score > 0.8)
- 🟡 Suspicious activity (score 0.6–0.8)
- 🔄 Migration detected (process/container moved)
- 🔐 Credential access detected
- 🌐 Network anomalies

### Web Dashboard

```bash
python3 dashboard.py --port 5010
```

Dark-themed dashboard showing:
- Live container/service/process counts
- Active drifters with scores and evidence
- Recent migrations with similarity scores
- Credential access section
- Network anomalies section
- Auto-refreshes every 10 seconds

### Credential Monitoring

Scans processes for open sensitive files:
- `.env` files with API keys
- SSH private keys (`id_rsa`, `id_ed25519`)
- Cloud credentials (`.aws/credentials`, `.kube/config`)
- `/etc/shadow` and `/etc/passwd`

### Network Anomaly Detection

Tracks outbound connections and flags:
- Suspicious ports (4444, 6666, 31337, etc.)
- High connection counts (>10)
- Connections to known bad destinations

## How It Works

### Scanning
nomad scans three layers on every interval:

| Layer | What it sees |
|-------|-------------|
| **Docker** | All containers (state, image, ports, labels, age) |
| **systemd** | Running services (PID, CPU, memory) |
| **Processes** | All processes (cmdline, ports, connections, age, resources) |

### Fingerprinting
Each entity gets a **drift score** (0.0–1.0) based on:

| Signal | Score boost |
|--------|------------|
| Agent name pattern (`agent`, `bot`, `worker`, `swarm`...) | +0.15 |
| API keys in command line (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`...) | +0.20 |
| Ephemeral lifetime (< 5 minutes) | +0.20 |
| Exposed ports on high-numbered ports | +0.10 |
| High CPU/memory usage | +0.10 |
| Volatile container state (created, restarting) | +0.10 |
| Known infrastructure (docker, n8n, systemd) | −0.40 |

### Score Thresholds

| Range | Meaning |
|-------|---------|
| 0.0–0.4 | Known infrastructure — ignore |
| 0.4–0.6 | Unlikely agent — logged |
| 0.6–0.8 | Suspicious — possible agent activity |
| 0.8–1.0 | **Drifter** — alert/block |

### Migration Detection
When a process dies and a similar one spawns nearby, nomad flags it as a migration:
- Same image, different container name → container migration
- Same ports, same user, similar cmdline → process migration
- Similarity score 0.0–1.0 with evidence

### Blocking
```bash
# Dry-run (default) — detect only
python3 cli.py scan

# Block mode — kill high-confidence drifters (>0.85)
python3 cli.py scan --block
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NOMAD_TELEGRAM_TOKEN` | — | Telegram bot token (Pro) |
| `NOMAD_TELEGRAM_CHAT_ID` | — | Telegram chat ID (Pro) |
| `NOMAD_SCAN_INTERVAL` | `30` | Background scan interval (seconds) |

### Config File

`config.py` contains tuning knobs:

| Setting | Default | What it does |
|---------|---------|-------------|
| `EPHEMERAL_THRESHOLD_SEC` | 300 | Processes younger than this get ephemeral bonus |
| `FINGERPRINT_TRIGGER` | 0.6 | Minimum score to flag as drifter |
| `HIGH_CHURN_THRESHOLD` | 3 | Migration events before escalation |

### Agent Patterns

Edit `AGENT_NAME_PATTERNS` in `config.py` to add/remove detection targets:
```python
AGENT_NAME_PATTERNS = [
    "agent", "bot", "worker", "runner", "executor",
    "openai", "anthropic", "langchain", "autogpt",
    # add your own...
]
```

## Files

```
nomad/
├── nomad.py          # Core engine (Scanner, Tracker, Fingerprinter, Alerter, Blocker)
├── cli.py            # Command-line interface
├── dashboard.py      # Flask web dashboard (Pro)
├── config.py         # Configuration and patterns
├── setup.py          # Interactive setup wizard
├── install.sh        # One-command installer
├── requirements.txt  # Python dependencies
├── SKILL.md          # Agent skill definition
├── nomad-dashboard.service  # Systemd: web UI on port 5010 (Pro)
├── nomad-watch.service      # Systemd: background scanning + alerts (Pro)
├── state/            # Runtime snapshots (auto-managed)
│   ├── last_snapshot.json
│   ├── network_state.json
│   └── history/      # Hourly snapshots (auto-cleaned after 24h)
└── logs/             # Alert and event logs
    ├── alerts.jsonl
    └── events.jsonl
```

## API

The dashboard (Pro) exposes a REST API:

```bash
POST /api/scan          # Trigger manual scan, returns results
GET  /api/last          # Last scan results
GET  /api/alerts        # Alert history (optional ?limit=N)
GET  /api/health        # Dashboard health status
```

## Systemd

nomad runs as two separate user services (Pro):
- **nomad-dashboard.service** — web UI on port 5010
- **nomad-watch.service** — background scanning + alerts (30s interval)

```bash
# Install both services
cp nomad-dashboard.service nomad-watch.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now nomad-dashboard.service nomad-watch.service

# Check status
systemctl --user status nomad-dashboard.service
systemctl --user status nomad-watch.service

# View logs
journalctl --user -u nomad-watch.service -f
```

## License

The core detection engine is **MIT licensed** and free forever.

Pro features (Telegram alerts, web dashboard, credential monitoring, network anomaly detection, systemd services) require a Pro license. Contact: [45dgof8.com](https://45dgof8.com)

## Disclaimer

nomad is provided "as is" without warranty of any kind. It is a monitoring tool, not a security guarantee.

**What nomad does:** Scans your local machine for processes, containers, and services that exhibit agent-like behavior. Alerts you when it finds something suspicious.

**What nomad does NOT do:**
- It does not prevent attacks. It watches and reports.
- It does not guarantee detection. Sophisticated agents may evade fingerprinting.
- It does not protect remote infrastructure. It monitors one machine at a time.
- It does not replace proper security practices (firewalls, least privilege, network segmentation).

**Blocking mode:** When enabled (`--block`), nomad will kill processes and containers with high drift scores (>0.85). This can terminate legitimate processes if they happen to match agent patterns. Use blocking mode only after understanding the risks. The authors are not responsible for any damage caused by blocking.

**False positives:** nomad may flag legitimate software that happens to match agent name patterns (e.g., a service named "worker" or "bot"). Review alerts before taking action.

By using nomad, you agree that you are responsible for configuring and monitoring it appropriately for your environment.
