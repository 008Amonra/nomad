import os
from pathlib import Path

BASE_DIR = Path(__file__).parent
STATE_DIR = BASE_DIR / "state"
LOGS_DIR = BASE_DIR / "logs"

STATE_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

SNAPSHOT_FILE = STATE_DIR / "last_snapshot.json"
HISTORY_DIR = STATE_DIR / "history"
HISTORY_DIR.mkdir(exist_ok=True)

ALERT_LOG = LOGS_DIR / "alerts.jsonl"
EVENT_LOG = LOGS_DIR / "events.jsonl"


def _load_env():
    env_file = BASE_DIR / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip())

_load_env()

TELEGRAM_TOKEN = os.environ.get("NOMAD_TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("NOMAD_TELEGRAM_CHAT_ID", "")

SCAN_INTERVAL = int(os.environ.get("NOMAD_SCAN_INTERVAL", "30"))

EPHEMERAL_THRESHOLD_SEC = 300
MIGRATION_WINDOW_SEC = 60
HIGH_CHURN_THRESHOLD = 3
FINGERPRINT_TRIGGER = 0.6

AGENT_NAME_PATTERNS = [
    "agent", "bot", "worker", "runner", "executor", "dispatcher",
    "nomad", "spawn", "orchestrator", "scheduler", "handler",
    "openai", "anthropic", "langchain", "autogpt", "camel",
    "crew", "swarm", "hive", "colony", "drone", "workerbee",
]

AGENT_ENV_PATTERNS = [
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "COHERE_API_KEY",
    "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "REPLICATE_API_TOKEN",
    "AGENT_", "BOT_TOKEN", "WORKER_ID", "TASK_ID",
    "ORCHESTRATOR", "SWARM_ID",
]

KNOWN_INFRASTRUCTURE = {
    "n8n", "docker", "containerd", "systemd", "dbus",
    "cron", "ssh", "nginx", "caddy", "traefik",
    "gunicorn", "uvicorn", "supervisord",
}

KNOWN_AGENTS = {
    "opencode", "claude", "codex", "cursor", "copilot",
    "hermes", "openclaw", "gstack",
}

# Credential monitoring
CREDENTIAL_FILE_PATTERNS = [
    r"\.env$",
    r"\.env\.",
    r"\.env$",
    r"id_rsa$",
    r"id_ed25519$",
    r"/\.ssh/",
    r"credentials\.json$",
    r"token\.json$",
    r"secret\.json$",
    r"/\.aws/credentials$",
    r"/\.config/gcloud/",
    r"/\.kube/config$",
    r"/etc/shadow$",
    r"/etc/passwd$",
    r"\.npmrc$",
    r"\.pypirc$",
    r"\.netrc$",
]

CREDENTIAL_ALERT_THRESHOLD = 3

# Network monitoring
KNOWN_OUTBOUND_PORTS = {80, 443, 53, 8080, 8443}
SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 1337}
NETWORK_ALERT_THRESHOLD = 5
