#!/usr/bin/env bash
#
# nomad install — one-command setup
# Installs deps, creates .env, optionally sets up systemd service
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/008Amonra/nomad/main/install.sh | bash
#   ./install.sh --upgrade
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Process-substitution invocation (bash <(curl ...)) runs from /dev/fd — use cwd instead
if [[ "$SCRIPT_DIR" == /dev/fd* ]]; then
    SCRIPT_DIR="$(pwd)"
fi
REPO_URL="https://github.com/008Amonra/nomad.git"
NOMAD_PATH="."
UPGRADE_MODE=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Parse flags
for arg in "$@"; do
    case "$arg" in
        --upgrade) UPGRADE_MODE=true ;;
    esac
done

# ---- Upgrade mode ----
if $UPGRADE_MODE; then
    echo -e "${CYAN}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║   nomad — upgrade                        ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    if [ -d "$SCRIPT_DIR/.git" ]; then
        echo -e "  Upgrading from GitHub..."
        git -C "$SCRIPT_DIR" pull --ff-only 2>/dev/null && \
            echo -e "  ${GREEN}✓${NC} Upgraded to $(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo 'latest')" || \
            echo -e "  ${RED}✗${NC} Upgrade failed — check git status"
    else
        echo -e "  ${YELLOW}⚠${NC} Not a git install — re-run without --upgrade to install from GitHub"
    fi
    python3 -m pip install -q -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC} Dependencies updated"
    exit 0
fi

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   nomad — drift detector installer       ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

# Install from GitHub if piped via curl
if [ ! -f "$SCRIPT_DIR/cli.py" ]; then
    echo -e "  ${YELLOW}Downloading from GitHub...${NC}"
    rm -rf /tmp/nomad-repo
    git clone --depth 1 "$REPO_URL" /tmp/nomad-repo 2>/dev/null
    cp -r /tmp/nomad-repo/.gitignore /tmp/nomad-repo/* "$SCRIPT_DIR/" 2>/dev/null || cp -r /tmp/nomad-repo/* "$SCRIPT_DIR/"
    rm -rf /tmp/nomad-repo
    echo -e "  ${GREEN}✓${NC} Downloaded nomad $(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo 'latest')"
fi

# Backup recommendation
echo -e "  ${YELLOW}⚠  RECOMMENDED: Back up your system before hardening.${NC}"
echo -e "  Timeshift creates system snapshots in seconds:"
echo -e "    ${CYAN}sudo apt install timeshift${NC}"
echo -e "    ${CYAN}sudo timeshift --create --comments 'before nomad'${NC}"
echo -e "  ${YELLOW}Only proceed if your system is backed up.${NC}"
echo ""
echo -e "  ${YELLOW}⚠  nomad monitors and can block processes on your system.${NC}"
echo -e "  ${YELLOW}   Use --block mode only after understanding the risks.${NC}"
echo -e "  ${YELLOW}   See LICENSE for full terms.${NC}"
echo ""
if [ -t 0 ]; then
    read -p "  Continue with install? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "  ${YELLOW}Aborted. Create a backup first, then re-run this script.${NC}"
        exit 0
    fi
else
    echo -e "  ${GREEN}✓${NC} Non-interactive install (curl | bash) — proceeding with defaults"
fi

# Check Python
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}  ✗ python3 not found${NC}"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "  ${GREEN}✓${NC} Python $PY_VER"

# Check Docker
if command -v docker &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Docker $(docker --version 2>/dev/null | awk '{print $3}')"
else
    echo -e "  ${YELLOW}⚠${NC} Docker not found — container monitoring disabled"
fi

# Install Python deps
echo -e "\n  Installing dependencies..."
python3 -m pip install -q -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null && \
    echo -e "  ${GREEN}✓${NC} Dependencies installed" || \
    echo -e "  ${YELLOW}⚠${NC} Some deps may need manual install"

# Create .env if missing
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo -e "\n  ${YELLOW}No .env found — running setup wizard...${NC}\n"
    python3 "$SCRIPT_DIR/setup.py"
else
    echo -e "  ${GREEN}✓${NC} .env exists"
fi

# Optional: install systemd services
echo ""
if [ -t 0 ]; then
    read -p "  Install systemd services for auto-start? [y/N] " -n 1 -r
    echo
fi
if [[ $REPLY =~ ^[Yy]$ ]]; then
    DEST="$HOME/.config/systemd/user"
    mkdir -p "$DEST"
    sed "s|__NOMAD_DIR__|$SCRIPT_DIR|g" "$SCRIPT_DIR/nomad-dashboard.service" > "$DEST/nomad-dashboard.service"
    sed "s|__NOMAD_DIR__|$SCRIPT_DIR|g" "$SCRIPT_DIR/nomad-watch.service" > "$DEST/nomad-watch.service"
    systemctl --user daemon-reload
    systemctl --user enable nomad-dashboard.service nomad-watch.service
    systemctl --user start nomad-dashboard.service nomad-watch.service
    echo -e "  ${GREEN}✓${NC} nomad-dashboard.service + nomad-watch.service installed"
    echo -e "  Dashboard: http://127.0.0.1:5010"
    echo -e "  Watcher:   running (30s scan interval)"
fi

# Summary
echo -e "\n  ${CYAN}── Quick Start ──${NC}"
echo "  python3 $SCRIPT_DIR/cli.py scan        # one-shot scan (free)"
echo "  python3 $SCRIPT_DIR/cli.py watch        # continuous monitoring (free)"
echo "  python3 $SCRIPT_DIR/dashboard.py        # web dashboard (pro)"
echo "  python3 $SCRIPT_DIR/setup.py            # reconfigure"
echo ""
echo -e "  ${CYAN}── Free vs Pro ──${NC}"
echo "  Free: scan, fingerprint, state, CLI alerts"
echo "  Pro:  Telegram alerts, web dashboard, credential monitoring, systemd services"
  echo "  Upgrade: bash install.sh --upgrade"
echo ""
