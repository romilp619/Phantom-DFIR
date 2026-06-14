#!/usr/bin/env bash
# PHANTOM DFIR - SIFT/Ubuntu/WSL installe
# Run from the cloned repository:
#   bash install.sh
# Optional native DFIR tools:
#   bash install.sh --with-system-deps
# Validation only:
#   bash install.sh --check

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHANTOM_DIR="${PHANTOM_DIR:-$SCRIPT_DIR}"
VENV_DIR="${VENV_DIR:-$PHANTOM_DIR/.venv}"
VOL3_HOME="${VOL3_HOME:-$HOME/volatility3}"
VOL2_HOME="${VOL2_HOME:-$HOME/volatility2}"
VOL2_ENV="${VOL2_ENV:-$HOME/vol2_env}"
LOCAL_BIN="$HOME/.local/bin"
WITH_SYSTEM_DEPS=0
CHECK_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --with-system-deps) WITH_SYSTEM_DEPS=1 ;;
        --check) CHECK_ONLY=1 ;;
        --help|-h)
            cat <<'HELP'
PHANTOM DFIR installe

Usage:
  bash install.sh
  bash install.sh --with-system-deps
  bash install.sh --check

Default behavior:
  - creates .venv inside the current cloned repository
  - installs Python dependencies from requirements.txt
  - clones/validates Volatility 3 at ~/volatility3
  - creates a Python 2.7 Volatility 2 environment at ~/vol2_env
  - clones/validates Volatility 2.6.1 at ~/volatility2
  - creates launchers: ~/phantom, ~/phantom-memory, ~/.local/bin/vol, ~/.local/bin/vol2

--with-system-deps additionally installs common native DFIR tools with apt:
  git, build-essential, python2, python2-dev, python3-venv, sleuthkit, tshark,
  ewf-tools, plaso, clamav, clamav-daemon, libbde-utils, dislocker, gnupg,
  p7zip-full, file, libyara-dev, libjpeg-dev, zlib1g-dev

--check verifies:
  - Python 3 PHANTOM venv works
  - Volatility 3 loads
  - vol2 launcher exists
  - Python 2 environment works
  - distorm3 imports
  - Volatility 2 plugins load with vol.py --info
HELP
            exit 0
            ;;
        *) echo "[ERROR] Unknown argument: $arg"; exit 1 ;;
    esac
done

info() { echo "[*] $*"; }
ok() { echo "[OK] $*"; }
warn() { echo "[WARN] $*"; }
fail() { echo "[ERROR] $*" >&2; exit 1; }

need_cmd() {
    local cmd="$1"
    local help_text="${2:-Install it and rerun install.sh.}"
    command -v "$cmd" >/dev/null 2>&1 || fail "$cmd not found. $help_text"
}

check_vol2() {
    info "Checking Volatility 2 installation"

    [ -x "$VOL2_ENV/bin/python" ] || fail "Python 2 virtualenv missing: $VOL2_ENV"
    "$VOL2_ENV/bin/python" -c "import sys; raise SystemExit(0 if sys.version_info[0] == 2 else 1)" \
        || fail "vol2_env is not running Python 2"
    ok "Python 2 environment works"

    "$VOL2_ENV/bin/python" -c "import distorm3" \
        || fail "distorm3 missing from $VOL2_ENV"
    ok "distorm3 installed"

    "$VOL2_ENV/bin/python" -c "import Crypto, PIL, construct" \
        || fail "One or more Volatility 2 dependencies are missing: pycrypto, pillow, construct"
    ok "Volatility 2 Python dependencies import"

    if "$VOL2_ENV/bin/python" -c "import yara" >/dev/null 2>&1; then
        ok "yara-python installed"
    else
        warn "yara-python not installed or not supported on this Python 2 build"
    fi

    [ -f "$VOL2_HOME/vol.py" ] || fail "Volatility 2 vol.py missing: $VOL2_HOME/vol.py"
    "$VOL2_ENV/bin/python" "$VOL2_HOME/vol.py" --info >/dev/null \
        || fail "Volatility 2 plugins failed to load with vol.py --info"
    ok "Volatility 2 plugins load"

    [ -x "$LOCAL_BIN/vol2" ] || fail "vol2 launcher missing: $LOCAL_BIN/vol2"
    "$LOCAL_BIN/vol2" --info >/dev/null \
        || fail "vol2 launcher exists but cannot load plugins"
    ok "vol2 launcher works"
}

check_vol3() {
    info "Checking Volatility 3 installation"

    [ -x "$VENV_DIR/bin/python" ] || fail "Python 3 virtualenv missing: $VENV_DIR"
    if [ -f "$VOL3_HOME/vol.py" ]; then
        "$VENV_DIR/bin/python" "$VOL3_HOME/vol.py" -h >/dev/null \
            || fail "Volatility 3 source checkout failed to run: $VOL3_HOME/vol.py -h"
        ok "Volatility 3 source checkout works"
    elif command -v vol >/dev/null 2>&1; then
        vol -h >/dev/null || fail "vol command exists but failed"
        ok "Volatility 3 launcher works"
    else
        fail "Volatility 3 not found. Expected $VOL3_HOME/vol.py or a vol command."
    fi
}

run_checks() {
    info "Repository: $PHANTOM_DIR"
    info "Virtualenv : $VENV_DIR"
    check_vol3
    check_vol2
    ok "PHANTOM install check passed"
}

cat <<'BANNER'
+======================================================+
|        PHANTOM DFIR - Installing on SIFT/WSL         |
+======================================================+
BANNER

if [ "$CHECK_ONLY" -eq 1 ]; then
    run_checks
    exit 0
fi

info "Repository: $PHANTOM_DIR"
info "Virtualenv : $VENV_DIR"
info "Vol3 source: $VOL3_HOME"
info "Vol2 source: $VOL2_HOME"
info "Vol2 env   : $VOL2_ENV"

need_cmd python3 "On Ubuntu/WSL run: sudo apt install -y python3 python3-venv"

if ! python3 -m venv --help >/dev/null 2>&1; then
    fail "python3-venv is missing. On Ubuntu/WSL run: sudo apt install -y python3-venv"
fi

if [ "$WITH_SYSTEM_DEPS" -eq 1 ]; then
    if command -v apt-get >/dev/null 2>&1; then
        info "Installing native DFIR tools with apt"
        sudo apt-get update
        sudo apt-get install -y \
            git \
            build-essential \
            python3-venv \
            sleuthkit \
            tshark \
            ewf-tools \
            plaso \
            clamav \
            clamav-daemon \
            libbde-utils \
            dislocker \
            gnupg \
            p7zip-full \
            file \
            libyara-dev \
            libjpeg-dev \
            zlib1g-dev
        if sudo apt-get install -y python2 python2-dev; then
            ok "Python 2 system packages installed"
        else
            warn "apt could not install python2/python2-dev on this distro. If python2 is absent, install Python 2.7 manually or use SIFT."
        fi
        ok "Native DFIR tools installed"
    else
        warn "apt-get not found; skipping native DFIR tools"
    fi
else
    warn "Skipping native DFIR tools. Run 'bash install.sh --with-system-deps' if needed."
fi

need_cmd git "Install git first, or run with --with-system-deps on Ubuntu/WSL."

info "Creating Python 3 virtual environment"
python3 -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
ok "Python 3 venv ready"

info "Installing Python dependencies from requirements.txt"
python -m pip install --upgrade pip
python -m pip install -r "$PHANTOM_DIR/requirements.txt"
ok "Python dependencies installed"

info "Installing/validating Volatility 3"
if [ ! -d "$VOL3_HOME/.git" ]; then
    git clone https://github.com/volatilityfoundation/volatility3.git "$VOL3_HOME"
else
    info "Volatility 3 checkout already exists"
fi
"$VENV_DIR/bin/python" "$VOL3_HOME/vol.py" -h >/dev/null \
    || fail "Volatility 3 failed validation: python3 $VOL3_HOME/vol.py -h"
mkdir -p "$LOCAL_BIN"
cat > "$LOCAL_BIN/vol" <<LAUNCHER
#!/usr/bin/env bash
source "$VENV_DIR/bin/activate"
python "$VOL3_HOME/vol.py" "\$@"
LAUNCHER
chmod +x "$LOCAL_BIN/vol"
ok "Volatility 3 installed"
ok "vol launcher created"

info "Creating Volatility cache directories"
mkdir -p "$HOME/.cache/volatility3" "$HOME/.volatility3/symbols"
ok "Volatility caches ready"

info "Installing/validating Volatility 2"
need_cmd python2 "Volatility 2 requires Python 2.7. On SIFT it is usually present. On Ubuntu/WSL try: sudo apt install -y python2 python2-dev"

python -m pip install "virtualenv<20.22"
if [ ! -d "$VOL2_ENV" ]; then
    python -m virtualenv -p "$(command -v python2)" "$VOL2_ENV"
else
    info "Volatility 2 virtualenv already exists"
fi

"$VOL2_ENV/bin/python" -m pip install --upgrade "pip<21" "setuptools<45" "wheel<0.38"
"$VOL2_ENV/bin/pip" install \
    "distorm3==3.5.2" \
    "pycrypto==2.6.1" \
    "Pillow<7" \
    "construct<2.9"

if "$VOL2_ENV/bin/pip" install "yara-python<4" >/dev/null 2>&1; then
    ok "yara-python installed"
else
    warn "yara-python could not be installed on this Python 2 build; continuing because it is optional when unsupported"
fi

if [ ! -d "$VOL2_HOME/.git" ]; then
    git clone https://github.com/volatilityfoundation/volatility.git "$VOL2_HOME"
else
    info "Volatility 2 checkout already exists"
fi

(
    cd "$VOL2_HOME"
    git fetch --tags --quiet || true
    git checkout 2.6.1 >/dev/null 2>&1 || git checkout v2.6.1 >/dev/null 2>&1 || warn "Could not checkout tag 2.6.1; using current Volatility 2 checkout"
)

if [ -f "$VOL2_HOME/setup.py" ]; then
    "$VOL2_ENV/bin/pip" install -e "$VOL2_HOME"
fi

mkdir -p "$LOCAL_BIN"
cat > "$LOCAL_BIN/vol2" <<'LAUNCHER'
#!/bin/bash
source ~/vol2_env/bin/activate
python ~/volatility2/vol.py "$@"
LAUNCHER
chmod +x "$LOCAL_BIN/vol2"

check_vol2
ok "Volatility 2 installed"
ok "vol2 launcher created"

info "Checking optional Ollama model"
if command -v ollama >/dev/null 2>&1; then
    ok "Ollama found"
    if ollama list 2>/dev/null | grep -q "qwen2.5:14b"; then
        ok "qwen2.5:14b already installed"
    else
        warn "qwen2.5:14b not found. Optional pull: ollama pull qwen2.5:14b"
    fi
else
    warn "Ollama not found. PHANTOM still works with --no-llm."
fi

info "Checking forensic command availability"
for cmd in vol vol2 fls mmls icat tshark clamdscan clamscan bdeinfo dislocker gpg; do
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd found: $(command -v "$cmd")"
    else
        warn "$cmd not found"
    fi
done

info "Creating PHANTOM launchers"
cat > "$HOME/phantom" <<LAUNCHER
#!/usr/bin/env bash
set -e
source "$VENV_DIR/bin/activate"
python3 "$PHANTOM_DIR/phantom_router.py" "\$@"
LAUNCHER
chmod +x "$HOME/phantom"

cat > "$HOME/phantom-memory" <<LAUNCHER
#!/usr/bin/env bash
set -e
source "$VENV_DIR/bin/activate"
python3 "$PHANTOM_DIR/main.py" "\$@"
LAUNCHER
chmod +x "$HOME/phantom-memory"
ok "Launchers created: ~/phantom and ~/phantom-memory"

cat <<'DONE'

+======================================================+
|        PHANTOM DFIR Installed Successfully           |
+======================================================+

Quick checks:
  ./install.sh --check
  vol -h
  vol2 --info
  ~/phantom --help
  ~/phantom-memory --help

Memory self-correction:
  ~/phantom-memory -f /path/to/memory.img --no-llm --self-correct

Volatility 2 direct use:
  vol2 -f memory.raw imageinfo

Unified router:
  ~/phantom /path/to/evidence --deep --no-llm

MCP server:
  source .venv/bin/activate
  python3 mcpserver/mcp_server.py --transport http --port 8765

First Volatility Windows run may download symbols and take several minutes.
Do not interrupt the first symbols download.
DONE
