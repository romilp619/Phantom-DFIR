#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  PHANTOM DFIR — SIFT Workstation Installer
#  Run: bash install.sh
# ═══════════════════════════════════════════════════════════

set -e

PHANTOM_DIR="$HOME/Phantom-DFIR"
VENV_DIR="$PHANTOM_DIR/.venv"

echo "╔══════════════════════════════════════════════════════╗"
echo "║        PHANTOM DFIR — Installing on SIFT            ║"
echo "╚══════════════════════════════════════════════════════╝"

# ── 1. Copy files ─────────────────────────────────────────
echo "[1] Copying PHANTOM-DFIR to $PHANTOM_DIR..."

mkdir -p "$PHANTOM_DIR"
cp -r . "$PHANTOM_DIR/" || true

echo "    ✓ Files copied"

# ── 2. Create Python venv ────────────────────────────────
echo "[2] Creating Python virtual environment..."

python3 -m venv "$VENV_DIR"

source "$VENV_DIR/bin/activate"

echo "    ✓ venv created at $VENV_DIR"

# ── 3. Install Python dependencies ───────────────────────
echo "[3] Installing Python dependencies..."

pip install --quiet --upgrade pip

pip install --quiet \
    langgraph \
    langchain-ollama \
    langchain-core \
    volatility3 \
    fastapi \
    uvicorn \
    mcp \
    pefile

echo "    ✓ Python packages installed"

# ── 4. Create Volatility cache ───────────────────────────
echo "[4] Creating Volatility cache directories..."

mkdir -p ~/.cache/volatility3
mkdir -p ~/.volatility3/symbols

echo "    ✓ Symbol cache ready"

# ── 5. Check Ollama ──────────────────────────────────────
echo "[5] Checking Ollama..."

if command -v ollama &>/dev/null; then
    echo "    ✓ Ollama found"

    if ollama list 2>/dev/null | grep -q "qwen2.5:14b"; then
        echo "    ✓ qwen2.5:14b already installed"
    else
        echo "    [!] qwen2.5:14b not found"
        echo "    [!] Pulling model (this may take several minutes)..."

        ollama pull qwen2.5:14b || \
        echo "    [!] Model pull failed. Run manually: ollama pull qwen2.5:14b"
    fi

else
    echo "    [!] Ollama not found"
    echo "    [!] Install using:"
    echo "        curl -fsSL https://ollama.com/install.sh | sh"
    echo ""
    echo "    [!] PHANTOM can still run in --no-llm mode"
fi

# ── 6. Verify Volatility ─────────────────────────────────
echo "[6] Verifying Volatility installation..."

if command -v vol &>/dev/null; then
    echo "    ✓ Volatility 3 found"
    echo "    ✓ $(vol --version 2>/dev/null | head -1)"
else
    echo "    [!] Volatility 3 not found"
fi

if command -v vol2 &>/dev/null; then
    echo "    ✓ Volatility 2 found"
else
    echo "    [!] Volatility 2 not found"
    echo "    [!] Some legacy plugins may be unavailable"
fi

# ── 7. Create launcher ───────────────────────────────────
echo "[7] Creating PHANTOM launcher..."

cat > "$HOME/phantom" << 'LAUNCHER'
#!/bin/bash

PHANTOM_DIR="$HOME/Phantom-DFIR"

source "$PHANTOM_DIR/.venv/bin/activate"

python3 "$PHANTOM_DIR/main.py" "$@"
LAUNCHER

chmod +x "$HOME/phantom"

echo "    ✓ Launcher created at ~/phantom"

# ── 8. MCP Server Instructions ───────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════"
echo " Start MCP Server"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "python3 mcpserver/mcp_server.py --transport http --port 8765"
echo ""

# ── 9. Symbol Download Warning ───────────────────────────
echo "═══════════════════════════════════════════════════════"
echo " IMPORTANT — FIRST VOLATILITY RUN"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "The first Windows memory analysis may take 5–15 minutes."
echo ""
echo "Volatility downloads Microsoft kernel symbols during:"
echo ""
echo "    vol -f memory.img windows.info"
echo ""
echo "DO NOT interrupt this process."
echo ""

# ── Done ─────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════╗"
echo "║         PHANTOM DFIR Installed Successfully         ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║ Usage:                                              ║"
echo "║                                                      ║"
echo "║   ~/phantom -f memory.img                           ║"
echo "║                                                      ║"
echo "║   ~/phantom -f memory.img --no-llm                  ║"
echo "║                                                      ║"
echo "║   ~/phantom -f memory.img --model qwen2.5:14b       ║"
echo "║                                                      ║"
echo "║ MCP Server:                                         ║"
echo "║   python3 mcpserver/mcp_server.py                   ║"
echo "║       --transport http --port 8765                  ║"
echo "╚══════════════════════════════════════════════════════╝"
