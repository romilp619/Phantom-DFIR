#!/bin/bash
# ═══════════════════════════════════════════════════════════
#  PHANTOM DFIR — SIFT Workstation Installer
#  Run: bash install.sh
# ═══════════════════════════════════════════════════════════
set -e

PHANTOM_DIR="$HOME/phantom-dfir"
VENV_DIR="$PHANTOM_DIR/.venv"

echo "╔══════════════════════════════════════════════════════╗"
echo "║        PHANTOM DFIR — Installing on SIFT            ║"
echo "╚══════════════════════════════════════════════════════╝"

# ── 1. Copy files ─────────────────────────────────────────
echo "[1] Copying phantom-dfir to $PHANTOM_DIR..."
mkdir -p "$PHANTOM_DIR"
cp -r . "$PHANTOM_DIR/"
echo "    ✓ Files copied"

# ── 2. Python venv ────────────────────────────────────────
echo "[2] Creating Python venv..."
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"
echo "    ✓ venv at $VENV_DIR"

# ── 3. Install dependencies ───────────────────────────────
echo "[3] Installing Python dependencies..."
pip install --quiet --upgrade pip
pip install --quiet \
    "langgraph>=0.2.0" \
    "langchain-ollama>=0.1.0" \
    "langchain-core>=0.2.0"
echo "    ✓ langgraph, langchain-ollama installed"

# ── 4. Check Ollama ───────────────────────────────────────
echo "[4] Checking Ollama..."
if command -v ollama &>/dev/null; then
    echo "    ✓ Ollama found"
    if ollama list 2>/dev/null | grep -q "qwen2.5:14b"; then
        echo "    ✓ qwen2.5:14b model ready"
    else
        echo "    [!] qwen2.5:14b not found — pulling (this may take a while)..."
        ollama pull qwen2.5:14b || echo "    [!] Pull failed — run: ollama pull qwen2.5:14b"
    fi
else
    echo "    [!] Ollama not found. Install: curl https://ollama.ai/install.sh | sh"
    echo "    [!] PHANTOM will fall back to rule-based mode (--no-llm)"
fi

# ── 5. Check Vol tools ────────────────────────────────────
echo "[5] Checking Volatility tools..."
if command -v vol &>/dev/null; then
    echo "    ✓ vol (Vol3): $(vol --version 2>/dev/null | head -1)"
else
    echo "    [!] vol (Volatility 3) not found"
fi

if command -v vol2 &>/dev/null; then
    echo "    ✓ vol2 (Vol2) found"
else
    echo "    [!] vol2 not found — credential dumping will be unavailable"
fi

# ── 6. Create launcher ────────────────────────────────────
echo "[6] Creating phantom launcher script..."
cat > "$HOME/phantom" << 'LAUNCHER'
#!/bin/bash
PHANTOM_DIR="$HOME/phantom-dfir"
source "$PHANTOM_DIR/.venv/bin/activate"
python3 "$PHANTOM_DIR/main.py" "$@"
LAUNCHER
chmod +x "$HOME/phantom"
echo "    ✓ Launcher: ~/phantom"

# ── Done ──────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  PHANTOM DFIR installed!                            ║"
echo "║                                                      ║"
echo "║  Usage:                                              ║"
echo "║    ~/phantom -f base-admin-memory.img                ║"
echo "║    ~/phantom -f memory.raw --no-llm                  ║"
echo "║    ~/phantom -f image.img --model llama3.1:8b        ║"
echo "╚══════════════════════════════════════════════════════╝"
