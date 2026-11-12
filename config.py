"""
PHANTOM DFIR — Configuration
Tool paths, LLM provider, plugin timeouts.
"""
import shutil, os

# ── LLM Provider ─────────────────────────────────────────────────────────────
# Supported: "ollama" (default, free, local), "claude", "openai", "groq"
# Override via CLI: --provider claude --api-key sk-...
LLM_PROVIDER    = os.environ.get("PHANTOM_PROVIDER", "ollama")
LLM_API_KEY     = os.environ.get("PHANTOM_API_KEY",  None)

# ── Ollama (default provider) ────────────────────────────────────────────────
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL    = os.environ.get("PHANTOM_MODEL",   "qwen2.5:14b")

# ── Skills ───────────────────────────────────────────────────────────────────
SKILLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills")

# ── Tool aliases (SIFT Workstation) ──────────────────────────────────────────
VOL3_CMD  = shutil.which("vol")  or "vol"
VOL2_CMD  = shutil.which("vol2") or "vol2"
LOG2TL    = shutil.which("log2timeline.py") or "log2timeline.py"
MACTIME   = shutil.which("mactime") or "mactime"
MMLS      = shutil.which("mmls")   or "mmls"
FLS       = shutil.which("fls")    or "fls"
ICAT      = shutil.which("icat")   or "icat"
STRINGS   = shutil.which("strings") or "strings"
YARA      = shutil.which("yara") or "yara"

# ── Timeouts (seconds) ───────────────────────────────────────────────────────
TIMEOUT_OS_DETECT   = 120   # Per engine OS detection
TIMEOUT_PLUGIN_FAST = 120   # pslist, netscan etc.
TIMEOUT_PLUGIN_SLOW = 180   # malfind, psscan, shimcache (was 300)
TIMEOUT_VOL2_HASH   = 180   # hashdump/lsadump
TIMEOUT_LLM         = 120   # Per Ollama call
TIMEOUT_STRINGS_TRIAGE = int(os.environ.get("PHANTOM_STRINGS_TRIAGE_TIMEOUT", "90"))
TIMEOUT_YARA_MEMORY    = int(os.environ.get("PHANTOM_YARA_MEMORY_TIMEOUT", "120"))
MAX_PARALLEL_WORKERS = 16   # ThreadPoolExecutor workers (was 8)

# ── Adversarial loop settings ─────────────────────────────────────────────────
MAX_SKEPTIC_ROUNDS   = 3    # How many times Skeptic can challenge
MIN_SOURCES_CRITICAL = 3    # IOC sources needed for CRITICAL confidence
MIN_SOURCES_MEDIUM   = 2    # IOC sources needed for MEDIUM confidence

# ── Output ───────────────────────────────────────────────────────────────────
REPORT_DIR = os.path.expanduser("~")
