"""
PHANTOM DFIR — Vol2 Tool Wrappers v2.0
Tool alias on SIFT: `vol2`
Vol2 is used for: hashdump, cachedump, lsadump, consoles (fallback),
and profile-based analysis when Vol3 symbols aren't available.

v2.0 — Dynamic profile detection (no hardcoded profile)
"""
import subprocess
from config import VOL2_CMD, TIMEOUT_VOL2_HASH, TIMEOUT_PLUGIN_FAST, TIMEOUT_PLUGIN_SLOW

# Default profile — will be overridden at runtime from kdbgscan
DEFAULT_PROFILE = None
_detected_profile = None


def _detect_profile(filepath: str) -> str:
    """Auto-detect Vol2 profile via kdbgscan if not already cached."""
    global _detected_profile
    if _detected_profile:
        return _detected_profile

    out = kdbgscan(filepath)
    if "Suggested Profile" in out or "Profile" in out:
        for line in out.splitlines():
            if "Suggested Profile" in line or "Profile" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    candidates = [p.strip() for p in parts[1].split(",")]
                    if candidates and candidates[0]:
                        _detected_profile = candidates[0]
                        return _detected_profile
    return "Win10x64_16299"  # last-resort fallback


def _get_profile(filepath: str, profile: str = None) -> str:
    """Get the best profile to use."""
    if profile:
        return profile
    return _detect_profile(filepath)


def _vol2(filepath: str, plugin: str, profile: str = None,
          extra: str = "", timeout: int = TIMEOUT_PLUGIN_FAST) -> str:
    prof = _get_profile(filepath, profile)
    cmd = f"{VOL2_CMD} -f '{filepath}' --profile={prof} {plugin} {extra} 2>&1"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return f"[ERROR] {e}"


def kdbgscan(filepath: str) -> str:
    """Fast OS/profile detection — no profile needed."""
    cmd = f"{VOL2_CMD} -f '{filepath}' kdbgscan 2>&1 | head -40"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=90, errors="replace")
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"


# ── Credentials (NOT in Vol3 — Vol2 only) ────────────────────────────────────
def hashdump(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "hashdump", profile, timeout=TIMEOUT_VOL2_HASH)

def cachedump(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "cachedump", profile, timeout=TIMEOUT_VOL2_HASH)

def lsadump(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "lsadump", profile, timeout=TIMEOUT_VOL2_HASH)


# ── Process Plugins (Vol2 fallback) ──────────────────────────────────────────
def pslist(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "pslist", profile)

def psscan(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "psscan", profile, timeout=TIMEOUT_PLUGIN_SLOW)

def cmdline(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "cmdline", profile)

def malfind(filepath: str, profile: str = None, pid: int = None) -> str:
    extra = f"-p {pid}" if pid else ""
    return _vol2(filepath, "malfind", profile, extra, timeout=TIMEOUT_PLUGIN_SLOW)

def svcscan(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "svcscan", profile)


# ── Network (Vol2 fallback) ───────────────────────────────────────────────────
def netscan(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "netscan", profile)

def connections(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "connections", profile)

def connscan(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "connscan", profile)


# ── Console / CMD history ─────────────────────────────────────────────────────
def consoles(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "consoles", profile)

def cmdscan(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "cmdscan", profile)


# ── Registry ──────────────────────────────────────────────────────────────────
def shimcache(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "shimcache", profile)

def userassist(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "userassist", profile)

def autoruns(filepath: str, profile: str = None) -> str:
    return _vol2(filepath, "autoruns", profile)
