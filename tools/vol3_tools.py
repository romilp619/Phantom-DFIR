"""
PHANTOM DFIR — Vol3 Tool Wrappers
All plugins verified against: vol --help (Volatility 3 Framework 2.28.0)
Tool alias on SIFT: `vol`

v1.1 — Added full Linux plugin suite
"""
import subprocess, sys
from config import VOL3_CMD, TIMEOUT_PLUGIN_FAST, TIMEOUT_PLUGIN_SLOW


def _run(cmd: str, timeout: int = TIMEOUT_PLUGIN_FAST) -> str:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, errors="replace"
        )
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]"
    except Exception as e:
        return f"[ERROR] {e}"


def _vol3(filepath: str, plugin: str, extra: str = "", timeout: int = TIMEOUT_PLUGIN_FAST) -> str:
    cmd = f"{VOL3_CMD} -q -f '{filepath}' {plugin} {extra} 2>&1"
    out = _run(cmd, timeout)
    bad = ["Unsatisfied requirement", "A translation layer requirement",
           "symbol_table_name", "Progress:", "Stacking attempts"]
    lines = [l for l in out.splitlines() if not any(b in l for b in bad)]
    return "\n".join(lines).strip()


# ── OS Detection ──────────────────────────────────────────────────────────────
def windows_info(filepath: str) -> str:
    return _vol3(filepath, "windows.info", timeout=120)

def linux_banner(filepath: str) -> str:
    return _vol3(filepath, "banners.Banners", timeout=60)


# ═══════════════════════════════════════════════════════════════
# WINDOWS PLUGINS
# ═══════════════════════════════════════════════════════════════

def pslist(filepath: str) -> str:
    return _vol3(filepath, "windows.pslist", timeout=TIMEOUT_PLUGIN_FAST)

def psscan(filepath: str) -> str:
    return _vol3(filepath, "windows.psscan", timeout=TIMEOUT_PLUGIN_SLOW)

def pstree(filepath: str) -> str:
    return _vol3(filepath, "windows.pstree", timeout=TIMEOUT_PLUGIN_FAST)

def cmdline(filepath: str) -> str:
    return _vol3(filepath, "windows.cmdline", timeout=TIMEOUT_PLUGIN_FAST)

def dlllist(filepath: str, pid: int = None) -> str:
    extra = f"--pid {pid}" if pid else ""
    return _vol3(filepath, "windows.dlllist", extra, timeout=TIMEOUT_PLUGIN_SLOW)

def handles(filepath: str, pid: int = None) -> str:
    extra = f"--pid {pid}" if pid else ""
    return _vol3(filepath, "windows.handles", extra, timeout=TIMEOUT_PLUGIN_SLOW)

def envars(filepath: str) -> str:
    return _vol3(filepath, "windows.envars", timeout=TIMEOUT_PLUGIN_FAST)

def privileges(filepath: str) -> str:
    return _vol3(filepath, "windows.privileges", timeout=TIMEOUT_PLUGIN_FAST)

def getsids(filepath: str) -> str:
    return _vol3(filepath, "windows.getsids", timeout=TIMEOUT_PLUGIN_FAST)

def sessions(filepath: str) -> str:
    return _vol3(filepath, "windows.sessions", timeout=TIMEOUT_PLUGIN_FAST)

def malfind(filepath: str, pid: int = None) -> str:
    extra = f"--pid {pid}" if pid else ""
    return _vol3(filepath, "windows.malware.malfind", extra, timeout=TIMEOUT_PLUGIN_SLOW)

def hollowprocesses(filepath: str) -> str:
    return _vol3(filepath, "windows.malware.hollowprocesses", timeout=TIMEOUT_PLUGIN_SLOW)

def psxview(filepath: str) -> str:
    return _vol3(filepath, "windows.malware.psxview", timeout=TIMEOUT_PLUGIN_SLOW)

def svcdiff(filepath: str) -> str:
    return _vol3(filepath, "windows.malware.svcdiff", timeout=TIMEOUT_PLUGIN_FAST)

def suspicious_threads(filepath: str) -> str:
    return _vol3(filepath, "windows.malware.suspicious_threads", timeout=TIMEOUT_PLUGIN_FAST)

def pebmasquerade(filepath: str) -> str:
    return _vol3(filepath, "windows.malware.pebmasquerade", timeout=TIMEOUT_PLUGIN_FAST)

def processghosting(filepath: str) -> str:
    return _vol3(filepath, "windows.malware.processghosting", timeout=TIMEOUT_PLUGIN_FAST)

def etwpatch(filepath: str) -> str:
    return _vol3(filepath, "windows.etwpatch", timeout=TIMEOUT_PLUGIN_FAST)

def ldrmodules(filepath: str) -> str:
    return _vol3(filepath, "windows.malware.ldrmodules", timeout=TIMEOUT_PLUGIN_SLOW)

def drivermodule(filepath: str) -> str:
    return _vol3(filepath, "windows.malware.drivermodule", timeout=TIMEOUT_PLUGIN_SLOW)

def callbacks(filepath: str) -> str:
    return _vol3(filepath, "windows.callbacks", timeout=TIMEOUT_PLUGIN_FAST)

def ssdt(filepath: str) -> str:
    return _vol3(filepath, "windows.ssdt", timeout=TIMEOUT_PLUGIN_FAST)

def unhooked_syscalls(filepath: str) -> str:
    return _vol3(filepath, "windows.malware.unhooked_system_calls", timeout=TIMEOUT_PLUGIN_FAST)

def mutantscan(filepath: str) -> str:
    return _vol3(filepath, "windows.mutantscan", timeout=TIMEOUT_PLUGIN_FAST)

def filescan(filepath: str) -> str:
    return _vol3(filepath, "windows.filescan", timeout=TIMEOUT_PLUGIN_SLOW)

def modscan(filepath: str) -> str:
    return _vol3(filepath, "windows.modscan", timeout=TIMEOUT_PLUGIN_FAST)

def modules(filepath: str) -> str:
    return _vol3(filepath, "windows.modules", timeout=TIMEOUT_PLUGIN_FAST)

def netscan(filepath: str) -> str:
    return _vol3(filepath, "windows.netscan", timeout=TIMEOUT_PLUGIN_FAST)

def netstat(filepath: str) -> str:
    return _vol3(filepath, "windows.netstat", timeout=TIMEOUT_PLUGIN_FAST)

def shimcachemem(filepath: str) -> str:
    return _vol3(filepath, "windows.shimcachemem", timeout=TIMEOUT_PLUGIN_FAST)

def cmdscan(filepath: str) -> str:
    return _vol3(filepath, "windows.cmdscan", timeout=TIMEOUT_PLUGIN_FAST)

def consoles(filepath: str) -> str:
    return _vol3(filepath, "windows.consoles", timeout=TIMEOUT_PLUGIN_FAST)

def amcache(filepath: str) -> str:
    return _vol3(filepath, "windows.registry.amcache", timeout=TIMEOUT_PLUGIN_SLOW)

def hivelist(filepath: str) -> str:
    return _vol3(filepath, "windows.registry.hivelist", timeout=TIMEOUT_PLUGIN_FAST)

def userassist(filepath: str) -> str:
    return _vol3(filepath, "windows.registry.userassist", timeout=TIMEOUT_PLUGIN_FAST)

def scheduled_tasks(filepath: str) -> str:
    return _vol3(filepath, "windows.registry.scheduled_tasks", timeout=TIMEOUT_PLUGIN_FAST)

def svcscan(filepath: str) -> str:
    return _vol3(filepath, "windows.svcscan", timeout=TIMEOUT_PLUGIN_FAST)

def svclist(filepath: str) -> str:
    return _vol3(filepath, "windows.svclist", timeout=TIMEOUT_PLUGIN_FAST)

def getservicesids(filepath: str) -> str:
    return _vol3(filepath, "windows.getservicesids", timeout=TIMEOUT_PLUGIN_FAST)

def targeted_pid_evidence(filepath: str, pid: int) -> dict:
    return {
        "pslist_pid":  pslist(filepath) + f"\n(filter PID={pid})",
        "cmdline_pid": _vol3(filepath, "windows.cmdline", f"--pid {pid}"),
        "malfind_pid": malfind(filepath, pid),
        "dlllist_pid": dlllist(filepath, pid),
    }

def targeted_ip_evidence(filepath: str, ip: str) -> dict:
    ns = netscan(filepath)
    nt = netstat(filepath)
    return {
        "netscan_ip": "\n".join(l for l in ns.splitlines() if ip in l),
        "netstat_ip": "\n".join(l for l in nt.splitlines() if ip in l),
    }


# ═══════════════════════════════════════════════════════════════
# LINUX PLUGINS  (v1.1)
# ═══════════════════════════════════════════════════════════════

# ── Linux Process Plugins ─────────────────────────────────────────────────────
def linux_pslist(filepath: str) -> str:
    """All processes from task_struct list."""
    return _vol3(filepath, "linux.pslist.PsList", timeout=TIMEOUT_PLUGIN_FAST)

def linux_psscan(filepath: str) -> str:
    """Scan for hidden/unlinked tasks — rootkit detection."""
    return _vol3(filepath, "linux.psscan.PsScan", timeout=TIMEOUT_PLUGIN_SLOW)

def linux_pstree(filepath: str) -> str:
    return _vol3(filepath, "linux.pstree.PsTree", timeout=TIMEOUT_PLUGIN_FAST)

def linux_psaux(filepath: str) -> str:
    """Full command line arguments per process."""
    return _vol3(filepath, "linux.psaux.PsAux", timeout=TIMEOUT_PLUGIN_FAST)

def linux_envars(filepath: str) -> str:
    """Environment variables — reveals LD_PRELOAD, suspicious vars."""
    return _vol3(filepath, "linux.envars.Envars", timeout=TIMEOUT_PLUGIN_FAST)

def linux_capabilities(filepath: str) -> str:
    """Process capabilities — detect cap_setuid/cap_sys_admin abuse."""
    return _vol3(filepath, "linux.capabilities.Capabilities", timeout=TIMEOUT_PLUGIN_FAST)

def linux_pidhashtable(filepath: str) -> str:
    """PID hash table enumeration — cross-check with pslist for hidden procs."""
    return _vol3(filepath, "linux.pidhashtable.PIDHashTable", timeout=TIMEOUT_PLUGIN_FAST)

def linux_ptrace(filepath: str) -> str:
    """Ptrace relationships — detect process injection via ptrace."""
    return _vol3(filepath, "linux.ptrace.Ptrace", timeout=TIMEOUT_PLUGIN_FAST)


# ── Linux Network Plugins ─────────────────────────────────────────────────────
def linux_sockstat(filepath: str) -> str:
    """All network connections per process — equivalent of ss/netstat."""
    return _vol3(filepath, "linux.sockstat.Sockstat", timeout=TIMEOUT_PLUGIN_FAST)

def linux_sockscan(filepath: str) -> str:
    """Scan for socket structures — finds hidden connections."""
    return _vol3(filepath, "linux.sockscan.Sockscan", timeout=TIMEOUT_PLUGIN_SLOW)

def linux_netfilter(filepath: str) -> str:
    """Netfilter hooks — rootkit network interception detection."""
    return _vol3(filepath, "linux.malware.netfilter.Netfilter", timeout=TIMEOUT_PLUGIN_FAST)

def linux_ip_addr(filepath: str) -> str:
    return _vol3(filepath, "linux.ip.Addr", timeout=TIMEOUT_PLUGIN_FAST)


# ── Linux Execution History ───────────────────────────────────────────────────
def linux_bash(filepath: str) -> str:
    """Bash command history from memory — most valuable Linux artifact."""
    return _vol3(filepath, "linux.bash.Bash", timeout=TIMEOUT_PLUGIN_FAST)

def linux_lsof(filepath: str) -> str:
    """Open files per process — detect /proc/mem reads, deleted-but-running files."""
    return _vol3(filepath, "linux.lsof.Lsof", timeout=TIMEOUT_PLUGIN_FAST)

def linux_pagecache_files(filepath: str) -> str:
    """Files in page cache — recover deleted files still in memory."""
    return _vol3(filepath, "linux.pagecache.Files", timeout=TIMEOUT_PLUGIN_SLOW)

def linux_mountinfo(filepath: str) -> str:
    """Mount points — detect tmpfs, unusual mounts used for hiding."""
    return _vol3(filepath, "linux.mountinfo.MountInfo", timeout=TIMEOUT_PLUGIN_FAST)

def linux_kmsg(filepath: str) -> str:
    """Kernel log buffer — may show crash/OOM/attack evidence."""
    return _vol3(filepath, "linux.kmsg.Kmsg", timeout=TIMEOUT_PLUGIN_FAST)


# ── Linux Malware / Rootkit Detection ────────────────────────────────────────
def linux_malfind(filepath: str) -> str:
    """
    RWX memory regions — primary indicator of shellcode injection,
    fileless malware, and process hollowing.
    """
    return _vol3(filepath, "linux.malware.malfind.Malfind", timeout=TIMEOUT_PLUGIN_SLOW)

def linux_check_syscall(filepath: str) -> str:
    """
    Syscall table integrity check — #1 rootkit detection method.
    Hooked entries = kernel-level compromise.
    """
    return _vol3(filepath, "linux.malware.check_syscall.Check_syscall", timeout=TIMEOUT_PLUGIN_FAST)

def linux_check_idt(filepath: str) -> str:
    """Interrupt Descriptor Table hook check."""
    return _vol3(filepath, "linux.malware.check_idt.Check_idt", timeout=TIMEOUT_PLUGIN_FAST)

def linux_check_afinfo(filepath: str) -> str:
    """Network protocol function pointer integrity — detect netfilter rootkit hooks."""
    return _vol3(filepath, "linux.malware.check_afinfo.Check_afinfo", timeout=TIMEOUT_PLUGIN_FAST)

def linux_check_creds(filepath: str) -> str:
    """Shared credential structures — privilege escalation via cred sharing."""
    return _vol3(filepath, "linux.malware.check_creds.Check_creds", timeout=TIMEOUT_PLUGIN_FAST)

def linux_hidden_modules(filepath: str) -> str:
    """
    Carve memory for kernel modules NOT in lsmod — definitive LKM rootkit detection.
    Finds diamorphine, reptile, azazel etc.
    """
    return _vol3(filepath, "linux.malware.hidden_modules.Hidden_modules", timeout=TIMEOUT_PLUGIN_SLOW)

def linux_modxview(filepath: str) -> str:
    """Consolidated lsmod + check_modules + hidden_modules — best single rootkit plugin."""
    return _vol3(filepath, "linux.malware.modxview.Modxview", timeout=TIMEOUT_PLUGIN_SLOW)

def linux_tty_check(filepath: str) -> str:
    """TTY device hooks — rootkit keystroke logging detection."""
    return _vol3(filepath, "linux.malware.tty_check.Tty_Check", timeout=TIMEOUT_PLUGIN_FAST)

def linux_keyboard_notifiers(filepath: str) -> str:
    """Keyboard notifier chain — rootkit keylogger."""
    return _vol3(filepath, "linux.malware.keyboard_notifiers.Keyboard_notifiers", timeout=TIMEOUT_PLUGIN_FAST)

def linux_process_spoofing(filepath: str) -> str:
    """
    Detect process name spoofing — comm vs cmdline vs exe path mismatch.
    Catches LD_PRELOAD hijacks and userland rootkit tricks.
    """
    return _vol3(filepath, "linux.malware.process_spoofing.ProcessSpoofing", timeout=TIMEOUT_PLUGIN_FAST)

def linux_ebpf(filepath: str) -> str:
    """
    Enumerate eBPF programs — detect modern fileless rootkits.
    Critical 2024-2025 attack vector (BPFDoor, pamspy etc).
    """
    return _vol3(filepath, "linux.ebpf.EBPF", timeout=TIMEOUT_PLUGIN_FAST)

def linux_check_ftrace(filepath: str) -> str:
    """Ftrace hooking detection — kernel hook mechanism used by modern rootkits."""
    return _vol3(filepath, "linux.tracing.ftrace.CheckFtrace", timeout=TIMEOUT_PLUGIN_FAST)

def linux_check_tracepoints(filepath: str) -> str:
    """Tracepoint hooking detection."""
    return _vol3(filepath, "linux.tracing.tracepoints.CheckTracepoints", timeout=TIMEOUT_PLUGIN_FAST)


# ── Linux Kernel Modules ──────────────────────────────────────────────────────
def linux_lsmod(filepath: str) -> str:
    """Loaded kernel modules — compare with hidden_modules."""
    return _vol3(filepath, "linux.lsmod.Lsmod", timeout=TIMEOUT_PLUGIN_FAST)

def linux_library_list(filepath: str) -> str:
    """Libraries per process — detect LD_PRELOAD injection."""
    return _vol3(filepath, "linux.library_list.LibraryList", timeout=TIMEOUT_PLUGIN_FAST)

def linux_elfs(filepath: str) -> str:
    """Memory-mapped ELF files — detect packed/injected binaries."""
    return _vol3(filepath, "linux.elfs.Elfs", timeout=TIMEOUT_PLUGIN_FAST)

def linux_proc_maps(filepath: str) -> str:
    """Memory maps — equivalent of /proc/PID/maps."""
    return _vol3(filepath, "linux.proc.Maps", timeout=TIMEOUT_PLUGIN_SLOW)

def linux_boottime(filepath: str) -> str:
    return _vol3(filepath, "linux.boottime.Boottime", timeout=TIMEOUT_PLUGIN_FAST)

def linux_iomem(filepath: str) -> str:
    return _vol3(filepath, "linux.iomem.IOMem", timeout=TIMEOUT_PLUGIN_FAST)

def linux_vma_regexscan(filepath: str, pattern: str) -> str:
    """Scan all VMA regions with regex — hunt C2 URLs, shellcode sigs."""
    escaped = pattern.replace("'", "\\'")
    return _vol3(filepath, "linux.vmaregexscan.VmaRegExScan",
                 f"--pattern '{escaped}'", timeout=TIMEOUT_PLUGIN_SLOW)

def linux_targeted_pid_evidence(filepath: str, pid: int) -> dict:
    """Linux equivalent of targeted_pid_evidence."""
    return {
        "linux_lsof_pid":    _vol3(filepath, "linux.lsof.Lsof",    f"--pid {pid}"),
        "linux_maps_pid":    _vol3(filepath, "linux.proc.Maps",     f"--pid {pid}"),
        "linux_envars_pid":  _vol3(filepath, "linux.envars.Envars", f"--pid {pid}"),
        "linux_malfind":     linux_malfind(filepath),
    }

# ========== ADVANCED DETECTION TECHNIQUES ==========

def detect_dkom(filepath: str) -> dict:
    """DKOM detection - compare pslist vs psscan to find hidden processes"""
    pslist_out = pslist(filepath)
    psscan_out = psscan(filepath)
    
    # Extract PIDs from both
    pslist_pids = set()
    psscan_pids = set()
    
    for line in pslist_out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            pslist_pids.add(int(parts[0]))
    
    for line in psscan_out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            psscan_pids.add(int(parts[0]))
    
    hidden = psscan_pids - pslist_pids
    
    return {
        "pslist_count": len(pslist_pids),
        "psscan_count": len(psscan_pids),
        "hidden_processes": list(hidden),
        "dkom_detected": len(hidden) > 0
    }

def vadinfo(filepath: str) -> str:
    """VAD analysis - catches VAD remapping attacks"""
    return _vol3(filepath, "windows.vadinfo", timeout=TIMEOUT_PLUGIN_SLOW)

def detect_module_stomping(filepath: str) -> dict:
    """Detect module stomping - dlllist vs modscan discrepancy"""
    dlllist_out = _vol3(filepath, "windows.dlllist", timeout=TIMEOUT_PLUGIN_SLOW)
    modscan_out = _vol3(filepath, "windows.modscan", timeout=TIMEOUT_PLUGIN_SLOW)
    
    # Parse and compare
    dll_modules = set()
    mod_modules = set()
    
    for line in dlllist_out.splitlines():
        if ".dll" in line.lower():
            parts = line.split()
            for part in parts:
                if ".dll" in part.lower():
                    dll_modules.add(part.lower())
                    break
    
    for line in modscan_out.splitlines():
        if ".dll" in line.lower():
            parts = line.split()
            for part in parts:
                if ".dll" in part.lower():
                    mod_modules.add(part.lower())
                    break
    
    stomped = mod_modules - dll_modules
    
    return {
        "dlllist_count": len(dll_modules),
        "modscan_count": len(mod_modules),
        "stomped_modules": list(stomped)[:20],
        "module_stomping_detected": len(stomped) > 0
    }

def ptemalfind(filepath: str) -> str:
    """Page Table based malfind - bypasses VAD manipulation"""
    return _vol3(filepath, "windows.ptemalfind", timeout=TIMEOUT_PLUGIN_SLOW)

def detect_unhooking(filepath: str) -> dict:
    """Detect EDR unhooking via ntdll analysis"""
    ntdll_info = _vol3(filepath, "windows.dlllist --pid 0", timeout=TIMEOUT_PLUGIN_SLOW)
    
    suspicious = []
    for line in ntdll_info.splitlines():
        if "ntdll" in line.lower() and "mismatch" in line.lower():
            suspicious.append(line.strip())
    
    return {
        "unhooking_detected": len(suspicious) > 0,
        "suspicious_entries": suspicious[:10]
    }


