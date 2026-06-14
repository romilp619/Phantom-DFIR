"""
PHANTOM DFIR - Parallel Evidence Collector
Runs ALL Vol3 + Vol2 plugins in parallel threads.
Race OS detection: first engine to answer wins.

v1.1 - Full Linux plugin suite added
"""
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import tools.vol3_tools as v3
import tools.vol2_tools as v2
import tools.memory_triage as mt
from state import InvestigationState
from config import VOL3_CMD, VOL2_CMD, MAX_PARALLEL_WORKERS
import shutil


def detect_engines() -> dict:
    engines = {}
    if shutil.which("vol"):
        engines["vol3"] = shutil.which("vol")
    if shutil.which("vol2"):
        engines["vol2"] = shutil.which("vol2")
    return engines


def detect_os_parallel(filepath: str, engines: dict) -> tuple:
    result = {"os": None, "profile": None, "winner": None}
    done   = threading.Event()

    def try_vol3():
        if done.is_set(): return
        print("  [Vol3] windows.info racing...", flush=True)
        out = v3.windows_info(filepath)
        if not done.is_set() and "NtMajorVersion" in out:
            result.update({"os": "windows", "profile": None, "winner": "Vol3"})
            done.set()
            return
        if done.is_set(): return
        print("  [Vol3] banners.Banners racing...", flush=True)
        out = v3.linux_banner(filepath)
        if not done.is_set() and "Linux version" in out and "NtMajorVersion" not in out:
            result.update({"os": "linux", "profile": None, "winner": "Vol3-banners"})
            done.set()

    def try_vol2():
        if not engines.get("vol2") or done.is_set(): return
        print("  [Vol2] kdbgscan racing...", flush=True)
        out = v2.kdbgscan(filepath)
        if done.is_set(): return
        if "Suggested Profile(s)" in out or "Win" in out:
            profile = None
            for line in out.splitlines():
                if "Suggested Profile" in line or "Profile" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        candidates = [p.strip() for p in parts[1].split(",")]
                        if candidates:
                            profile = candidates[0]
                            break
            os_type = "windows" if profile and "Win" in profile else "linux"
            if not done.is_set():
                result.update({"os": os_type, "profile": profile, "winner": "Vol2-kdbgscan"})
                done.set()

    def try_strings():
        if done.is_set(): return
        import subprocess
        try:
            out = subprocess.run(
                f"strings -n 8 '{filepath}' | grep -m 1 -E 'NtMajorVersion|Linux version [0-9]'",
                shell=True, capture_output=True, text=True, timeout=30
            ).stdout
        except Exception:
            return
        if done.is_set(): return
        if "NtMajorVersion" in out:
            result.update({"os": "windows", "profile": None, "winner": "strings"})
            done.set()
        elif "Linux version" in out:
            result.update({"os": "linux", "profile": None, "winner": "strings"})
            done.set()

    threads = [
        threading.Thread(target=try_vol3,   daemon=True),
        threading.Thread(target=try_vol2,   daemon=True),
        threading.Thread(target=try_strings, daemon=True),
    ]
    for t in threads:
        t.start()
    done.wait(timeout=180)

    os_type = result.get("os") or "unknown"
    profile = result.get("profile")
    winner  = result.get("winner") or "timeout"
    print(f"  [OK] OS: {os_type} | profile: {profile or 'auto'} | via: {winner}", flush=True)
    return os_type, profile


def collect_windows_evidence(filepath: str, engines: dict) -> tuple:
    tasks = {
        "memory:strings_ioc": lambda: mt.run_strings_ioc(filepath),
        "memory:yara_scan":   lambda: mt.run_yara_memory_scan(filepath),
    }

    if engines.get("vol3"):
        tasks.update({
            # Process
            "vol3:pslist":             lambda: v3.pslist(filepath),
            "vol3:psscan":             lambda: v3.psscan(filepath),
            "vol3:pstree":             lambda: v3.pstree(filepath),
            "vol3:cmdline":            lambda: v3.cmdline(filepath),
            "vol3:envars":             lambda: v3.envars(filepath),
            "vol3:sessions":           lambda: v3.sessions(filepath),
            # Network
            "vol3:netscan":            lambda: v3.netscan(filepath),
            "vol3:netstat":            lambda: v3.netstat(filepath),
            # Malware detection
            "vol3:malfind":            lambda: v3.malfind(filepath),
            "vol3:hollowprocesses":    lambda: v3.hollowprocesses(filepath),
            "vol3:psxview":            lambda: v3.psxview(filepath),
            "vol3:svcdiff":            lambda: v3.svcdiff(filepath),
            "vol3:suspicious_threads": lambda: v3.suspicious_threads(filepath),
            "vol3:pebmasquerade":      lambda: v3.pebmasquerade(filepath),
            "vol3:processghosting":    lambda: v3.processghosting(filepath),
            "vol3:etwpatch":           lambda: v3.etwpatch(filepath),
            "vol3:ldrmodules":         lambda: v3.ldrmodules(filepath),
            "vol3:drivermodule":       lambda: v3.drivermodule(filepath),
            "vol3:callbacks":          lambda: v3.callbacks(filepath),
            "vol3:ssdt":               lambda: v3.ssdt(filepath),
            "vol3:unhooked_syscalls":  lambda: v3.unhooked_syscalls(filepath),
            "vol3:mutantscan":         lambda: v3.mutantscan(filepath),
            "vol3:modscan":            lambda: v3.modscan(filepath),
            "vol3:modules":            lambda: v3.modules(filepath),
            # Execution artifacts
            "vol3:svcscan":            lambda: v3.svcscan(filepath),
            "vol3:svclist":            lambda: v3.svclist(filepath),
            "vol3:shimcachemem":       lambda: v3.shimcachemem(filepath),
            "vol3:cmdscan":            lambda: v3.cmdscan(filepath),
            "vol3:consoles":           lambda: v3.consoles(filepath),
            # Registry
            "vol3:hivelist":           lambda: v3.hivelist(filepath),
            "vol3:userassist":         lambda: v3.userassist(filepath),
            "vol3:scheduled_tasks":    lambda: v3.scheduled_tasks(filepath),
            "vol3:amcache":            lambda: v3.amcache(filepath),
            # Privileges
            "vol3:privileges":         lambda: v3.privileges(filepath),
            "vol3:getsids":            lambda: v3.getsids(filepath),
        })

    if engines.get("vol2"):
        tasks.update({
            "vol2:hashdump":  lambda: v2.hashdump(filepath),
            "vol2:cachedump": lambda: v2.cachedump(filepath),
            "vol2:lsadump":   lambda: v2.lsadump(filepath),
            "vol2:svcscan":   lambda: v2.svcscan(filepath),
            "vol2:consoles":  lambda: v2.consoles(filepath),
            "vol2:cmdscan":   lambda: v2.cmdscan(filepath),
            "vol2:shimcache": lambda: v2.shimcache(filepath),
            "vol2:netscan":   lambda: v2.netscan(filepath),
        })

    return _run_parallel(tasks)


def collect_linux_evidence(filepath: str, engines: dict) -> tuple:
    """
    Full Linux evidence collection - equivalent depth to Windows.
    Covers: processes, network, bash history, rootkit detection,
    eBPF malware, kernel module tampering, fileless indicators.
    """
    tasks = {
        "memory:strings_ioc": lambda: mt.run_strings_ioc(filepath),
        "memory:yara_scan":   lambda: mt.run_yara_memory_scan(filepath),
    }

    if engines.get("vol3"):
        tasks.update({
            # -- Process enumeration ------------------------------------------
            "vol3:linux_pslist":         lambda: v3.linux_pslist(filepath),
            "vol3:linux_psscan":         lambda: v3.linux_psscan(filepath),
            "vol3:linux_pstree":         lambda: v3.linux_pstree(filepath),
            "vol3:linux_psaux":          lambda: v3.linux_psaux(filepath),
            "vol3:linux_envars":         lambda: v3.linux_envars(filepath),
            "vol3:linux_capabilities":   lambda: v3.linux_capabilities(filepath),
            "vol3:linux_pidhashtable":   lambda: v3.linux_pidhashtable(filepath),
            "vol3:linux_ptrace":         lambda: v3.linux_ptrace(filepath),

            # -- Network connections ------------------------------------------
            "vol3:linux_sockstat":       lambda: v3.linux_sockstat(filepath),
            "vol3:linux_sockscan":       lambda: v3.linux_sockscan(filepath),
            "vol3:linux_netfilter":      lambda: v3.linux_netfilter(filepath),
            "vol3:linux_ip_addr":        lambda: v3.linux_ip_addr(filepath),

            # -- Execution history --------------------------------------------
            "vol3:linux_bash":           lambda: v3.linux_bash(filepath),
            "vol3:linux_lsof":           lambda: v3.linux_lsof(filepath),
            "vol3:linux_mountinfo":      lambda: v3.linux_mountinfo(filepath),
            "vol3:linux_boottime":       lambda: v3.linux_boottime(filepath),
            "vol3:linux_kmsg":           lambda: v3.linux_kmsg(filepath),

            # -- Malware / fileless / injection detection ---------------------
            "vol3:linux_malfind":        lambda: v3.linux_malfind(filepath),
            "vol3:linux_process_spoof":  lambda: v3.linux_process_spoofing(filepath),
            "vol3:linux_ebpf":           lambda: v3.linux_ebpf(filepath),

            # -- Rootkit detection --------------------------------------------
            "vol3:linux_check_syscall":  lambda: v3.linux_check_syscall(filepath),
            "vol3:linux_check_idt":      lambda: v3.linux_check_idt(filepath),
            "vol3:linux_check_afinfo":   lambda: v3.linux_check_afinfo(filepath),
            "vol3:linux_check_creds":    lambda: v3.linux_check_creds(filepath),
            "vol3:linux_hidden_modules": lambda: v3.linux_hidden_modules(filepath),
            "vol3:linux_modxview":       lambda: v3.linux_modxview(filepath),
            "vol3:linux_tty_check":      lambda: v3.linux_tty_check(filepath),
            "vol3:linux_keyboard_ntfy":  lambda: v3.linux_keyboard_notifiers(filepath),
            "vol3:linux_check_ftrace":   lambda: v3.linux_check_ftrace(filepath),
            "vol3:linux_check_tracepoints": lambda: v3.linux_check_tracepoints(filepath),

            # -- Library / module analysis ------------------------------------
            "vol3:linux_lsmod":          lambda: v3.linux_lsmod(filepath),
            "vol3:linux_library_list":   lambda: v3.linux_library_list(filepath),
            "vol3:linux_elfs":           lambda: v3.linux_elfs(filepath),

            # -- Banners / OS info --------------------------------------------
            "vol3:banners":              lambda: v3.linux_banner(filepath),
        })

        # Targeted regex scans for common C2 and attacker patterns
        tasks["vol3:vma_c2_http"] = lambda: v3.linux_vma_regexscan(
            filepath, r"https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
        tasks["vol3:vma_base64"] = lambda: v3.linux_vma_regexscan(
            filepath, r"[A-Za-z0-9+/]{80,}={0,2}")
        tasks["vol3:vma_reverse_shell"] = lambda: v3.linux_vma_regexscan(
            filepath, r"/dev/tcp|/dev/udp|mkfifo|nc -e|bash -i")

    return _run_parallel(tasks)


def _run_parallel(tasks: dict) -> tuple:
    """Run a dict of {name: callable} in parallel, return (results, errors)."""
    raw_evidence = {}
    errors       = []
    total        = len(tasks)
    completed    = 0
    t_start      = time.time()

    print(f"\n  Running {total} plugins in parallel ({MAX_PARALLEL_WORKERS} workers)...", flush=True)
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_WORKERS) as ex:
        future_map  = {ex.submit(fn): name for name, fn in tasks.items()}
        future_start = {name: time.time() for name in tasks}
        for future in as_completed(future_map):
            name = future_map[future]
            completed += 1
            elapsed_plugin = time.time() - future_start.get(name, time.time())
            try:
                result = future.result()
                raw_evidence[name] = result or ""
                status = "[OK]" if result and "[TIMEOUT]" not in result and "[ERROR]" not in result else "[FAIL]"
                print(f"    [{completed:>2}/{total}] {status} {name:<30} ({elapsed_plugin:.1f}s)", flush=True)
            except Exception as e:
                errors.append(f"{name}: {e}")
                raw_evidence[name] = f"[ERROR] {e}"
                print(f"    [{completed:>2}/{total}] [FAIL] {name:<30} (FAILED: {e})", flush=True)

    wall_time = time.time() - t_start
    succeeded = total - len(errors)
    print(f"\n  -- {succeeded}/{total} plugins succeeded in {wall_time:.1f}s "
          f"({len(errors)} failed) --", flush=True)

    return raw_evidence, errors


def run_collector(state: InvestigationState) -> InvestigationState:
    filepath = state["filepath"]
    engines  = state.get("engines") or detect_engines()

    print("\n==================================================", flush=True)
    print("  PHASE 1 - PARALLEL EVIDENCE COLLECTION", flush=True)
    print("==================================================", flush=True)
    print(f"  Target : {filepath}", flush=True)
    print(f"  Engines: {list(engines.keys())}", flush=True)

    print("\n  [OS Detection] Racing Vol3 vs Vol2 vs strings...", flush=True)
    os_type, vol2_profile = detect_os_parallel(filepath, engines)

    t0 = time.time()
    if os_type == "windows":
        raw_evidence, errors = collect_windows_evidence(filepath, engines)
    elif os_type == "linux":
        print(f"  [Linux] Running full Linux plugin suite...", flush=True)
        raw_evidence, errors = collect_linux_evidence(filepath, engines)
    else:
        print(f"  [!] OS unknown - running banners + strings fallback", flush=True)
        raw_evidence = {"vol3:banners": v3.linux_banner(filepath)}
        errors = []

    elapsed = time.time() - t0
    raw_evidence["memory:timeline_hints"] = mt.build_memory_timeline_hints(raw_evidence, os_type)
    raw_evidence["memory:triage_summary"] = mt.build_triage_summary(raw_evidence)
    print(f"\n  Collection complete: {len(raw_evidence)} plugins in {elapsed:.1f}s", flush=True)

    # -- Reasoning Trace ---------------------------------------------------
    import time as _time
    reasoning = state.get("reasoning_log", [])
    reasoning.append({
        "agent": "Collector",
        "action": "OS Detection",
        "rationale": f"Raced Vol3 windows.info vs Vol2 kdbgscan vs strings in parallel - "
                     f"first responder wins to minimize detection time",
        "result": f"OS={os_type}, profile={vol2_profile or 'auto'}, detected via parallel race",
        "timestamp": _time.time(),
    })
    reasoning.append({
        "agent": "Collector",
        "action": f"Plugin Selection ({os_type})",
        "rationale": f"Selected {len(raw_evidence)} {os_type}-specific plugins covering "
                     f"processes, network, persistence, malware detection, and credentials. "
                     f"Ran all in parallel with {MAX_PARALLEL_WORKERS} workers to minimize wall time.",
        "result": f"{len(raw_evidence)} plugins completed in {elapsed:.1f}s, "
                  f"{len(errors)} errors",
        "timestamp": _time.time(),
    })
    reasoning.append({
        "agent": "Collector",
        "action": "Memory triage enrichment",
        "rationale": "Ran bounded strings/YARA triage and condensed timeline hints after Volatility collection. "
                     "These are lead-generation artifacts used by Investigator and self-correction, not standalone proof.",
        "result": raw_evidence.get("memory:triage_summary", "")[:500],
        "timestamp": _time.time(),
    })

    return {
        **state,
        "os_type":      os_type,
        "vol2_profile": vol2_profile,
        "engines":      engines,
        "raw_evidence": raw_evidence,
        "collection_errors": errors,
        "reasoning_log": reasoning,
    }
