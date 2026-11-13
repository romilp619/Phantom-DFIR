"""
PHANTOM DFIR - Dynamic Legitimacy Engine v4.0
Two-layer scoring: IDENTITY (who are you?) + BEHAVIOR (what are you doing?)

A process is only LEGITIMATE if BOTH identity AND behavior are clean.
A trusted file doing suspicious things = LOLBin attack = SUSPICIOUS.

v4.0 enhancements:
  - Damerau-Levenshtein masquerading detection (replaces hardcoded pairs)
  - Process instance count validation (lsass.exe should be 1 instance)
  - Double file extension detection (invoice.doc.exe)

Scores:
  Identity (0-100): path, parent, known process database
  Behavior (0-100): command line, memory anomalies, network destinations
  Final = identity * 0.4 + behavior * 0.6  (behavior weighs more)

Verdict:
  >70 = LEGITIMATE - both identity and behavior are clean
  30-70 = UNCERTAIN - keep for investigation
  <30 = SUSPICIOUS - likely malicious
"""
import re
from typing import Optional

from tools.trusted_resources import (
    lookup_ip, lookup_process, is_trusted_path, is_trusted_port,
    LEGITIMATE_PATH_PATTERNS_WINDOWS, LEGITIMATE_PATH_PATTERNS_LINUX,
)


# -- LOLBin indicators: trusted tools used maliciously -------------------------
LOLBIN_PATTERNS = {
    "powershell": [
        r"-enc\b", r"-encodedcommand\b", r"-e\b\s+[A-Za-z0-9+/=]{20,}",
        r"invoke-expression", r"\biex\b", r"downloadstring",
        r"downloadfile", r"net\.webclient", r"start-process",
        r"bypass", r"-nop\b", r"-noni\b", r"-w\s+hidden",
        r"frombase64string", r"convertto-securestring",
    ],
    "certutil": [
        r"-urlcache", r"-split\s+-f", r"http[s]?://",
        r"-decode", r"-encode",
    ],
    "mshta": [
        r"javascript:", r"vbscript:", r"wscript\.shell",
        r"activexobject", r"http[s]?://",
    ],
    "rundll32": [
        r"javascript:", r"mshtml", r"shell32\.dll.*shellexec",
        r"http[s]?://", r"advpack\.dll.*launchinf",
    ],
    "regsvr32": [
        r"/s\s+/u\s+/i:http", r"scrobj\.dll", r"http[s]?://",
    ],
    "wmic": [
        r"process\s+call\s+create", r"os\s+get", r"/node:",
        r"http[s]?://",
    ],
    "bitsadmin": [
        r"/transfer", r"/download", r"http[s]?://",
    ],
    "cscript": [
        r"http[s]?://", r"wscript\.shell", r"activexobject",
    ],
    "wscript": [
        r"http[s]?://", r"wscript\.shell", r"activexobject",
    ],
    "cmd": [
        r"/c\s+.*powershell", r"/c\s+.*certutil", r"/c\s+.*bitsadmin",
        r"&&\s*.*del\s+", r"echo\s+.*>\s+.*\.bat",
    ],
}

# -- Memory anomaly indicators -------------------------------------------------
MEMORY_ANOMALY_PATTERNS = [
    "PAGE_EXECUTE_READWRITE",
    "MZ header",
    "This program cannot",
    "Hollowed",
    "VadS",
]

# -- Suspicious command line patterns (any process) ----------------------------
SUSPICIOUS_CMDLINE_PATTERNS = [
    r"base64", r"encodedcommand", r"-enc\s",
    r"http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP-based URLs
    r"\\appdata\\local\\temp\\",  # Execution from temp
    r"\\users\\public\\",         # Execution from public folder
    r"\\programdata\\(?!microsoft)",  # ProgramData but not Microsoft
    r"cmd\.exe\s+/c",             # cmd launching commands
    r"\|.*nc\s+-",                # Piped to netcat
    r"/dev/tcp",                  # Bash reverse shell
    r"mkfifo",                    # Named pipe reverse shell
]

# -- Process name masquerading - Damerau-Levenshtein distance ------------------
# v4.0: Algorithmic detection replaces hardcoded pairs.
# Any process within edit distance 1 of a known system process is suspicious.
# Catches novel typosquats we never anticipated (csvhost.exe, winloqon.exe).
# Based on PHANTOM DFIR forensic process name research
SYSTEM_PROCESS_NAMES = [
    "csrss.exe", "dllhost.exe", "explorer.exe", "iexplore.exe",
    "lsass.exe", "sihost.exe", "smss.exe", "svchost.exe",
    "winlogon.exe", "services.exe", "wininit.exe", "taskhost.exe",
    "taskhostw.exe", "spoolsv.exe", "lsm.exe",
]

# -- Expected process instance counts -----------------------------------------
# v4.0: If lsass.exe appears >1 time -> likely injection.
EXPECTED_INSTANCE_COUNTS = {
    "lsass.exe": 1,
    "lsm.exe": 1,
    "services.exe": 1,
    "wininit.exe": 1,
    "lsaiso.exe": 1,
}


def _damerau_levenshtein(s1: str, s2: str) -> int:
    """Compute Damerau-Levenshtein distance between two strings.
    Catches insertions, deletions, substitutions, AND transpositions."""
    len1, len2 = len(s1), len(s2)
    if s1 == s2:
        return 0
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1

    matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1):
        matrix[i][0] = i
    for j in range(len2 + 1):
        matrix[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            matrix[i][j] = min(
                matrix[i - 1][j] + 1,       # deletion
                matrix[i][j - 1] + 1,       # insertion
                matrix[i - 1][j - 1] + cost, # substitution
            )
            # Transposition
            if (i > 1 and j > 1
                    and s1[i - 1] == s2[j - 2]
                    and s1[i - 2] == s2[j - 1]):
                matrix[i][j] = min(matrix[i][j], matrix[i - 2][j - 2] + cost)

    return matrix[len1][len2]


class DynamicLegitimacyEngine:
    """
    Two-layer legitimacy scorer: Identity + Behavior.
    A trusted file doing bad things = LOLBin attack = NOT legitimate.
    """

    def __init__(self, os_type: str = "windows"):
        self.os_type = os_type.lower()

    def analyze_process(self, ioc: str, raw_evidence: dict,
                        hypothesis: dict = None) -> dict:
        """
        Score a process for legitimacy using identity + behavior.

        Returns:
            {
                "ioc": str,
                "score": int (0-100),
                "identity_score": int,
                "behavior_score": int,
                "verdict": "LEGITIMATE" | "UNCERTAIN" | "SUSPICIOUS",
                "reasons": [str],
            }
        """
        ioc_lower = ioc.lower()
        identity_reasons = []
        behavior_reasons = []

        # ==================================================================
        # LAYER 1: IDENTITY - Who are you?
        # ==================================================================
        identity_score = 50

        # 1a. Path check (+25 / -15)
        ps, pr = self._score_path(ioc_lower, raw_evidence)
        identity_score += ps
        identity_reasons.append(pr)

        # 1b. Parent check (+20 / -10)
        ps, pr = self._score_parent(ioc_lower, raw_evidence)
        identity_score += ps
        identity_reasons.append(pr)

        # 1c. Known process database (+10)
        ps, pr = self._score_known_process(ioc_lower)
        identity_score += ps
        identity_reasons.append(pr)

        # 1d. Name masquerading check - Damerau-Levenshtein (-30)
        ps, pr = self._check_masquerading(ioc_lower)
        identity_score += ps
        if ps < 0:
            identity_reasons.append(pr)

        # 1e. Process instance count check (-20)
        ps, pr = self._check_instance_count(ioc_lower, raw_evidence)
        identity_score += ps
        if ps < 0:
            identity_reasons.append(pr)

        # 1f. Double file extension check (-25)
        ps, pr = self._check_double_extension(ioc_lower)
        identity_score += ps
        if ps < 0:
            identity_reasons.append(pr)

        identity_score = max(0, min(100, identity_score))

        # ==================================================================
        # LAYER 2: BEHAVIOR - What are you doing?
        # ==================================================================
        behavior_score = 80  # Start high, deduct for bad behavior

        # 2a. Command line anomalies (-20 to -40)
        bs, br = self._score_cmdline(ioc_lower, raw_evidence)
        behavior_score += bs
        if bs < 0:
            behavior_reasons.append(br)

        # 2b. LOLBin detection (-40)
        bs, br = self._score_lolbin(ioc_lower, raw_evidence)
        behavior_score += bs
        if bs < 0:
            behavior_reasons.append(br)

        # 2c. Memory anomalies (-15 to -40)
        bs, br = self._score_memory(ioc_lower, raw_evidence)
        behavior_score += bs
        behavior_reasons.append(br)

        # 2d. Network destination check (+10 / -20)
        bs, br = self._score_network(ioc_lower, raw_evidence)
        behavior_score += bs
        behavior_reasons.append(br)

        behavior_score = max(0, min(100, behavior_score))

        # ==================================================================
        # FINAL SCORE: Identity (40%) + Behavior (60%)
        # Behavior weighs more because LOLBins have perfect identity
        # ==================================================================
        if identity_score >= 70:
            # Known good file - behavior matters even more
            final_score = int(identity_score * 0.35 + behavior_score * 0.65)
        else:
            # Unknown file - equal weight
            final_score = int(identity_score * 0.5 + behavior_score * 0.5)

        final_score = max(0, min(100, final_score))

        # Verdict
        all_reasons = [r for r in identity_reasons + behavior_reasons if r]

        if identity_score >= 70 and behavior_score < 50:
            verdict = "SUSPICIOUS"  # LOLBin: good file, bad behavior
            all_reasons.insert(0, "[WARN] LOLBin pattern: trusted file with suspicious behavior")
        elif final_score > 70:
            verdict = "LEGITIMATE"
        elif final_score < 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "UNCERTAIN"

        return {
            "ioc": ioc,
            "score": final_score,
            "identity_score": identity_score,
            "behavior_score": behavior_score,
            "verdict": verdict,
            "reasons": all_reasons,
        }

    # -- IDENTITY CHECKS --------------------------------------------------

    def _score_path(self, ioc_lower: str, raw_evidence: dict) -> tuple:
        """Check if binary runs from a legitimate directory."""
        path_plugins = ["vol3:pstree", "vol3:cmdline", "vol3:dlllist",
                        "vol3:svcscan", "vol3:svclist"]
        found_paths = []

        ioc_stem = ioc_lower.replace(".exe", "").replace(".e", "")
        for plugin in path_plugins:
            text = raw_evidence.get(plugin, "")
            if not text:
                continue
            for line in text.splitlines():
                if ioc_stem in line.lower():
                    found_paths.append(line.lower())

        if not found_paths:
            return (0, f"No path found for {ioc_lower}")

        for path_line in found_paths:
            if is_trusted_path(path_line, self.os_type):
                legit_paths = (LEGITIMATE_PATH_PATTERNS_WINDOWS
                               if self.os_type == "windows"
                               else LEGITIMATE_PATH_PATTERNS_LINUX)
                for legit in legit_paths:
                    if legit in path_line:
                        return (+25, f"Trusted path: {legit}")
                return (+25, "Trusted directory")

        return (-15, "Path not in trusted directories")

    def _score_parent(self, ioc_lower: str, raw_evidence: dict) -> tuple:
        """Check for expected parent-child relationship."""
        if self.os_type != "windows":
            return (0, "Parent check N/A for non-Windows")

        pstree = raw_evidence.get("vol3:pstree", "")
        if not pstree:
            return (0, "No pstree data")

        ioc_stem = ioc_lower.replace(".exe", "").replace(".e", "")
        proc_info = lookup_process(ioc_lower)

        lines = pstree.splitlines()
        for i, line in enumerate(lines):
            if ioc_stem in line.lower():
                parent_name = self._find_parent(lines, i)
                if parent_name:
                    if proc_info["known"] and proc_info["expected_parents"]:
                        if parent_name.lower() in [p.lower() for p in proc_info["expected_parents"]]:
                            return (+20, f"Expected parent: {parent_name}")
                        else:
                            return (-10, f"Wrong parent: {parent_name} "
                                         f"(expected {', '.join(proc_info['expected_parents'])})")
                    else:
                        parent_info = lookup_process(parent_name)
                        if parent_info["known"]:
                            return (+15, f"Parent is system process: {parent_name}")
                        return (0, f"Unknown parent: {parent_name}")

        return (0, f"Parent not determined")

    def _score_known_process(self, ioc_lower: str) -> tuple:
        """Bonus if in known-good process database."""
        proc_info = lookup_process(ioc_lower)
        if proc_info["known"]:
            return (+10, f"Known system process: {proc_info['process']}")
        return (0, "Not in known-good database")

    def _check_masquerading(self, ioc_lower: str) -> tuple:
        """Detect process name typosquatting using Damerau-Levenshtein distance.
        v4.0: Algorithmic - catches ANY typosquat within edit distance 1.
        e.g. svch0st.exe, csvhost.exe, winloqon.exe, lsaas.exe
        """
        # Skip if the process IS a known system process (exact match)
        if ioc_lower in SYSTEM_PROCESS_NAMES:
            return (0, "")

        # Check distance against every known system process
        for system_name in SYSTEM_PROCESS_NAMES:
            distance = _damerau_levenshtein(ioc_lower, system_name)
            if distance == 1:
                return (-30, f"Name masquerading detected: '{ioc_lower}' is 1 edit "
                             f"away from '{system_name}' (T1036.005)")
        return (0, "")

    def _check_instance_count(self, ioc_lower: str, raw_evidence: dict) -> tuple:
        """Check if process has more instances than expected.
        v4.0: lsass.exe should only have 1 instance.
        Multiple instances may indicate process injection (T1036.005).
        """
        if ioc_lower not in EXPECTED_INSTANCE_COUNTS:
            return (0, "")

        expected = EXPECTED_INSTANCE_COUNTS[ioc_lower]
        pstree = raw_evidence.get("vol3:pslist", "") or raw_evidence.get("vol3:pstree", "")
        if not pstree:
            return (0, "")

        ioc_stem = ioc_lower.replace(".exe", "")
        count = 0
        for line in pstree.splitlines():
            # Match the process name in pstree/pslist output
            if re.search(rf'\b{re.escape(ioc_stem)}(\.exe)?\b', line, re.I):
                count += 1

        if count > expected:
            return (-20, f"Instance count anomaly: found {count} instances of "
                         f"{ioc_lower}, expected {expected} (T1036.005)")
        return (0, "")

    def _check_double_extension(self, ioc_lower: str) -> tuple:
        """Detect double file extensions used for social engineering.
        v4.0: catches invoice.doc.exe, update.pdf.exe.
        ATT&CK T1036.007 - Masquerading: Double File Extension.
        """
        dot_count = ioc_lower.count('.')
        if dot_count > 1:
            return (-25, f"Double file extension detected: '{ioc_lower}' - "
                         f"likely masquerading (T1036.007)")
        return (0, "")

    # -- BEHAVIOR CHECKS --------------------------------------------------

    def _score_cmdline(self, ioc_lower: str, raw_evidence: dict) -> tuple:
        """Check command line for suspicious patterns."""
        cmdline_text = raw_evidence.get("vol3:cmdline", "")
        if not cmdline_text:
            return (0, "No cmdline data")

        ioc_stem = ioc_lower.replace(".exe", "").replace(".e", "")
        process_cmdlines = []

        for line in cmdline_text.splitlines():
            if ioc_stem in line.lower():
                process_cmdlines.append(line)

        if not process_cmdlines:
            return (0, "No command line found")

        combined = " ".join(process_cmdlines).lower()
        hits = []
        for pattern in SUSPICIOUS_CMDLINE_PATTERNS:
            if re.search(pattern, combined, re.I):
                hits.append(pattern)

        if len(hits) >= 3:
            return (-40, f"Multiple suspicious cmdline patterns: {len(hits)} hits")
        elif len(hits) >= 1:
            return (-20, f"Suspicious cmdline pattern detected")
        return (0, "Command line looks normal")

    def _score_lolbin(self, ioc_lower: str, raw_evidence: dict) -> tuple:
        """Detect Living-off-the-Land Binary abuse."""
        ioc_stem = ioc_lower.replace(".exe", "").replace(".e", "")

        # Check if this process IS a known LOLBin
        matching_lolbin = None
        for lolbin_name in LOLBIN_PATTERNS:
            if lolbin_name in ioc_stem:
                matching_lolbin = lolbin_name
                break

        if not matching_lolbin:
            return (0, "Not a LOLBin")

        # It's a LOLBin - check if it's being used maliciously
        cmdline_text = raw_evidence.get("vol3:cmdline", "")
        pstree_text = raw_evidence.get("vol3:pstree", "")
        combined = (cmdline_text + "\n" + pstree_text).lower()

        patterns = LOLBIN_PATTERNS[matching_lolbin]
        hits = []
        for pattern in patterns:
            # Only match lines that contain our process
            for line in combined.splitlines():
                if ioc_stem in line.lower():
                    if re.search(pattern, line, re.I):
                        hits.append(pattern)
                        break

        if hits:
            return (-40, f"LOLBin abuse: {matching_lolbin} with {len(hits)} "
                         f"malicious pattern(s)")
        return (0, f"{matching_lolbin} present but no malicious patterns")

    def _score_memory(self, ioc_lower: str, raw_evidence: dict) -> tuple:
        """Check for memory injection/hollowing."""
        malfind = raw_evidence.get("vol3:malfind", "")
        hollowed = raw_evidence.get("vol3:hollowprocesses", "")
        ioc_stem = ioc_lower.replace(".exe", "").replace(".e", "")

        anomaly_count = 0

        if malfind:
            in_section = False
            for line in malfind.splitlines():
                if ioc_stem in line.lower():
                    in_section = True
                elif in_section and line.strip() == "":
                    in_section = False
                if in_section:
                    for pattern in MEMORY_ANOMALY_PATTERNS:
                        if pattern.lower() in line.lower():
                            anomaly_count += 1

        if hollowed and ioc_stem in hollowed.lower():
            anomaly_count += 3

        if anomaly_count == 0:
            return (+5, "Memory clean - no injection detected")
        elif anomaly_count <= 2:
            return (-15, f"{anomaly_count} memory anomalies")
        else:
            return (-40, f"{anomaly_count} memory anomalies (injection/hollowing)")

    def _score_network(self, ioc_lower: str, raw_evidence: dict) -> tuple:
        """Check if network destinations match expectations."""
        net_plugins = ["vol3:netscan", "vol3:netstat"]
        ioc_stem = ioc_lower.replace(".exe", "").replace(".e", "")
        connections = []

        for plugin in net_plugins:
            text = raw_evidence.get(plugin, "")
            if not text:
                continue
            for line in text.splitlines():
                if ioc_stem in line.lower():
                    ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    for ip in ips:
                        if ip not in ("0.0.0.0", "127.0.0.1", "*"):
                            connections.append(ip)

        if not connections:
            return (0, "No network connections")

        unknown_ips = []
        vendors_seen = set()
        for ip in set(connections):
            result = lookup_ip(ip)
            if result["trusted"]:
                vendors_seen.add(result["vendor"])
            else:
                unknown_ips.append(ip)

        if not unknown_ips:
            vendor_str = ", ".join(sorted(vendors_seen)[:3])
            return (+10, f"All connections trusted ({vendor_str})")
        elif len(unknown_ips) == 1 and len(connections) > 2:
            return (+5, f"Mostly trusted, 1 unknown: {unknown_ips[0]}")
        else:
            return (-20, f"{len(unknown_ips)} unknown IPs: {', '.join(unknown_ips[:3])}")

    # -- HELPERS -----------------------------------------------------------

    def _find_parent(self, lines: list, child_idx: int) -> Optional[str]:
        """Find parent process from pstree indentation."""
        child_line = lines[child_idx]
        child_indent = len(child_line) - len(child_line.lstrip("* "))

        for i in range(child_idx - 1, -1, -1):
            line = lines[i]
            indent = len(line) - len(line.lstrip("* "))
            if indent < child_indent:
                m = re.search(r'(\S+\.exe\S*)', line, re.I)
                if m:
                    return m.group(1)
                parts = line.strip().strip("* ").split()
                for part in parts:
                    if ".exe" in part.lower():
                        return part
                break
        return None


# ==============================================================================
# PUBLIC API
# ==============================================================================

def filter_legitimate_hypotheses(hypotheses: list, raw_evidence: dict,
                                  os_type: str = "windows",
                                  threshold: int = 70) -> tuple:
    """
    Filter hypotheses through the two-layer legitimacy engine.

    Returns:
        (kept, filtered) - kept stays for investigation,
                           filtered marked LEGITIMATE/CLEARED.
    """
    engine = DynamicLegitimacyEngine(os_type)
    kept = []
    filtered = []

    for h in hypotheses:
        ioc = h.get("ioc", "")

        # -- Check IP-based IOCs against trusted vendor ranges ---------
        ip_match = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ioc)
        if ip_match:
            ip_str = ip_match.group(1)
            ip_result = lookup_ip(ip_str)
            if ip_result["trusted"] and not ip_result["is_private"]:
                # Known vendor IP - auto-clear
                h["legitimacy_score"] = 90
                h["legitimacy_reasons"] = [f"IP {ip_str} belongs to {ip_result['vendor']}"]
                h["confidence"] = "CLEARED"
                h["claim"] = (f"{h['claim']} [AUTO-CLEARED: {ip_str} is "
                              f"{ip_result['vendor']} infrastructure]")
                filtered.append(h)
                print(f"    [LEGIT] {ioc} -> {ip_result['vendor']} IP -> CLEARED",
                      flush=True)
                continue
            elif ip_result["is_private"]:
                # Private/internal IP - keep but note it's internal
                h["legitimacy_score"] = 60
                kept.append(h)
                print(f"    [KEEP]  {ioc} -> internal/private IP", flush=True)
                continue
            else:
                # Unknown IP - keep for investigation
                kept.append(h)
                continue

        # Skip path-based and PID-based IOCs (not processes)
        if ioc.startswith("/") and not ioc.endswith(".exe"):
            kept.append(h)
            continue
        if ioc.isdigit():
            kept.append(h)
            continue

        result = engine.analyze_process(ioc, raw_evidence, h)

        if result["verdict"] == "LEGITIMATE" and result["score"] >= threshold:
            h["legitimacy_score"] = result["score"]
            h["identity_score"] = result["identity_score"]
            h["behavior_score"] = result["behavior_score"]
            h["legitimacy_reasons"] = result["reasons"]
            h["confidence"] = "CLEARED"
            h["claim"] = (f"{h['claim']} [AUTO-CLEARED: identity={result['identity_score']}, "
                          f"behavior={result['behavior_score']}, "
                          f"final={result['score']}/100]")
            filtered.append(h)
            print(f"    [LEGIT] {ioc} -> identity={result['identity_score']} "
                  f"behavior={result['behavior_score']} "
                  f"final={result['score']} -> CLEARED", flush=True)

        elif result["verdict"] == "SUSPICIOUS" and result["identity_score"] >= 70:
            # LOLBin detected - trusted file doing bad things
            h["legitimacy_score"] = result["score"]
            h["legitimacy_reasons"] = result["reasons"]
            kept.append(h)
            print(f"    [LOLBIN] {ioc} -> identity={result['identity_score']} "
                  f"behavior={result['behavior_score']} "
                  f"-> KEEPING (trusted file, suspicious behavior!)", flush=True)
        else:
            h["legitimacy_score"] = result["score"]
            kept.append(h)
            if result["score"] > 40:
                print(f"    [KEEP]  {ioc} -> score={result['score']} "
                      f"-> keeping for investigation", flush=True)

    return kept, filtered
