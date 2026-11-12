"""
PHANTOM DFIR - Memory triage helpers.

These helpers sit beside Volatility. They do not replace plugin output; they
generate lightweight leads from raw memory so the investigator and
self-correction loop can ask better questions.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Iterable

from config import STRINGS, TIMEOUT_STRINGS_TRIAGE, TIMEOUT_YARA_MEMORY, YARA


TRIAGE_PATTERNS = [
    (
        "credential_theft",
        re.compile(
            r"\b(mimikatz|sekurlsa|logonpasswords|lsass\.dmp|procdump|comsvcs\.dll|wdigest)\b",
            re.I,
        ),
    ),
    (
        "c2_framework",
        re.compile(
            r"\b(meterpreter|metasploit|cobalt\s*strike|beacon|reflective\s+loader|empire|sliver|havoc)\b",
            re.I,
        ),
    ),
    (
        "powershell_stager",
        re.compile(
            r"\b(powershell|pwsh)\b.*\b(-enc|-encodedcommand|frombase64string|downloadstring|invoke-expression|\biex\b)\b",
            re.I,
        ),
    ),
    (
        "suspicious_shell",
        re.compile(
            r"\b(cmd\.exe\s+/c|rundll32\.exe|regsvr32\.exe|mshta\.exe|wscript\.exe|cscript\.exe)\b",
            re.I,
        ),
    ),
    (
        "linux_reverse_shell",
        re.compile(r"(/dev/tcp|/dev/udp|mkfifo|nc\s+-e|bash\s+-i)", re.I),
    ),
    (
        "network_indicator",
        re.compile(r"https?://[^\s\"'<>]{4,}|(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}", re.I),
    ),
]


BENIGN_URL_MARKERS = (
    "microsoft.com/pki",
    "crl.microsoft.com",
    "www.w3.org",
    "schemas.microsoft.com",
    "windowsupdate.com",
    "ocsp.",
)

SUSPICIOUS_URL_MARKERS = (
    "pastebin",
    "raw.githubusercontent",
    "githubusercontent",
    "bit.ly",
    "tinyurl",
    "hiderefer",
    "sqlmap",
    "metasploit",
    "exploit",
    "payload",
    "shell",
    "cmd=",
    "powershell",
)


YARA_RULES = r"""
rule PHANTOM_Memory_Mimikatz {
    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa::logonpasswords" nocase
        $c = "kerberos::golden" nocase
    condition:
        any of them
}

rule PHANTOM_Memory_C2_Framework {
    strings:
        $a = "meterpreter" nocase
        $b = "cobalt strike" nocase
        $c = "reflective loader" nocase
        $d = "metasploit" nocase
    condition:
        any of them
}

rule PHANTOM_Memory_PowerShell_Stager {
    strings:
        $a = "FromBase64String" nocase
        $b = "-EncodedCommand" nocase
        $c = "DownloadString" nocase
        $d = "Invoke-Expression" nocase
    condition:
        any of them
}

rule PHANTOM_Memory_Linux_ReverseShell {
    strings:
        $a = "/dev/tcp" nocase
        $b = "bash -i" nocase
        $c = "mkfifo" nocase
        $d = "nc -e" nocase
    condition:
        any of them
}
"""


def _available(cmd: str | None) -> bool:
    if not cmd:
        return False
    return bool(shutil.which(cmd) or os.path.exists(cmd))


def _clip_line(line: str, max_len: int = 260) -> str:
    line = line.replace("\x00", "").strip()
    if len(line) <= max_len:
        return line
    return line[: max_len - 3] + "..."


def _keep_network_indicator(line: str) -> bool:
    ll = line.lower()
    if any(marker in ll for marker in BENIGN_URL_MARKERS):
        return False
    if any(marker in ll for marker in SUSPICIOUS_URL_MARKERS):
        return True
    if re.search(r"(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}", line):
        return True
    return False


def _keep_shell_indicator(line: str) -> bool:
    """Keep LOLBin hits only when the surrounding string looks operationally suspicious."""
    ll = line.lower()
    if "cmd.exe /c" in ll:
        return any(x in ll for x in ("powershell", "bitsadmin", "certutil", "http", "appdata", "temp", "\\users\\"))
    if "mshta.exe" in ll:
        return any(x in ll for x in ("http", "javascript:", "vbscript:", ".hta", "appdata", "temp", "\\users\\"))
    if "regsvr32.exe" in ll:
        return any(x in ll for x in ("scrobj.dll", "/i:", "http", ".sct", "appdata", "temp", "\\users\\"))
    if "rundll32.exe" in ll:
        return any(x in ll for x in ("javascript:", "mshtml", "http", ".dll,", ",#", "appdata", "temp", "\\users\\"))
    if "wscript.exe" in ll or "cscript.exe" in ll:
        return any(x in ll for x in (".vbs", ".js", "http", "appdata", "temp", "\\users\\"))
    return False


def run_strings_ioc(filepath: str, max_hits: int = 200, timeout: int | None = None) -> str:
    """Stream strings output and keep only high-value IOC-like matches."""
    timeout = timeout or TIMEOUT_STRINGS_TRIAGE
    if not _available(STRINGS):
        return "[SKIPPED] strings not found"

    hits: list[str] = []
    seen: set[str] = set()
    started = time.time()

    try:
        proc = subprocess.Popen(
            [STRINGS, "-a", "-n", "6", filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
        )
    except Exception as exc:
        return f"[ERROR] strings launch failed: {exc}"

    try:
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            if time.time() - started > timeout:
                proc.kill()
                hits.append(f"[TIMEOUT] strings IOC triage stopped after {timeout}s")
                break
            line = _clip_line(raw_line)
            if not line:
                continue
            for category, pattern in TRIAGE_PATTERNS:
                if pattern.search(line):
                    if category == "network_indicator" and not _keep_network_indicator(line):
                        continue
                    if category == "suspicious_shell" and not _keep_shell_indicator(line):
                        continue
                    key = (category, line.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    hits.append(f"[{category}] {line}")
                    break
            if len(hits) >= max_hits:
                hits.append(f"[TRUNCATED] first {max_hits} memory string IOC hits retained")
                proc.kill()
                break
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception as exc:
        try:
            proc.kill()
        except Exception:
            pass
        return f"[ERROR] strings IOC triage failed: {exc}"

    if not hits:
        return "[NO IOC STRINGS] No high-value memory string indicators matched"
    return "\n".join(hits)


def run_yara_memory_scan(filepath: str, timeout: int | None = None) -> str:
    """Run embedded lightweight YARA rules when yara is installed."""
    timeout = timeout or TIMEOUT_YARA_MEMORY
    if not _available(YARA):
        return "[SKIPPED] yara not installed"

    rule_path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".yar", delete=False, encoding="utf-8") as fh:
            fh.write(YARA_RULES)
            rule_path = fh.name

        proc = subprocess.run(
            [YARA, "-w", rule_path, filepath],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        output = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        if proc.returncode not in (0, 1) and stderr:
            return f"[ERROR] yara failed rc={proc.returncode}: {_clip_line(stderr, 500)}"
        if not output:
            return "[NO YARA HITS] Embedded PHANTOM memory rules did not match"
        lines = [_clip_line(line) for line in output.splitlines() if line.strip()]
        if len(lines) > 200:
            lines = lines[:200] + ["[TRUNCATED] first 200 YARA hits retained"]
        return "\n".join(lines)
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] yara memory scan stopped after {timeout}s"
    except Exception as exc:
        return f"[ERROR] yara scan failed: {exc}"
    finally:
        if rule_path:
            try:
                os.unlink(rule_path)
            except OSError:
                pass


def _interesting_lines(text: str, keywords: Iterable[str], limit: int = 40) -> list[str]:
    found: list[str] = []
    lowered_keywords = [k.lower() for k in keywords]
    for line in (text or "").splitlines():
        ll = line.lower()
        if any(k in ll for k in lowered_keywords):
            clipped = _clip_line(line, 220)
            if clipped and clipped not in found:
                found.append(clipped)
        if len(found) >= limit:
            break
    return found


def build_memory_timeline_hints(raw_evidence: dict, os_type: str) -> str:
    """Create a compact analyst timeline from command, network, service, and IOC evidence."""
    sections: list[str] = []
    section_specs = [
        (
            "Process and command activity",
            ["vol3:cmdline", "vol2:cmdscan", "vol2:consoles", "vol3:linux_bash", "vol3:linux_psaux"],
            ["powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "putty", "wget", "curl", "/dev/tcp"],
        ),
        (
            "Network activity",
            ["vol3:netscan", "vol3:netstat", "vol2:netscan", "vol3:linux_sockstat", "vol3:linux_sockscan"],
            ["established", "listen", "tcp", "udp", ":4444", ":8080", ":1337", ":22"],
        ),
        (
            "Persistence and services",
            ["vol3:svcscan", "vol3:svclist", "vol2:svcscan", "vol3:linux_lsmod", "vol3:linux_check_syscall"],
            [".exe", "service", "kernel", "module", "hook", "sys_call_table"],
        ),
        (
            "Memory anomaly evidence",
            ["vol3:malfind", "vol3:linux_malfind", "memory:strings_ioc", "memory:yara_scan"],
            ["[", "vad", "mimikatz", "meterpreter", "encoded", "reverse", "yara", "phantom"],
        ),
    ]

    for title, keys, keywords in section_specs:
        lines: list[str] = []
        for key in keys:
            text = raw_evidence.get(key, "")
            for line in _interesting_lines(text, keywords, limit=15):
                lines.append(f"{key}: {line}")
                if len(lines) >= 30:
                    break
            if len(lines) >= 30:
                break
        if lines:
            sections.append(f"## {title}\n" + "\n".join(lines[:30]))

    if not sections:
        return f"[NO TIMELINE HINTS] No high-value {os_type} memory timeline hints were extracted"
    return "\n\n".join(sections)


def build_triage_summary(raw_evidence: dict) -> str:
    """Summarise memory triage signals for reporting and self-correction."""
    strings_text = raw_evidence.get("memory:strings_ioc", "")
    yara_text = raw_evidence.get("memory:yara_scan", "")
    malfind_text = "\n".join(
        raw_evidence.get(k, "")
        for k in ("vol3:malfind", "vol3:linux_malfind")
        if raw_evidence.get(k)
    )

    categories = {}
    for line in strings_text.splitlines():
        m = re.match(r"\[([a-z_]+)\]", line)
        if m:
            categories[m.group(1)] = categories.get(m.group(1), 0) + 1

    yara_hits = [
        line for line in yara_text.splitlines()
        if line.strip() and not line.startswith("[")
    ]
    malfind_signal = bool(malfind_text and "[ERROR]" not in malfind_text and "[TIMEOUT]" not in malfind_text)

    lines = [
        "Memory triage summary:",
        f"- strings_ioc_categories: {categories or 'none'}",
        f"- yara_hits: {len(yara_hits)}",
        f"- malfind_output_present: {malfind_signal}",
    ]
    if yara_hits:
        lines.append("- yara_examples: " + "; ".join(yara_hits[:5]))
    return "\n".join(lines)
