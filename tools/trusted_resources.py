"""
PHANTOM DFIR — Trusted Resources Database v1.0
Comprehensive database of trusted IP ranges, processes, paths, and ports.
Used by the DynamicLegitimacyEngine for false positive prevention.

Sources:
  - Microsoft: https://www.microsoft.com/en-us/download/details.aspx?id=56519
  - Google:    https://www.gstatic.com/ipranges/goog.json
  - AWS:       https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html
  - Cloudflare: https://www.cloudflare.com/ips/
  - IANA Ports: https://www.iana.org/assignments/service-names-port-numbers/
"""
import ipaddress
import re
from functools import lru_cache


# ══════════════════════════════════════════════════════════════════════════════
# 1. TRUSTED IP RANGES (CIDR notation)
# ══════════════════════════════════════════════════════════════════════════════

TRUSTED_IP_RANGES = {
    "Microsoft": [
        "13.64.0.0/11", "13.104.0.0/14", "20.33.0.0/16", "20.34.0.0/15",
        "20.36.0.0/14", "20.40.0.0/13", "20.44.0.0/14", "20.48.0.0/12",
        "20.128.0.0/16", "20.150.0.0/15", "20.190.128.0/18",
        "40.64.0.0/10", "40.112.0.0/13", "51.104.0.0/15", "51.124.0.0/16",
        "52.96.0.0/12", "52.112.0.0/14", "52.120.0.0/14", "52.224.0.0/11",
        "104.40.0.0/13", "104.208.0.0/13", "131.253.0.0/16",
        "157.55.0.0/16", "157.56.0.0/14", "168.61.0.0/16", "168.62.0.0/15",
    ],
    "Google": [
        "8.8.4.0/24", "8.8.8.0/24", "8.34.208.0/20", "8.35.192.0/20",
        "34.64.0.0/10", "34.128.0.0/10", "35.184.0.0/13", "35.192.0.0/14",
        "35.196.0.0/15", "35.198.0.0/16", "35.199.0.0/17", "35.200.0.0/13",
        "35.208.0.0/12", "64.233.160.0/19", "66.102.0.0/20", "66.249.64.0/19",
        "70.32.128.0/19", "72.14.192.0/18", "74.125.0.0/16",
        "108.177.0.0/17", "142.250.0.0/15", "172.217.0.0/16",
        "172.253.0.0/16", "173.194.0.0/16", "209.85.128.0/17",
        "216.58.192.0/19", "216.239.32.0/19",
    ],
    "Amazon": [
        "3.0.0.0/9", "13.32.0.0/15", "13.224.0.0/14", "13.248.0.0/14",
        "15.177.0.0/18", "15.230.0.0/15", "18.0.0.0/11", "18.128.0.0/9",
        "34.192.0.0/10", "35.152.0.0/13", "35.160.0.0/13",
        "44.192.0.0/10", "52.0.0.0/11", "52.32.0.0/11", "52.64.0.0/12",
        "52.92.0.0/14", "52.94.0.0/18", "54.0.0.0/9",
        "63.32.0.0/14", "99.77.0.0/18", "99.150.0.0/21",
    ],
    "Apple": [
        "17.0.0.0/8",
        "65.199.0.0/18", "96.0.0.0/13", "139.178.0.0/16",
        "144.178.0.0/16", "204.109.16.0/20", "204.109.32.0/20",
    ],
    "Cloudflare": [
        "104.16.0.0/13", "104.24.0.0/14", "131.0.72.0/22",
        "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
        "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
        "197.234.240.0/22", "198.41.128.0/17",
    ],
    "Akamai": [
        "23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11",
        "72.246.0.0/15", "96.6.0.0/15", "96.16.0.0/15", "104.64.0.0/10",
        "184.24.0.0/13", "184.50.0.0/15", "184.84.0.0/14",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "104.156.80.0/20", "146.75.0.0/16", "151.101.0.0/16",
        "157.52.64.0/18", "167.82.0.0/17", "185.31.16.0/22",
    ],
    "GitHub": [
        "140.82.112.0/20", "185.199.108.0/22",
        "192.30.252.0/22", "20.200.0.0/16",
    ],
    "Adobe": [
        "130.248.0.0/16", "153.32.0.0/16", "185.34.188.0/22",
        "192.147.117.0/24", "192.243.224.0/19",
    ],
    "VMware": [
        "65.52.0.0/14", "185.102.136.0/22",
    ],
    "Intel": [
        "192.55.40.0/21", "192.55.48.0/20", "192.55.64.0/18",
    ],
    "Cisco": [
        "64.100.0.0/14", "72.163.0.0/16", "173.36.0.0/14",
        "173.39.0.0/17",
    ],
}

# Private/internal ranges — always legitimate
PRIVATE_RANGES = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "fe80::/10", "::1/128",
]


# ══════════════════════════════════════════════════════════════════════════════
# 2. TRUSTED PROCESS DEFINITIONS (path + expected parent)
# ══════════════════════════════════════════════════════════════════════════════

TRUSTED_PROCESSES = {
    # ── Windows Core ──────────────────────────────────────────────────────
    "system":            {"paths": [],                                   "parents": []},
    "registry":          {"paths": [],                                   "parents": ["system"]},
    "smss.exe":          {"paths": [r"system32"],                        "parents": ["system"]},
    "csrss.exe":         {"paths": [r"system32"],                        "parents": ["smss.exe"]},
    "wininit.exe":       {"paths": [r"system32"],                        "parents": ["smss.exe"]},
    "winlogon.exe":      {"paths": [r"system32"],                        "parents": ["smss.exe"]},
    "services.exe":      {"paths": [r"system32"],                        "parents": ["wininit.exe"]},
    "lsass.exe":         {"paths": [r"system32"],                        "parents": ["wininit.exe"]},
    "lsaiso.exe":        {"paths": [r"system32"],                        "parents": ["wininit.exe"]},
    "svchost.exe":       {"paths": [r"system32"],                        "parents": ["services.exe"]},
    "dwm.exe":           {"paths": [r"system32"],                        "parents": ["winlogon.exe"]},
    "logonui.exe":       {"paths": [r"system32"],                        "parents": ["winlogon.exe"]},
    "fontdrvhost.exe":   {"paths": [r"system32"],                        "parents": ["wininit.exe", "winlogon.exe"]},
    "explorer.exe":      {"paths": [r"windows"],                         "parents": ["userinit.exe", "winlogon.exe"]},
    "conhost.exe":       {"paths": [r"system32"],                        "parents": ["csrss.exe"]},
    "ctfmon.exe":        {"paths": [r"system32"],                        "parents": ["svchost.exe"]},
    "sihost.exe":        {"paths": [r"system32"],                        "parents": ["svchost.exe"]},
    "taskhostw.exe":     {"paths": [r"system32"],                        "parents": ["svchost.exe"]},
    "runtimebroker.exe": {"paths": [r"system32"],                        "parents": ["svchost.exe"]},
    "dllhost.exe":       {"paths": [r"system32"],                        "parents": ["svchost.exe"]},
    "wmiprvse.exe":      {"paths": [r"system32", r"syswow64"],           "parents": ["svchost.exe"]},
    "searchui.exe":      {"paths": [r"systemapps"],                      "parents": ["svchost.exe"]},
    "spoolsv.exe":       {"paths": [r"system32"],                        "parents": ["services.exe"]},
    "msdtc.exe":         {"paths": [r"system32"],                        "parents": ["services.exe"]},
    "wudfhost.exe":      {"paths": [r"system32"],                        "parents": ["svchost.exe"]},
    "searchindexer.exe": {"paths": [r"system32"],                        "parents": ["services.exe"]},

    # ── Windows Defender / Security ───────────────────────────────────────
    "msmpeng.exe":       {"paths": [r"windows defender", r"programdata"],  "parents": ["services.exe"]},
    "nissrv.exe":        {"paths": [r"windows defender"],                  "parents": ["services.exe"]},
    "mpcmdrun.exe":      {"paths": [r"windows defender"],                  "parents": ["svchost.exe"]},
    "securityhealthservice.exe": {"paths": [r"system32"],                  "parents": ["services.exe"]},

    # ── Windows UWP / Store Apps ──────────────────────────────────────────
    "applicationframehost.exe": {"paths": [r"system32"],               "parents": ["svchost.exe"]},
    "shellexperiencehost.exe":  {"paths": [r"systemapps"],             "parents": ["svchost.exe"]},
    "startmenuexperiencehost.exe": {"paths": [r"systemapps"],          "parents": ["svchost.exe"]},

    # ── Telemetry / Diagnostics ───────────────────────────────────────────
    "compattelrunner.exe": {"paths": [r"system32"],                    "parents": ["svchost.exe"]},
    "devicecensus.exe":    {"paths": [r"system32"],                    "parents": ["svchost.exe"]},

    # ── Graphics Drivers ──────────────────────────────────────────────────
    "nvcontainer.exe":  {"paths": [r"nvidia"],       "parents": ["services.exe"]},
    "igfxem.exe":       {"paths": [r"intel"],        "parents": ["explorer.exe"]},

    # ── Audio ─────────────────────────────────────────────────────────────
    "audiodg.exe":      {"paths": [r"system32"],     "parents": ["svchost.exe"]},

    # ── Printer ───────────────────────────────────────────────────────────
    "printisolationhost.exe": {"paths": [r"system32"], "parents": ["spoolsv.exe"]},
    "splwow64.exe":          {"paths": [r"system32"],  "parents": ["spoolsv.exe"]},

    # ── Linux Core ────────────────────────────────────────────────────────
    "systemd":          {"paths": ["/usr/lib/systemd", "/lib/systemd"], "parents": ["init"]},
    "sshd":             {"paths": ["/usr/sbin", "/usr/bin"],            "parents": ["systemd"]},
    "cron":             {"paths": ["/usr/sbin", "/usr/bin"],            "parents": ["systemd"]},
    "rsyslogd":         {"paths": ["/usr/sbin"],                       "parents": ["systemd"]},
    "dockerd":          {"paths": ["/usr/bin"],                        "parents": ["systemd"]},
    "containerd":       {"paths": ["/usr/bin"],                        "parents": ["systemd"]},
}


# ══════════════════════════════════════════════════════════════════════════════
# 3. LEGITIMATE PATH PATTERNS (directories that indicate trusted software)
# ══════════════════════════════════════════════════════════════════════════════

LEGITIMATE_PATH_PATTERNS_WINDOWS = [
    r"c:\\windows\\system32",
    r"c:\\windows\\syswow64",
    r"c:\\windows\\systemapps",
    r"c:\\windows\\winsxs",
    r"c:\\windows\\servicing",
    r"c:\\windows\\microsoft\.net",
    r"c:\\program files\\",
    r"c:\\program files \(x86\)\\",
    r"windowsapps",
    # Vendor-specific
    r"puppet labs", r"chef", r"opscode",
    r"vmware", r"microsoft", r"apple",
    r"google", r"mozilla", r"adobe",
    r"intel", r"nvidia", r"amd",
    r"sentinelone", r"crowdstrike", r"carbon black",
    r"symantec", r"mcafee", r"trend micro",
    r"kaspersky", r"bitdefender", r"eset",
    r"malwarebytes", r"sophos", r"avast",
]

LEGITIMATE_PATH_PATTERNS_LINUX = [
    "/usr/bin/", "/usr/sbin/", "/usr/lib/",
    "/usr/local/bin/", "/usr/local/sbin/",
    "/bin/", "/sbin/", "/lib/",
    "/opt/", "/snap/",
]


# ══════════════════════════════════════════════════════════════════════════════
# 4. TRUSTED PORTS
# ══════════════════════════════════════════════════════════════════════════════

TRUSTED_PORTS = {
    "web":       {80, 443, 8080, 8443},
    "email":     {25, 587, 465, 993, 995, 110, 143},
    "dns":       {53},
    "ntp":       {123},
    "kerberos":  {88},
    "ldap":      {389, 636},
    "smb":       {139, 445},
    "rdp":       {3389},
    "ssh":       {22},
    "winrm":     {5985, 5986},
    "ad":        {3268, 3269},
    "apple":     {5223, 2195, 2196},
    "google":    {5228, 5229, 5230},
    "microsoft": {3544},
}

# Flatten for quick lookup
ALL_TRUSTED_PORTS = set()
for ports in TRUSTED_PORTS.values():
    ALL_TRUSTED_PORTS.update(ports)


# ══════════════════════════════════════════════════════════════════════════════
# 5. LOOKUP FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

# Pre-compile IP networks for fast lookup
_compiled_networks = {}


def _get_compiled_networks():
    """Lazily compile CIDR strings into ipaddress.IPv4Network objects."""
    global _compiled_networks
    if _compiled_networks:
        return _compiled_networks

    for vendor, cidrs in TRUSTED_IP_RANGES.items():
        nets = []
        for cidr in cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
        _compiled_networks[vendor] = nets

    # Add private ranges
    _compiled_networks["Private"] = []
    for cidr in PRIVATE_RANGES:
        try:
            _compiled_networks["Private"].append(
                ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass

    return _compiled_networks


def lookup_ip(ip_str: str) -> dict:
    """
    Check if an IP belongs to a known trusted vendor.

    Returns:
        {"trusted": bool, "vendor": str or None, "is_private": bool}
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"trusted": False, "vendor": None, "is_private": False}

    networks = _get_compiled_networks()

    # Check private first
    for net in networks.get("Private", []):
        if addr in net:
            return {"trusted": True, "vendor": "Private/Internal", "is_private": True}

    # Check vendors
    for vendor, nets in networks.items():
        if vendor == "Private":
            continue
        for net in nets:
            if addr in net:
                return {"trusted": True, "vendor": vendor, "is_private": False}

    return {"trusted": False, "vendor": None, "is_private": False}


def lookup_process(process_name: str) -> dict:
    """
    Check if a process name has a known trusted definition.

    Returns:
        {"known": bool, "expected_paths": list, "expected_parents": list}
    """
    name_lower = process_name.lower().strip()
    # Handle truncated names (Volatility truncates to 14 chars)
    for proc, info in TRUSTED_PROCESSES.items():
        if name_lower == proc.lower() or name_lower.startswith(proc.lower()[:14]):
            return {
                "known": True,
                "process": proc,
                "expected_paths": info["paths"],
                "expected_parents": info["parents"],
            }
    return {"known": False, "process": None, "expected_paths": [], "expected_parents": []}


def is_trusted_path(path: str, os_type: str = "windows") -> bool:
    """Check if a file path is in a known-legitimate directory."""
    path_lower = path.lower()
    patterns = (LEGITIMATE_PATH_PATTERNS_WINDOWS if os_type == "windows"
                else LEGITIMATE_PATH_PATTERNS_LINUX)
    return any(p in path_lower for p in patterns)


def is_trusted_port(port: int) -> bool:
    """Check if a port is a known legitimate service port."""
    return port in ALL_TRUSTED_PORTS
