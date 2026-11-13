# PHANTOM DFIR: version history

What changed between engine versions, as recorded by the author at the time.

## v2.1 Improvements (Latest)

| Area | v2.0 | v2.1 |
|------|------|------|
| **False positives** | Ruby flagged as Metasploit C2 | ✅ CLEARED — path-aware benign detection |
| **Confidence levels** | CRITICAL/MEDIUM/LOW/REFUTED | + **CLEARED** (investigated, benign) |
| **Report quality** | IOC list | **Attack narrative** — coherent breach story |
| **Timeline** | All events incl. system noise | **Attacker-focused** — VMware/Defender filtered |
| **Evidence quotes** | IOC name only (`ruby.exe`) | Rich forensic lines with PIDs, paths, timestamps |
| **MITRE accuracy** | ruby.exe → false T1059 | Ruby removed from IOC map, zero false positives |
| **Timeline events** | Raw Volatility output | **Human-readable** (`Process 'ruby.exe' (PID 3204) created`) |

## v2.0 Improvements

| Area | v1.0 | v2.0 |
|------|------|------|
| **Speed** | 8 parallel workers → 306s collection | 16 workers → ~150-180s collection |
| **MITRE accuracy** | 5/13 false positives (tool names as IOCs) | IOC-only mapping, zero false positives |
| **IOC detection** | Hardcoded IPs/ports | Dynamic extraction from evidence |
| **SSH analysis** | None | Extracts @hostname targets from cmdlines |
| **Remediation** | Hardcoded to test case | Dynamic from attack phases + MITRE |
| **Timeline** | Hardcoded keywords | Dynamic from discovered IOCs |
| **Vol2 profile** | Hardcoded Win10x64_16299 | Auto-detect via kdbgscan |
| **Linux support** | Collection only | Collection + Evidence verification |
| **Plugin timeouts** | 300s slow plugins | 180s (faster failure) |
