# MITRE ATT&CK Technique Mapping

## Mapping Rules
1. ONLY map techniques with CONFIRMED evidence — never speculate
2. Each technique needs at least 1 raw evidence source
3. Map to the most SPECIFIC sub-technique available
4. Include the data source that confirmed the mapping

## Common Memory Forensics Technique Mappings

| Technique | Sub-Tech | Evidence Source | What to Look For |
|-----------|----------|----------------|-----------------|
| T1055 | .001-.013 | malfind, vadinfo | Injected executable code |
| T1003 | .001 | hashdump, lsadump | Credential material in memory |
| T1543 | .003 | svcscan | Malicious Windows services |
| T1053 | .005 | scheduled_tasks | Suspicious scheduled tasks |
| T1547 | .001 | registry printkey | Run key persistence |
| T1021 | .001-.004 | netscan, cmdline | RDP/SSH/SMB connections |
| T1071 | .001 | netscan | HTTP/HTTPS C2 traffic |
| T1059 | .001 | cmdline | PowerShell execution |
| T1218 | .* | cmdline, pslist | LOLBin execution |
| T1036 | .005 | pslist, pstree | Process name masquerading |
| T1014 | - | ssdt, callbacks | Rootkit activity |
| T1105 | - | netscan, cmdline | File download (certutil, bitsadmin) |

## Kill Chain Assembly
Order techniques into kill chain phases:
Initial Access → Execution → Persistence → Privilege Escalation →
Defense Evasion → Credential Access → Discovery → Lateral Movement →
Collection → C2 → Exfiltration → Impact
