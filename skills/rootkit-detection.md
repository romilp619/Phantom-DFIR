# Rootkit and Fileless Malware Detection

## Rootkit Indicators
- Processes in psscan but NOT in pslist (DKOM hiding)
- SSDT hooks — system call table modification
- IRP hooks — driver dispatch table modification
- Hidden drivers — loaded modules not in PsLoadedModuleList
- Modified kernel objects — EPROCESS/ETHREAD manipulation

## Detection with Volatility
- `windows.ssdt` — check for hooked system service descriptors
- `windows.callbacks` — kernel callback registrations
- `windows.driverirp` — IRP handler analysis
- `windows.modscan` vs `windows.modules` — find hidden kernel modules
- `windows.psxview` — cross-reference process lists

## Fileless Malware Indicators
- PowerShell with encoded commands (T1059.001 + T1027)
- WMI event subscriptions executing scripts
- .NET assemblies loaded from memory (Assembly.Load from byte array)
- Script interpreters (wscript, cscript, mshta) with no file arguments
- Registry-stored payloads (T1112)
- reflective DLL loading — no file on disk

## MITRE ATT&CK Mapping
- T1014 — Rootkit
- T1620 — Reflective Code Loading
- T1059.001 — PowerShell
- T1546.003 — WMI Event Subscription
- T1027 — Obfuscated Files or Information
