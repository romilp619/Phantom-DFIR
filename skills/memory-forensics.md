# Memory Forensics with Volatility 3

## Key Process Analysis Rules
- **Parent validation**: svchost.exe parent MUST be services.exe (PID 732 typically)
- **lsass.exe**: only ONE instance allowed. Multiple = credential injection (T1003)
- **csrss.exe**: parent must be smss.exe. Misspellings (csrs.exe, cssrs.exe) = masquerading
- **smss.exe**: first user-mode process. Parent is System (PID 4)
- **winlogon.exe**: parent must be smss.exe or wininit.exe

## Critical Volatility 3 Plugins
- `windows.pslist` — active processes (DKOM-visible)
- `windows.psscan` — pool tag scan (finds DKOM-hidden processes)
- `windows.malfind` — injected code regions (PAGE_EXECUTE_READWRITE)
- `windows.netscan` — network connections with process attribution
- `windows.cmdline` — full command lines (reveals LOLBin abuse)
- `windows.handles` — open handles (files, registry, mutexes)
- `windows.dlllist` — loaded DLLs per process
- `windows.svcscan` — Windows services (persistence mechanism)

## Hidden Process Detection
Compare pslist vs psscan PIDs. Any PID in psscan but NOT in pslist = DKOM-hidden.
This is a CRITICAL finding (rootkit or advanced malware hiding from task manager).

## Code Injection Indicators
- PAGE_EXECUTE_READWRITE protection on non-image regions
- MZ header in non-file-backed memory sections
- Hollowed processes: image mapped but original code overwritten
