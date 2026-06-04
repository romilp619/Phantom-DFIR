# Persistence Mechanism Detection (MITRE T1543, T1053, T1547)

## Windows Service Persistence (T1543.003)
- Non-standard service binary paths (outside System32/SysWOW64)
- Services with SERVICE_AUTO_START but unusual ImagePath
- Service DLLs loaded from temp/user directories
- svchost.exe -k groups with unknown DLL ServiceDll keys

## Registry Persistence (T1547.001)
- Run/RunOnce keys: HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- Winlogon: Shell, Userinit, Notify values
- AppInit_DLLs: loaded into every user process
- Image File Execution Options: debugger hijacking

## Scheduled Tasks (T1053.005)
- Tasks with suspicious actions (powershell -enc, cmd /c, mshta)
- Tasks created by non-admin users
- Tasks with high-frequency triggers (beaconing)
- Tasks pointing to temp/appdata/user directories

## Detection with Volatility
- `windows.svcscan` — enumerate all service records
- `windows.registry.printkey` — check Run keys
- `windows.scheduled_tasks` — task XML parsing
- `windows.shimcache` — execution history (even deleted binaries)
- `windows.userassist` — GUI program execution frequency

## Red Flags
- Service binary not in System32 → SUSPICIOUS
- Binary path contains spaces without quotes → potential DLL hijack
- Service running as SYSTEM from user-writable path → CRITICAL
- Scheduled task created during off-hours → investigate
