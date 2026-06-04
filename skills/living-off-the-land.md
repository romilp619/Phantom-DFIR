# Living Off the Land (LOLBin) Detection (MITRE T1218, T1059)

## Common LOLBins and Suspicious Usage
- **certutil.exe**: -urlcache -f (download), -decode (base64 decode)
- **mshta.exe**: executing HTA from URL or with VBScript
- **regsvr32.exe**: /s /n /u /i:http (Squiblydoo attack)
- **rundll32.exe**: executing DLLs from temp paths or with unusual exports
- **wmic.exe**: process call create, /node: for lateral movement
- **msiexec.exe**: /q /i http:// (silent install from URL)
- **bitsadmin.exe**: /transfer (stealthy download)
- **powershell.exe**: -enc (encoded commands), -nop -w hidden
- **cmstp.exe**: /ni /s (UAC bypass via INF)
- **forfiles.exe**: /p /m /c (command execution bypass)
- **pcalua.exe**: -a (application compatibility bypass)
- **SyncAppvPublishingServer.exe**: PowerShell execution bypass

## Detection Rules
1. ANY of the above executing from non-System32 path → masquerading
2. certutil with -urlcache → download activity (T1105)
3. powershell with -enc or -encodedcommand → obfuscation (T1027)
4. rundll32 loading DLL from %TEMP%, %APPDATA%, or UNC path → malicious
5. wmic /node: → lateral movement attempt
6. mshta with http/https URL → script execution from web

## False Positive Guidance
- certutil for certificate management is legitimate
- powershell without -enc for system administration is normal
- rundll32 loading system DLLs from System32 is expected
- SCCM/WSUS may use msiexec legitimately
