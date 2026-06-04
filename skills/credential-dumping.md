# Credential Dumping Detection (MITRE T1003)

## Attack Techniques
- **LSASS Memory** (T1003.001): Mimikatz, procdump, comsvcs.dll MiniDump
- **SAM Database** (T1003.002): reg save HKLM\SAM, Volume Shadow Copy
- **NTDS.dit** (T1003.003): ntdsutil, DCSync via DRS replication
- **LSA Secrets** (T1003.004): reg save HKLM\SECURITY
- **Cached Credentials** (T1003.005): Domain cached credentials (DCC2)

## Detection with Volatility
- `windows.hashdump` — extract SAM hashes from memory
- `windows.lsadump` — extract LSA secrets
- `windows.cachedump` — domain cached credentials

## Key Indicators in Memory
- Multiple processes accessing LSASS (only ONE should: wininit.exe)
- procdump.exe or comsvcs.dll in cmdline targeting lsass.exe
- Mimikatz strings: "sekurlsa", "kerberos", "wdigest", "logonpasswords"
- rundll32.exe with comsvcs.dll MiniDump arguments
- Unknown process with SeDebugPrivilege enabled

## Kerberoasting (T1558.003)
- Excessive TGS-REQ for service accounts
- RC4 encryption requested (downgrade from AES)
- Tools: Rubeus, Invoke-Kerberoast, GetUserSPNs.py
