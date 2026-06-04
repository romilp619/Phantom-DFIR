# Lateral Movement Detection (MITRE T1021)

## SSH/RDP Movement (T1021.004 / T1021.001)
- Multiple PuTTY/ssh.exe instances from single host → systematic pivoting
- SSH connections to internal hosts on port 22
- RDP (port 3389) connections to multiple internal servers
- cmdline arguments showing target hostnames (@hostname pattern)

## WMI/DCOM (T1021.003 / T1021.006)
- wmic.exe process calls with /node: argument
- WMI event subscriptions (wmiprvse.exe with unusual children)
- mmc.exe connecting to remote DCOM interfaces

## PsExec/SMB (T1021.002)
- PSEXESVC.exe service on target (persistence artifact)
- Named pipes: \PIPE\PSEXECSVC
- SMB connections on port 445 to internal hosts
- services.exe creating child processes from network shares

## Pass-the-Hash (T1550.002)
- NTLM authentication from non-domain-joined machines
- Type 3 logon events with NtLmSsp from unexpected sources
- sekurlsa::pth artifacts in memory

## Detection with Volatility
- `windows.netscan` — identify SSH/RDP/SMB connections to internal IPs
- `windows.cmdline` — PuTTY/ssh.exe command lines with target hosts
- `windows.pslist` — multiple instances of lateral movement tools
- `windows.svcscan` — look for PSEXESVC or other remote service artifacts

## Key Patterns
- Same user account connecting to many hosts in short timeframe
- SSH/RDP tools spawned by non-interactive parent (services.exe, cmd.exe)
- Network connections to private IPs (10.x, 172.16-31.x, 192.168.x) on ports 22, 3389, 445, 5985
