# PHANTOM DFIR — Multi-Case Benchmark Matrix

This matrix documents the ground truth and reproduction targets for the cases
tested during development. The machine-readable version is
`benchmarks/ground_truth_cases.json`.

## Summary

| Case | Evidence Type | Current Target |
|---|---:|---|
| Base-admin memory | Memory | Compromise: service persistence, C2, PuTTY lateral movement, benign Puppet Ruby cleared |
| SysInternals | Disk | Fake SysInternals execution chain with timestamps, VMToolsIO, SRUM/BAM/USN/Prefetch |
| Ali Hadi Web Server | Full memory/disk | Webshell + SQLMap + command injection + account/RDP persistence |
| CFReDS Data Leakage | Disk | Insider exfiltration via Outlook, Google Drive, USB, CD-R, renamed confidential files |
| Ali Hadi Encrypt Them All | Disk | AES README secret, GPG plaintext, BitLocker R2D2 unlock |
| M57 Jean | Disk | Phishing-induced disclosure of `m57biz.xls` to `tuckgorge@gmail.com` |
| Nitroba | PCAP | Harassment attribution: actor, alias, victim, webmail/IP chain |

## Case Targets

### Base-admin Memory

Required reproduction:

- `subject_srv.exe` malicious service persistence.
- `172.16.4.10` C2 connection.
- `putty.exe` lateral movement.
- SSH targets including `onion-master`.
- Puppet Ruby and VMware Tools treated as benign context.

### SysInternals

Required reproduction:

- `C:\Users\Public\Downloads\SysInternals.exe` executed.
- Download timestamp around `2022-11-15 21:18:51`.
- UserAssist execution at `2022-11-15 21:19:00`.
- HOSTS redirects to `192.168.15.10` for `www.sysinternals.com` and `www.malware430.com`.
- Defender exclusion/configuration before execution.
- SRUM bytes received/sent: `600880` / `8347`.
- BAM last execution around `21:21:09`.
- `VMToolsIO` service installed through Event ID 7045.
- USN confirms SysInternals deletion and Prefetch deletion.
- Shutdown at `21:21:12`.
- Slowdown explanation from Prefetch cleanup.

### Ali Hadi Web Server

Required reproduction:

- Webshell activity and PHP webshell files.
- SQLMap user-agent/activity.
- `/exec` abuse and command injection payloads.
- Account creation: `net user user1 ... /add`.
- RDP persistence: Remote Desktop Users group and firewall enablement.
- Apache access log and `httpd.exe` memory/string evidence.

### CFReDS Data Leakage

Required reproduction:

- Outlook conspiracy between `iaman.informant@nist.gov` and `spy.conspirator@nist.gov`.
- Google Drive files including `happy_holiday.jpg` and `do_u_wanna_build_a_snow_man.mp3`.
- Renamed/disguised confidential files such as `pricing_decision.xlsx` to `happy_holiday.jpg`.
- SanDisk USB devices and `IAMAN $_@` volume evidence.
- `\\10.11.11.128\secured_drive` network share access.
- CD-R burn/format/delete sequence.
- Eraser/CCleaner anti-forensics.
- Final narrative: copied, renamed, uploaded, written to USB/CD-R, cleanup attempted.

### Ali Hadi Encrypt Them All

Required reproduction:

- `README.txt.aes` identified as the AES target.
- AES password `StarWars!` recovered.
- README plaintext recovered with the YouTube clue.
- GPG passphrase `May the force be with you` recovered.
- `Keys.txt` decrypted to `MT4orceBWY23`.
- BitLocker/FVE volume `R2D2` unlocked with `MT4orceBWY23`.
- `NoLuck.png` recorded as a clue/decoy, not the final answer.

### M57 Jean

Required reproduction:

- Sensitive spreadsheet `m57biz.xls` identified.
- External recipient `tuckgorge@gmail.com`.
- Spoofed/internal identity `alison@m57.biz`.
- Phishing request email: `Please send me the information now`.
- Receipt confirmation and secrecy request.
- Outlook/PST corpus parsed.
- Browser-cache malware signatures treated as background artifacts unless execution is proven.

### Nitroba PCAP

Required reproduction:

- Primary suspect `jcoachj@gmail.com`.
- Threat alias `the_whole_world_is_watching@nitroba.org`.
- Primary victim `lilytuckrige@yahoo.com`.
- Internal source IP `192.168.15.4`.
- Webmail/HTTP POST communication attribution.
- Verdict is attribution/harassment, not compromise/malware.
- Router Evidence Gap Controller reaches target confidence with no gaps.

## Benchmark Commands

Score the latest available report for one case:

```bash
python3 benchmark_reports.py --case nitroba_harassment_pcap --reports-dir /home/romil --latest
```

Score all latest reports:

```bash
python3 benchmark_reports.py --all --reports-dir /home/romil --latest --output /home/romil/phantom_multi_case_benchmark.json
```

Score a specific report. Prefer JSON reports when available; unified router
JSON reports automatically include their child/source reports:

```bash
python3 benchmark_reports.py --case m57_jean_phishing --report /path/to/report.md
```

## Notes

This benchmark checks PHANTOM's final report artifacts. It is deliberately
separate from parser unit tests: the goal is to confirm that extracted evidence
is promoted into reasoning, narrative, role assignment, and final verdicts.
