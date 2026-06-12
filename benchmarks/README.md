# PHANTOM DFIR Benchmark Ground Truth

This folder contains the multi-case benchmark set used to validate PHANTOM DFIR
against the cases exercised during development.

## Cases Covered

| Case ID | Evidence | Main Expected Outcome |
|---|---:|---|
| `base_admin_memory` | memory | Metasploit-style compromise with service persistence, C2, and PuTTY lateral movement |
| `sysinternals_case` | disk | Fake SysInternals execution, HOSTS tampering, Defender exclusion, VMToolsIO, SRUM/BAM/USN/Prefetch reconstruction |
| `ali_hadi_web_server` | full | Webshell compromise, SQLMap, command injection, account creation, RDP persistence |
| `cfreds_data_leakage` | disk | Insider exfiltration through Outlook, Google Drive, USB, CD-R, renamed files, anti-forensics |
| `ali_hadi_encrypt_them_all` | disk | AES README secret, GPG passphrase, Keys.txt plaintext, BitLocker R2D2 unlock |
| `m57_jean_phishing` | disk | Phishing-induced disclosure of `m57biz.xls` to `tuckgorge@gmail.com` |
| `nitroba_harassment_pcap` | pcap | Harassment attribution: `jcoachj@gmail.com`, `the_whole_world_is_watching@nitroba.org`, `lilytuckrige@yahoo.com` |

## Scoring Reports

Score a single generated report. Prefer JSON reports when available; unified
router JSON reports automatically include their child/source reports:

```bash
python3 benchmark_reports.py \
  --case nitroba_harassment_pcap \
  --report /home/romil/phantom_unified_pcap_nitroba.pcap_20260612_174103.json
```

Find and score the latest likely report for a case:

```bash
python3 benchmark_reports.py \
  --case m57_jean_phishing \
  --reports-dir /home/romil \
  --latest
```

Score all cases from the latest likely reports in `/home/romil`:

```bash
python3 benchmark_reports.py \
  --all \
  --reports-dir /home/romil \
  --latest \
  --output /home/romil/phantom_multi_case_benchmark.json
```

## Status Labels

- `FULLY_REPRODUCED`: required evidence and expected verdict reproduced with no blocking false-positive phrase.
- `PARTIALLY_REPRODUCED`: major evidence present, but at least one important artifact/verdict/role remains weak.
- `NOT_REPRODUCED`: insufficient required evidence in the report.

This benchmark is intentionally report-based. It validates PHANTOM's final
analyst-facing output rather than only low-level parser counters.
