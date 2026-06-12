# PHANTOM DFIR — Dataset Documentation

## Test Data

### Primary: base-admin-memory.img
- **Source**: SANS "Find Evil!" Hackathon 2026 provided dataset
- **Type**: Full memory capture (Windows 10 x64)
- **Size**: 5,120 MB (5 GB)
- **SHA256**: `d58343cb4e4a06ecc56012c8e25760b297594bf4695303527a5cbb2331726891`
- **OS**: Windows 10 x64 (detected via Vol3 windows.info)
- **Capture Tool**: Unknown (provided as-is)

### Ground Truth: base-admin case

Documented in `ground_truth_base_admin.json`. Key findings:

| IOC | Verdict | Evidence |
|-----|---------|----------|
| `subject_srv.exe` | 🔴 MALICIOUS | Running from `C:\windows\` (NOT System32), registered as service, shimcache confirms execution 2018-04-10 |
| `putty.exe` | 🔴 MALICIOUS | Multiple instances, SSH to internal hosts (onion-master, base-elk, proxy) — lateral movement |
| `powershell.exe` | 🟡 SUSPICIOUS | User-launched from explorer.exe — potential post-exploitation |
| `ruby.exe` | ✅ BENIGN | Path: `C:\Program Files\Puppet Labs\Puppet\sys\ruby\bin\ruby.exe` — legitimate Puppet installation |
| `rubyw.exe` | ✅ BENIGN | Same Puppet Labs path — legitimate |
| `vmtoolsd.exe` | ✅ BENIGN | VMware Tools — standard virtualization agent |

### What PHANTOM Found

When run against `base-admin-memory.img`:

- **232 processes** enumerated via pslist
- **134 network connections** analyzed
- **4 suspicious processes** flagged for investigation
- **1 suspicious service** identified (subject_srv.exe)
- **Shimcache** confirmed subject_srv.exe execution on 2018-04-10

### Disk Correlation (when disk image available)

The `disk_correlator.py` module can cross-reference against a disk image (E01/raw) using:
- `log2timeline.py` for super timeline
- `fls` for MFT file listing
- `icat` for file extraction
- Prefetch execution evidence
- Registry persistence analysis

## Reproducibility

To reproduce PHANTOM's analysis:

```bash
# On SANS SIFT Workstation
bash install.sh
python3 main.py -f /path/to/base-admin-memory.img

# With benchmarking
python3 benchmark.py -f /path/to/base-admin-memory.img \
  --ground-truth ground_truth_base_admin.json
```

All outputs are deterministic for the static rule engine. LLM outputs may vary slightly between runs due to model temperature (set to 0.1 for near-determinism).

## Multi-Case Challenge Corpus

Additional ground truth for the cases exercised during development is maintained
in `benchmarks/ground_truth_cases.json`:

| Case ID | Evidence Type | Primary Objective |
|---|---:|---|
| `sysinternals_case` | disk | Reconstruct fake SysInternals execution, HOSTS tampering, Defender exclusion, VMToolsIO, SRUM/BAM/USN/Prefetch evidence |
| `ali_hadi_web_server` | full | Reconstruct webshell compromise, SQLMap, command injection, account creation, and RDP persistence |
| `cfreds_data_leakage` | disk | Reconstruct Outlook, Google Drive, USB, CD-R, renamed-file, and anti-forensics exfiltration chain |
| `ali_hadi_encrypt_them_all` | disk | Recover AES, GPG, and BitLocker secrets |
| `m57_jean_phishing` | disk | Identify phishing-induced disclosure of `m57biz.xls` to `tuckgorge@gmail.com` |
| `nitroba_harassment_pcap` | pcap | Attribute harassment traffic to `jcoachj@gmail.com` and identify the victim/alias chain |

Run report-level scoring with:

```bash
python3 benchmark_reports.py --case nitroba_harassment_pcap \
  --report /home/romil/phantom_unified_pcap_nitroba.pcap_20260612_174103.json
```
