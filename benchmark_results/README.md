# PHANTOM DFIR Benchmark Results

This folder contains the final judge-facing benchmark scorecards generated from
PHANTOM's completed reports.

## Summary

| Case | Result | Score |
|------|--------|-------|
| CFReDS data leakage | FULLY_REPRODUCED | 100.0% |
| Ali Hadi Encrypt Them All | FULLY_REPRODUCED | 100.0% |
| M57 Jean phishing | FULLY_REPRODUCED | 90.0% |
| Nitroba harassment PCAP | FULLY_REPRODUCED | 95.0% |
| SysInternals challenge | FULLY_REPRODUCED | 100.0% |

Overall average adjusted score: 97.0%.

Primary combined scorecard: `all_cases_benchmark_summary.json`.

## Reproduce the Scorecards

Run these commands from the repository root after PHANTOM has generated final
JSON reports for each case.

### Single Case

```bash
python3 benchmark_reports.py \
  --case <case_id> \
  --report /path/to/phantom_report.json \
  --output benchmark_results/<case_id>_benchmark_result.json
```

Supported case IDs used in the final package:

```text
sysinternals_case
cfreds_data_leakage
ali_hadi_encrypt_them_all
m57_jean_phishing
nitroba_harassment_pcap
```

Examples:

```bash
python3 benchmark_reports.py \
  --case ali_hadi_encrypt_them_all \
  --report "/home/romil/phantom_correlation_A (disk-only)_AF-Case2_E01_20260613_182951.json" \
  --output benchmark_results/encrypt_them_all_benchmark_result.json

python3 benchmark_reports.py \
  --case nitroba_harassment_pcap \
  --report "/home/romil/phantom_correlation_A (disk-only)_nitroba_pcap_20260613_111646.json" \
  --output benchmark_results/nitroba_benchmark_result.json
```

### All Cases From a Reports Directory

If the final reports are in one directory, PHANTOM can search for the latest
matching report per case:

```bash
python3 benchmark_reports.py \
  --all \
  --reports-dir /path/to/final/reports \
  --latest \
  --output benchmark_results/all_cases_benchmark_summary.json
```

If reports are grouped into subfolders, score each case individually and then
combine the resulting `*_benchmark_result.json` files into a summary. The
committed `all_cases_benchmark_summary.json` is the final combined judge
scoreboard used for this package.
