# PHANTOM DFIR Final Execution Logs

This directory contains selected final run logs used for Stage One verification.

## Logs

- `final_runs/cfreds_data_leakage.log`
  - CFReDS insider/data leakage run.
  - Supports benchmark case: `cfreds_data_leakage`.

- `final_runs/ali_hadi_encrypt_them_all.log`
  - Ali Hadi Encrypt Them All crypto workflow run.
  - Supports benchmark case: `ali_hadi_encrypt_them_all`.

- `final_runs/m57_jean_phishing.log`
  - M57 Jean phishing-induced disclosure run.
  - Supports benchmark case: `m57_jean_phishing`.

- `final_runs/nitroba_harassment_pcap.log`
  - Nitroba PCAP harassment attribution run.
  - Supports benchmark case: `nitroba_harassment_pcap`.

- `final_runs/sysinternals_case.log`
  - SysInternals disk challenge run.
  - Supports benchmark case: `sysinternals_case`.

## Benchmark Traceability

Machine-readable benchmark scorecards are stored in:

- `benchmark_results/all_cases_benchmark_summary.json`
- `benchmark_results/cfreds_benchmark_result.json`
- `benchmark_results/encrypt_them_all_benchmark_result.json`
- `benchmark_results/jean_benchmark_result.json`
- `benchmark_results/nitroba_benchmark_result.json`
- `benchmark_results/sysinternals_benchmark_result.json`

These files map final findings to case ground truth in:

- `benchmarks/ground_truth_cases.json`
