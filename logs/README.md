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

- `final_runs/memory_self_correction.log`
  - Memory-only autonomous self-correction run against the Ali Hadi memory image.
  - Demonstrates Volatility 2/3 collection, rule-based no-LLM mode, weak-finding downgrade, benign TrustedInstaller clearance, and gap-controller traceability.

- `final_runs/memory_self_correction_report.md`
  - Stable Markdown report from the memory self-correction run.

- `final_runs/memory_self_correction_execution_log.json`
  - Structured execution log with reasoning trace, evidence integrity hashes, self-correction history, and `memory_gap_controller` output.
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
