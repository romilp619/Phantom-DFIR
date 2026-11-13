# Scripts

Every script here is meant to be run from the repository root. Grouped by what you
would be doing when you reach for it.

## Reproduce the result

| script | what it does |
|---|---|
| `smoke_harness.py` | proves the harness drives the real upstream verification code |
| `run_red_team.py` | generates the attack set and runs a condition over it |
| `summarize_results.py` | prints a comparison JSON as a readable table |
| `verify_report_claims.py` | **checks every quoted figure against the stored results** |

## Check the scanner

| script | what it does |
|---|---|
| `validate_scanner.py` | recall on labelled payloads, false positives on controls |
| `probe_normalize.py` | 17 benign forensic artifacts and 400 random blobs against normalisation |
| `check_normalization_equivalence.py` | guard vs Python on all 460 corpus artifacts |
| `run_rust_guard.py` | guard over the attack corpus, writes a divergence report |

## Probe for problems

These exist because each one already found something. Run them after touching the
scan loop or the rule table.

| script | what it does |
|---|---|
| `probe_quadratic.sh` | dense repeated matches at rising sizes; rising ms/KB means superlinear |
| `bench_scaling.sh` | guard vs Python from 64 KB to 16 MB |
| `probe_adversarial.py` | normalisation cost on hostile input, cache-poisoning attempts |
| `bench_cache.py` | cache hit rate and batching benefit |
| `bench_guard.py` | guard timing on the attack corpus |
| `check_syntax.sh` | parse-checks every Python file in the repo |

## Real memory image

| script | what it does |
|---|---|
| `run_real_image_plugins.sh` | 7 real Volatility plugins over a downloaded image |
| `test_real_image.py` | scans that output, cross-checks the guard, reports false positives |

## Figures

| script | what it does |
|---|---|
| `make_figures.py` | regenerates `docs/img/*.png` from measured results |

Every figure number is either copied from `results/` or measured in the script. No
figure is hand-drawn or illustrative.

## One-off investigations

These were written to answer a specific question during the build. They are kept
because each documents a decision that would otherwise be lost, and because a reader
can re-run them to check the reasoning.

| script | the question it answered |
|---|---|
| `probe_hf_access.py` | are the Cohere Labs checkpoints actually downloadable? |
| `check_model_compat.py` | can the training stack load a Cohere checkpoint at all? |
| `inspect_stack_api.py` | what are the real AlignTune and CuratorKIT APIs? |
| `inspect_sft_entry.py` | what does an SFT entry point actually require? |
| `inspect_sft_entry2.py` | what are the PEFT and evaluation config fields? |
| `curatorkit_curate.py` | first curation run, after two probe-driven corrections |
| `curatorkit_curate_hardened.py` | curation guarded against the toolkit's three silent failures |
| `diagnose_seed_split.py` | why do two families fail on the held-out seed but pass on the tuned seed? |
| `build_dashboard.py` | renders `dashboard/index.html` from result JSON |

## Conventions

- Scripts that change results take an `--out` or `--write` flag. Nothing overwrites a
  result file without being asked.
- Probes print a table and exit non-zero on failure, so they can be wired into CI.
- Bash scripts are bash, not sh, and are written to be run through WSL on Windows.
  They avoid inline `-c` one-liners: nested quoting through pwsh and wsl silently
  corrupts loop variables, which has already produced one false alarm here
  (`check_syntax.sh` documents it).