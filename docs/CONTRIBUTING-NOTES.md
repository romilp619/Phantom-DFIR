# Notes for the next person

Written for whoever picks this up cold. Read this before changing anything that a
reported number depends on.

## The one rule that governs the rest

**Every number in the README and the docs is checked against a stored result.**

`scripts/verify_report_claims.py` reads `results/*.json`, recomputes the claimed
figures, and greps the README for the headline table. It exits non-zero if any of it
disagrees. Run it before you commit anything that touches a measurement:

```bash
python scripts/verify_report_claims.py
```

If you change a metric, change the result file and the prose in the same commit. The
check is deliberately strict because a report that silently disagrees with its own
data is worse than no report.

## Where the pieces are

| you want to | go to |
|---|---|
| change what gets detected | `phantom_ai_safety/evidence_scanner/scanner.py`, `RULES` |
| change what gets decoded first | `phantom_ai_safety/evidence_scanner/normalize.py` |
| change the compiled scanner | `phantom-guard/src/main.rs` |
| change the verdict logic | `phantom_ai_safety/grounding/verifier.py` |
| add an attack family | `phantom_ai_safety/red_team/rows.py` |
| change a metric | `phantom_ai_safety/evaluation/metrics.py` |

## The three ways this breaks

### 1. The guard and the Python scanner diverge

Every rule exists twice, once in Python and once in Rust, and they are held to exact
agreement on category, severity, `char_offset`, and finding count across all 460
corpus artifacts.

If you add a rule to `scanner.py`, **you must add it to `main.rs` too**, in the same
position, with the same severity and the same regex. If you only add it to one side,
`scripts/check_normalization_equivalence.py` fails and so does
`tests/test_rust_guard.py`.

The one thing that is easy to get wrong: Rust `regex` matches on **bytes**, Python
`re` matches on **characters**. `char_offset` must be a character offset for the two
to agree on non-ASCII evidence, which forensic output contains routinely (hostnames,
usernames, paths). That conversion is in `scan_artifact`, and it is the single most
performance-sensitive line in the file. Read the comment before you touch it.

### 2. A new rule fires on ordinary evidence

This is the failure mode that kills the tool in practice. A scanner that flags
`mimikatz` in a malware-analysis report gets turned off, and then it protects nothing.
The target is manipulation **of the analyst**, not text that merely looks hostile.

Before any rule lands, run all three:

```bash
python scripts/probe_normalize.py     # 17 benign forensic artifacts, 400 random blobs
python scripts/test_real_image.py     # 324k chars of real Volatility output
pytest tests/test_scanner_normalization.py -q
```

Zero false positives is the bar on all three. If your rule trips one, the rule is
wrong, not the corpus.

### 3. Something becomes superlinear

Both scanners run over attacker-controlled text. Cost that grows faster than the
input is a denial of service against the analyst.

This already happened once: the guard converted each match offset by rescanning the
whole prefix, which is O(n) per match and O(n*m) overall. It was invisible at small
sizes and took 8.5 seconds on a 2 MB crafted artifact.

Before and after any change to the scan loop:

```bash
bash scripts/probe_quadratic.sh    # feeds dense repeated matches at increasing sizes
bash scripts/bench_scaling.sh      # guard vs python across 64 KB to 16 MB
```

The signal is **ms per KB**. Flat means linear. Rising means you reintroduced the bug.
`tests/test_guard_bounded.py` asserts the ratio stays bounded, so the test suite
catches a regression even if you forget to run the probes.

## Why the evaluation pipeline imports `scanner`, not `guard`

`comparison.py`, `evaluator.py`, `dataset.py`, and `run_red_team.py` all use
`phantom_ai_safety.evidence_scanner.scanner`.

That is deliberate. The Python module is the reference implementation, and the guard
is tested for equivalence against it. Keeping the pipeline on the reference means the
reported numbers are produced by the implementation that is itself verified, and a
reader can read the detection rules in the same file as the numbers they produce.

Swapping to the guard is a one-line import with an identical signature. It is a
reasonable thing to do once you trust the equivalence tests. It changes which process
runs the rules, not which rules run.

## Things that are deliberately absent

- **No fine-tuned model is used in any reported number.** The adapter is trained
  separately and no claim depends on it. Do not wire it into a metric without
  re-measuring everything.
- **No real memory image is committed.** `test-images/` is gitignored. Fetch it with
  `scripts/run_real_image_plugins.sh`.
- **No sandbox claim.** The guard is a process boundary, not a privilege boundary. It
  does not defend against a local attacker who can replace the binary. Do not describe
  it as a sandbox.
- **No accuracy claim on real evidence.** A real image has no ground-truth label for
  "did the agent correctly refuse to confirm", so it cannot reproduce the McNemar
  numbers. What the real image proves is narrower and stated in
  `docs/REAL-IMAGE-TEST.md`: the scanner is silent on genuine evidence.

## If you only have five minutes

```bash
pytest tests/ -q                      # expect 112 passed, 7 skipped
python scripts/verify_report_claims.py # expect all quoted figures match
```

If both pass, the repository is consistent with itself. That is the floor, not proof
the work is correct, but it catches the failures that are easiest to introduce and
hardest to notice.