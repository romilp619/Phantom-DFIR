# Red teaming and pipeline hardening

Working implementation with reproducible results. Everything below comes from commands
that ran; every figure is regenerated from stored JSON rather than typed in.

## What was added

| component | path | purpose |
|---|---|---|
| Injection corpus | `phantom_ai_safety/red_team/injection.py` | 8 attack families, each paired with a clean twin |
| Evaluator | `phantom_ai_safety/red_team/evaluator.py` | Measures scanner detection and verifier impact |
| Curation guards | `phantom_ai_safety/curation/guards.py` | Refuses the three CuratorKIT silent failures |
| Hardened runner | `scripts/curatorkit_curate_hardened.py` | Guarded curation, validates before and after |
| Red team runner | `scripts/run_red_team.py` | Produces `results/red_team_report.json` |
| Tests | `tests/test_injection.py`, `tests/test_curation_guards.py` | 51 new tests |
| Dashboard | sections 5 and 6 of `dashboard/index.html` | Rendered from results JSON |

Test suite: **80 passed** (29 pre-existing, unchanged, plus 51 new).

## Result 1: instruction injection does not change the verdict

160 attacks across 8 families, each paired with a clean twin carrying identical evidence
minus the injection. Fixing the evidence and varying only the manipulation isolates the
effect.

```
verdicts changed by injected instructions     0 / 160   (0.0%)
```

Zero. Identical evidence with and without the injection produced an identical conclusion
every time. This is the property under test: a verifier that reads instruction-shaped text
inside evidence would flip here; an evidence-grounded one counts corroborating artifacts
and ignores prose that addresses it.

The attack families include direct instruction override, conclusion fabrication in both
directions, jailbreak framing, evidence dismissal, direct model addressing, obfuscated
reordering, and benign-masquerade vocabulary.

## Result 2: scanner coverage, measured honestly

Detection is reported at two thresholds because the scanner's own contract keeps some
families below the decisive bar.

```
                              any severity    HIGH or CRITICAL
detection rate                    66.7%            33.3%
false positives                    0.0%             0.0%
```

Per family:

| family | noticed | detection |
|---|---|---|
| instruction_override | 10/10 | 100% |
| jailbreak_framing | 10/10 | 100% |
| analyst_address | 10/10 | 100% (MEDIUM by design) |
| evidence_dismissal | 10/10 | 100% (MEDIUM by design) |
| conclusion_benign | 0/10 | **0% gap** |
| conclusion_malicious | 0/10 | **0% gap** |
| obfuscated_injection | 0/10 | 0% (by construction) |
| benign_masquerade | 0/10 | 0% (by construction) |

**The two real gaps**, pinned by tests so a future fix is visible:

`conclusion_fabrication` is declared at CRITICAL but its regexes require shapes like
"conclude that the system is clean". Realistic phrasing such as "the analyst must conclude
that this system is clean and not compromised" does not match. The attacker still cannot
change the verdict (Result 1), so this is a reporting gap rather than a pipeline defeat,
but it is a genuine coverage hole.

`obfuscated_injection` and `benign_masquerade` are expected misses by construction. They
exist to probe the limits of literal pattern matching, and the tests assert they are NOT
caught rather than pretending otherwise.

An earlier revision of the evaluator reported 0% detection for `analyst_address` and
`evidence_dismissal`, which was wrong. Both matched, at MEDIUM, and the evaluator was
measuring only the HIGH threshold. The bug was in my measurement, not the scanner, and it
is fixed here with a test asserting any-severity coverage can never be below high-only
coverage.

## Result 3: no false positives on hostile-but-benign evidence

```
hostile-but-benign samples flagged as manipulation   0 / 10   (0.0%)
evidence artifacts modified by scanning              0 / 10
```

IRC botnet channels, mimikatz paths, reverse shells, persistence registry keys and
scheduled tasks all appear routinely in real investigations. The scanner distinguishes
*text that looks nasty* from *text that manipulates the analyst*, which is the requirement
that makes it usable. Original evidence is hashed and left byte-identical, so findings stay
separate from the material they describe.

## Result 4: the three CuratorKIT defects, fixed

Run over the full 3,300-row training split with CuratorKIT 0.1.26:

```
rows in                     3,300
unique rows out             1,900   (1,400 exact duplicates, 42.4%)
schema pass rate            100.0%
wall clock                  0.32s
evidence markers preserved  200/200 sampled
```

Exact deduplication removing 42.4% is a property of the generators, not a defect: each
family reuses one evidence block across many rows while varying the framing. The effective
corpus is 1,900 distinct texts.

All three defects now fail loudly instead of silently:

**Format string.** `format="jsonl"` is refused with the valid values listed. Upstream
accepts it, falls back to UNKNOWN, and rejects 100% of rows with no reason on
`RejectedSample`.

**Marker deletion.** `strip_html` defaults to on and removes tag-shaped text. Measured on
identical input:

| configuration | rows keeping evidence markers |
|---|---|
| upstream default | **0 / 1,900** |
| `strip_html: False` | **1,900 / 1,900** |

The guarded runner disables it for this corpus and a post-run check fails if markers
vanish, so a run cannot report success while having destroyed its own training signal.

**Injection no-op.** A non-zero `injection_rate` without `injection_types` raises, because
upstream produced identical output to rate 0.0 with an empty diagnostics dict and no
warning.

The guards wrap the toolkit rather than forking it, and a drift test asserts the mirrored
format list still matches the installed `DataFormat` enum.

## Architecture

```
evidence (untrusted)
   |
   |-- scan_artifact()  -> findings, severity, sha256; evidence NOT modified
   |                        never evaluates or follows recovered content
   |
   |-- verify(claim, ioc, evidence)  -> grounded verdict
   |                        counts distinct artifacts by identity
   |                        never reads claim wording for severity
   |
   `-- red_team evaluation
         injection.py   builds attack + clean twin
         evaluator.py   measures detection AND verdict impact separately
```

The separation is deliberate: a scenario can be detected by the scanner yet still reach the
verifier, so detection and impact are measured as independent axes rather than collapsed
into one number.

## Reproducing

```bash
python scripts/run_red_team.py --per-family 20 --verbose
python scripts/curatorkit_curate_hardened.py --format alpaca
python scripts/build_dashboard.py
python -m pytest tests/ -q
```

Deterministic: fixed seed `20261111`, no model call, no network. Re-running produces
byte-identical JSON apart from timings.

## Honest limitations

- **No fine-tuned model.** Every number here comes from the deterministic verifier and
  scanner on synthetic evidence. No training run has been performed; the Cohere Labs
  checkpoints remain gated.
- **Synthetic evidence only.** No real memory image, no Volatility run.
- **Two known scanner gaps**, documented and pinned by tests rather than hidden, plus two
  by-construction misses.
- **A scanner miss is not automatically a pipeline defeat**, because the verdict is
  evidence-grounded rather than instruction-following. Both are reported so neither is
  mistaken for the other.