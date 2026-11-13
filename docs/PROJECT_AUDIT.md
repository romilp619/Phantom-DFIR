# PROJECT_AUDIT.md — PHANTOM DFIR

Audit performed 2026-11-10 against the public upstream clone at `Phantom-DFIR/` (commit `3005762`, clean tree). Nothing in this document is taken from documentation alone; every claim carries a file:line that was read directly.

## 1. What the project is

A LangGraph multi-agent DFIR investigator. It runs Volatility 3 (primary) and Volatility 2 (fallback) over a memory image, optionally correlates a disk image through a separate 20,713-line pipeline, generates hypotheses, scores their confidence, and emits a Markdown/JSON incident report.

Its advertised differentiator is an adversarial "Skeptic" agent that cross-examines findings before they can be reported as CRITICAL.

Scale: 31 Python files. `disk_correlator.py` alone is 20,713 lines, roughly 3.5x the rest of the repository combined.

## 2. Verified capability

Working and substantive:

- A real parallel collection layer: `agents/collector.py:103-241` runs Windows and Linux plugin sets through a 16-worker pool, with engine detection.
- A large tool surface: `tools/vol3_tools.py` (349 lines) and `tools/vol2_tools.py` (94 lines) wrap 40+ Windows and 30+ Linux plugins.
- A targeted evidence agent: `agents/evidence.py` re-queries by PID or IP to gather corroboration. This is the only writer of `verified_sources` (`agents/evidence.py:227`).
- A path-aware benign detector: `tools/legitimacy_engine.py:620-632` scores identity and behaviour and can reach an explicit CLEARED verdict. This is genuine, and it is a real improvement over naive IOC flagging.
- A read-only MCP surface: `mcpserver/mcp_server.py` (733 lines) exposes typed tools rather than a shell.
- Self-correction plumbing exists: `agents/skeptic.py:249-281` plus `agents/orchestrator.py:116-198` write a progress file per round.

## 3. Verified defects

These are the red-team findings. Each was read in the source, and D2 was corrected after the attack-surface analysis refuted the first reading.

### D1 — The Skeptic verdict has no decision authority
`agents/skeptic.py:76` injects a precomputed `required_verdict` into the prompt, telling the model the answer. `:121-130` then overrides the model whenever it disagrees. `:191-194` assigns confidence from `score(sources, h)`, which never receives `verdict`. `:89-110` the no-LLM fallback emits the identical mapping.

Net: for the verification path the LLM changes nothing. README.md:16 and PROJECT_DESCRIPTION.md:13 advertise "two agents that argue"; the code implements a threshold on an integer.

### D2 — The evidence count is inflated by key multiplicity (no attacker needed)
`agents/evidence.py:83-86` builds per-PID keys such as `vol3:malfind[pid]`, `vol3:dlllist[pid]`, `vol3:cmdline[pid]`; `:168-171` never canonicalises plugin aliases; `:93-99,108,118` recount text already counted at `:220`. One kernel artifact becomes three to five "independent sources" on every run.

Correction to an earlier reading: `agents/evidence.py:225,227` collapses literal duplicates, so `correlation/confidence.py:44`'s `set()` is a no-op here. The divergence is latent; multiplicity is the live mechanism.

### D3 — Claim text controls severity (highest impact)
`correlation/confidence.py:18-25` lists substrings including `"benign"` and `"not malicious"`. `:34` matches them against the hypothesis `claim`, and `:47-48` returns CLEARED before any count comparison. No sanitisation exists upstream: `agents/investigator.py` validates IOC shape (`:118-137`) but never strips severity words from claim text.

So the agent under investigation can suppress its own critical finding by choosing its wording.

### D4 — Marketing metrics are satisfiable by trivial strategies
`benchmark.py:134-138` is the entire metric set.
- `:137` computes `false_positive_rate = |fp| / |flagged|`, which is 1 minus precision, not a rate over negatives.
- `:131,138` computes `hallucination_rate = |refuted| / (flagged + cleared)`, which measures refutation activity, not fabrication. It is 0.00 for any system that never refutes. This is the 0.0% in `ACCURACY_REPORT.md:42`.
- `:82` matches IOCs by loose substring over prose, so an IOC that is merely mentioned counts as a true positive.
- `tools/accuracy.py` returns precision 1.0 and FPR 0.0 when nothing is detected, and is dead code with no call sites.
- `benchmark_reports.py:81-89,131-134` scores whole reports by alias containment anywhere in flattened text, with the forbidden-phrase penalty capped at 0.25. Per `JUDGE_READINESS_CHECKLIST.md:168-180` this runs against pre-saved JSON under `/home/romil`, not a fresh pipeline run.

The `ACCURACY_REPORT.md:32-48` headline of F1 100.0% / FPR 0.0% / hallucination 0.0% derives from one unseeded run on a 4-malicious / 4-benign ground truth (`ground_truth_base_admin.json`).

### D5 — Two-source true positives can never escalate
`agents/skeptic.py:259-265` re-queries only `UNVERIFIED` or `LOW` hypotheses with fewer than three sources. A hypothesis at exactly two sources has confidence MEDIUM (`config.py:44`), so it is excluded from the loop and sits at MEDIUM permanently.

## 4. What cannot run on this machine

The pipeline requires external forensic tooling that is absent, and `config.py:21-29` resolves those tools with `shutil.which`, silently falling back to bare command names. Missing: `vol`, `vol2`, `mmls`, `fls`, `icat`, `log2timeline.py`, `mactime`, `yara`. Also absent: any memory image or disk image to analyse.

Consequence for the project: the full end-to-end forensic pipeline cannot be executed or demonstrated here. The verification and scoring components, however, are pure functions of text and structured objects, and can be exercised directly against synthetic evidence with the collection layer stubbed. That is the basis of the evaluation design, and it means the red-team findings and the repair are testable without forensic images.

## 5. Audit conclusion

The forensic tooling is real and substantial. The verification layer advertised as the project's core innovation does not verify: it counts, and it counts a number the checked agent supplies, while its severity decision can be rewritten by claim wording. The evaluation harness that produced the headline numbers cannot detect either failure.

This is a legitimate Track 2 subject: a safety mechanism that provides no safety, with a measurable, reproducible failure and a testable repair.