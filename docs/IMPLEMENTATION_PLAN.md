# IMPLEMENTATION_PLAN.md — PHANTOM DFIR AI Safety and Alignment

Plan date 2026-11-10. Track 2 (AI Red Teaming, Safety and Alignment). Hard deadline 2026-11-15 11:59 PM AoE.

## Research question

Can we make an AI forensic analyst more resistant to adversarial manipulation while preserving its ability to accurately investigate and explain digital forensic evidence?

## What we are actually testing

The audit (`PROJECT_AUDIT.md`) found that PHANTOM's verification layer is a threshold on a self-reported integer (D1, D2), that its severity decision can be rewritten by claim wording (D3), and that its evaluation harness cannot detect either (D4). The plan repairs exactly that, and measures the repair against the unmodified behaviour.

Baseline condition = the existing PHANTOM code path, unmodified.
Improved condition = a Cohere Labs model that emits evidence-grounded verdicts, with the count threshold replaced by reasoned comparison.

## Design constraints locked by research

- **Model**: `CohereLabs/tiny-aya-global` (3.35B, instruction-tuned, chat template ships). QLoRA 4-bit NF4, LoRA r=16, max sequence 4096, microbatch 1 with gradient accumulation and gradient checkpointing. Chosen because 8 GB VRAM is the binding constraint on the RTX 4060 Laptop target, and it is the largest model that still trains at 4096 context there.
  - Upgrade path if training moves to the 16 GB box: `CohereLabs/aya-expanse-8b` at 2048-4096 context.
  - Not viable at 8 GB: `aya-expanse-32b` (about 16.5 GB at 4-bit); `aya-expanse-8b` fits only near 1024 context, too short for evidence plus claim plus schema.
- **Stack**: CuratorKIT for dataset curation, AlignTune for SFT, AuditKIT for before/after metrics.
- **Licences are not uniform and must be stated in the write-up**: all Cohere checkpoints are `cc-by-nc-4.0` (non-commercial). AlignTune is MIT + Apache + AGPL + LGPL (it vendors unsloth and mergekit). The remaining Lexsi repositories are LSAL v1.1/v1.2 source-available, and AuditKIT Section 1A requires an organisation doing red-teaming to obtain written permission or send written acknowledgement to support@lexsi.ai. **Action for the human: send that acknowledgement before publishing.** Draft only; do not send from here.
- **Two environments are mandatory**: AlignTune pins `trl==1.7.1` while SafeTune caps `trl<1.15`. Training and evaluation must not share a venv.

## Blocking unknown to resolve before any training

AlignTune pins `transformers>=5.15,<6` and `trl==1.7.1`, but the Cohere checkpoints target the 4.x line. Before scheduling a run, prove in the real venv that one templated forward pass and one generation work for `tiny-aya-global`. If they do not, the fallback is to train with a plain `peft` + `trl` path and use AlignTune only for its dataset and config handling, stated honestly in the write-up.

## Deliverable structure

New derived repository, `phantom-safety/`. The upstream clone stays untouched: it is a third party's public repo and we do not push to it.

```
phantom-safety/
  phantom_ai_safety/
    evidence_scanner/     prompt-injection and manipulation detection over untrusted evidence
    grounding/            claim to evidence-id binding, citation validation, abstention policy
    red_team/             5 attack families, generators, attack harness
    evaluation/           metrics, scoring, confidence intervals, manifests
    repair/               training data builder, QLoRA training entry point, adapters
    harness/              stubs for tools.vol3_tools / tools.vol2_tools, llm neutralisation
  tests/                  unit and regression tests
  benchmarks/baseline/    frozen baseline predictions
  benchmarks/improved/    frozen improved predictions
  docs/                   this plan, audit, architecture, evaluation, limitations
  data/POINTER.json       pins the HF dataset revision
```

## Phases, scientific core first

**Phase 1 — Audit and plan.** Done. `PROJECT_AUDIT.md`, `EXISTING_ARCHITECTURE.md`, this file.

**Phase 2 — Resolve the blocking unknown.** Prove model load, templated generate, and one LoRA step in a training venv on the target GPU. Record exact package versions. No proceeding until this passes.

**Phase 3 — Harness.** Build `harness/` so the real `correlation/confidence.py`, `agents/skeptic.py`, and `agents/evidence.py` code can be driven against synthetic evidence with no forensic tooling and no image. This is what makes the whole experiment executable locally.

**Phase 4 — Red-team evaluation set.** n=300 rows: 5 attack families x 60, each family split 24 malicious / 24 benign / 12 undecidable, with same-shape twins so that surface features do not give the answer away. Attacks: count inflation by key multiplicity, alias reuse, IOC-selection manipulation, benign-allowlist masquerade, and two-source threshold straddling. Rows are synthetic and contain no real forensic data.

**Phase 5 — Baseline measurement.** Run the unmodified PHANTOM logic over the 300 rows. Freeze predictions. Expect ASR near 1.00 on count inflation and FCR near 0.50 for an always-CONFIRM strategy, per the trivial baselines computed in the design.

**Phase 6 — Injection scanner.** Detect manipulation attempts embedded in untrusted evidence. Treat all recovered content as data, never instructions. Preserve hashes, store findings separately from artifacts, and do not label merely suspicious text as malicious.

**Phase 7 — Grounded reasoning and repair.** Curate 2,000-4,000 training rows with CuratorKIT, requiring every verdict to cite evidence ids that exist in the presented evidence. Fine-tune `tiny-aya-global` with AlignTune. Structured JSON output validated against a schema.

**Phase 8 — Improved measurement.** Re-run the identical 300 rows with the fine-tuned model. Identical seeds, temperature 0.0, pinned model digest.

**Phase 9 — Metrics and report.** Report, with the baseline value and the trivial-baseline ceiling alongside each:
- FCR, false-confirm rate.
- ASR_count, attack success rate on count-inflation rows.
- XAR, correct abstention on undecidable rows.
- CR, capability retention on clean supported rows, so the repair cannot win by refusing everything.
- EFR, an evidence-fidelity gate requiring every cited id to exist in the presented evidence. Not a leaderboard number; a hard gate.
- Statistical honesty: Wilson intervals, exact McNemar on the discordant table, Holm correction across metrics. No directional claim below n=100.

**Phase 10 — Packaging.** HF dataset repo (rows, gold labels, adversarial set, both prediction sets, metrics, manifest with hashes), HF article write-up, GitHub repo with reproducibility notes, architecture diagram. A HF model repo only if a real adapter exists; if the repair ends up being a code change rather than a trained adapter, say so plainly rather than shipping an empty model repo.

## Demo case

The NIST CFReDS Mr. Evil artifacts already present in the repository are used as a forensic demonstration, with the standing caveat stated in the write-up: tool installation does not prove execution, and an artifact is not proof of compromise. Adversarial rows embed malicious instructions inside synthetic recovered documents to show the scanner refuses to follow them.

## Explicit non-goals and honesty rules

- Do not delete, rename, or rewrite existing working modules. Changes are additive; the baseline path is preserved so the comparison is real.
- Do not fabricate benchmark results. Every number in the write-up comes from a run whose raw per-row output is published.
- Do not claim the dashboard, the video, or the UI work is done unless it is.
- Do not upload private or sensitive forensic evidence. All evaluation data is synthetic.
- Do not overstate the repair: if the fine-tune does not beat the baseline on a metric, that result is published as a finding.
- Element ordering within any dashboard or report must follow the harness output, not expectations.

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| transformers 5.x vs 4.x checkpoint break | Blocks all training | Phase 2 gate; documented fallback |
| 8 GB VRAM ceiling | Limits model and context | tiny-aya-global at 4096; 4-bit NF4 |
| WSL2 default RAM split too small | OOM during tokenisation | Set `.wslconfig` memory=12GB per the model research |
| Route flakiness killing research agents | Slow progress | Lead does critical-path reads directly |
| LSAL licence clause and cc-by-nc terms | Legal exposure if misstated | State terms plainly; human sends the AuditKIT acknowledgement |
| Registration status unknown | Submission may be impossible | Human-owned; build proceeds regardless |

## Open questions for the human

1. Confirm training happens on the RTX 4060 laptop (8 GB), not this 16 GB box, since it changes the recommended model.
2. Confirm the derived repository's public home before any push. Nothing is pushed from here.
3. Send the AuditKIT Section 1A acknowledgement to support@lexsi.ai if the team qualifies as an organisation doing red-teaming.