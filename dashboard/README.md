# AI SAFETY & RED TEAMING dashboard

A single self-contained HTML file. Open `index.html` in any browser; it needs no
server, no network and no build step, so it works offline on a reviewer's machine.

## It is generated, not hand-written

Every figure on the page is read from `results/comparison.json`,
`results/heldout_rule_only.json` and `results/baseline.json`. Nothing is typed in, so
the page cannot drift from the measured data. After any re-run, regenerate it:

```
python -m phantom_ai_safety.evaluation.comparison --quiet --out results/comparison.json
python -m phantom_ai_safety.repair.eval_model --rule-only --out results/heldout_rule_only.json
python scripts/build_dashboard.py --out dashboard/index.html
```

The builder re-reads the file it wrote and refuses to claim success unless the page
parses, carries the before/after table, flags the one family the repair still fails, and
states that no fine-tuned model exists.

## Two things the page deliberately shows

The per-family table marks `behavioural_mention` as **still fails**, because the repair
scores ASR 1.00 on it. That family was written after the verifier was frozen, which makes
it the only measurement in this project that was not tuned against. A page that showed
only the improvement would be misleading.

The "What this does not claim" section lists the absent artefacts - no fine-tuned model,
no real memory image, no Volatility, no reproduced upstream benchmark - so the page
cannot be read as claiming more than was measured.

## Visual verification

Because this is a UI deliverable, it was checked by rendering it rather than by reading
the markup: `msedge --headless --screenshot` over `file://`, then the image inspected.
That is how two layout defects were caught - a note running into its own table label,
and a 0.875 accuracy bar rendering as a warning colour.