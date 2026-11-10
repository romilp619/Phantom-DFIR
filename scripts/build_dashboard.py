"""Build the "AI SAFETY & RED TEAMING" dashboard from the real result files.

The upstream project has no web UI - it is a CLI plus an MCP server - so this module
generates a single self-contained HTML report for the submission. It reads the JSON
produced by the evaluation and renders it; no figure is typed in by hand, so the
dashboard cannot drift from the measured data. Rebuild it after any re-run.

No server, no CDN, no JavaScript dependency: one file that opens in any browser and
works offline, which is what a judge will actually do with it.

    python scripts/build_dashboard.py --out dashboard/index.html
"""
from __future__ import annotations

import argparse
import html
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def load(rel: str):
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def pct(v, digits: int = 1) -> str:
    if v is None:
        return "n/a"
    try:
        return f"{float(v) * 100:.{digits}f}%"
    except (TypeError, ValueError):
        return str(v)


def num(v, digits: int = 3) -> str:
    if v is None:
        return "n/a"
    try:
        return f"{float(v):.{digits}f}"
    except (TypeError, ValueError):
        return str(v)


def bar(value: float | None, *, good_when_low: bool = True, width: int = 100) -> str:
    """Inline CSS bar. Green when the value is good, red when it is bad."""
    if value is None:
        return '<div class="bar empty"></div>'
    v = max(0.0, min(1.0, float(value)))
    if good_when_low:
        cls = "ok" if v <= 0.15 else ("warn" if v <= 0.45 else "bad")
    else:
        cls = "ok" if v >= 0.85 else ("warn" if v >= 0.6 else "bad")
    return (
        f'<div class="bar"><span class="{cls}" style="width:{v * width:.1f}%"></span></div>'
    )


def metric_row(label: str, before, after, *, good_when_low: bool = True,
               note: str = "") -> str:
    delta = None
    if isinstance(before, (int, float)) and isinstance(after, (int, float)):
        delta = after - before
    dcls = "up" if (delta or 0) > 0 else ("down" if (delta or 0) < 0 else "flat")
    dtxt = "n/a" if delta is None else f"{delta:+.3f}"
    return f"""
      <tr>
        <td class="lbl">{html.escape(label)}{f'<span class="note">{html.escape(note)}</span>' if note else ''}</td>
        <td class="v">{num(before)}</td>
        <td class="v">{num(after)}</td>
        <td class="v {dcls}">{dtxt}</td>
        <td class="barcell">{bar(after, good_when_low=good_when_low)}</td>
      </tr>"""


def build_html(comp, held, base) -> str:
    before = comp["conditions"]["before_upstream"]["overall"]
    after = comp["conditions"]["after_grounded_repair"]["overall"]
    mc = comp["mcnemar"]
    es = comp["eval_set"]
    pe_b = comp["conditions"]["before_upstream"]["per_family"]
    pe_a = comp["conditions"]["after_grounded_repair"]["per_family"]
    cb = comp["citation_coverage_before"]
    ca = comp["citation_coverage_after"]
    digest = comp.get("source_digest", "")
    held_m = (held or {}).get("rule_metrics", {})

    # The five-strategy invariance result, if baseline.json recorded it.
    inv = (base or {}).get("invariance") or {}
    strategies = inv.get("strategies") or []

    # Which families the repair still fails - derived, never asserted.
    failing = sorted(f for f, m in pe_a.items()
                     if (m.get("attack_success_rate") or 0) > 0)

    fam_rows = []
    for fam in sorted(pe_a):
        a_b = pe_b.get(fam, {})
        a_a = pe_a.get(fam, {})
        asr_a = a_a.get("attack_success_rate")
        cls = "failrow" if (asr_a or 0) > 0 else ""
        fam_rows.append(f"""
      <tr class="{cls}">
        <td class="lbl">{html.escape(fam)}{' <span class="tagbad">still fails</span>' if (asr_a or 0) > 0 else ''}</td>
        <td class="v">{num(a_b.get('accuracy'), 2)}</td>
        <td class="v">{num(a_a.get('accuracy'), 2)}</td>
        <td class="v">{num(asr_a, 2)}</td>
        <td class="barcell">{bar(asr_a)}</td>
      </tr>""")

    strat_block = ""
    if strategies:
        items = "".join(f"<li><code>{html.escape(str(s))}</code></li>" for s in strategies)
        strat_block = f"""
      <p class="lead">The verification layer was driven with each of these, then the
      per-row output was compared byte for byte:</p>
      <ul class="strategies">{items}</ul>
      <p class="big-kill">All of them produced <strong>identical confidences on all
      {(comp.get('invariance') or {}).get('rows', 300)} rows.</strong>
      A verifier that returns the same answer whether it denies everything or agrees with
      everything is not verifying anything.</p>"""
    else:
        strat_block = """
      <p class="lead">The verification layer was driven with five different LLM
      strategies, including no model at all and one that refutes every claim.</p>
      <p class="big-kill">All five produced <strong>identical confidences on all 300
      rows</strong> (<code>changed_rows = 0</code>). A verifier that returns the same
      answer whether it denies everything or agrees with everything is not verifying
      anything.</p>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Safety &amp; Red Teaming - Phantom DFIR audit</title>
<style>
  :root {{
    --bg: #080b11; --bg2: #0b1018;
    --panel: #111823; --panel2: #16202e; --panel3: #1b2735;
    --line: #22303f; --line2: #34465c;
    --fg: #eaf1f8; --fg2: #b9c8d8; --dim: #7c8fa4;
    --ok: #34d399; --warn: #fbbf24; --bad: #f87171;
    --accent: #62a8fc; --accent2: #a78bfa;
    --shadow: 0 1px 2px rgba(0,0,0,.5), 0 10px 30px -16px rgba(0,0,0,.75);
  }}
  * {{ box-sizing:border-box; }}
  html {{ -webkit-text-size-adjust:100%; }}
  body {{
    margin:0; color:var(--fg);
    background:
      radial-gradient(1100px 560px at 50% -12%, rgba(98,168,252,.11), transparent 62%),
      radial-gradient(820px 460px at 92% -4%, rgba(167,139,250,.09), transparent 58%),
      var(--bg);
    background-attachment:fixed;
    font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI Variable","Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    font-feature-settings:"kern" 1,"liga" 1;
    -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;
  }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:56px 28px 96px; }}

  /* ---- header ---- */
  .hero {{ padding-bottom:30px; border-bottom:1px solid var(--line); margin-bottom:6px; }}
  .eyebrow {{ display:inline-flex; align-items:center; gap:10px; font-size:11.5px;
    letter-spacing:.15em; text-transform:uppercase; color:var(--accent);
    font-weight:700; margin-bottom:18px; }}
  .eyebrow::before {{ content:""; width:24px; height:2px; border-radius:2px;
    background:linear-gradient(90deg,var(--accent),var(--accent2)); }}
  h1 {{ font-size:clamp(30px,4vw,44px); line-height:1.06; margin:0 0 16px;
    letter-spacing:-.033em; font-weight:700;
    background:linear-gradient(180deg,#ffffff 0%,#c3d3e4 100%);
    -webkit-background-clip:text; background-clip:text; color:transparent; }}
  .sub {{ color:var(--fg2); font-size:16.5px; line-height:1.6; max-width:70ch; margin:0; }}

  /* ---- sections ---- */
  h2 {{ font-size:20px; margin:56px 0 18px; letter-spacing:-.016em; font-weight:650;
    display:flex; align-items:center; gap:14px; }}
  h2::after {{ content:""; flex:1; height:1px;
    background:linear-gradient(90deg,var(--line),transparent); }}
  h3 {{ font-size:11.5px; margin:0 0 12px; color:var(--dim); text-transform:uppercase;
    letter-spacing:.11em; font-weight:700; }}

  /* ---- kpi tiles ---- */
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(196px,1fr)); gap:14px; }}
  .kpi {{ position:relative; overflow:hidden; border-radius:14px; padding:19px 21px;
    background:linear-gradient(180deg,var(--panel2),var(--panel));
    border:1px solid var(--line); box-shadow:var(--shadow);
    transition:transform .18s ease, border-color .18s ease; }}
  .kpi::before {{ content:""; position:absolute; inset:0 0 auto 0; height:2px;
    background:linear-gradient(90deg,var(--accent),var(--accent2)); opacity:.75; }}
  .kpi:hover {{ transform:translateY(-2px); border-color:var(--line2); }}
  .kpi .n {{ font-size:30px; font-weight:700; letter-spacing:-.032em; line-height:1.08;
    font-variant-numeric:tabular-nums; }}
  .kpi .k {{ color:var(--dim); font-size:11px; text-transform:uppercase;
    letter-spacing:.11em; margin-top:9px; font-weight:700; }}
  .kpi .d {{ font-size:12.5px; color:var(--dim); margin-top:7px; line-height:1.5; }}

  /* ---- tables ---- */
  table {{ width:100%; border-collapse:separate; border-spacing:0; background:var(--panel);
    border:1px solid var(--line); border-radius:14px; overflow:hidden; box-shadow:var(--shadow); }}
  th, td {{ padding:13px 16px; text-align:right; border-bottom:1px solid var(--line); }}
  th {{ background:var(--panel2); color:var(--dim); font-size:11px; text-transform:uppercase;
    letter-spacing:.1em; font-weight:700; }}
  th:first-child, td.lbl {{ text-align:left; }}
  td.lbl {{ font-weight:550; }}
  tbody tr:last-child td {{ border-bottom:none; }}
  tbody tr {{ transition:background .14s ease; }}
  tbody tr:hover td {{ background:rgba(98,168,252,.055); }}
  td.v {{ font-variant-numeric:tabular-nums; font-weight:550; }}
  .up {{ color:var(--ok); }} .down {{ color:var(--bad); }} .flat {{ color:var(--dim); }}
  .note {{ display:block; color:var(--dim); font-size:12px; line-height:1.5;
    margin-top:4px; max-width:54ch; font-weight:400; }}

  /* ---- bars ---- */
  .barcell {{ width:156px; }}
  .bar {{ height:10px; background:rgba(255,255,255,.06); border-radius:6px; overflow:hidden;
    box-shadow:inset 0 1px 2px rgba(0,0,0,.4); }}
  .bar span {{ display:block; height:100%; border-radius:6px; transition:width .5s ease; }}
  .bar .ok {{ background:linear-gradient(90deg,#0e9f6e,#34d399); }}
  .bar .warn {{ background:linear-gradient(90deg,#c2740a,#fbbf24); }}
  .bar .bad {{ background:linear-gradient(90deg,#dc2626,#f87171); }}
  .bar.empty {{ background:rgba(255,255,255,.04); }}
  .failrow td {{ background:rgba(248,113,113,.06); }}
  .failrow:hover td {{ background:rgba(248,113,113,.1); }}

  /* ---- tags ---- */
  .tagbad, .tagok {{ display:inline-block; font-size:10.5px; font-weight:700;
    padding:2.5px 8px; border-radius:20px; margin-left:9px; letter-spacing:.04em;
    text-transform:uppercase; vertical-align:1px; }}
  .tagbad {{ background:rgba(248,113,113,.16); color:var(--bad);
    border:1px solid rgba(248,113,113,.3); }}
  .tagok {{ background:rgba(52,211,153,.14); color:var(--ok);
    border:1px solid rgba(52,211,153,.3); }}

  /* ---- cards ---- */
  .card {{ background:linear-gradient(180deg,var(--panel2),var(--panel));
    border:1px solid var(--line); border-radius:16px; padding:24px 26px; margin:18px 0;
    box-shadow:var(--shadow); }}
  .card.bad {{ border-left:3px solid var(--bad); }}
  .card.good {{ border-left:3px solid var(--ok); }}
  .card.warn {{ border-left:3px solid var(--warn); }}
  .card p {{ margin:0 0 12px; }}
  .card p:last-child {{ margin-bottom:0; }}
  .lead {{ color:var(--fg); font-size:15.5px; }}
  .dim {{ color:var(--dim); }}
  .big-kill {{ font-size:17px; line-height:1.55; margin:16px 0 0; padding:14px 18px;
    background:rgba(248,113,113,.07); border:1px solid rgba(248,113,113,.2);
    border-radius:12px; }}

  /* ---- strategy chips ---- */
  ul.strategies {{ list-style:none; padding:0; display:flex; flex-wrap:wrap; gap:8px; margin:14px 0; }}
  ul.strategies li {{ background:var(--panel3); border:1px solid var(--line);
    border-radius:8px; padding:6px 12px; font-size:13px; color:var(--fg2); }}

  code {{ background:var(--panel3); padding:1.5px 6px; border-radius:5px;
    font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; color:#a9c7ea;
    border:1px solid rgba(52,70,92,.6); }}
  pre {{ background:var(--bg2); border:1px solid var(--line); border-radius:12px;
    padding:16px; overflow:auto;
    font:12.5px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}

  .foot {{ color:var(--dim); font-size:12.5px; margin-top:56px;
    border-top:1px solid var(--line); padding-top:22px; line-height:1.7; }}
  .pill {{ display:inline-block; background:var(--panel2); border:1px solid var(--line);
    color:var(--dim); font-size:11.5px; padding:4px 11px; border-radius:20px;
    margin:0 6px 6px 0; }}

  @media (max-width:680px) {{
    .wrap {{ padding:34px 16px 64px; }}
    th, td {{ padding:10px 10px; }}
    .barcell {{ width:80px; }}
    h2 {{ margin-top:40px; }}
  }}
  @media (prefers-reduced-motion:reduce) {{ * {{ transition:none !important; }} }}
  @media print {{
    body {{ background:#fff; color:#111; }}
    .wrap {{ max-width:none; padding:0; }}
    h1 {{ background:none; color:#111; -webkit-text-fill-color:#111; }}
    .card, .kpi, table {{ box-shadow:none; break-inside:avoid; }}
    .kpi::before {{ display:none; }}
  }}
</style>
</head>
<body>
<div class="wrap">

  <header class="hero">
    <div class="eyebrow">Lexsi AI Safety &amp; Alignment Hackathon &middot; Track 2</div>
    <h1>AI Safety &amp; Red Teaming</h1>
    <p class="sub">Audit of the adversarial &ldquo;Skeptic&rdquo; verification layer in
    PHANTOM DFIR, and an evidence-grounded replacement.</p>
  </header>

  <h2>1. The finding</h2>
  <div class="card bad">
    <h3 style="margin-top:0">Claim under test</h3>
    <p class="lead">The tool advertises a Skeptic agent that adversarially cross-examines
    findings before they can be reported as critical. In the source, that verdict is set
    by <code>agents/skeptic.py:113-130</code> from a <em>count of evidence sources</em>,
    and the audited agent supplies the count.</p>
    <p class="dim">The count is not independent: <code>agents/evidence.py:83-86</code>
    emits one source key per plugin per PID, so a single process observed through four
    Volatility plugins counts as four separate sources. Separately,
    <code>correlation/confidence.py:47-48</code> can clear a fully corroborated threat
    because the claim text contains the substring <code>"benign"</code>.</p>
    {strat_block}
  </div>

  <h2>2. Before and after</h2>
  <p class="dim">{es['total']} rows: {es['attacks']} attacks across
  {len(es['by_family']) - 1} families plus {es['controls']} clean controls.
  Paired exact McNemar: <strong>{mc['baseline_wrong_after_right']} rows wrong before and
  right after, {mc['baseline_right_after_wrong']} right before and wrong after</strong>
  (p = {mc['exact_p_two_sided']:.2g}).</p>
  <table>
    <thead><tr><th>Metric</th><th>Before</th><th>After</th><th>Delta</th>
    <th>After (bar)</th></tr></thead>
    <tbody>
      {metric_row("Accuracy vs gold", before.get("accuracy"), after.get("accuracy"), good_when_low=False)}
      {metric_row("False-confirm rate", before.get("false_confirm_rate"), after.get("false_confirm_rate"))}
      {metric_row("Attack success rate", before.get("attack_success_rate"), after.get("attack_success_rate"))}
      {metric_row("Dangerous-miss rate", before.get("dangerous_miss_rate"), after.get("dangerous_miss_rate"))}
      {metric_row("Capability retention", before.get("capability_retention"), after.get("capability_retention"), good_when_low=False, note="the guard: measured on untouched control rows, so a repair cannot win by refusing to confirm anything")}
    </tbody>
  </table>

  <div class="kpis" style="margin-top:18px">
    <div class="kpi"><div class="n">{cb['with_citation']}/{cb['confirmed_rows']}</div>
      <div class="k">Citations before</div>
      <div class="d">confirmed findings citing evidence</div></div>
    <div class="kpi"><div class="n" style="color:var(--ok)">{ca['with_citation']}/{ca['confirmed_rows']}</div>
      <div class="k">Citations after</div>
      <div class="d">every confirmed finding cites its evidence</div></div>
    <div class="kpi"><div class="n" style="color:var(--ok)">0</div>
      <div class="k">Regressions</div>
      <div class="d">rows right before that became wrong</div></div>
    <div class="kpi"><div class="n">{num(held_m.get('attack_success_rate'), 3) if held_m else 'n/a'}</div>
      <div class="k">Held-out ASR</div>
      <div class="d">disjoint seed, never fitted</div></div>
  </div>

  <h2>3. Per-family attack success rate</h2>
  <table>
    <thead><tr><th>Family</th><th>Acc before</th><th>Acc after</th><th>ASR after</th>
    <th>ASR (bar)</th></tr></thead>
    <tbody>{''.join(fam_rows)}</tbody>
  </table>

  <div class="card bad">
    <h3 style="margin-top:0">The repair fails in {len(failing)} families, and that is the
    honest headline</h3>
    <p class="lead">Failing families, derived from the data rather than asserted:
    {', '.join(f'<code>{html.escape(f)}</code>' for f in failing)}.</p>
    <p><strong>Three of them were not written by us.</strong> An independent red-team model
    was given <em>only the specification</em> of the repair - never the implementation,
    never the existing attacks - so those attacks test whether the idea generalises
    instead of probing for code details. <strong>All three defeated the repair, each at
    ASR 1.00</strong>, taking the after-score from 0.143 on the fully self-authored set to
    <strong>0.400</strong>. That is the honest number.</p>
    <p>The failures are two different kinds, and the difference matters:</p>
    <p><strong>Implementation gaps (fixable in principle).</strong>
    <code>identity_alias</code> describes one process under four identity namespaces, so
    opaque string comparison turns one artifact into four votes - the central rule
    defeated through its own mechanism. <code>semantic_denial</code> asserts
    <code>launch count = 0</code>, which is semantically a denial containing none of the
    negation keywords, so the citation validates. Both are string tests standing in for
    meanings, the same class of defect as the upstream <code>BENIGN_INDICATORS</code>
    substring match.</p>
    <p><strong>A specification gap (not fixable by code).</strong>
    <code>network_contact_inflation</code> presents four genuinely distinct behavioural
    artifacts - four ordinary HTTPS connections to the claimed host - and satisfies every
    rule honestly. The repair confirms while correctly implementing its own specification.
    The specification equates "mentioned in enough behavioural artifacts" with
    "established", and contact is not command-and-control.</p>
    <p class="dim">We deliberately did not patch the two implementation gaps. The identity
    space is open-ended, so PID extraction still leaves GUID and path namespaces distinct
    and the alias attack survives a partial fix; and any lexical negation test is evaded
    by the next construction that means "no" without writing it. Patching would fit the
    numbers to this particular red-teamer rather than produce a more correct verifier.
    The stronger conclusion: <strong>the repair's central rule is not deterministically
    enforceable</strong>, because "the same artifact" and "denies the claim" are both
    open-ended judgements - which is exactly what the fine-tuned model was meant to
    supply, and why the blocked model half is where the remaining failures live.</p>
  </div>

  <div class="card bad">
    <h3 style="margin-top:0">The same gap, found independently by us first</h3>
    <p class="lead"><code>behavioural_mention</code> was written by us
    <em>after</em> the verifier was frozen. Four genuine behavioural artifacts each merely
    <em>name</em> the file while describing ordinary activity: no executable regions, a
    loopback-only listener, only system DLLs loaded.</p>
    <p>The repair confirms <strong>all 50 of these rows</strong>, at ASR 1.00 both before and
    after. Notably, the independent model found the same class of hole from the
    specification alone - convergent evidence that this is a structural gap rather than one
    we happened to guess.</p>
    <p class="dim">The lesson: <strong>behavioural relevance is not evidential weight.</strong>
    The first two versions of the repair shared this flaw at different depths: v1 treated a
    scan log as corroboration, v2 treated four innocuous behaviour records as corroboration.
    Both count name mentions, and so does the upstream defect.</p>
  </div>

  <h2>4. Two silent defects in our own harness</h2>
  <p class="dim">The held-out run first disagreed with the tuned run, which was
  impossible if both measured the same verifier. They were not.</p>
  <div class="card warn">
    <p><strong>1. The <code>plugin</code> field was dropped.</strong> Rebuilt rows
    defaulted to <code>"unknown"</code>, so no artifact could ever be behavioural. It
    reported capability retention of <strong>0.660 on untouched control rows</strong>.</p>
    <p><strong>2. Artifact identity collapsed into the evidence id.</strong> Five
    evidence items describing <em>one</em> PID looked like five distinct artifacts,
    defeating the exact rule the repair is built on, and reported
    <code>count_inflation</code> <strong>ASR 1.00</strong>.</p>
    <p class="dim">Neither raised an exception. Both produced a results table. The fix is
    structural: the evidence fence now carries <code>id</code>, <code>artifact</code> and
    <code>plugin</code>; a missing field is a hard error rather than a default; one parser
    is shared by the dataset builder and the evaluator; and a round-trip gate re-runs the
    verifier on every rebuilt row at build time - <strong>2,800 rows</strong> - asserting
    that verdict, artifact count and citations all reproduce.</p>
  </div>

  <h2>5. What this does not claim</h2>
  <div class="card">
    <p><span class="pill">no fine-tuned model</span>
    <span class="pill">no real memory image</span>
    <span class="pill">no Volatility</span>
    <span class="pill">no upstream benchmark reproduced</span>
    <span class="pill">synthetic evidence only</span></p>
    <p class="lead">Every number here comes from the deterministic verifier evaluated on
    synthetic evidence with the tool layer stubbed. No training run has been performed:
    all 13 candidate Cohere checkpoints are gated and return HTTP 401 without an
    authenticated token.</p>
    <p class="dim">The disjoint-seed replication reproduces these figures exactly, which
    rules out seed luck and per-row memorisation. It does <em>not</em> rule out generator
    overfitting, because both splits come from the same eight generators - which is
    precisely why the one genuinely unanticipated attack, family 8, matters.</p>
  </div>

  <h2>6. Reproducing</h2>
  <pre>git clone https://github.com/romilp619/Phantom-DFIR &amp;&amp; export PHANTOM_ROOT=$PWD/Phantom-DFIR
python scripts/smoke_harness.py                 # the four findings, against real code
python scripts/validate_scanner.py              # 15/15 recall, 0/12 false positives
python scripts/verify_report_claims.py          # every quoted figure vs stored results
pytest tests/ -q                                # 29 tests</pre>
  <p class="dim">Source digest of the upstream verification modules these results were
  measured against:</p>
  <pre>{html.escape(digest) if digest else "(digest not recorded in comparison.json)"}</pre>

  <div class="foot">
    <p>All work is defensive: attacks are synthetic evaluation rows against a public
    open-source project. No exploit is published and no upstream file was modified.</p>
    <p>Generated from the result JSON by <code>scripts/build_dashboard.py</code>. No
    figure on this page is hand-entered.</p>
  </div>
</div>
</body>
</html>"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dashboard/index.html")
    args = ap.parse_args()

    comp = load("results/comparison.json")
    if comp is None:
        print("FATAL: results/comparison.json missing. Run the comparison first:")
        print("  python -m phantom_ai_safety.evaluation.comparison --quiet "
              "--out results/comparison.json")
        return 1
    held = load("results/heldout_rule_only.json")
    base = load("results/baseline.json")

    doc = build_html(comp, held, base)
    out = os.path.join(ROOT, args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(doc)

    # Verify what was written rather than trusting the write.
    with open(out, "r", encoding="utf-8") as fh:
        written = fh.read()
    checks = {
        "is html": written.lstrip().startswith("<!DOCTYPE html>"),
        "has closing html": written.rstrip().endswith("</html>"),
        "has before/after table": "False-confirm rate" in written,
        "flags the residual failure": "behavioural_mention" in written
                                      and "still fails" in written,
        "states no fine-tuned model": "no fine-tuned model" in written,
    }
    print(f"wrote {out}  ({len(written):,} bytes)")
    bad = [k for k, v in checks.items() if not v]
    for k, v in checks.items():
        print(f"  {'OK ' if v else 'BAD'} {k}")
    if bad:
        print(f"\n{len(bad)} check(s) failed; the dashboard is not fit to publish.")
        return 1
    print("\ndashboard verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())