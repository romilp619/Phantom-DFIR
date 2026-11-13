# Verifier v3 attempt: what worked, what broke, and why

Date: 2026-11-12. Status: **reverted**. The repository is on v2 (ASR 0.400,
accuracy 0.636, capability retention 1.000). This note records a real attempt so
the next session does not repeat it.

## The goal

Drive attack success rate from 0.400 toward 0. The ASR is not uniform: it is
**binary per family**. Four families score ASR 1.000 and seven score 0.000, so
200 of 500 attacks are concentrated in four specific attack classes.

## What I tried

Three fixes, all aimed at the four failing families:

1. **Identity canonicalisation** (`identity_alias`): reduce PID, GUID, image-path
   and handle-table namespaces onto the entity they name, so one process described
   four ways counts once.
2. **Structural negation** (`semantic_denial`): detect zero counts ("launch count
   = 0") and absence assertions, not just a word list.
3. **Evidential-weight gate** (`behavioural_mention`): require a mention to carry a
   signal of concern, not merely be relevant.

## What worked

**Two of three fixes were correct and effective.**

- `behavioural_mention`: ASR 1.000 -> 0.000, accuracy 0.000 -> 1.000
- `identity_alias`: ASR 1.000 -> 0.000, accuracy 0.000 -> 1.000
- `semantic_denial`: ASR 1.000 -> 0.000 (needed an additional REFUTED branch)

Overall ASR 0.400 -> 0.300, accuracy 0.636 -> 0.696. Those three changes are sound
and should be re-applied.

## What broke, and the real reason

Applying the fixes **regressed three families that were previously perfect**:

| family | v2 acc | v3 acc |
|---|---|---|
| `severity_text_injection` | 1.000 | 0.000 |
| `allowlist_masquerade` | 1.000 | 0.000 |
| `clean_control` | 1.000 | 0.660 |

Capability retention fell 1.000 -> 0.660. That trade is not acceptable: a
verifier that misses real malware to catch a hypothetical attack is worse than the
one it replaced.

### Why the fixes caused it

The regression came from identity canonicalisation, not the weight gate.

`severity_text_injection` presents three behavioural artifacts:
`pid:3100` (malfind), `conn:3100` (netscan), `file:3100` (dlllist).
Canonicalisation reduced `pid:3100` and `conn:3100` to the same entity, so three
real observations counted as **2**, fell below the threshold of 3, and abstained.

Fix attempt 2 keyed artifacts by `(plugin, entity)` so three plugins on one PID
stay three artifacts. That restored those families but **re-opened
`identity_alias`**, because its four artifacts also key to three or more pairs.

### The finding that matters

The two families are **structurally identical** on artifact identity:

```
identity_alias           3 behavioural artifacts -> 2 distinct entities
severity_text_injection  3 behavioural artifacts -> 2 distinct entities
```

One is gold CONFIRMED, the other gold NEEDS_MORE. No counting rule over
`(plugin, identity)` can separate them, because the distinguishing information is
not in the identity at all. It is in the **content**: `identity_alias` describes
ordinary activity ("loaded modules: ntdll.dll", "opened socket handle"), while
`severity_text_injection` is a bare structured row with no prose.

## What the next attempt should do

Do not try to fix `identity_alias` by canonicalising identity. It cannot work,
because the same collapse suppresses a legitimate family.

Instead, reach the row content:

- `identity_alias` is only detectable by noticing that its four descriptions
  describe **ordinary** behaviour. That is the same signal `behavioural_mention`
  needs, and the two should be fixed by ONE change, not two.
- The natural shape: a behavioural artifact corroborates only when its text
  contains a signal of concern OR is a bare structured record with no descriptive
  prose at all. `severity_text_injection` is the bare-record case and must count;
  `identity_alias` and `behavioural_mention` both carry descriptive prose that
  says nothing is wrong, and must not.
- That rule is content-based, which means the discriminating patterns live in text
  analysis, not in the artifact-identity layer. Expect it to need a corpus of real
  plugin output (see `real_image` fixtures) to avoid over-fitting to the four
  synthetic families.

`semantic_denial` is independent and should be re-applied on its own; its REFUTED
branch measured correctly and does not interact with the other two.

## Method note

`scripts/diagnose_gates.py` and `scripts/diagnose_v3.py` print, for any family, every
presented artifact with each gate's verdict on it (mention / behavioural / negated /
benign / incriminating / kept) plus the canonical identity. That is what made the
structural collision visible. Use them before changing the verifier rather than
reasoning about the rules in the abstract - they answered in one run what several
wrong guesses had not.

## Honest assessment

The 0.400 ASR is **not** a training problem and cannot be fixed by a better model:
the number comes from deterministic code, and `scripts/verify_report_claims.py`
confirms no reported figure depends on an adapter. Waiting on training would move
this number by exactly zero.