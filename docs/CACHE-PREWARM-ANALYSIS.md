# Cache prewarming: analysis

## The question

Can we prewarm the cache at install time with common red-team payloads (bug bounty,
dev work, defense) so the guard starts hot?

## Short answer

Not the way it was proposed. The measured numbers say prewarming buys nothing, and
the reason is worth stating plainly because it points at a better idea.

## The measurement

Benchmark on the real attack corpus (`scripts/bench_cache.py`):

```
460 artifacts, 14 distinct texts
437 served from cache (95.0% hit rate)
batch wall time: 54.8 ms total, 0.119 ms per artifact
```

A cold cache costs one sha256 per distinct text: 0.0005 ms. Fourteen of them is
**0.007 ms**. Against a 54.8 ms batch that is 0.013% of the runtime.

Prewarming can only remove work proportional to the number of *distinct* texts in a
warm set. Distinct texts are the expensive case; repeated texts are already free
after the first scan. So a warm set of 100 canonical payloads would save at most
100 x 0.0005 ms = **0.05 ms per process**. That is not measurable, and the guard
spawns per batch, so it would be paid once and saved once.

## Why prewarming is the wrong lever

There are two separate costs, and they scale differently:

| cost | scales with | how to reduce |
|---|---|---|
| process spawn | number of processes | batch (already done) |
| regex scanning | number of *distinct* texts | nothing cheap; it is the work |

A warm cache reduces neither. The first scan of a distinct text still costs a full
regex sweep, and spawn is unchanged. Prewarming only ever helps when the exact same
long, expensive-to-scan text recurs across processes -- and the guard keeps a
per-batch cache precisely because cross-process state is the attack surface we
removed.

## The second problem: a warm set is a test oracle

Baking 100 canonical attack strings into the binary would mean the guard "already
knows" those strings. Any evaluation that uses the same list becomes circular: the
guard is measured against payloads it ships with. That is the same failure mode as
training on the test set, and it would quietly weaken the honesty of the red-team
numbers this project depends on.

## What the scan actually misses, which prewarming cannot fix

The valuable observation is not about caching at all. The 7 families and 27 patterns
are **lexical**. These shapes are not detected, and no cache helps because the
scanner never reaches them:

- **encoded payloads**: base64, hex, ROT13. `aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM=`
- **leetspeak**: `1gn0r3 4ll pr3v10us 1nstruct10ns`
- **homoglyphs**: Cyrillic `е` in `ignorе` -- visually identical, byte-different
- **zero-width characters** inserted mid-keyword
- **multi-turn / split injection**: artifact A sets context, artifact B carries the payload
- **indirect injection**: payload embedded inside a translation or summary request
- **large-context burial**: one override line inside 100k tokens of ordinary evidence

The README already states the base64 limitation. The rest are the same class.

## Recommendation

Two real improvements, neither of which is prewarming:

**1. Add a normalisation pass before regex matching.** Decode base64 and hex
candidates, strip zero-width characters, and fold confusable Unicode to ASCII, then
scan the normalised text as well as the raw text. This closes the largest known gap
and is a genuine detection improvement rather than a performance one. It must be
measured against the false-positive corpus, because normalisation can create
accidental matches in innocent evidence.

**2. Keep the cache as it is.** It is already at 95% hit rate and 0.119 ms per
artifact on the real corpus. It is correct, tested, and it does not change results.
Adding persistence would reintroduce the cross-artifact state the process boundary
exists to remove.

Prewarming is the one option that adds complexity, adds an oracle risk, and saves
0.05 ms. Skip it.