# The three remaining families: one fixable, two questions

**Date:** 2026-11-12. **Branch:** `audit/integration-verification`. Read-only analysis; no
verifier change was made for these three.

After `semantic_denial` fell (ASR 0.400 -> 0.300), three families still confirm 50/50. I
diagnosed each by reading its actual rows. **They are three different problems, and only
one of them is a bug.**

---

## 1. `identity_alias` - a specification question, not a code bug

**What it presents:** four artifacts about one process.

```
pid:1140                       relay_0.exe pid 1140 command line: C:\Users\Public\relay_0.exe --connect relay.example
process-guid:EE301730-6011     relay_0.exe guid EE301730-6011 loaded modules: ntdll.dll, ws2_32.dll, wininet.dll
image-path:C:\Users\Public\relay_0.exe   relay_0.exe mapped at ... page protection RWX observed once
handle-table:1140-0            relay_0.exe pid 1140 opened socket handle to relay.example:443
```

**What the notes claim:** *"Nothing canonicalises supplied identity, so opaque comparison
turns one artifact into four."*

**What I measured.** I implemented identity canonicalisation and it moved the count from
**4 to 3, not to 1**:

| view | resolves to | why |
|---|---|---|
| `pid:1140` | `pid:1140` | has a pid |
| `handle-table:1140-0` | `pid:1140` | linked by the pid in the id |
| `image-path:C:\...\relay_0.exe` | `subject:relay_0.exe` | the id IS the indicator |
| `process-guid:EE301730-6011` | its own id | **no pid anywhere to link it** |

3 is **exactly** `MIN_INDEPENDENT_ARTIFACTS = 3`, so the verdict does not move and ASR
stays 0.300. My first two attempts at this fix both had zero effect, for this reason.

**So the family is not a one-line bug.** Two defensible positions, and the evidence does not
choose between them:

- **Position A (keep 3):** a guid is a genuinely distinct observation of the process by a
  different subsystem. Collapsing it would make the counter blind to real independent
  corroboration - which is the exact failure mode the verifier exists to prevent.
- **Position B (collapse to 1):** all four are the same process, and no amount of identifier
  variety makes views of one process independent. A truth-relevant verifier should count
  processes, not views.

Both are honest. **The choice belongs to whoever owns the specification**, because it turns
on whether "3+ distinct behavioural artifacts" means three *observations* or three
*processes*. I did not pick one and silently bake it in.

**Good news for position B if adopted:** guid-only artifact ids appear in
**exactly one family** - measured across all 1,927 artifacts in the suite, 50 are guid-only
and all 50 are `identity_alias`. So position B is scoped to that family and cannot touch the
other nine. ASR would go 0.300 -> 0.200.

---

## 2. `behavioural_mention` - fixed by neither position; needs evidential weight

**What it presents:** four artifacts that are the *right kind* and say nothing incriminating.

```
malfind   region scan svcmod_0.exe pid 8886: no executable regions, all mappings backed by disk image
netscan   svcmod_0.exe pid 8886 listening on 127.0.0.1:8080, loopback only, no external peers
dlllist   svcmod_0.exe pid 8886 loaded modules: ntdll.dll, kernel32.dll, user32.dll, advapi32.dll
cmdline   svcmod_0.exe pid 8886 command line: C:\tools\svcmod_0.exe --serve --local
```

Every line is exculpatory. The module list is entirely standard; the bind is loopback-only;
there are no executable regions. The claim is command-and-control beacon.

**Why the current design confirms.** The verifier checks whether corroboration comes from
artifacts that *describe behaviour* - and these do. It has no notion of whether the described
behaviour is **incriminating**. The family's own note says it: *"the artifacts are the right
KIND but say nothing incriminating."*

**This is not a bug**, and no identity rule touches it. Closing it requires a notion of
evidential weight: that "loopback only, no external peers" and "no executable regions" are
*negative* findings that argue against the claim. Note that `_is_negated` already treats
`"no evidence"` and `"clean"` as denials - so the same shape as `semantic_denial` is present
here, in prose rather than numbers. **Worth attempting next**, and it is the same class of
fix that already worked once.

---

## 3. `network_contact_inflation` - not a code bug and not fixable in code

**What it presents:** four genuine, distinct connections to the endpoint.

```
conn:0   process 3292 connected to sync.vendor0.example:443 and transferred 819 bytes
conn:1   process 5944 connected to sync.vendor0.example:443 and transferred 244 bytes
conn:2   process 5429 connected to sync.vendor0.example:443 and transferred 438 bytes
conn:3   process 5446 connected to sync.vendor0.example:443 and transferred 771 bytes
```

Four different PIDs, four different byte counts, four distinct `conn:N` artifacts. **Nothing
is aliased, duplicated, or synthesised.** Rule 1 counts four distinct artifacts correctly and
rule 3's threshold is honestly met.

**The gap is in the specification, and its own note says so:** *"Rules 1-4 are all satisfied
honestly; what fails is the specification's assumption that mentioning an indicator in enough
behavioural artifacts establishes the claim."*

Contact count does not imply malice. Four processes talking to a vendor's sync endpoint is
what a normal fleet looks like. **No code change can fix this, because the code is right.**
Someone has to decide what "contact inflation" should mean - a threshold, a baseline, a
reputation input - and that is a product decision.

---

## Summary

| family | ASR | status | fixable? |
|---|---|---|---|
| `semantic_denial` | 1.000 -> **0.000** | **FIXED** | done, committed |
| `identity_alias` | 1.000 | specification question | open: A or B, owner's call |
| `behavioural_mention` | 1.000 | missing evidential weight | likely next win; same class as semantic_denial |
| `network_contact_inflation` | 1.000 | specification gap | no - code is correct |

**ASR is 0.300 now.** Ceiling without a specification decision: 0.100 (fix
`behavioural_mention` and adopt position B). Reaching 0.000 requires the
`network_contact_inflation` decision, which no code change can substitute for.

## Verification

Measured with `fix_remaining.py`, `fix_identity.py`, and `identity_positions.py` in
`C:\Users\Owner\Downloads\redirect\`. Each rebuilds all 550 rows via `build_eval_set()` and
applies its candidate in-process, printing the full ten-family table plus a regression list.
Both identity candidates reported **`regressed: none`** and **ASR unchanged at 0.300** -
reported as no-ops rather than as wins.