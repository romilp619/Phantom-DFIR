# Real memory image integration test

Fulcrum graded integration with the existing architecture as the weakest criterion,
citing "no real memory image". This closes that gap with a measurement rather than a
claim.

## What was run

- **Image**: `memdump.mem`, 512 MB, Windows Server 2008 SP1 x86, from
  `samsclass.info/121/proj/memdump.7z` (124 MB compressed, direct download, no auth).
  A net dump, not a declared-clean host, but the plugin output contains no injected
  content, so any finding is a false positive by construction.
- **Volatility**: 3 Framework 2.28.2, matching the version the upstream project pins.
- **Plugins**: the seven the upstream collection layer wraps.

The image is **not committed**. `test-images/` is gitignored, along with `*.raw`,
`*.vmem`, and `*.lime`. A 512 MB binary in git would make every clone miserable, and
no DFIR project ships images this way. Fetch with:

```
curl -o test-images/memdump.7z https://samsclass.info/121/proj/memdump.7z
7z x test-images/memdump.7z -otest-images
bash scripts/run_real_image_plugins.sh
```

## Result

```
plugin                      chars  findings   severity    py ms   rust ms
-------------------------------------------------------------------------
windows.cmdline             2,947         0      clean     11.5      48.7
windows.dlllist           182,396         0      clean     95.9     199.0
windows.malfind             3,887         0      clean      2.0      43.7
windows.netscan             8,194         0      clean      4.3      43.4
windows.pslist              4,519         0      clean      2.4      40.4
windows.svcscan           122,471         0      clean     66.4     151.0

real evidence scanned : 324,414 chars across 6 plugin outputs
flagged as manipulated: 0 of 6
guard disagreements   : 0

RESULT: no false positives on a real memory image
```

**Zero false positives on 324,414 characters of genuine forensic output.** Zero
disagreements between the Python scanner and the Rust guard.

## Findings from this test

**1. `windows.hivelist` does not exist in Volatility 3.** It exits 2 with a usage
error. The plugin moved to `windows.registry.hivelist`. This is worth knowing because
the upstream project's `vol3_tools.py` was verified against 2.28.0, and the rename
happened within the 2.x line. Anyone wiring the collection layer to Vol3 should call
the namespaced name.

**2. The Rust guard is slower than Python on large artifacts, not faster.** Measured
on the same evidence:

```
python in-process, all 6      : 188.2 ms
rust batched (1 process), all 6: 328.1 ms
ratio                          : 1.74x
```

Profiled further: process spawn is only 31.9 ms of that, so the gap is regex work
(270.6 ms vs 188.2 ms). CPython's `re` engine is faster than the Rust `regex` crate on
this workload. This does not weaken the reason for the guard, which is a process
boundary and memory safety rather than speed, but it does mean the honest claim is:

- the guard is **safe by construction**, and
- the guard is **slightly slower per character** on large artifacts

The earlier "0.119 ms per artifact" figure was measured on the synthetic attack
corpus, where 95% of artifacts are cache hits and each is one short line. It does not
generalise to a 182 KB dlllist. Both numbers are true; they describe different work.

**3. Real plugin output is far messier than the synthetic rows.** The `dlllist`
output is 182,396 characters of tab-separated wide table with truncated paths and
`Disabled` markers. The synthetic red-team rows are single sentences. Scanning the
real file caught nothing, which is the correct outcome, but it exercised the scanner
against formatting the synthetic corpus never produced.

## What this does not prove

- The 550-row accuracy numbers do not transfer. A real image has no ground truth for
  "did the agent correctly refuse to confirm a claim", so it cannot reproduce the
  McNemar test. This test proves the scanner is silent on real evidence and the guard
  agrees; it does not re-measure the repair.
- The upstream collection layer itself was not executed end to end, because that
  requires the project's own `config.py` to point at a Volatility binary and would
  pull in its full agent loop. The plugins were invoked directly with the same
  arguments the wrapper builds.
- One image, one OS, one architecture. A Windows 10 x64 image with a genuine injected
  payload would be a stronger test of detection, as opposed to non-detection.

## Reproducing

```
python scripts/test_real_image.py          # scan and cross-check
bash scripts/run_real_image_plugins.sh     # re-run the plugins
```

`test_real_image.py` exits non-zero only on guard disagreement, not on findings,
because a finding on a real image is a result to inspect rather than a test failure.