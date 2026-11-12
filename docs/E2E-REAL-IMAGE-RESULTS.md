# Local end-to-end run: results, and two corrections to my own findings

**Date:** 2026-11-12. **Scope:** local only. The repository working tree was not modified;
all work happened in `/tmp` and `C:\Users\Owner\Downloads\redirect\`.

---

## What was run

The real engine against the **real 512 MB memory image** at
`phantom-safety/test-images/memdump.mem`, using the installed toolchain:

```
vol : /root/phantom-eval-venv/bin/vol   (Volatility 3 Framework 2.28.2)
img : 536,870,912 bytes
```

This matters because **imports are not runs**. Phase E proved the modules load; this proves
the forensic pipeline actually processes evidence.

### The image is genuine, verified by three independent signals

| check | result |
|---|---|
| Size | 536,870,912 bytes exactly (512 MiB) |
| Non-zero content | `RCRD` record structure at offset 16,777,216 |
| Provenance | 2014-01-08 11:54:23, matching the CFReDS admin memory dump |

### Volatility identified it correctly

```
Kernel Base  0x8183a000
Is64Bit      False
IsPAE        True
NTBuildLab   6001.18000.x86fre.longhorn_rtm.0
Major/Minor  15.6001
SystemTime   2014-01-08 17:54:20+00:00
NtSystemRoot C:\Windows
Symbols      ntkrpamp.pdb/37D328E3...json.xz   (resolved)
```

Windows Server 2008 SP1, 32-bit, PAE, x86 kernel (hence `ntkrpamp`). **Symbol resolution
worked** - it fetched and matched the correct PDB. That is the single most likely thing to
break in a memory-forensics pipeline, and it works.

### Real plugin output

```
windows.info     OK   symbols resolved, 32 fields
windows.pslist   OK   52 lines, 50 processes with PID/PPID/Offset/Threads/CreateTime
windows.cmdscan  OK   4 lines
windows.consoles OK   4 lines
windows.registry.hivelist  OK  17 lines
```

`pslist` output is real: `System` (PID 4), `smss.exe` (404), `csrss.exe` (472/516),
`wininit.exe` (524), all with timestamps from 2014-01-08 02:17. The engine is processing
genuine evidence, not a fixture.

---

## Correction 1: `windows.hivelist` IS invalid, and the repo already knows

```
windows.hivelist           exit=2  "invalid choice"
windows.registry.hivelist  exit=0  17 lines
```

The plugin was **renamed** in Volatility 3. `scripts/run_real_image_plugins.sh:14` already
documents this:

> `# windows.hivelist does not exist and exits 2; windows.registry.hivelist works.`

So the current harness script is correct. The stale name survives only in an older
`test-images/plugin-output/` snapshot, which is why that directory contains a
`windows.hivelist.err` with 5,976 bytes of usage text and a zero-byte output file.

**Verdict: not a live bug.** It is a stale artefact from a pre-fix run. Worth regenerating
that snapshot so a reader does not mistake it for a current failure.

---

## Correction 2: my `windows.consoles` finding was a FALSE POSITIVE

I reported `windows.consoles` as invalid and called it "a real, live bug in shipped engine
code, called from three places." **That was wrong.**

The method was bad: I ran `vol <plugin> --help` and treated "invalid choice" as proof. But
`vol` cannot resolve a plugin name without an image loaded, so that probe produces false
negatives. Running it properly against the image:

```
windows.consoles  exit=0  4 lines    -> VALID
```

It appears in `disk_correlator.py:2541`, `disk_correlator.py:2684`, and
`tools/vol3_tools.py:143`, and **all three are fine.** No bug. No fix needed.

The lesson matches one already learned this session: a probe that does not reproduce the
real invocation is not evidence. `--help` on a plugin name is not the same operation as
running the plugin.

---

## Untested surface, named

- **The Python pipeline itself** (`main.py`, `phantom_router.py`) was not driven end-to-end.
  Volatility works and the tools modules import, but nothing has walked evidence from the
  tool layer through correlation into a report.
- **`disk_correlator.py`'s full plugin sweep** - 11 plugins including the renamed one was
  not executed as a unit.
- **The LLM layer** - `tools/llm_provider.py` imported cleanly, but no provider was called,
  so `langchain-core>=0.3.0` remains unexercised at runtime.
- **`curatorkit`** - publishability still unknown.

---

## Summary

| finding | status |
|---|---|
| Engine runs against real evidence | **CONFIRMED** - symbols resolve, pslist real |
| `windows.hivelist` invalid | true, pre-documented, stale-artefact only |
| `windows.consoles` invalid | **FALSE - my error, corrected here** |
| Repository touched | no - all work in `/tmp` |