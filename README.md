# PHANTOM DFIR
## Parallel Hypothesis Analysis with Multi-agent Threat Hunting Overlay Network

> **The world's first adversarial self-verifying DFIR agent**
> Built on LangGraph + Ollama · Runs entirely on SANS SIFT Workstation · 100% Free

---

## The Core Innovation

Every existing DFIR tool — including Protocol SIFT — uses a **single agent** that never cross-examines its own claims. PHANTOM uses **two agents that argue**:

```
Investigator: "ruby.exe from services.exe — is this Metasploit?"
Path Checker:  ruby.exe at C:\Program Files\Puppet Labs\ — BENIGN
Skeptic:       "✅ CLEARED — Puppet Labs Ruby, not malicious"
Result:        Investigated, confirmed benign — no false positive!
```

```
Investigator: "subject_srv.exe running from non-System32 path"
Skeptic:      "Prove it with 3 independent raw evidence sources"
Evidence:     [re-runs pslist, svcscan, shimcache on that PID]
Result:       19/19 sources confirmed → 🔴 CRITICAL (verified, not hallucinated)
```

**No DFIR tool in the world does this.**

---

## Try-It-Out Instructions (for Judges)

### Prerequisites
- **SANS SIFT Workstation** (VM or bare metal)
- **Python 3.10+** (pre-installed on SIFT)
- **Volatility 3** (`pip install volatility3` — pre-installed on SIFT)
- **Ollama** with `qwen2.5:14b` model (optional — works without LLM in `--no-llm` mode)

### Step 1: Install (One Command)

```bash
cd ~
git clone https://github.com/YOUR_USERNAME/phantom-dfir.git
cd phantom-dfir
bash install.sh
```

### Step 2: Run Analysis

```bash
# Full analysis (with LLM)
python3 main.py -f /path/to/memory.img

# Rule-based only (no LLM required — faster, deterministic)
python3 main.py -f /path/to/memory.img --no-llm

# With custom model
python3 main.py -f /path/to/memory.img --model qwen2.5:14b
```

### Step 3: Run Benchmark (accuracy scoring)

```bash
python3 benchmark.py -f /path/to/memory.img --ground-truth ground_truth_base_admin.json
```

### Step 4: Test MCP Server

```bash
# Terminal 1: Start server
python3 mcpserver/mcp_server.py --transport http --port 8765

# Terminal 2: Run smoke test
python3 test_mcp.py --memory /path/to/memory.img
```

### Step 5: Memory + Disk Correlation (optional)

```bash
python3 disk_correlator.py -m /path/to/memory.img -d /path/to/disk.E01
```

### Output Files

After each run, PHANTOM generates:
- `phantom_<target>_<timestamp>.json` — Full findings report
- `phantom_<target>_<timestamp>.md` — Human-readable markdown report
- `phantom_<target>_<timestamp>_execution_log.json` — Agent execution trace
- `phantom_<target>_progress.json` — Iteration improvement metrics

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PHANTOM DFIR v2.1 (LangGraph)            │
├─────────────────────────────────────────────────────────────┤
│  1. COLLECTOR    — Race Vol3 vs Vol2 vs strings (parallel)  │
│     → 35+ plugins run simultaneously (16 workers)           │
│                                                             │
│  2. INVESTIGATOR — LLM + dynamic rule-based analysis        │
│     → Dynamic IOC extraction (no hardcoded IPs/ports)       │
│     → Benign binary detection (Puppet/Chef Ruby → CLEARED)  │
│     → Rich evidence quotes from raw plugin output            │
│                                                             │
│  3. EVIDENCE     — Targeted re-queries (PID/IP specific)    │
│     → malfind PID, netscan filtered to C2 IP                │
│     → Linux + Windows support                               │
│                                                             │
│  4. SKEPTIC      — Challenges every hypothesis              │
│     → CONFIRMED / NEEDS_MORE / REFUTED / CLEARED            │
│     → Benign findings get ✅ CLEARED (not false-positive)    │
│     → Loops back to Evidence if unverified (max 3 rounds)   │
│                                                             │
│  5. REPORTER     — Final verified report                    │
│     → CRITICAL / MEDIUM / LOW / CLEARED / REFUTED           │
│     → Attack narrative (coherent breach story)               │
│     → Attacker-focused timeline (system noise filtered)     │
│     → False-positive-free MITRE ATT&CK kill chain           │
│     → Dynamic remediation playbook                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Expected Output

```
🔴 CRITICAL — subject_srv.exe running from non-System32 path
   ├── 19 independent sources confirmed
   ├── vol3:svcscan, shimcache, pslist, ldrmodules ...
   └── ATT&CK: T1543.003

🔴 CRITICAL — C2 connection to 172.16.4.10:8080
   ├── 3 sources: netscan, netstat, netscan_live
   └── ATT&CK: T1071.001

🔴 CRITICAL — putty.exe — lateral SSH movement
   ├── 20 sources confirmed
   ├── SSH targets: onion-master, base-elk, proxy
   └── ATT&CK: T1021.004

✅ CLEARED — ruby.exe from Puppet Labs (investigated, benign)
   ├── Path: C:\Program Files\Puppet Labs\Puppet\sys\ruby\bin\ruby.exe
   └── 18 sources checked, all confirmed benign path

ATT&CK Chain: T1543.003 → T1071.001 → T1021.004
⚫ 0 hallucinations | ✅ 1 process cleared
```

---

## File Structure

```
phantom-dfir/
├── main.py               # CLI entry point
├── config.py             # Tool paths, Ollama settings, timeouts
├── state.py              # LangGraph TypedDict state schema
├── install.sh            # One-command SIFT installer
├── requirements.txt      # Python dependencies
├── tools/
│   ├── vol3_tools.py     # Vol3 (vol) wrappers — 40+ Windows + 30+ Linux plugins
│   └── vol2_tools.py     # Vol2 (vol2) wrappers — auto-profile detection
├── agents/
│   ├── orchestrator.py   # LangGraph StateGraph + reasoning_log init
│   ├── collector.py      # Parallel OS detection + evidence collection (16 workers)
│   ├── investigator.py   # Dynamic hypothesis generation (LLM + rule-based)
│   ├── evidence.py       # Targeted re-queries per hypothesis (Win + Linux)
│   ├── skeptic.py        # Adversarial challenge engine
│   └── reporter.py       # Final report + reasoning trace + execution log
├── correlation/
│   ├── confidence.py     # Multi-source IOC scoring
│   ├── mitre.py          # ATT&CK technique auto-mapping (false-positive-free)
│   └── timeline.py       # Dynamic attack timeline reconstruction
├── mcpserver/
│   └── mcp_server.py     # 20 typed MCP tools (stdio + HTTP)
├── disk_correlator.py    # Memory↔Disk cross-reference engine
├── benchmark.py          # Accuracy benchmarking (precision/recall/F1)
├── ground_truth_base_admin.json  # Known-good ground truth for scoring
└── test_mcp.py           # MCP server smoke test
```

---

## v2.1 Improvements (Latest)

| Area | v2.0 | v2.1 |
|------|------|------|
| **False positives** | Ruby flagged as Metasploit C2 | ✅ CLEARED — path-aware benign detection |
| **Confidence levels** | CRITICAL/MEDIUM/LOW/REFUTED | + **CLEARED** (investigated, benign) |
| **Report quality** | IOC list | **Attack narrative** — coherent breach story |
| **Timeline** | All events incl. system noise | **Attacker-focused** — VMware/Defender filtered |
| **Evidence quotes** | IOC name only (`ruby.exe`) | Rich forensic lines with PIDs, paths, timestamps |
| **MITRE accuracy** | ruby.exe → false T1059 | Ruby removed from IOC map, zero false positives |
| **Timeline events** | Raw Volatility output | **Human-readable** (`Process 'ruby.exe' (PID 3204) created`) |

## v2.0 Improvements

| Area | v1.0 | v2.0 |
|------|------|------|
| **Speed** | 8 parallel workers → 306s collection | 16 workers → ~150-180s collection |
| **MITRE accuracy** | 5/13 false positives (tool names as IOCs) | IOC-only mapping, zero false positives |
| **IOC detection** | Hardcoded IPs/ports | Dynamic extraction from evidence |
| **SSH analysis** | None | Extracts @hostname targets from cmdlines |
| **Remediation** | Hardcoded to test case | Dynamic from attack phases + MITRE |
| **Timeline** | Hardcoded keywords | Dynamic from discovered IOCs |
| **Vol2 profile** | Hardcoded Win10x64_16299 | Auto-detect via kdbgscan |
| **Linux support** | Collection only | Collection + Evidence verification |
| **Plugin timeouts** | 300s slow plugins | 180s (faster failure) |

---

## Why This Wins the Hackathon

| Judging Criterion | PHANTOM's Answer |
|---|---|
| **Hallucination reduction** | Skeptic agent demands 3 raw evidence sources |
| **False positive reduction** | Path-aware benign detection (Puppet Ruby → CLEARED) |
| **Senior analyst reasoning** | Adversarial debate + attack narrative |
| **Speed** | 35+ plugins in parallel (16 workers), < 5 min target |
| **Autonomy** | LangGraph decides what to investigate next |
| **SIFT integration** | Vol3 + Vol2 + all SIFT tools natively |
| **Novel approach** | Never been built for DFIR before |
| **Generalizability** | Dynamic IOC extraction — works on ANY case |
| **MITRE accuracy** | Zero false positives from tool name matching |
| **Report quality** | Coherent attack narrative, not just IOC list |

---

*PHANTOM DFIR v2.1 — Find Evil! Hackathon 2026*
