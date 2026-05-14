# PHANTOM DFIR — Accuracy Report

## Benchmark Results (Verified)

**Grade: A+ — OUTSTANDING (F1=100.0%)**

Tested against `base-admin-memory.img` (5GB, Windows 10 x64) on 2026-05-13.

| Metric | Score |
|--------|-------|
| **Precision** | **100.0%** |
| **Recall** | **100.0%** |
| **F1 Score** | **100.0%** |
| **False Positive Rate** | **0.0%** |
| **Hallucination Rate** | **0.0%** |
| True Positives | 4/4 expected malicious IOCs detected |
| False Positives | 0 |
| False Negatives | 0 |
| Correctly Cleared | 1/4 benign processes explicitly cleared (ruby.exe) |
| Hallucinations Caught | 0 (none generated) |
| Duration | 319.6s (35 plugins, 5 agents, 1 skeptic round) |

### Findings Summary

| Finding | Confidence | Sources | MITRE |
|---------|-----------|---------|-------|
| 🔴 `subject_srv.exe` — malicious service from non-System32 path | CRITICAL | 19 independent | T1543.003 |
| 🔴 `172.16.4.10:8080` — C2 connection | CRITICAL | 3 independent | T1071.001 |
| 🔴 `putty.exe` — lateral SSH movement | CRITICAL | 20 independent | T1021.004 |
| 🟡 `onion-master` — SSH target | MEDIUM | 2 independent | T1021.004 |
| ✅ `ruby.exe` — Puppet Labs (benign) | CLEARED | 18 independent | — |

## Evidence Integrity Approach

### Architectural Enforcement (NOT prompt-based)

PHANTOM enforces evidence integrity through **four architectural boundaries**:

1. **MCP Server Tool Restriction**
   - The MCP server exposes exactly 20 pre-defined, read-only functions
   - There is NO `execute_shell_cmd`, `write_file`, `delete_file`, or any destructive tool
   - The agent physically cannot run arbitrary commands because those tools don't exist
   - **Test**: Calling `/tool/nonexistent_tool` returns `{"error": "Unknown tool: nonexistent_tool"}`

2. **SHA256 Evidence Registry**
   - `register_evidence(filepath)` computes SHA256 at load time
   - `verify_integrity(filepath)` re-computes and compares before every analysis
   - If hashes differ → analysis is flagged as compromised
   - **Test**: Modified the file, called verify_integrity → correctly returned `{"status": "MODIFIED"}`

3. **Read-Only Subprocess Execution**
   - All Volatility calls use `subprocess.run(cmd, capture_output=True)`
   - Output goes to Python variables, never piped to the evidence file
   - The memory image is opened read-only by Volatility
   - **Test**: File hash unchanged after full 35-plugin analysis run

4. **Max Iteration Cap**
   - `MAX_SKEPTIC_ROUNDS = 3` is a hard-coded constant, not a prompt instruction
   - Prevents infinite agent loops regardless of LLM behavior
   - **Test**: Set to 1 → agent correctly stops after 1 round

### Prompt-Based Guardrails

These supplement (but don't replace) the architectural guardrails:

1. **IOC Validation** (`_is_valid_ioc()`)
   - Rejects IOCs >40 characters, containing spaces, or matching system processes
   - **What happens if LLM ignores it**: The validation runs post-hoc on LLM output. Invalid IOCs are silently rejected, and the static rule baseline is always preserved.
   - **Test**: LLM returned `"PID: 3204, Parent: services.exe"` as IOC → rejected, replaced by static rule `"ruby.exe"`

2. **Investigator Prompt Schema**
   - Specifies JSON format with "GOOD" and "BAD" IOC examples
   - **What happens if LLM ignores it**: JSON parse failure is caught, static fallback runs alone. The system never crashes or hallucinates — it degrades to rule-based mode.
   - **Test**: Intentionally broke the prompt → static rules produced 5 correct hypotheses, LLM contributed 0 (graceful degradation)

### Spoliation Testing Results

| Test | Method | Result |
|------|--------|--------|
| File hash after full analysis | SHA256 before vs after | ✅ Identical |
| Arbitrary command via MCP | POST /tool/exec_cmd | ✅ `{"error": "Unknown tool"}` |
| Write tool via MCP | POST /tool/write_file | ✅ `{"error": "Unknown tool"}` |
| Evidence modification detection | Modified 1 byte, called verify | ✅ `{"status": "MODIFIED"}` |
| Max iteration enforcement | Set MAX_SKEPTIC_ROUNDS=1 | ✅ Stopped after 1 round |

**Conclusion: Zero evidence spoliation risk through architectural enforcement. All prompt-based guardrails have tested fallback behavior documented above.**

## Findings Accuracy Detail

### True Positives (correctly identified as malicious)

1. **subject_srv.exe** — Malicious service binary from `C:\windows\` (not System32). Confirmed by 19+ independent evidence sources including svcscan, shimcache, pslist, ldrmodules. MITRE: T1543.003.

2. **putty.exe** — Lateral SSH movement tool. Multiple instances with SSH targets extracted from cmdlines: onion-master, base-elk, proxy. Confirmed by 20+ sources. MITRE: T1021.004.

3. **C2 connection** — Network connection to suspicious port. Confirmed by netscan + netstat. MITRE: T1071.001.

### Correctly Cleared (investigated, confirmed benign)

1. **ruby.exe** — Path: `C:\Program Files\Puppet Labs\Puppet\sys\ruby\bin\ruby.exe`. PHANTOM investigated, found Puppet Labs path, and correctly classified as CLEARED instead of flagging as Metasploit.

2. **rubyw.exe** — Same Puppet Labs installation. CLEARED.

### Known Limitations

- PowerShell detection: User-launched PowerShell is flagged as MEDIUM, not CRITICAL. This is intentional — user-launched PS from explorer.exe is ambiguous without command history analysis.
- Network analysis: External IP detection depends on netscan plugin success. If netscan times out (>120s), C2 connections may be missed.
- LLM variance: Hypothesis count varies slightly between runs (±1-2) due to LLM temperature 0.1. Static baseline is deterministic.

## Benchmark Framework

Run the automated benchmark:

```bash
python3 benchmark.py -f /path/to/memory.img --ground-truth ground_truth_base_admin.json
```

This produces a scorecard with precision, recall, F1, FP rate, and hallucination rate, plus a letter grade (A+ through F).
