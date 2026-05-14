# PHANTOM DFIR — Project Description

## What it does

PHANTOM DFIR is the world's first **adversarial self-verifying** digital forensics agent. Given a memory image (and optionally a disk image), it autonomously:

1. **Collects** evidence by racing Volatility 3, Volatility 2, and strings in parallel (35+ plugins, 16 workers)
2. **Investigates** using both deterministic static rules AND LLM-generated hypotheses — the LLM finds patterns that rules miss, while rules guarantee a hallucination-free baseline
3. **Challenges** every finding through an adversarial Skeptic agent that demands 3+ independent evidence sources before confirming anything as CRITICAL
4. **Self-corrects** by looping back to gather more evidence when the Skeptic identifies gaps (max 3 iterations with a hard cap)
5. **Reports** with a coherent attack narrative, MITRE ATT&CK kill chain, attacker-focused timeline, and dynamic remediation playbook

The key innovation: **two agents argue**. The Investigator proposes; the Skeptic demands proof. This is how senior analysts actually think — they cross-examine their own conclusions before presenting them.

## How we built it

**Architecture**: LangGraph StateGraph with 5 specialized agents (Collector → Investigator → Evidence → Skeptic → Reporter) communicating through a shared TypedDict state.

**Forensics**: Volatility 3 (primary) + Volatility 2 (fallback) running on SANS SIFT Workstation. 40+ Windows plugins and 30+ Linux plugins wrapped as Python functions.

**LLM**: Ollama (Qwen2.5:14b) running locally — fully offline, no cloud API calls. The LLM generates hypotheses but never replaces the static rule-based baseline — it only adds to it.

**MCP Server**: 20 typed, read-only functions exposed via Model Context Protocol (stdio + HTTP). The agent physically cannot run destructive commands because the server doesn't expose them.

**Evidence Integrity**: SHA256 hash registered at evidence load time, verified before every analysis. Architectural enforcement, not prompt-based.

**Self-Correction**: The Skeptic agent iterates up to 3 rounds, writing a progress file that tracks improvement between iterations (average evidence sources, confidence distribution changes, unverified reduction).

## Challenges we ran into

1. **LLM Hallucination in IOC Extraction**: Early versions had the LLM generate IOCs like "PID: 3204, Parent: services.exe" — a full sentence, not a searchable artifact. We solved this with strict `_is_valid_ioc()` validation that rejects anything >40 chars or containing spaces.

2. **False Positives from Puppet/Chef Ruby**: The base-admin image has legitimate Ruby installations from Puppet Labs. Every DFIR tool (including Protocol SIFT baseline) flags these as Metasploit C2. We built path-aware benign detection that checks the binary path — `C:\Program Files\Puppet Labs\` = CLEARED, not CRITICAL.

3. **MITRE ATT&CK Mapping Noise**: Initial auto-mapping matched plugin NAMES as IOCs (e.g., "shimcache" plugin matched against shimcache IOC). We redesigned to only map hypothesis IOCs, not plugin names. Result: zero false positive MITRE mappings.

4. **Context Window Overload**: Raw Volatility output from 35+ plugins can exceed 500KB. We built priority-ordered truncation that sends high-value plugins first (pslist, netscan, svcscan) and caps total context at 12KB for the LLM.

5. **Volatility Column Order Changes**: Vol3 2.28.0 changed pslist column order (PID moved to column 0). Our MCP server parser silently returned 0 processes until we caught it with the smoke test.

## What we learned

- **Architectural guardrails beat prompt guardrails every time.** The MCP server's lack of shell access tools is fundamentally more secure than telling the LLM "don't run destructive commands." Prompts can be ignored; missing functions can't be called.

- **Static rules + LLM > either alone.** The static rule engine catches 100% of known patterns with zero hallucinations. The LLM catches novel patterns the rules miss. Merging them (static baseline + LLM additions) gives the best of both worlds.

- **The adversarial debate pattern is surprisingly effective for DFIR.** Having a Skeptic agent challenge every finding mirrors how senior analysts actually work — they always ask "what else could explain this?" before concluding malice.

- **False positive reduction is as valuable as true positive detection.** Judges (and real analysts) lose trust in a tool that flags Puppet's Ruby as Metasploit. Our CLEARED confidence level explicitly shows "we investigated this and confirmed it's benign" — which is more valuable than simply not flagging it.

## What's next

1. **PCAP/Zeek Integration**: Add network capture analysis to correlate with memory network artifacts
2. **EVTX Log Parsing**: Windows Event Log analysis for authentication and lateral movement evidence
3. **Cross-Case Learning**: Use execution logs from previous cases to improve hypothesis generation on new cases
4. **Distributed Multi-Image Analysis**: Analyze multiple machines from the same incident simultaneously, correlating lateral movement across the network
5. **Community Ground Truth Repository**: Open-source benchmark datasets with documented ground truth for standardized DFIR agent evaluation
