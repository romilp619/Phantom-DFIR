# IOC Analysis and Validation

## IOC Types and Confidence Levels
- **File hashes (MD5/SHA256)**: HIGH confidence — exact match
- **IP addresses**: MEDIUM confidence — may change, CDN/shared hosting
- **Domain names**: MEDIUM-HIGH — more stable than IPs
- **Process names**: LOW without path context — easily spoofed
- **Registry keys**: MEDIUM — legitimate software may use same keys
- **Mutex names**: HIGH — unique to malware families

## Validation Checklist
1. Is the IOC from a CONFIRMED source (not just LLM-generated)?
2. Does raw evidence contain the exact string?
3. Is it corroborated by 2+ independent data sources?
4. Could this be a false positive (CDN IP, shared hosting, common process)?
5. Does the IOC relate to known malware family/campaign?

## Network IOC Analysis
- Private IP ranges (10.x, 172.16-31.x, 192.168.x) are internal — not C2 by default
- But internal IPs on unusual ports (8080, 4444, 1337) may be pivot points
- Cloud provider IPs (AWS, Azure, GCP) need careful analysis
- CDN IPs (Akamai, Cloudflare, Fastly) are almost always false positives

## MITRE ATT&CK Mapping Rules
- Map techniques based on OBSERVED behavior, not assumptions
- T1071.001 (Web Protocols) — only if HTTP/HTTPS C2 is confirmed
- T1543.003 (Windows Service) — only if malicious service is found
- T1021.004 (SSH) — only if SSH lateral movement is confirmed
- T1055 (Process Injection) — only if malfind shows injected code
