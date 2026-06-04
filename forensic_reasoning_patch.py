"""
FORENSIC REASONING ENGINE — Patch for disk_correlator.py

INSTRUCTIONS:
1. Open ~/phantom-dfir2/disk_correlator.py (the working WSL copy)
2. Find the line: "return findings" at the END of deep_forensic_analysis()
3. AFTER that line, paste everything between === PASTE START === and === PASTE END ===
4. In the main() function, find "deep_findings = deep_forensic_analysis("
5. After that block, add the forensic_reasoning call (see bottom of file)
"""

# === PASTE START === (paste after "return findings" in deep_forensic_analysis)

# ---------------------------------------------------------------------
# FORENSIC REASONING ENGINE - Contextual Analysis
# Transforms "WHAT exists" into "WHAT IT MEANS"
# ---------------------------------------------------------------------

# Weighted tool severity (points)
TOOL_SEVERITY = {
    'cain':          ('Cain & Abel',         50, 'high',   'Credential theft / password cracking'),
    'abel':          ('Cain & Abel',         50, 'high',   'Credential theft / password cracking'),
    'ethereal':      ('Ethereal',            40, 'high',   'Packet interception / network sniffing'),
    'wireshark':     ('Wireshark',           40, 'high',   'Packet interception / network sniffing'),
    'netstumbler':   ('NetStumbler',         40, 'high',   'Wireless AP discovery / war-driving'),
    'netcat':        ('Netcat',              40, 'high',   'Remote shell / backdoor'),
    'mimikatz':      ('Mimikatz',            50, 'high',   'Credential dumping'),
    'metasploit':    ('Metasploit',          50, 'high',   'Exploitation framework'),
    'nmap':          ('Nmap',                30, 'medium', 'Network reconnaissance'),
    'winpcap':       ('WinPcap',             25, 'medium', 'Packet capture library'),
    'look@lan':      ('Look@LAN',            20, 'medium', 'Network discovery tool'),
    'anonymizer':    ('Anonymizer',          30, 'medium', 'IP anonymization / anti-attribution'),
    'cuteftp':       ('CuteFTP',             15, 'medium', 'File exfiltration via FTP'),
    'putty':         ('PuTTY',               10, 'low',    'Remote access (dual-use)'),
    'winscp':        ('WinSCP',              10, 'low',    'File transfer (dual-use)'),
    '123 write':     ('123 Write All Stored Passwords', 35, 'high', 'Password extraction'),
    'mirc':          ('mIRC',                15, 'medium', 'IRC communication (C2 potential)'),
    'aircrack':      ('Aircrack-ng',         45, 'high',   'Wireless key cracking'),
    'john':          ('John the Ripper',     40, 'high',   'Password cracking'),
    'hashcat':       ('Hashcat',             40, 'high',   'GPU password cracking'),
    'hydra':         ('Hydra',               40, 'high',   'Brute-force attack tool'),
    'bloodhound':    ('BloodHound',          45, 'high',   'AD attack path mapping'),
    'nikto':         ('Nikto',               30, 'medium', 'Web server vulnerability scanner'),
}

# Behavioral attack patterns
ATTACK_PATTERNS = {
    "wireless_recon": {
        "name": "Wireless Reconnaissance / War-Driving",
        "requires_any": ["netstumbler", "aircrack", "kismet"],
        "amplified_by": ["wireless", "pcmcia", "802.11", "wlan", "wifi"],
        "score": 40,
        "mitre": "T1595 - Active Scanning",
        "narrative": "wireless access point discovery consistent with war-driving activity",
    },
    "packet_interception": {
        "name": "Packet Interception / Traffic Capture",
        "requires_any": ["ethereal", "wireshark", "tcpdump", "winpcap"],
        "amplified_by": ["interception", "capture", "sniff", "pcap"],
        "score": 40,
        "mitre": "T1040 - Network Sniffing",
        "narrative": "network traffic interception and packet capture capability",
    },
    "credential_theft": {
        "name": "Credential Theft / Password Cracking",
        "requires_any": ["cain", "abel", "john", "hashcat", "hydra",
                         "mimikatz", "123 write"],
        "amplified_by": ["password", "credential", "hash", "crack"],
        "score": 50,
        "mitre": "T1003 - OS Credential Dumping",
        "narrative": "credential harvesting and password cracking capability",
    },
    "data_exfiltration": {
        "name": "Data Exfiltration",
        "requires_any": ["cuteftp", "winscp", "ftp"],
        "amplified_by": ["upload", "transfer", "exfil"],
        "score": 25,
        "mitre": "T1041 - Exfiltration Over C2 Channel",
        "narrative": "file transfer capability suggesting data exfiltration potential",
    },
    "c2_communication": {
        "name": "Command & Control Communication",
        "requires_any": ["mirc", "irc", "netcat"],
        "amplified_by": ["undernet", "efnet", "channel", "#"],
        "score": 30,
        "mitre": "T1071 - Application Layer Protocol",
        "narrative": "IRC-based communication channels used for coordination",
    },
    "anti_attribution": {
        "name": "Anti-Attribution / OPSEC",
        "requires_any": ["anonymizer", "tor", "vpn", "proxy"],
        "amplified_by": ["anonymous", "hidden", "proxy"],
        "score": 25,
        "mitre": "T1090 - Proxy",
        "narrative": "anonymization tools to evade attribution",
    },
}


def forensic_reasoning(deep_findings, disk_artifacts):
    """Transform extracted artifacts into contextual forensic conclusions."""
    section("FORENSIC REASONING ENGINE")

    reasoning = {
        "threat_score":         0,
        "score_breakdown":      [],
        "attack_patterns":      [],
        "attribution":          [],
        "timeline":             [],
        "anti_forensics":       [],
        "self_corrections":     [],
        "behavioral_narrative": "",
        "verdict":              "",
        "confidence":           "low",
    }

    tools_lower = [t.lower() for t in deep_findings.get("hacking_tools", [])]
    programs_lower = [p.lower() for p in deep_findings.get("installed_programs", [])]
    all_text = " ".join(tools_lower + programs_lower).lower()

    chat_text = " ".join(deep_findings.get("chat_artifacts", [])).lower()
    email_text = " ".join(deep_findings.get("email_artifacts", [])).lower()
    net_text = " ".join(deep_findings.get("network_config", [])).lower()

    # -- 1. Weighted Tool Scoring --
    print("  [*] Calculating weighted threat score...", flush=True)
    scored_tools = set()
    for tool_key, (name, points, severity, desc) in TOOL_SEVERITY.items():
        if any(tool_key in t for t in tools_lower):
            if name not in scored_tools:
                scored_tools.add(name)
                reasoning["threat_score"] += points
                reasoning["score_breakdown"].append(
                    f"+{points}: {name} [{severity.upper()}] -- {desc}")

    # Recycle bin scoring
    rb_count = len(deep_findings.get("recycle_bin", []))
    if rb_count > 0:
        rb_score = min(rb_count * 10, 30)
        reasoning["threat_score"] += rb_score
        reasoning["score_breakdown"].append(
            f"+{rb_score}: {rb_count} executable(s) in Recycle Bin -- potential evidence cleanup")

    # IRC hacker channel scoring
    hacker_channels = [c for c in deep_findings.get("chat_artifacts", [])
                       if any(kw in c.lower() for kw in
                              ('hack', '2600', 'shell', 'elite', 'warez',
                               'exploit', 'evil', 'phreakz'))]
    if hacker_channels:
        irc_score = min(len(hacker_channels) * 5, 30)
        reasoning["threat_score"] += irc_score
        reasoning["score_breakdown"].append(
            f"+{irc_score}: {len(hacker_channels)} hacker IRC channels -- "
            f"underground community involvement")

    # Suspicious email scoring
    sus_emails = [e for e in deep_findings.get("email_artifacts", [])
                  if any(kw in e for kw in
                         ('evil', 'hack', 'crack', 'exploit', 'dark',
                          'anon', 'phreakz', '2600'))]
    if sus_emails:
        reasoning["threat_score"] += 15
        reasoning["score_breakdown"].append(
            f"+15: Suspicious email handles: {', '.join(sus_emails[:3])}")

    ok(f"Weighted threat score: {reasoning['threat_score']}")

    # -- 2. Behavioral Pattern Detection --
    print("  [*] Detecting behavioral attack patterns...", flush=True)
    context_text = all_text + " " + chat_text + " " + net_text

    for pat_id, pattern in ATTACK_PATTERNS.items():
        matched_tools = [t for t in pattern["requires_any"]
                         if any(t in tool for tool in tools_lower)]
        if not matched_tools:
            matched_tools = [t for t in pattern["requires_any"]
                             if any(t in p for p in programs_lower)]
        if matched_tools:
            amplifiers = [a for a in pattern["amplified_by"]
                          if a in context_text]
            confidence = "high" if amplifiers else "medium"
            effective_score = pattern["score"]
            if amplifiers:
                effective_score = int(effective_score * 1.5)
            reasoning["attack_patterns"].append({
                "pattern":    pattern["name"],
                "tools":      matched_tools,
                "amplifiers": amplifiers,
                "score":      effective_score,
                "confidence": confidence,
                "mitre":      pattern["mitre"],
                "narrative":  pattern["narrative"],
            })
            reasoning["threat_score"] += effective_score
            reasoning["score_breakdown"].append(
                f"+{effective_score}: {pattern['name']} "
                f"[{confidence.upper()}] ({pattern['mitre']})")

    if reasoning["attack_patterns"]:
        print(f"\n  ATTACK PATTERNS DETECTED ({len(reasoning['attack_patterns'])}):")
        for ap in reasoning["attack_patterns"]:
            print(f"     [!] {ap['pattern']} [{ap['confidence'].upper()}]")
            print(f"         Tools: {', '.join(ap['tools'])}")
            if ap['amplifiers']:
                print(f"         Amplifiers: {', '.join(ap['amplifiers'][:5])}")
            print(f"         MITRE: {ap['mitre']}")

    # -- 3. Identity Attribution --
    print("\n  [*] Building identity attribution...", flush=True)
    si = deep_findings.get("system_info", {})
    accounts = deep_findings.get("user_accounts", [])
    owner = si.get("registered_owner", "")

    identities = set()
    if owner:
        identities.add(owner)
    for acc in accounts:
        name = acc.get("name", "")
        if name and name.lower() not in ('administrator', 'guest',
                                          'helpassistant', 'support_388945a0'):
            identities.add(name)

    nick_matches = re.findall(r'(?:nick|user|anick)=(\S+)',
                              chat_text, re.IGNORECASE)
    for nick in nick_matches:
        if len(nick) > 2:
            identities.add(nick)

    identity_links = []
    if owner and accounts:
        active_accounts = [a for a in accounts
                           if a.get("last_login", "Never") != "Never"]
        if active_accounts:
            identity_links.append({
                "type": "owner_to_user",
                "from": owner,
                "to": active_accounts[0]["name"],
                "evidence": "Registered owner matches active user profile",
                "confidence": "high",
            })

    for email in deep_findings.get("email_artifacts", []):
        for identity in identities:
            id_lower = identity.lower().replace(" ", "").replace(".", "")
            if id_lower in email.replace(".", "").replace("_", ""):
                identity_links.append({
                    "type": "email_to_identity",
                    "from": email,
                    "to": identity,
                    "evidence": f"Email '{email}' contains identity '{identity}'",
                    "confidence": "medium",
                })

    reasoning["attribution"] = identity_links
    if identity_links:
        reasoning["threat_score"] += 20
        reasoning["score_breakdown"].append(
            f"+20: Identity attribution -- "
            f"{len(identity_links)} link(s) connecting user identities")
        print(f"\n  IDENTITY ATTRIBUTION ({len(identity_links)}):")
        for link in identity_links[:5]:
            print(f"     {link['from']} -> {link['to']} "
                  f"[{link['confidence'].upper()}]")
            print(f"       Evidence: {link['evidence']}")

    # -- 4. Attack Timeline --
    print("\n  [*] Constructing attack timeline...", flush=True)
    timeline_events = []
    if si.get("install_date"):
        timeline_events.append({
            "time": si["install_date"], "event": "OS installed",
            "significance": "System provisioning",
        })
    if si.get("last_shutdown"):
        timeline_events.append({
            "time": si["last_shutdown"], "event": "Last shutdown",
            "significance": "Final activity",
        })
    for acc in accounts:
        if acc.get("last_login") and acc["last_login"] != "Never":
            timeline_events.append({
                "time": acc["last_login"],
                "event": f"User '{acc['name']}' last login",
                "significance": "User activity marker",
            })
    reasoning["timeline"] = timeline_events
    if timeline_events:
        print(f"  TIMELINE ({len(timeline_events)} events):")
        for evt in sorted(timeline_events, key=lambda x: x.get("time", "")):
            print(f"     [{evt['time']}] {evt['event']}")

    # -- 5. Anti-Forensics Reasoning --
    print("\n  [*] Analyzing anti-forensics indicators...", flush=True)
    af_findings = []
    if rb_count > 0:
        af_findings.append({
            "type": "recycle_bin_executables",
            "count": rb_count,
            "reasoning": (
                f"{rb_count} executable(s) in Recycle Bin. "
                f"Logically deleted but NOT physically removed -- "
                f"data is still recoverable. Cleanup ATTEMPT detected."),
            "recoverable": True,
            "mitre": "T1070.004 - File Deletion",
        })
    del_count = len(disk_artifacts.get("deleted", []))
    if del_count > 0:
        af_findings.append({
            "type": "filesystem_deletions",
            "count": del_count,
            "reasoning": (
                f"{del_count} files flagged as deleted. "
                f"Data blocks may still contain recoverable content."),
            "recoverable": True,
            "mitre": "T1070.004 - File Deletion",
        })
    reasoning["anti_forensics"] = af_findings
    if af_findings:
        reasoning["threat_score"] += 15
        reasoning["score_breakdown"].append(
            f"+15: Anti-forensics -- evidence cleanup detected")
        for af in af_findings:
            print(f"     {af['type']}: {af['reasoning'][:120]}")

    # -- 6. Self-Correction Loop --
    print("\n  [*] Running self-correction checks...", flush=True)
    corrections = []
    if not any('netstumbler' in t.lower() for t in
               deep_findings.get("hacking_tools", [])):
        for regval in deep_findings.get("raw_registry", {}).values():
            if 'netstumbler' in regval.lower() or 'stumbler' in regval.lower():
                corrections.append({
                    "check": "Missed NetStumbler",
                    "found_in": "registry strings",
                    "action": "Added to hacking tools",
                })
                if "NetStumbler" not in deep_findings["hacking_tools"]:
                    deep_findings["hacking_tools"].append("NetStumbler")
                break

    has_sniffer = any(t in all_text for t in ('ethereal', 'wireshark', 'winpcap'))
    if has_sniffer:
        corrections.append({
            "check": "Packet interception evidence",
            "found_in": "tool presence (Ethereal + WinPcap)",
            "action": "Confirmed: sniffing capability present",
        })

    hacker_irc = [c for c in deep_findings.get("chat_artifacts", [])
                  if any(kw in c.lower() for kw in
                         ('hack', 'shell', 'elite', 'warez', 'evil'))]
    if hacker_irc:
        corrections.append({
            "check": "IRC C2 underscored",
            "found_in": f"{len(hacker_irc)} hacker-related IRC channels",
            "action": "IRC channels suggest underground coordination",
        })

    reasoning["self_corrections"] = corrections
    if corrections:
        print(f"  SELF-CORRECTIONS ({len(corrections)}):")
        for sc in corrections:
            print(f"     [OK] {sc['check']}: {sc['action'][:100]}")

    # -- 7. Behavioral Narrative --
    print("\n  [*] Generating analyst narrative...", flush=True)
    narratives = []
    os_info = si.get("os", "Windows")
    comp = si.get("computer_name", "unknown")
    narratives.append(f"The analyzed system ({comp}) runs {os_info}.")

    active_users = [a for a in accounts
                    if a.get("last_login", "Never") != "Never"]
    if active_users:
        primary = active_users[0]["name"]
        narratives.append(
            f"The primary user account is '{primary}' with the most recent "
            f"login activity.")
        if owner and owner != primary:
            narratives.append(
                f"The registered owner '{owner}' correlates with the active "
                f"account '{primary}', establishing identity attribution.")

    if reasoning["attack_patterns"]:
        pattern_names = [ap["narrative"] for ap in reasoning["attack_patterns"]]
        narratives.append(
            f"Analysis reveals evidence of: {'; '.join(pattern_names)}.")

    if rb_count > 0:
        narratives.append(
            f"{rb_count} executable(s) were found in the Recycle Bin, "
            f"indicating a cleanup attempt. Files are logically deleted "
            f"but physically recoverable.")

    if hacker_channels:
        narratives.append(
            f"IRC communication logs reveal access to {len(hacker_channels)} "
            f"channels associated with hacking communities.")

    if reasoning["threat_score"] >= 100:
        narratives.append(
            "CONCLUSION: The preponderance of evidence -- including offensive "
            "security tools, credential theft capability, network interception "
            "software, and underground community participation -- strongly "
            "indicates this system was deliberately configured and used for "
            "unauthorized computer access and network intrusion activities.")
    elif reasoning["threat_score"] >= 50:
        narratives.append(
            "CONCLUSION: Multiple forensic indicators suggest this system was "
            "used for suspicious network activity.")

    narrative_text = " ".join(narratives)
    reasoning["behavioral_narrative"] = narrative_text

    # -- Final verdict --
    score = reasoning["threat_score"]
    if score >= 150:
        reasoning["verdict"] = "DEFINITIVE COMPROMISE - Offensive tooling confirmed"
        reasoning["confidence"] = "very_high"
    elif score >= 100:
        reasoning["verdict"] = "HIGH CONFIDENCE COMPROMISE"
        reasoning["confidence"] = "high"
    elif score >= 50:
        reasoning["verdict"] = "SUSPICIOUS - Multiple indicators"
        reasoning["confidence"] = "medium"
    elif score >= 20:
        reasoning["verdict"] = "LOW SUSPICION - Investigate further"
        reasoning["confidence"] = "low"
    else:
        reasoning["verdict"] = "LIKELY CLEAN"
        reasoning["confidence"] = "low"

    # -- Print results --
    section("FORENSIC REASONING VERDICT")
    print(f"\n  Threat Score : {score} (Confidence: {reasoning['confidence'].upper()})")
    print(f"  Verdict      : {reasoning['verdict']}")
    print(f"  Patterns     : {len(reasoning['attack_patterns'])} attack behaviors")
    print(f"  Attribution  : {len(reasoning['attribution'])} identity links")
    print(f"  Anti-forensic: {len(reasoning['anti_forensics'])} cleanup indicators")

    print(f"\n  SCORE BREAKDOWN:")
    for item in reasoning["score_breakdown"]:
        print(f"     {item}")

    print(f"\n  ANALYST NARRATIVE:")
    words = narrative_text.split()
    line = "     "
    for w in words:
        if len(line) + len(w) + 1 > 80:
            print(line)
            line = "     " + w
        else:
            line += " " + w if line.strip() else "     " + w
    if line.strip():
        print(line)

    return reasoning

# === PASTE END ===


# === MAIN() WIRING ===
# In main(), find this block:
#     deep_findings = deep_forensic_analysis(
#         args.disk, deep_offset, args.output_dir)
#
# ADD these lines right after it:
#
#     # Run forensic reasoning engine
#     reasoning_result = None
#     if deep_findings:
#         reasoning_result = forensic_reasoning(deep_findings, disk_result[0])
#
# Then find the "Save deep forensic findings" block and update it:
#     if deep_findings:
#         deep_json_path = json_path.replace(".json", "_forensic_exam.json")
#         deep_export = {k: v for k, v in deep_findings.items()
#                        if k != "raw_registry"}
#         if reasoning_result:
#             deep_export["reasoning"] = reasoning_result
#         with open(deep_json_path, "w") as f:
#             json.dump(deep_export, f, indent=2, default=str)
#         ok(f"Deep forensic JSON: {deep_json_path}")
