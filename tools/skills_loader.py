"""
PHANTOM DFIR — Skills Loader
Loads curated forensic skill knowledge from SKILL.md files.
These provide domain-expert context to the LLM agents.

Smart loading:
  - Ollama (4k context): compact hints only (~300 chars)
  - Claude/OpenAI (100k+): full skill knowledge (~2000 chars)
"""
import os
import glob
import config


def _is_cloud_provider() -> bool:
    """Check if using a cloud provider with large context window."""
    provider = getattr(config, "LLM_PROVIDER", "ollama").lower()
    return provider in ("claude", "openai", "groq")


def load_skills_for_phase(phase: str) -> str:
    """Load skill knowledge relevant to a specific investigation phase.

    For Ollama (small context): returns compact expert hints (~300 chars)
    For cloud providers (large context): returns full skill docs (~2000 chars)

    Args:
        phase: "investigator" or "skeptic"
    Returns:
        Formatted skill context string, or "" if no skills found.
    """
    skills_dir = getattr(config, "SKILLS_DIR", "")
    if not skills_dir or not os.path.isdir(skills_dir):
        return ""

    # Map phases to relevant skill files
    phase_skills = {
        "investigator": [
            "memory-forensics",
            "process-injection",
            "credential-dumping",
            "persistence",
            "lateral-movement",
            "living-off-the-land",
        ],
        "skeptic": [
            "rootkit-detection",
            "indicators-of-compromise",
            "mitre-attack-mapping",
        ],
    }

    skill_names = phase_skills.get(phase, [])
    if not skill_names:
        return ""

    if _is_cloud_provider():
        return _load_full(skills_dir, skill_names)
    else:
        return _load_compact(skills_dir, skill_names)


def _load_full(skills_dir: str, skill_names: list) -> str:
    """Full skill content for cloud providers with large context."""
    parts = []
    for name in skill_names:
        path = os.path.join(skills_dir, f"{name}.md")
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read().strip()
                    if content:
                        parts.append(content)
            except Exception:
                continue

    if not parts:
        return ""

    return (
        "\n\n=== FORENSIC EXPERTISE (from curated skill library) ===\n"
        + "\n\n---\n".join(parts)
        + "\n=== END EXPERTISE ===\n"
    )


def _load_compact(skills_dir: str, skill_names: list) -> str:
    """Compact hints for Ollama (small context window).
    Extracts only section headers and key rules — ~300 chars total.
    """
    hints = []
    for name in skill_names:
        path = os.path.join(skills_dir, f"{name}.md")
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        # Grab only top-level headers and key bullet points
                        if line.startswith("# "):
                            hints.append(line.replace("# ", ""))
                        elif line.startswith("- **") and len(hints) < 12:
                            # Extract key terms like "- **lsass.exe**: only ONE instance"
                            hints.append(line[:80])
            except Exception:
                continue

    if not hints:
        return ""

    # Keep it under 400 chars for Ollama
    compact = "\n".join(hints[:12])
    if len(compact) > 400:
        compact = compact[:400]

    return f"\n\nExpert hints:\n{compact}\n"


def list_available_skills() -> list:
    """List all available skill files."""
    skills_dir = getattr(config, "SKILLS_DIR", "")
    if not skills_dir or not os.path.isdir(skills_dir):
        return []
    return [
        os.path.basename(f).replace(".md", "")
        for f in sorted(glob.glob(os.path.join(skills_dir, "*.md")))
    ]
