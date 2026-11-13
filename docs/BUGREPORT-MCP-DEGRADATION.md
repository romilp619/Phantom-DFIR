# Bug report for Romil: `mcpserver/mcp_server.py` crashes instead of degrading

**File:** `mcpserver/mcp_server.py`
**Found by:** the integration audit, 2026-11-12
**Severity:** low to moderate - only bites when the `mcp` package is missing, but then it
takes down the whole MCP server entry point rather than the one feature
**Provenance:** **pre-existing in your code.** Reproduced identically on the untouched
original tree, so the safety module did not introduce it.

---

## The fault

The module deliberately handles a missing `mcp` package. Lines 30-39:

```python
# ── MCP SDK ──────────────────────────────────────────────────────────────────
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    print("[WARN] mcp package not installed. Run: pip install mcp --break-system-packages",
          file=sys.stderr)
```

That is a correct, deliberate graceful-degradation pattern: catch the import failure, set
a flag, warn the user, carry on.

**But the flag is never consulted before it is too late.** Line 644 is module-level code
with no guard:

```python
TOOL_DEFINITIONS = [
    # Evidence integrity
    Tool(name="register_evidence",
         description="Register evidence file and compute SHA256 baseline. MUST call before analysis.",
         inputSchema={"type":"object","properties":{"filepath":{"type":"string"}},"required":["filepath"]}),
    ...
]
```

There are **20 `Tool(...)` call sites** in that list, from line 646 to beyond. When the
`mcp` import failed, the name `Tool` does not exist, so evaluating the list raises
`NameError` and the module dies at import time.

**The net effect is worse than not having the try/except at all.** Without it, the user
would see a clean `ModuleNotFoundError: No module named 'mcp'`. With the broken guard, they
see the `[WARN]` line followed by a confusing crash about a name that looks like it should
be defined - and the `MCP_AVAILABLE = False` path is dead code that can never run.

## Reproduction

Install the package, then run the script with `mcp` made unimportable:

```
python artifacts/prove_degradation.py
```

(The script is in this repo under `artifacts/`; a copy of the body follows at the end.)

Observed output:

```
[WARN] mcp package not installed. Run: pip install mcp --break-system-packages
running mcpserver/mcp_server.py with `mcp` blocked...
expect on success: the [WARN] line, then continued execution
------------------------------------------------------------
------------------------------------------------------------
RESULT: NameError -> name 'Tool' is not defined
VERDICT: NOT graceful. The try/except printed its warning, then
         module-level TOOL_DEFINITIONS crashed the script anyway.
```

With `mcp` installed normally, `python -c "import mcpserver.mcp_server"` succeeds. So this
only triggers on a machine without `mcp` - which is exactly the case the guard was written
for.

## Fix (one of two, your call)

**Option A - guard the definitions.** Wrap the list so it is only built when the SDK is
available:

```python
if MCP_AVAILABLE:
    TOOL_DEFINITIONS = [
        Tool(name="register_evidence", ...),
        ...
    ]
else:
    TOOL_DEFINITIONS = []
```

Then the module imports, `MCP_AVAILABLE` is `False`, and the warning is the whole story.

**Option B - fail loudly and early.** If the MCP server genuinely cannot run without the
SDK, drop the pretence of degrading and make the message actionable:

```python
except ImportError as exc:
    raise SystemExit(
        "The MCP SDK is required for mcpserver/mcp_server.py.\n"
        "  pip install mcp\n"
        f"  (import error was: {exc})"
    ) from exc
```

**A is the better match for the code's own intent** - the flag and the warning already say
the author wanted to degrade rather than abort. B is better if you consider a running
server with no tools useless.

Either way, the current state is the one to avoid: it announces a fallback it cannot
deliver.

## Copy of the reproduction script

```python
import importlib.abc, runpy, sys

class Blocker(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "mcp" or fullname.startswith("mcp."):
            raise ImportError("mcp blocked for this test")
        return None

sys.meta_path.insert(0, Blocker())
sys.argv = ["mcp_server.py", "--help"]

try:
    runpy.run_path("mcpserver/mcp_server.py", run_name="__main__")
except NameError as exc:
    print(f"RESULT: NameError -> {exc}")
```

## A note on how this was found, since it affects the other findings

While auditing, I first reported this as `mcpserver.mcp_server` failing with
`NameError: name 'Tool' is not defined` during an import-smoke test, and described it as
"the MCP server cannot start at all". **That framing was too strong.** My test venv did not
have `mcp` installed, so the module failed for want of a dependency, not because of an
independent defect. With `mcp` present it imports fine.

The real, narrower defect is the one above: the guard is defeated by unguarded module-level
code. That is worth fixing, and it is not a blocker for anything you are running today, as
long as `mcp` is installed - which `requirements.txt` already specifies.