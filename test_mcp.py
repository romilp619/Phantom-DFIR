#!/usr/bin/env python3
"""
PHANTOM DFIR — MCP Server Smoke Test
Tests all critical endpoints to verify the server is working.

Usage:
  1. Start server:  python3 mcpserver/mcp_server.py --transport http --port 8765
  2. Run this test: python3 test_mcp.py [--memory /path/to/memory.img]
"""
import json
import sys
import time
import urllib.request
import urllib.error

BASE_URL = "http://localhost:8765"
MEMORY_FILE = None

# Parse args
for i, arg in enumerate(sys.argv):
    if arg == "--memory" and i + 1 < len(sys.argv):
        MEMORY_FILE = sys.argv[i + 1]

passed = 0
failed = 0
total  = 0


def test(name, method, path, body=None):
    global passed, failed, total
    total += 1
    url = f"{BASE_URL}{path}"
    try:
        if method == "GET":
            req = urllib.request.Request(url)
        else:
            data = json.dumps(body).encode() if body else b"{}"
            req = urllib.request.Request(url, data=data, method="POST",
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            result = json.loads(resp.read().decode())
            print(f"  ✅ {name}")
            # Show key info
            if isinstance(result, dict):
                for k in list(result.keys())[:3]:
                    v = result[k]
                    if isinstance(v, (str, int, float, bool)):
                        print(f"     {k}: {v}")
                    elif isinstance(v, list):
                        print(f"     {k}: [{len(v)} items]")
            passed += 1
            return result
    except urllib.error.URLError as e:
        print(f"  ❌ {name} — {e}")
        failed += 1
        return None
    except Exception as e:
        print(f"  ❌ {name} — {e}")
        failed += 1
        return None


print("=" * 50)
print("  PHANTOM DFIR — MCP Server Smoke Test")
print("=" * 50)
print()

# ── Basic endpoints ──────────────────────────────────────────
print("▸ Testing basic endpoints...")
test("Health check", "GET", "/health")
tools = test("List tools", "GET", "/tools")
if tools and "tools" in tools:
    print(f"     → {len(tools['tools'])} tools available")
print()

# ── Memory analysis tools (only if file provided) ────────────
if MEMORY_FILE:
    print(f"▸ Testing memory tools on: {MEMORY_FILE}")
    print(f"  (some tools may take 30-120s...)")
    print()

    test("Register evidence",
         "POST", "/tool/register_evidence",
         {"filepath": MEMORY_FILE})

    test("Verify integrity",
         "POST", "/tool/verify_integrity",
         {"filepath": MEMORY_FILE})

    test("Process list",
         "POST", "/tool/get_process_list",
         {"filepath": MEMORY_FILE})

    test("Process tree",
         "POST", "/tool/get_process_tree",
         {"filepath": MEMORY_FILE})

    test("Network connections",
         "POST", "/tool/get_network_connections",
         {"filepath": MEMORY_FILE})

    test("Services",
         "POST", "/tool/get_services",
         {"filepath": MEMORY_FILE})

    test("Command lines",
         "POST", "/tool/get_cmdline",
         {"filepath": MEMORY_FILE})

    test("SSDT hooks",
         "POST", "/tool/get_ssdt_hooks",
         {"filepath": MEMORY_FILE})

    test("Shimcache",
         "POST", "/tool/get_shimcache",
         {"filepath": MEMORY_FILE})
else:
    print("▸ Skipping memory tools (no --memory flag)")
    print("  Run with: python3 test_mcp.py --memory /path/to/memory.img")

print()
print("=" * 50)
print(f"  Results: {passed}/{total} passed, {failed} failed")
if failed == 0:
    print("  ✅ MCP Server is working correctly!")
else:
    print(f"  ⚠️  {failed} test(s) failed — check server output")
print("=" * 50)
