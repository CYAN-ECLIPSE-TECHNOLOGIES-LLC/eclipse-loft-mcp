#!/usr/bin/env python3
# Eclipse Strata MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Smoke: stdio tools/list (exactly 11), discover, forbidden-name refusal shape.
import json, subprocess, sys
from pathlib import Path
HERE = Path(__file__).parent
def main():
    reqs = [{"jsonrpc":"2.0","id":1,"method":"tools/list"},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"printers_discover","arguments":{}}},
            {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"raw_gcode","arguments":{"gcode":"G1 X10"}}}]
    inp = "\n".join(json.dumps(r) for r in reqs) + "\n"
    out = subprocess.run([sys.executable, str(HERE/"server.py")], input=inp, capture_output=True, text=True, timeout=120)
    lines = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
    tools = lines[0]["result"]["tools"]
    assert len(tools) == 11, len(tools)
    disc = json.loads(lines[1]["result"]["content"][0]["text"])
    assert len(disc["printers"]) == 3 and all(p["target_class"] == "simulator" for p in disc["printers"])
    assert lines[2]["error"]["code"] == -32602 and "RAW_GCODE_REFUSED" in lines[2]["error"]["message"]
    print("SMOKE OK: 11 tools, 3 simulator printers, raw_gcode refused -32602/RAW_GCODE_REFUSED")
if __name__ == "__main__": main()
# Eclipse Strata MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
