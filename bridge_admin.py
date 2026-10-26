#!/usr/bin/env python3
# Eclipse Strata MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Strata Bridge admin CLI — operator-only, bridge host, NEVER MCP-reachable (§8.4).

"""Operator CLI: toolchain registry, printer declaration, pin activation (human principal), pack export.
Usage: bridge_admin.py {list-printers|list-slicers|activate-design DESIGN_ID PRINCIPAL_ID|activate-profile PROFILE_ID PRINCIPAL_ID|export-pack PACK_ID}
Admin acts are receipted into the bridge log (bridge-admin.log), not agent packs.
"""
import json, sys
from pathlib import Path
HERE = Path(__file__).parent; sys.path.insert(0, str(HERE))
from strata_engine import Engine

def main(argv):
    e = Engine(HERE)
    log = HERE / "data" / "bridge-admin.log"
    def receipt(entry):
        log.parent.mkdir(exist_ok=True)
        with open(log, "a") as f: f.write(json.dumps(entry)+"\n")
    if not argv: print(__doc__); return 2
    cmd = argv[0]
    if cmd == "list-printers": print(json.dumps(e.printers_discover(), indent=1))
    elif cmd == "list-slicers": print(json.dumps(e.slicer_registry, indent=1))
    elif cmd == "activate-design":
        r = e.activate_design(argv[1], {"id": argv[2], "role": "human_principal"}); receipt({"act": cmd, "design_id": argv[1], "principal": argv[2]}); print(r["status"])
    elif cmd == "activate-profile":
        r = e.activate_profile(argv[1], {"id": argv[2], "role": "human_principal"}); receipt({"act": cmd, "profile_id": argv[1], "principal": argv[2]}); print(r["status"])
    else: print(f"unknown admin command: {cmd}"); return 2
    return 0
if __name__ == "__main__": raise SystemExit(main(sys.argv[1:]))
# Eclipse Strata MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
