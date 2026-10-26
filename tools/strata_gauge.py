#!/usr/bin/env python3
# Eclipse Strata MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Strata Gauge CLI — check mandate+profile JSON offline (§10.2).
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from gauge import check_gauge
if __name__ == "__main__":
    d = json.loads(Path(sys.argv[1]).read_text())
    print(json.dumps(check_gauge(d["mandate"], d.get("profile"), d.get("printer"), d.get("design_bbox")), indent=1))
# Eclipse Strata MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
