#!/usr/bin/env python3
# Eclipse Loft MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Loft MCP server — 11 typed tools, stdio JSON-RPC (Strata §8).

"""Eclipse Loft — governed design-to-print authority for agents.
Descriptor: governed design-to-print authority for agents — signed provenance
from model to machine, safety envelopes at the bridge, evidence for every print.
Transport: MCP over stdio, stdlib only. P0: simulators only.
Powered by Cyan Eclipse Technologies — https://cetech.ai
"""
import json, os, sys
from pathlib import Path
HERE = Path(__file__).parent; sys.path.insert(0, str(HERE))
import strata_engine as eng
from strata_engine import Engine, Refusal
from guards import ToolError, err32602, require_str, require_dict

ENGINE = Engine(Path(os.environ.get("ECLIPSE_STRATA_DIR", HERE)))
TOOLS = ["design_register","design_inspect","design_pin_get","printers_discover","session_open","job_prepare",
         "job_dispatch","job_status","job_abort","telemetry_read","session_close"]
DESCRIPTOR = "governed design-to-print authority for agents — signed provenance from model to machine, safety envelopes at the bridge, evidence for every print."
FORBIDDEN = {}
for n in ("raw_gcode","send_gcode","printer_command","gcode_script","execute_code","execute_blender_code","move_axis","set_heater","set_fan","heat_hotend"):
    FORBIDDEN[n] = "RAW_GCODE_REFUSED"
for n in ("config_write","firmware_update","set_max_temp","eeprom_save","write_config"):
    FORBIDDEN[n] = "CONFIG_WRITE_REFUSED"
FORBIDDEN["design_pin_activate"] = "AGENT_SELF_PIN_REFUSED"
FORBIDDEN["profile_pin_activate"] = "AGENT_SELF_PIN_REFUSED"

def _p(a, name):
    if name not in a: raise err32602(name, "ARG_REQUIRED")
    return a[name]

def call_tool(name, args):
    if name in FORBIDDEN:
        ENGINE.receipt(name, FORBIDDEN[name], "forbidden_name_on_surface")
        raise ToolError(-32602, refusal=FORBIDDEN[name], arg=name)
    if name not in TOOLS:
        raise ToolError(-32602, refusal="UNKNOWN_TOOL", arg=name)
    a = args or {}
    if not isinstance(a, dict): raise err32602("arguments")
    try:
        if name == "design_register":
            prof = a.get("profile")
            out = ENGINE.design_register(require_str(a.get("agent_identity"), "agent_identity") if a.get("agent_identity") else "agent-anon",
                                         _p(a, "source"), _p(a, "parameter_set"), a.get("source_kind", "code_first"))
            if prof is not None: out["profile_proposal"] = ENGINE.register_profile(a.get("agent_identity","agent"), prof)
            if a.get("activate"): ENGINE.refuse(name, "AGENT_SELF_PIN_REFUSED", "activate_flag_in_register")
            return out
        if name == "design_inspect": return ENGINE.design_inspect(require_str(_p(a,"design_id"),"design_id"))
        if name == "design_pin_get": return ENGINE.design_pin_get(require_str(_p(a,"design_id"),"design_id"))
        if name == "printers_discover": return ENGINE.printers_discover()
        if name == "session_open": return ENGINE.session_open(require_dict(_p(a,"mandate"),"mandate"), require_str(_p(a,"agent_identity"),"agent_identity"))
        if name == "job_prepare": return ENGINE.job_prepare(require_str(_p(a,"session_id"),"session_id"), require_str(_p(a,"design_id"),"design_id"),
                                        require_str(_p(a,"profile_id"),"profile_id"), require_str(_p(a,"printer_serial"),"printer_serial"), a.get("supplied_toolpath"))
        if name == "job_dispatch": return ENGINE.job_dispatch(require_str(_p(a,"session_id"),"session_id"), require_str(_p(a,"job_hash"),"job_hash"),
                                        a.get("supplied_toolpath"), a.get("scheduled_at"))
        if name == "job_status": return ENGINE.job_status(require_str(_p(a,"session_id"),"session_id"), require_str(_p(a,"job_hash"),"job_hash"))
        if name == "job_abort": return ENGINE.job_abort(require_str(_p(a,"session_id"),"session_id"), require_str(_p(a,"job_hash"),"job_hash"))
        if name == "telemetry_read": return ENGINE.telemetry_read(require_str(_p(a,"session_id"),"session_id"), require_str(_p(a,"printer_serial"),"printer_serial"))
        if name == "session_close": return ENGINE.session_close(require_str(_p(a,"session_id"),"session_id"))
    except Refusal as r:
        return {"is_error": True, "refusal_code": r.code, "factor": r.factor}
    raise err32602(name)

def handle(req):
    method = req.get("method"); rid = req.get("id")
    if method == "initialize":
        return {"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},
                "serverInfo":{"name":"Eclipse Loft","version":eng.VERSION,"description":DESCRIPTOR}}}
    if method == "tools/list":
        return {"jsonrpc":"2.0","id":rid,"result":{"tools":[{"name":t,"description":f"{t} — {DESCRIPTOR}","inputSchema":{"type":"object"}} for t in TOOLS]}}
    if method == "tools/call":
        params = req.get("params") or {}
        if not isinstance(params, dict):
            return {"jsonrpc":"2.0","id":rid,"error":{"code":-32602,"message":"INVALID_PARAMS: argument 'params'"}}
        try:
            result = call_tool(params.get("name"), params.get("arguments"))
            return {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":json.dumps(result, default=str)}], **({"isError": True} if isinstance(result, dict) and result.get("is_error") else {})}}
        except ToolError as e:
            return {"jsonrpc":"2.0","id":rid,"error":{"code":e.code,"message":f"{e.refusal or 'INVALID_PARAMS'}: argument '{e.arg}'"}}
        except Exception:
            # D3 house envelope hygiene: a malformed container NEVER kills stdio and
            # never surfaces as a bare -32603/traceback — named -32602, server lives.
            return {"jsonrpc":"2.0","id":rid,"error":{"code":-32602,"message":"MALFORMED_CONTAINER: argument 'tools/call'"}}
    return {"jsonrpc":"2.0","id":rid,"error":{"code":-32602,"message":f"UNKNOWN_METHOD: '{method}'"}}

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try: req = json.loads(line)
        except Exception:
            sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":None,"error":{"code":-32700,"message":"PARSE_ERROR"}})+"\n"); sys.stdout.flush(); continue
        if not isinstance(req, dict):
            sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":None,"error":{"code":-32602,"message":"INVALID_REQUEST: argument 'request'"}})+"\n"); sys.stdout.flush(); continue
        try: out = handle(req)
        except Exception:
            out = {"jsonrpc":"2.0","id":req.get("id"),"error":{"code":-32602,"message":"MALFORMED_CONTAINER: argument 'request'"}}
        if req.get("id") is not None: sys.stdout.write(json.dumps(out)+"\n"); sys.stdout.flush()

if __name__ == "__main__": main()
# Eclipse Loft MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
