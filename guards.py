#!/usr/bin/env python3
# Eclipse Strata MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# House guards: coerce_int_param, parse_time, require_ref_param (Strata).

"""House guards — reference implementations, not variants (spec §15)."""
import re
from datetime import datetime, timezone

class ToolError(Exception):
    def __init__(self, code, refusal=None, arg=None):
        self.code = code; self.refusal = refusal; self.arg = arg
        super().__init__(f"{code}" + (f":{refusal}" if refusal else "") + (f":{arg}" if arg else ""))

def err32602(arg, refusal=None):
    return ToolError(-32602, refusal=refusal, arg=arg)

def coerce_int_param(value, arg):
    """Blackbox reference: accepts real ints, int-shaped strings, integral floats; bools refused."""
    if isinstance(value, bool):
        raise err32602(arg, "INT_PARAM_FORMAT")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value.strip()):
        return int(value.strip())
    raise err32602(arg, "INT_PARAM_FORMAT")

def parse_time(value, arg="timestamp"):
    """Docket reference: offset-less timestamps refuse by name; never guessed, no now() substitution."""
    if not isinstance(value, str) or not value.strip():
        raise err32602(arg, f"{arg.upper()}_UNPARSEABLE")
    v = value.strip()
    # bare date: explicit UTC midnight convention
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        try:
            dt = datetime.fromisoformat(v)
        except ValueError:
            raise err32602(arg, f"{arg.upper()}_UNPARSEABLE")
        return dt.replace(tzinfo=timezone.utc)
    if v.endswith("z"):
        raise err32602(arg, f"{arg.upper()}_UNPARSEABLE")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        raise err32602(arg, f"{arg.upper()}_UNPARSEABLE")
    if dt.tzinfo is None:
        raise err32602(arg, f"{arg.upper()}_OFFSET_REQUIRED")
    return dt.astimezone(timezone.utc)

def require_ref_param(value, arg, prefix=None):
    """Span reference: reference-typed params validate as references, never free strings."""
    if not isinstance(value, dict) or "ref" not in value or not isinstance(value.get("ref"), str) or not value["ref"]:
        raise err32602(arg, "REF_PARAM_FORMAT")
    if prefix and not value["ref"].startswith(prefix):
        raise err32602(arg, "REF_PARAM_FORMAT")
    return value["ref"]

def require_str(value, arg):
    if not isinstance(value, str) or not value:
        raise err32602(arg, "STRING_PARAM_FORMAT")
    return value

def require_dict(value, arg):
    if not isinstance(value, dict):
        raise err32602(arg, "OBJECT_PARAM_FORMAT")
    return value
# Eclipse Strata MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
