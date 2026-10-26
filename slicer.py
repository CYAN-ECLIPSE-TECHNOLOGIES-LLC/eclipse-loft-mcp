#!/usr/bin/env python3
# Eclipse Strata MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Deterministic simulated slicer + canonical toolpath hash (Strata §4.3/S1).

"""Simulated slicer (P0, CPU-only): deterministic G-code derivation from pinned inputs.

Real PrusaSlicer/Orca CLI adapters slot behind this same interface at P1+.
Canonical hash per §17-S1: comments + volatile header stripped, blank lines
removed, whitespace normalized; rest byte-exact.
"""
import hashlib, json, math

VOLATILE_PREFIXES = ("; generated at", "; bridge host", "; session id", ";STRATA-VOLATILE")

def sha256_hex(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()
def canonical_number(n):
    if isinstance(n, float) and n.is_integer(): return int(n)
    return n

def canonicalize_toolpath(text: str):
    kept, stripped = [], []
    for raw in text.splitlines():
        line = raw
        # strip trailing comment
        code = line.split(";", 1)[0].rstrip() if ";" in line else line.rstrip()
        is_volatile = any(line.strip().startswith(p) for p in VOLATILE_PREFIXES)
        is_comment_only = line.strip().startswith(";")
        if is_volatile or is_comment_only:
            stripped.append(line); continue
        norm = " ".join(code.split())
        if not norm: continue
        kept.append(norm)
    return "\n".join(kept) + ("\n" if kept else ""), stripped

def canonical_hash(text: str) -> str:
    canon, _ = canonicalize_toolpath(text)
    return sha256_hex(canon.encode())
def raw_hash(text: str) -> str: return sha256_hex(text.encode())

def _num(v, what):
    if isinstance(v, bool) or not isinstance(v, (int, float)): raise ValueError(f"malformed numeric: {what}")
    return float(v)

def slice_design(design_source: str, params: dict, profile: dict, slicer_build: dict, volatile_seed="t0"):
    """Deterministically derive toolpath. Same pinned inputs -> same canonical hash."""
    if not isinstance(params, dict) or not isinstance(profile, dict): raise ValueError("malformed slice inputs")
    bbox = params.get("bbox_mm", {"x": 20, "y": 20, "z": 10})
    if not isinstance(bbox, dict): raise ValueError("malformed bbox_mm")
    for _ax in ("x", "y", "z"): _num(bbox.get(_ax, 20), f"bbox_mm.{_ax}")
    if not isinstance(profile.get("temps"), dict) or not isinstance(profile.get("filament"), dict):
        raise ValueError("malformed profile temps/filament")
    for _k in ("hotend", "bed", "first_layer_hotend", "first_layer_bed"): _num(profile["temps"].get(_k), f"temps.{_k}")
    for _k in ("diameter_mm", "density_g_cm3"): _num(profile["filament"].get(_k), f"filament.{_k}")
    layers = max(1, int(math.ceil(float(bbox["z"]) / 0.2)))
    temps = profile["temps"]; fil = profile["filament"]
    lines = [
        f"; generated at {volatile_seed}",
        "; bridge host /sim/bridge",
        f"; session id {volatile_seed}",
        "; Eclipse Strata simulated slice",
        "G21", "G90", "M83",
        f"M140 S{temps['first_layer_bed']}",
        f"M104 S{temps['first_layer_hotend']}",
        f"M190 S{temps['first_layer_bed']}",
        f"M109 S{temps['first_layer_hotend']}",
    ]
    for extra in profile.get("start_gcode_lines", []):
        lines.append(extra)
    total_e = 0.0
    for i in range(layers):
        if i == 1:
            lines.append(f"M104 S{temps['hotend']}"); lines.append(f"M140 S{temps['bed']}")
        z = round((i+1)*0.2, 3)
        e = round(float(bbox["x"]) * 0.1, 4); total_e += e*4
        lines.append(f"G1 Z{z} F600")
        lines.append(f"G1 X{float(bbox['x'])} Y0 E{e} F1200")
        lines.append(f"G1 X{float(bbox['x'])} Y{float(bbox['y'])} E{e} F1200")
        lines.append(f"G1 X0 Y{float(bbox['y'])} E{e} F1200")
        lines.append(f"G1 X0 Y0 E{e} F1200")
    lines += ["M104 S0", "M140 S0", "M84"]
    text = "\n".join(lines) + "\n"
    # estimates §6.3: grams from E-values, duration from layers
    area = math.pi * (float(fil["diameter_mm"])/2)**2
    grams = round(total_e * area * float(fil["density_g_cm3"]) / 1000 * 1000 / 1000 * 1000 / 1000, 4)  # mm3->cm3
    grams = round(total_e * area * float(fil["density_g_cm3"]) / 1000, 4)
    duration = layers * 12
    estimates = {"duration_s": duration, "grams": grams,
                 "max_hotend_C": max(temps["hotend"], temps["first_layer_hotend"]),
                 "max_bed_C": max(temps["bed"], temps["first_layer_bed"]),
                 "max_chamber_C": 0, "total_e_mm": round(total_e,4)}
    return text, estimates

PROHIBITED_EXACT = {"M112","M500","M501","M502","M503","M997","M999","M907"}
# §6.4 config-write / heater classes (D1 fix): PID writes (M301/M303/M304), steps-per-unit
# writes (M92), probe-offset writes (M851) refuse as content regardless of provenance.
CONFIG_WRITE_EXACT = {"M92","M301","M303","M304","M851"}
# Klipper/extended config-write + heater classes: a poisoned pinned profile does NOT
# launder its start_gcode — these refuse anywhere in the final (re-sliced) toolpath.
CONFIG_WRITE_KEYWORDS = {"SAVE_CONFIG","RESTART","FIRMWARE_RESTART","SET_HEATER_TEMPERATURE"}
CONFIG_WRITE_PREFIXES = ("M500","M502","M997","CONFIG")
NONPRINT_CMDS = {"M3","M4","M5","G0-LASER"}  # spindle/laser classes on multi-function machines

def scan_toolpath(canon_text: str, profile: dict):
    """§6.4 third line of defense. Returns refusal code or None.

    Scans the FINAL toolpath (prepare output = re-sliced pinned inputs incl.
    pinned-profile start_gcode_lines; dispatch candidate identical by hash-match).
    Provenance of the profile never launders its contents.
    """
    temps = (profile or {}).get("temps") or {}
    allowed_hotend = {temps.get("hotend"), temps.get("first_layer_hotend"), 0}
    allowed_bed = {temps.get("bed"), temps.get("first_layer_bed"), 0}
    for line in canon_text.splitlines():
        parts = line.split()
        if not parts: continue
        cmd = parts[0].upper()
        if cmd in ("M3","M4","M5") or "LASER" in line.upper() or "SPINDLE" in line.upper():
            return "NONPRINT_HEAD_REFUSED"
        if cmd in PROHIBITED_EXACT or cmd in CONFIG_WRITE_EXACT or cmd in CONFIG_WRITE_KEYWORDS:
            return "TOOLPATH_CONTENT_REFUSED"
        if cmd in ("M104","M109"):
            vals = [p[1:] for p in parts[1:] if p.startswith("S")]
            if vals:
                try: v = float(vals[0])
                except ValueError: return "TOOLPATH_CONTENT_REFUSED"
                if v not in allowed_hotend: return "TOOLPATH_CONTENT_REFUSED"
        if cmd in ("M140","M190"):
            vals = [p[1:] for p in parts[1:] if p.startswith("S")]
            if vals:
                try: v = float(vals[0])
                except ValueError: return "TOOLPATH_CONTENT_REFUSED"
                if v not in allowed_bed: return "TOOLPATH_CONTENT_REFUSED"
    return None
# Eclipse Strata MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
