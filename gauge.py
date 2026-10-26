#!/usr/bin/env python3
# Eclipse Strata MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Strata Gauge — static envelope conformance checker (Strata §10.2).

"""Eclipse Strata Gauge: ENVELOPE_SOUND | ENVELOPE_UNSOUND, violations named.

Defensive by law (§15 named-refusal hygiene): malformed containers (missing
temps, partial build-volume bounds, non-numeric budgets) yield named
violations, never raw exceptions.
"""
MATERIAL_BANDS = {"PLA": (170,250,0,80), "PETG": (210,270,0,100), "ABS": (220,290,70,130),
                  "ASA": (220,290,70,130), "TPU": (190,260,0,80)}
SITE_CLASSES = ("ATTENDED","UNATTENDED_RATED","UNKNOWN")

def _num(v):
    """Float value or None; bools and non-numerics are malformed, never coerced silently."""
    if isinstance(v, bool) or not isinstance(v, (int, float)): return None
    return float(v)

def check_gauge(mandate, profile, printer, design_bbox=None):
    v = []
    if not isinstance(mandate, dict): return {"verdict": "ENVELOPE_UNSOUND", "violations": ["mandate_not_object"]}
    env = mandate.get("thermal_envelope")
    if not isinstance(env, dict): v.append("thermal_envelope_missing_or_malformed"); env = {}
    fw = printer.get("firmware_limits", {}) if isinstance(printer, dict) else {}
    if not isinstance(fw, dict): fw = {}
    if printer:
        for key, fwkey, name in (("hotend_max_C","hotend_max_C","hotend"), ("bed_max_C","bed_max_C","bed")):
            e, f = _num(env.get(key)), _num(fw.get(fwkey))
            if env.get(key) is not None and e is None: v.append(f"thermal_envelope_{name}_non_numeric")
            elif e is not None and f is not None and e > f: v.append(f"envelope_{name}_exceeds_firmware_limit")
        ec, fc = _num(env.get("chamber_max_C")), _num(fw.get("chamber_max_C"))
        if ec is not None and fc is not None and ec > fc: v.append("envelope_chamber_exceeds_firmware_limit")
    if profile is not None:
        if not isinstance(profile, dict):
            v.append("profile_not_object")
        else:
            t = profile.get("temps")
            if not isinstance(t, dict) or any(_num(t.get(k)) is None for k in ("hotend","bed","first_layer_hotend","first_layer_bed")):
                v.append("profile_temps_missing_or_non_numeric"); t = None
            fil = profile.get("filament")
            if not isinstance(fil, dict) or _num(fil.get("diameter_mm")) is None or _num(fil.get("density_g_cm3")) is None:
                v.append("profile_filament_missing_or_non_numeric"); fil = None
            if t is not None:
                eh, eb = _num(env.get("hotend_max_C")), _num(env.get("bed_max_C"))
                if eh is not None and max(t["hotend"], t["first_layer_hotend"]) > eh: v.append("profile_hotend_exceeds_envelope")
                if eb is not None and max(t["bed"], t["first_layer_bed"]) > eb: v.append("profile_bed_exceeds_envelope")
                mat = mandate.get("material_class")
                if mat in MATERIAL_BANDS:
                    lo, hi, blo, bhi = MATERIAL_BANDS[mat]
                    if not (lo <= t["hotend"] <= hi): v.append("material_temperature_band_incoherent")
            if fil is not None and fil.get("material_class") != mandate.get("material_class"):
                v.append("profile_material_mismatch_mandate")
    bounds = mandate.get("build_volume_bounds")
    if bounds is not None and not isinstance(bounds, dict): v.append("build_volume_bounds_malformed"); bounds = None
    if design_bbox is not None and bounds:
        if not isinstance(design_bbox, dict):
            v.append("design_bbox_malformed")
        else:
            for ax in ("x","y","z"):
                dv, bv = _num(design_bbox.get(ax)), _num(bounds.get(f"{ax}_max_mm"))
                if dv is None: v.append("design_bbox_malformed"); break
                if bv is None: v.append(f"build_volume_bounds_incomplete_{ax}")
                elif dv > bv: v.append(f"design_bbox_exceeds_volume_{ax}")
    if printer and bounds:
        vol = printer.get("build_volume_mm") if isinstance(printer, dict) else None
        if isinstance(vol, dict):
            for ax in ("x","y","z"):
                bv, pv = _num(bounds.get(f"{ax}_max_mm")), _num(vol.get(ax))
                if bv is not None and pv is not None and bv > pv: v.append(f"volume_bounds_exceed_printer_{ax}")
    serials = mandate.get("printer_serials", [])
    if isinstance(serials, list):
        for s in serials:
            if "*" in str(s) or "?" in str(s): v.append("printer_serial_wildcard")
    for field, name in (("max_print_duration_s","max_print_duration_not_positive"), ("max_filament_grams","max_filament_grams_not_positive")):
        val = _num(mandate.get(field))
        if mandate.get(field) is not None and val is None: v.append(f"{field}_non_numeric")
        elif val is None or val <= 0: v.append(name)
    if mandate.get("site_class") not in SITE_CLASSES: v.append("site_class_missing_or_unknown_value")
    if not mandate.get("window") or not mandate.get("expiry"): v.append("window_or_expiry_missing")
    return {"verdict": "ENVELOPE_SOUND" if not v else "ENVELOPE_UNSOUND", "violations": v}
# Eclipse Strata MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
