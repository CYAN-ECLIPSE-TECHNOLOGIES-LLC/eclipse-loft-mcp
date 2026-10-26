#!/usr/bin/env python3
# Eclipse Strata MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Strata engine — mandate, bridge, simulators, provenance, evidence (Strata §4-§12).

"""Eclipse Strata engine v0.1.0 — P0 simulators only, no real printer, no network.

Core mechanism (§2.1/§4.2): bridge re-slices pinned inputs and canonical-hash
matches before dispatch. Safety law §5 enforced in code. Composition §7 by port.
"""
import copy, hashlib, json, os, secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path
import signing, slicer
from gauge import check_gauge
from guards import ToolError, err32602, parse_time, coerce_int_param

VERSION = "0.1.0"
REFUSALS = ["TOOLPATH_PROVENANCE_MISMATCH","PROFILE_PIN_MISMATCH","SLICER_BUILD_MISMATCH","PROFILE_UNRESOLVED",
 "TOOLPATH_CONTENT_REFUSED","NONPRINT_HEAD_REFUSED","CONFIG_DRIFT","SAFETY_CONFIG_UNVERIFIABLE","CONFIG_WRITE_REFUSED",
 "RAW_GCODE_REFUSED","MATERIAL_MISMATCH","LOADOUT_UNVERIFIED","AGENT_SELF_PIN_REFUSED","PRINTER_WILDCARD_REFUSED",
 "MANDATE_EXPIRED","MANDATE_WINDOW_REFUSED","MANDATE_SIGNATURE_INVALID","BUDGET_EXCEEDED_AT_PREPARE","BUDGET_EXCEEDED",
 "ENVELOPE_VIOLATION","TELEMETRY_GAP","VENDOR_AUTHORIZATION_REQUIRED","EVIDENCE_FAILURE","JOB_SESSION_MISMATCH"]

class Refusal(Exception):
    def __init__(self, code, factor=""):
        self.code = code; self.factor = factor; super().__init__(code)

def aware_now(override=None):
    return override or datetime.now(timezone.utc)

# ---------------------------------------------------------------- PinSigner port (§7.1)
class LocalSigner:
    """PinSigner port local fallback: operator-held Ed25519 key, Herald grammar."""
    signer_type = "local"
    def __init__(self, keys_dir):
        self.dir = Path(keys_dir); self.dir.mkdir(parents=True, exist_ok=True)
        f = self.dir / "local-signer.json"
        if f.exists():
            d = json.loads(f.read_text()); self._seed = bytes.fromhex(d["seed_hex"]); self.pk = bytes.fromhex(d["pk_hex"])
            self._mat = signing.generate_keypair(self._seed)
        else:
            self._seed = secrets.token_bytes(32); self._mat = signing.generate_keypair(self._seed); self.pk = self._mat[2]
            f.write_text(json.dumps({"seed_hex": self._seed.hex(), "pk_hex": self.pk.hex()}))
            try: os.chmod(f, 0o600)
            except OSError: pass
    @property
    def fingerprint(self): return signing.fingerprint(self.pk)
    def sign(self, payload_obj) -> str:
        sig, _ = signing.sign(self._mat, slicer.canonical_json(payload_obj)); return sig.hex()
    def verify(self, payload_obj, sig_hex, pk_hex=None) -> bool:
        try: return signing.verify(bytes.fromhex(pk_hex) if pk_hex else self.pk, slicer.canonical_json(payload_obj), bytes.fromhex(sig_hex))
        except Exception: return False

class HeraldPort:
    """Herald PinSigner port (§7): if a Herald signer is injected it is used; else local."""
    def __init__(self, local): self.local = local; self.herald = None
    @property
    def active(self): return self.herald or self.local
    def sign_mandate(self, m): return self.active.sign(m)
    def sign_pin(self, p): return self.active.sign(p)
    def verify(self, payload, sig, pk=None): return self.active.verify(payload, sig, pk)

class TillPort:
    """P3-gated port ONLY (§7/D9): no Till code paths active at P0."""
    enabled = False
    def settle(self, *a, **k): raise Refusal("EVIDENCE_FAILURE", "till_port_p3_gated_not_built")

# ---------------------------------------------------------------- Simulators (§13 P0)
class SimPrinter:
    def __init__(self, cfg):
        self.cfg = cfg; self.serial = cfg["serial"]; self.model = cfg["model"]; self.kind = cfg["kind"]
        self.firmware = cfg["firmware"]; self.firmware_limits = cfg["firmware_limits"]
        self.build_volume_mm = cfg["build_volume_mm"]; self.head = cfg.get("head", "print")
        self.config = {"max_hotend_C": cfg["firmware_limits"]["hotend_max_C"], "max_bed_C": cfg["firmware_limits"]["bed_max_C"],
                       "thermal_protection": True, "firmware": cfg["firmware"]}
        self.config_hash = slicer.sha256_hex(slicer.canonical_json(self.config))
        self.config_unverifiable = False
        self.material_loaded = cfg.get("material_loaded", "PLA"); self.material_attestable = cfg.get("material_attestable", True)
        self.plate_clear_attestable = cfg.get("plate_clear_attestable", True)
        self.state = "idle"; self.heated = False; self.progress = 0.0; self.elapsed_s = 0
        self.hotend_C = 24.0; self.bed_C = 24.0; self.telemetry_cut = False; self.last_telemetry_s = 0
        self.telemetry_gap_s = 0; self.job = None; self.paused = False
        self.site_class_declared = cfg.get("site_class", "ATTENDED")
    def attest_config(self):
        if self.config_unverifiable: return None
        self.config_hash = slicer.sha256_hex(slicer.canonical_json(self.config)); return self.config_hash
    def tamper_config(self, **kw): self.config.update(kw)
    def start(self, job):
        self.state = "printing"; self.heated = True; self.job = job; self.progress = 0.0; self.elapsed_s = 0; self.paused = False
    def tick(self, dt_s, estimates):
        if self.telemetry_cut:
            self.telemetry_gap_s += dt_s; return
        self.telemetry_gap_s = 0; self.last_telemetry_s += dt_s
        if self.state == "printing" and not self.paused:
            self.elapsed_s += dt_s
            dur = max(1, estimates["duration_s"]); self.progress = min(1.0, self.elapsed_s / dur)
            self.hotend_C = 205.0; self.bed_C = 60.0
            if self.progress >= 1.0: self.state = "completed"; self.heated = False
    def telemetry(self):
        if self.telemetry_cut: return None
        return {"hotend_C": self.hotend_C, "bed_C": self.bed_C, "target_hotend_C": 205 if self.heated else 0,
                "target_bed_C": 60 if self.heated else 0, "progress": self.progress, "elapsed_s": self.elapsed_s,
                "state": self.state, "fan_pct": 50 if self.heated else 0, "power_w": 120 if self.heated else 5}
    def pause(self): self.paused = True; self.state = "paused" if self.job else self.state
    def cancel(self): self.state = "idle"; self.heated = False; self.job = None; self.paused = False; self.hotend_C = 24.0; self.bed_C = 24.0

DEFAULT_PRINTERS = [
 {"serial": "SIM-OCTO-001", "model": "OctoPrint Virtual Printer", "kind": "octoprint_virtual",
  "firmware": "Marlin Virtual 2.1", "firmware_limits": {"hotend_max_C": 300, "bed_max_C": 130, "chamber_max_C": None},
  "build_volume_mm": {"x": 220, "y": 220, "z": 250}, "material_loaded": "PLA", "site_class": "ATTENDED"},
 {"serial": "SIM-KLIP-001", "model": "Virtual Klipper/Moonraker", "kind": "klipper_virtual",
  "firmware": "Klipper v0.12-virtual Moonraker", "firmware_limits": {"hotend_max_C": 300, "bed_max_C": 130, "chamber_max_C": 60},
  "build_volume_mm": {"x": 235, "y": 235, "z": 250}, "material_loaded": "PLA", "site_class": "ATTENDED"},
 {"serial": "SIM-MULTI-001", "model": "Virtual Multi-function (print head)", "kind": "klipper_virtual",
  "firmware": "Klipper v0.12-virtual", "firmware_limits": {"hotend_max_C": 300, "bed_max_C": 130, "chamber_max_C": None},
  "build_volume_mm": {"x": 200, "y": 200, "z": 200}, "material_loaded": "PLA", "site_class": "ATTENDED", "head": "print"},
]
SLICER_BUILD = {"name": "PrusaSlicer", "version": "2.8.0-sim", "binary_hash": slicer.sha256_hex(b"strata-sim-prusaslicer-2.8.0")}

# ---------------------------------------------------------------- Bridge / Engine
class Engine:
    def __init__(self, base_dir=None, printers=None, now_override=None):
        base = Path(base_dir) if base_dir else Path(__file__).parent
        self.pack_dir = base / "data" / "packs"; self.pack_dir.mkdir(parents=True, exist_ok=True)
        self.pack_store_available = True
        self.signer = LocalSigner(base / "keys"); self.pinsigner = HeraldPort(self.signer)
        self.printers = {p.serial: p for p in [SimPrinter(c) for c in (printers or DEFAULT_PRINTERS)]}
        self.slicer_build = dict(SLICER_BUILD); self.slicer_registry = [dict(SLICER_BUILD),
            {"name": "OrcaSlicer", "version": "2.1.0-sim", "binary_hash": slicer.sha256_hex(b"strata-sim-orca-2.1.0")}]
        self.designs = {}; self.profiles = {}; self.sessions = {}; self.jobs = {}
        self.refusal_log = []; self.findings = []; self.meter_records = []; self.packs = {}
        self._now_override = now_override; self.heartbeat_alive = True
        self.till = TillPort()  # port only, inactive
        # Census: REJECTED (§7) — no port, no attribute, by design.
    def now(self): return aware_now(self._now_override)
    def set_now(self, dt): self._now_override = dt

    # ---- receipts
    def receipt(self, tool, code, factor, mandate_id=None, printer_serial=None, heated=False):
        r = {"tool": tool, "mandate_id": mandate_id, "refusal_code": code, "factor": factor,
             "printer_serial": printer_serial, "printer_heated_by_refusal": heated, "at": self.now().isoformat()}
        self.refusal_log.append(r); return r
    def refuse(self, tool, code, factor="", mandate_id=None, printer_serial=None):
        self.receipt(tool, code, factor, mandate_id, printer_serial); raise Refusal(code, factor)

    # ---- design (§8.1, §4.4)
    def design_register(self, agent_identity, source, params, source_kind="code_first"):
        if not isinstance(source, str) or not source: raise err32602("source")
        if not isinstance(params, dict): raise err32602("parameter_set")
        export_bytes = slicer.canonical_json({"source": source, "params": params, "renderer": "strata-sim-export-v1"})
        pin = {"design_source_hash": slicer.sha256_hex(source.encode()),
               "parameter_set_hash": slicer.sha256_hex(slicer.canonical_json(params)),
               "export_hash": slicer.sha256_hex(export_bytes)}
        design_id = "design-" + pin["design_source_hash"][:12]
        geom = self._geometry(params)
        self.designs[design_id] = {"design_id": design_id, "status": "PROPOSED", "pin": pin, "source": source,
            "params": copy.deepcopy(params), "source_kind": source_kind, "proposed_by": agent_identity, "activation": None, "geometry": geom}
        return {"design_id": design_id, "status": "PROPOSED", "pin": pin, "geometry": geom,
                "note": "PROPOSED only — activation requires a human-principal signed pin record (§4.4)"}
    def _geometry(self, params):
        # D7 (honesty law): P0 geometry is DECLARED geometry only — facts are the
        # caller-declared parameter set plus arithmetic over it. No kernel/mesh
        # inspection of the artifact is performed; manifold / wall / triangle
        # facts are reported unchecked (None), never fabricated.
        # D3: malformed bbox containers refuse by name (-32602), never crash.
        bbox = params.get("bbox_mm", {"x": 20, "y": 20, "z": 10})
        if not isinstance(bbox, dict): raise err32602("parameter_set.bbox_mm", "BBOX_NOT_OBJECT")
        vals = {}
        for ax in ("x", "y", "z"):
            v = bbox.get(ax)
            if isinstance(v, bool) or not isinstance(v, (int, float)): raise err32602(f"parameter_set.bbox_mm.{ax}", "BBOX_NON_NUMERIC")
            vals[ax] = float(v)
        mw = params.get("min_wall_mm", 1.2)
        if isinstance(mw, bool) or not isinstance(mw, (int, float)): raise err32602("parameter_set.min_wall_mm", "MIN_WALL_NON_NUMERIC")
        vol = vals["x"]*vals["y"]*vals["z"]
        return {"geometry_basis": "declared_geometry_only", "inspection_basis": "declared_geometry_only_no_kernel_inspection",
                "bbox_mm": bbox, "volume_mm3": vol, "min_wall_mm": mw,
                "manifold": None, "triangle_count": None, "face_count": None}
    def design_inspect(self, design_id):
        d = self.designs.get(design_id)
        if not d: raise err32602("design_id", "DESIGN_NOT_FOUND")
        return dict(d["geometry"])
    def design_pin_get(self, design_id):
        d = self.designs.get(design_id)
        if not d: raise err32602("design_id", "DESIGN_NOT_FOUND")
        return {"design_id": design_id, "status": d["status"], "pin": d["pin"], "activation": d["activation"],
                "bound_mandate_ids": [s["mandate"].get("mandate_id") for s in self.sessions.values() if d["pin"] in s["mandate"].get("design_pins", [])]}
    # activation: NOT an MCP tool — human principal via admin CLI / signed pin record (§4.4, §8.4)
    def activate_design(self, design_id, principal, signature=None, signer_type="local"):
        d = self.designs.get(design_id)
        if not d: raise err32602("design_id", "DESIGN_NOT_FOUND")
        if not principal or principal.get("role") != "human_principal":
            self.refuse("design_pin_activate", "AGENT_SELF_PIN_REFUSED", "activator_not_human_principal")
        payload = {"design_id": design_id, "pin": d["pin"], "principal": principal["id"]}
        sig = signature or self.pinsigner.sign_pin(payload)
        if not self.pinsigner.verify(payload, sig): self.refuse("design_pin_activate", "MANDATE_SIGNATURE_INVALID", "pin_signature")
        d["status"] = "ACTIVATED"; d["activation"] = {"signer": signer_type, "principal": principal["id"], "at": self.now().isoformat(), "signature": sig}
        return d
    def register_profile(self, agent_identity, profile):
        if not isinstance(profile, dict): raise err32602("profile", "OBJECT_PARAM_FORMAT")
        if "inherits" in profile or "include" in profile:
            pid = "profile-" + slicer.sha256_hex(slicer.canonical_json(profile))[:12]
            self.profiles[pid] = {"profile_id": pid, "status": "PROPOSED_UNRESOLVED", "profile": copy.deepcopy(profile), "profile_hash": None, "activation": None}
            return {"profile_id": pid, "status": "PROPOSED_UNRESOLVED", "note": "unflattened profiles refuse PROFILE_UNRESOLVED at prepare"}
        ph = slicer.sha256_hex(slicer.canonical_json(profile))
        pid = "profile-" + ph[:12]
        self.profiles[pid] = {"profile_id": pid, "status": "PROPOSED", "profile": copy.deepcopy(profile), "profile_hash": ph, "activation": None}
        return {"profile_id": pid, "status": "PROPOSED", "profile_hash": ph}
    def activate_profile(self, profile_id, principal):
        p = self.profiles.get(profile_id)
        if not p: raise err32602("profile_id", "PROFILE_NOT_FOUND")
        if not principal or principal.get("role") != "human_principal":
            self.refuse("profile_pin_activate", "AGENT_SELF_PIN_REFUSED", "activator_not_human_principal")
        payload = {"profile_id": profile_id, "profile_hash": p["profile_hash"], "principal": principal["id"]}
        sig = self.pinsigner.sign_pin(payload)
        p["status"] = "ACTIVATED"; p["activation"] = {"signer": "local", "principal": principal["id"], "at": self.now().isoformat(), "signature": sig}
        return p

    # ---- mandate (§6.1)
    def sign_mandate(self, mandate_unsigned):
        m = copy.deepcopy(mandate_unsigned); m["signature"] = self.pinsigner.sign_mandate({k: v for k, v in m.items() if k != "signature"}); return m
    def validate_mandate(self, m, tool="session_open"):
        # D3: every container is shape-checked before any index/compare — malformed
        # mandates refuse by name (-32602 family), never raw KeyError/TypeError.
        if not isinstance(m, dict): raise err32602("mandate")
        for f in ("agent_identity","printer_serials","design_pins","slicer_build","profile_pins","material_class",
                  "thermal_envelope","build_volume_bounds","max_print_duration_s","max_filament_grams","site_class","window","expiry"):
            if f not in m: raise err32602(f"mandate.{f}", "MANDATE_FIELD_MISSING")
        if not isinstance(m["printer_serials"], list) or not m["printer_serials"]: raise err32602("mandate.printer_serials", "SERIALS_NOT_LIST")
        for s in m["printer_serials"]:
            if not isinstance(s, str) or not s: raise err32602("mandate.printer_serials", "SERIAL_NOT_STRING")
            if "*" in s or "?" in s: self.refuse(tool, "PRINTER_WILDCARD_REFUSED", "printer_serials", m.get("mandate_id"))
        if not isinstance(m["design_pins"], list): raise err32602("mandate.design_pins", "PINS_NOT_LIST")
        if not isinstance(m["profile_pins"], list): raise err32602("mandate.profile_pins", "PINS_NOT_LIST")
        if not isinstance(m["slicer_build"], dict): raise err32602("mandate.slicer_build", "SLICER_BUILD_NOT_OBJECT")
        if not isinstance(m["thermal_envelope"], dict): raise err32602("mandate.thermal_envelope", "ENVELOPE_NOT_OBJECT")
        for k, v in m["thermal_envelope"].items():
            if v is not None and (isinstance(v, bool) or not isinstance(v, (int, float))): raise err32602(f"mandate.thermal_envelope.{k}", "ENVELOPE_NON_NUMERIC")
        if not isinstance(m["build_volume_bounds"], dict): raise err32602("mandate.build_volume_bounds", "VOLUME_BOUNDS_NOT_OBJECT")
        for k, v in m["build_volume_bounds"].items():
            if isinstance(v, bool) or not isinstance(v, (int, float)): raise err32602(f"mandate.build_volume_bounds.{k}", "VOLUME_BOUNDS_NON_NUMERIC")
        if not isinstance(m["window"], dict): raise err32602("mandate.window", "WINDOW_NOT_OBJECT")
        dur = coerce_int_param(m["max_print_duration_s"], "max_print_duration_s")
        if isinstance(m["max_filament_grams"], bool) or not isinstance(m["max_filament_grams"], (int, float)):
            raise err32602("mandate.max_filament_grams", "NUMBER_PARAM_FORMAT")
        gap = coerce_int_param(m.get("telemetry_gap_threshold_s", 30), "telemetry_gap_threshold_s")
        if not (10 <= gap <= 300): raise err32602("telemetry_gap_threshold_s", "GAP_THRESHOLD_RANGE")
        # signature verifies over the record AS PRESENTED (coercions applied only after)
        payload = {k: v for k, v in m.items() if k != "signature"}
        if not m.get("signature") or not self.pinsigner.verify(payload, m["signature"]):
            self.refuse(tool, "MANDATE_SIGNATURE_INVALID", "signature", m.get("mandate_id"))
        m["max_print_duration_s"] = dur; m["telemetry_gap_threshold_s"] = gap
        m.setdefault("violation_policy", {"on_envelope_violation": "pause-then-cancel", "on_telemetry_gap": "pause-then-cancel", "cancel_after_s": 600})
        m.setdefault("hard_stop_at_expiry", False); m.setdefault("delegation", None)  # Span slot present from P0 (§7)
        # times via parse_time choke point (.get: a missing key is a named -32602, not a KeyError)
        nb = parse_time(m["window"].get("not_before"), "not_before"); na = parse_time(m["window"].get("not_after"), "not_after")
        exp = parse_time(m.get("expiry"), "expiry")
        if na > exp: raise err32602("mandate.window.not_after", "WINDOW_AFTER_EXPIRY")
        return m

    # ---- print tools (§8.2)
    def printers_discover(self):
        return {"printers": [{"serial": p.serial, "model": p.model, "kind": p.kind, "firmware": p.firmware,
            "firmware_limits": p.firmware_limits, "build_volume_mm": p.build_volume_mm, "head": p.head,
            "target_class": "simulator", "site_class": p.site_class_declared} for p in self.printers.values()]}
    SITE_CLASS_ENUM = ("ATTENDED", "UNATTENDED_RATED", "UNKNOWN")
    def session_open(self, mandate, agent_identity):
        presented = copy.deepcopy(mandate) if isinstance(mandate, dict) else mandate  # as-signed record, for packs (D2)
        m = self.validate_mandate(mandate)
        if m["agent_identity"] != agent_identity: self.refuse("session_open", "MANDATE_SIGNATURE_INVALID", "agent_identity_mismatch", m.get("mandate_id"))
        # D8 (§8.2): window/expiry verified at OPEN, not only at dispatch.
        now = self.now()
        if now > parse_time(m["expiry"], "expiry"): self.refuse("session_open", "MANDATE_EXPIRED", "expiry_at_open", m.get("mandate_id"))
        if not (parse_time(m["window"]["not_before"], "not_before") <= now <= parse_time(m["window"]["not_after"], "not_after")):
            self.refuse("session_open", "MANDATE_WINDOW_REFUSED", "window_at_open", m.get("mandate_id"))
        # D4 (§15 fail-closed): the enum check runs HERE — only exact enum values
        # grant tiers; UNKNOWN and anything else (unknown/near-miss/case variants) grant T0 only.
        tier = "T1" if m["site_class"] in ("ATTENDED", "UNATTENDED_RATED") else "T0"
        atts = {}
        for serial in m["printer_serials"]:
            p = self.printers.get(serial)
            if not p: raise err32602("printer_serial", f"PRINTER_SERIAL_UNKNOWN:{serial}")  # D10: unknown serial is a named -32602, not a wildcard refusal
            if p.head != "print": self.refuse("session_open", "NONPRINT_HEAD_REFUSED", serial, m.get("mandate_id"))
            h = p.attest_config()
            if h is None: self.refuse("session_open", "SAFETY_CONFIG_UNVERIFIABLE", serial, m.get("mandate_id"))
            atts[serial] = h
        sid = "session-" + secrets.token_hex(6)
        self.sessions[sid] = {"session_id": sid, "mandate": copy.deepcopy(m), "mandate_signed_record": presented,
                              "agent": agent_identity, "tier": tier,
                              "attestations": atts, "jobs": [], "opened_at": self.now().isoformat(), "closed": False}
        return {"session_id": sid, "tier": tier, "attestations": atts, "site_class": m["site_class"],
                "site_class_recognized": m["site_class"] in self.SITE_CLASS_ENUM}
    def _session(self, sid):
        s = self.sessions.get(sid)
        if not s or s["closed"]: raise err32602("session_id", "SESSION_NOT_FOUND")
        return s
    def _check_job_binding(self, tool, s, job):
        # D5 (§4.2/§8.2): a job is bound to its preparing session + mandate.
        if job.get("session_id") != s["session_id"] or job.get("mandate_id") != s["mandate"].get("mandate_id"):
            self.refuse(tool, "JOB_SESSION_MISMATCH", "job_prepared_under_different_session_or_mandate",
                        s["mandate"].get("mandate_id"), job.get("printer_serial"))
    def job_prepare(self, session_id, design_id, profile_id, printer_serial, supplied_toolpath=None):
        s = self._session(session_id); m = s["mandate"]
        if supplied_toolpath is not None and not isinstance(supplied_toolpath, str): raise err32602("supplied_toolpath", "STRING_PARAM_FORMAT")
        if printer_serial not in m["printer_serials"]: self.refuse("job_prepare", "PRINTER_WILDCARD_REFUSED", "serial_not_in_mandate", m.get("mandate_id"), printer_serial)
        if s["tier"] == "T0": self.refuse("job_prepare", "MANDATE_WINDOW_REFUSED", "site_class_unknown_t0_only", m.get("mandate_id"), printer_serial)
        d = self.designs.get(design_id); p_rec = self.profiles.get(profile_id)
        if not d: raise err32602("design_id", "DESIGN_NOT_FOUND")
        if not p_rec: raise err32602("profile_id", "PROFILE_NOT_FOUND")
        if d["status"] != "ACTIVATED" or d["pin"] not in m["design_pins"]: self.refuse("job_prepare", "AGENT_SELF_PIN_REFUSED", "design_pin_not_activated_or_not_in_mandate", m.get("mandate_id"), printer_serial)
        if p_rec["status"] == "PROPOSED_UNRESOLVED": self.refuse("job_prepare", "PROFILE_UNRESOLVED", profile_id, m.get("mandate_id"), printer_serial)
        if p_rec["profile_hash"] != slicer.sha256_hex(slicer.canonical_json(p_rec["profile"])): self.refuse("job_prepare", "PROFILE_PIN_MISMATCH", "profile_content_vs_pin_hash", m.get("mandate_id"), printer_serial)
        if p_rec["profile_hash"] not in [pp.get("profile_hash") if isinstance(pp, dict) else pp for pp in m["profile_pins"]] and p_rec["profile_hash"] not in m["profile_pins"]:
            self.refuse("job_prepare", "PROFILE_PIN_MISMATCH", "profile_not_in_mandate", m.get("mandate_id"), printer_serial)
        if p_rec["status"] != "ACTIVATED": self.refuse("job_prepare", "PROFILE_PIN_MISMATCH", "profile_not_activated", m.get("mandate_id"), printer_serial)
        if m["slicer_build"] != self.slicer_build: self.refuse("job_prepare", "SLICER_BUILD_MISMATCH", "mandate_slicer_vs_bridge", m.get("mandate_id"), printer_serial)
        printer = self.printers[printer_serial]
        gauge = check_gauge(m, p_rec["profile"], {"firmware_limits": printer.firmware_limits, "build_volume_mm": printer.build_volume_mm}, d["geometry"]["bbox_mm"])
        if gauge["verdict"] == "ENVELOPE_UNSOUND":
            # D10 vocabulary precision: structural profile defects are -32602 naming the
            # argument; budget-shaped defects are BUDGET_EXCEEDED_AT_PREPARE (§11).
            # Thermal/volume envelope defects keep the prepare refusal code of the
            # bench-passed H15 shape (byte-for-byte law for passed shapes).
            viol = gauge["violations"]
            if any(x.startswith(("profile_temps_", "profile_filament_")) for x in viol):
                raise err32602("profile.temps", "PROFILE_TEMPS_OR_FILAMENT_MALFORMED:" + ";".join(viol))
            if any(x.startswith(("max_print_duration", "max_filament_grams")) for x in viol):
                self.refuse("job_prepare", "BUDGET_EXCEEDED_AT_PREPARE", ";".join(viol), m.get("mandate_id"), printer_serial)
            self.receipt("job_prepare", "ENVELOPE_VIOLATION", ";".join(viol), m.get("mandate_id"), printer_serial)
            raise Refusal("ENVELOPE_VIOLATION", ";".join(viol))
        try:
            text, est = slicer.slice_design(d["source"], d["params"], p_rec["profile"], self.slicer_build, volatile_seed=self.now().isoformat())
        except (ValueError, TypeError, KeyError, AttributeError):
            raise err32602("parameter_set", "DESIGN_OR_PROFILE_PARAMS_MALFORMED")
        canon, stripped = slicer.canonicalize_toolpath(text)
        scan = slicer.scan_toolpath(canon, p_rec["profile"])
        if scan: self.refuse("job_prepare", scan, "toolpath_content_scan", m.get("mandate_id"), printer_serial)
        if supplied_toolpath is not None and slicer.canonical_hash(supplied_toolpath) != slicer.canonical_hash(text):
            self.refuse("job_prepare", "TOOLPATH_PROVENANCE_MISMATCH", "supplied_toolpath", m.get("mandate_id"), printer_serial)
        if est["grams"] > float(m["max_filament_grams"]) or est["duration_s"] > int(m["max_print_duration_s"]):
            self.refuse("job_prepare", "BUDGET_EXCEEDED_AT_PREPARE", f"grams={est['grams']} dur={est['duration_s']}", m.get("mandate_id"), printer_serial)
        job_hash = slicer.canonical_hash(text)
        job = {"job_hash": job_hash, "session_id": session_id, "design_id": design_id, "profile_id": profile_id,
               "printer_serial": printer_serial, "toolpath_text": text, "canonical_hash": job_hash, "raw_hash": slicer.raw_hash(text),
               "stripped_header_lines": stripped, "estimates": est, "state": "PREPARED", "telemetry_trace": [], "gaps": [],
               "pending_confirm": [], "dispatch_record": None, "mandate_id": m.get("mandate_id")}
        # readiness: plate-clear required if mandate says so
        if m.get("require_plate_clear_attested") and not printer.plate_clear_attestable:
            job["pending_confirm"] = ["plate_clear"]; job["state"] = "PENDING_PHYSICAL_CONFIRM"
        self.jobs[job_hash] = job; s["jobs"].append(job_hash)
        return {"job_hash": job_hash, "toolpath_canonical_hash": job_hash, "raw_hash": job["raw_hash"], "estimates": est,
                "profile_hash": p_rec["profile_hash"], "slicer_build": self.slicer_build, "state": job["state"],
                "pending_physical_confirm": job["pending_confirm"]}
    def job_dispatch(self, session_id, job_hash, supplied_toolpath=None, scheduled_at=None):
        s = self._session(session_id); m = s["mandate"]; job = self.jobs.get(job_hash)
        if not job: raise err32602("job_hash", "JOB_NOT_FOUND")
        if supplied_toolpath is not None and not isinstance(supplied_toolpath, str): raise err32602("supplied_toolpath", "STRING_PARAM_FORMAT")
        self._check_job_binding("job_dispatch", s, job)  # D5
        serial = job["printer_serial"]; printer = self.printers[serial]
        if scheduled_at is not None: self.refuse("job_dispatch", "MANDATE_EXPIRED", "queueing_not_supported_no_stale_authority", m.get("mandate_id"), serial)
        if not self.heartbeat_alive: self.refuse("job_dispatch", "TELEMETRY_GAP", "no_live_bridge_heartbeat", m.get("mandate_id"), serial)
        now = self.now()
        if now > parse_time(m["expiry"], "expiry"): self.refuse("job_dispatch", "MANDATE_EXPIRED", "expiry", m.get("mandate_id"), serial)
        if not (parse_time(m["window"]["not_before"], "not_before") <= now <= parse_time(m["window"]["not_after"], "not_after")):
            self.refuse("job_dispatch", "MANDATE_WINDOW_REFUSED", "window", m.get("mandate_id"), serial)
        if job["state"] == "PENDING_PHYSICAL_CONFIRM":
            return {"job_hash": job_hash, "state": "PENDING_PHYSICAL_CONFIRM", "pending": job["pending_confirm"], "dispatched": False}
        # config drift re-attestation (§5)
        h = printer.attest_config()
        if h is None: self.refuse("job_dispatch", "SAFETY_CONFIG_UNVERIFIABLE", serial, m.get("mandate_id"), serial)
        if h != s["attestations"].get(serial): self.refuse("job_dispatch", "CONFIG_DRIFT", serial, m.get("mandate_id"), serial)
        # material loadout (§6.2)
        if printer.material_attestable:
            if printer.material_loaded != m["material_class"]: self.refuse("job_dispatch", "MATERIAL_MISMATCH", f"loaded={printer.material_loaded} mandate={m['material_class']}", m.get("mandate_id"), serial)
            loadout_level = "machine-attested"
        else:
            if m.get("require_attested_loadout"): self.refuse("job_dispatch", "LOADOUT_UNVERIFIED", serial, m.get("mandate_id"), serial)
            loadout_level = "unchecked"  # D9 (§12 honesty): nothing was declared — never labeled human-declared
        # evidence failure pre-check (§5: no pack -> no dispatch)
        if not self.pack_store_available: self.refuse("job_dispatch", "EVIDENCE_FAILURE", "pack_store_unavailable", m.get("mandate_id"), serial)
        # RE-SLICE + HASH MATCH (§4.2 step 2) — the core mechanism
        d = self.designs[job["design_id"]]; p_rec = self.profiles[job["profile_id"]]
        if p_rec["profile_hash"] != slicer.sha256_hex(slicer.canonical_json(p_rec["profile"])):
            self.refuse("job_dispatch", "PROFILE_PIN_MISMATCH", "profile_tampered_since_prepare", m.get("mandate_id"), serial)
        if m["slicer_build"] != self.slicer_build: self.refuse("job_dispatch", "SLICER_BUILD_MISMATCH", "dispatch", m.get("mandate_id"), serial)
        try:
            re_text, _ = slicer.slice_design(d["source"], d["params"], p_rec["profile"], self.slicer_build, volatile_seed="reslice-different-banner")
        except (ValueError, TypeError, KeyError, AttributeError):
            raise err32602("parameter_set", "DESIGN_OR_PROFILE_PARAMS_MALFORMED")
        re_hash = slicer.canonical_hash(re_text)
        candidate = supplied_toolpath if supplied_toolpath is not None else job["toolpath_text"]
        if slicer.canonical_hash(candidate) != re_hash or re_hash != job["canonical_hash"]:
            self.refuse("job_dispatch", "TOOLPATH_PROVENANCE_MISMATCH", "reslice_mismatch", m.get("mandate_id"), serial)
        scan = slicer.scan_toolpath(slicer.canonicalize_toolpath(candidate)[0], p_rec["profile"])
        if scan: self.refuse("job_dispatch", scan, "toolpath_content_scan_dispatch", m.get("mandate_id"), serial)
        job["dispatch_record"] = {"prepare_hash": job["canonical_hash"], "dispatch_reslice_hash": re_hash, "match": True,
                                  "dispatch_time": now.isoformat(), "bridge_identity": "strata-bridge-sim-v0.1", "loadout_level": loadout_level}
        job["state"] = "PRINTING"; printer.start(job)
        return {"job_hash": job_hash, "state": "PRINTING", "dispatched": True, "dispatch_record": job["dispatch_record"]}
    def tick(self, session_id, dt_s=10):
        """Advance simulators; dead-man + expiry semantics (§5/§6.5)."""
        s = self._session(session_id); m = s["mandate"]; gap_thresh = int(m.get("telemetry_gap_threshold_s", 30))
        events = []
        for jh in list(s["jobs"]):
            job = self.jobs[jh]; printer = self.printers[job["printer_serial"]]
            if job["state"] not in ("PRINTING", "PAUSED_TELEMETRY_GAP"): continue
            printer.tick(dt_s, job["estimates"])
            if printer.telemetry_cut and printer.telemetry_gap_s > gap_thresh:
                if job["state"] != "PAUSED_TELEMETRY_GAP":
                    printer.pause(); job["state"] = "PAUSED_TELEMETRY_GAP"; job["gaps"].append({"type": "telemetry_gap", "gap_s": printer.telemetry_gap_s})
                    self.receipt("telemetry", "TELEMETRY_GAP", f"gap_s={printer.telemetry_gap_s}", m.get("mandate_id"), printer.serial)
                    self.findings.append({"kind": "friction_auto_filed", "adapter": printer.kind, "finding": "telemetry_gap", "serial": printer.serial})
                events.append({"job_hash": jh, "event": "TELEMETRY_GAP", "state": "UNKNOWN"})
                continue
            if job["state"] == "PAUSED_TELEMETRY_GAP" and not printer.telemetry_cut:
                # resume only after re-attestation (§6.5)
                h = printer.attest_config()
                if h != s["attestations"].get(printer.serial):
                    self.refuse("job_resume", "CONFIG_DRIFT", printer.serial, m.get("mandate_id"), printer.serial)
                printer.paused = False; printer.state = "printing"; job["state"] = "PRINTING"; events.append({"job_hash": jh, "event": "RESUMED_AFTER_REATTESTATION"})
            tel = printer.telemetry()
            if tel: job["telemetry_trace"].append(tel)
            # expiry mid-print != kill (§5), unless hard_stop
            if self.now() > parse_time(m["expiry"], "expiry"):
                job.setdefault("notices", []).append("mandate_expired_mid_print_continuing_monitored")
                # D6 (§14 H8): the expiry is SEALED into the pack as an event, once —
                # the honest record shows both the expiry and the completion.
                if not job.get("expiry_event_recorded"):
                    job["expiry_event_recorded"] = True
                    action = "hard_stop_cancel" if m.get("hard_stop_at_expiry") else "continuing_monitored"
                    job.setdefault("events", []).append({"type": "mandate_expired_mid_print", "expiry": m["expiry"],
                        "observed_at": self.now().isoformat(), "action": action})
                if m.get("hard_stop_at_expiry"): printer.cancel(); job["state"] = "ABORTED"
            if printer.state == "completed": job["state"] = "COMPLETED"
            # budget in-print
            actual_g = round(job["estimates"]["grams"] * printer.progress, 4)
            if actual_g > float(m["max_filament_grams"]): job["state"] = "PAUSED"; printer.pause(); self.receipt("telemetry", "BUDGET_EXCEEDED", "grams", m.get("mandate_id"), printer.serial)
        return events
    def job_status(self, session_id, job_hash):
        s = self._session(session_id); job = self.jobs.get(job_hash)
        if not job: raise err32602("job_hash", "JOB_NOT_FOUND")
        self._check_job_binding("job_status", s, job)  # D5
        printer = self.printers[job["printer_serial"]]
        return {"job_hash": job_hash, "state": job["state"], "telemetry": printer.telemetry(),
                "budget_consumption": {"grams_estimate": round(job["estimates"]["grams"]*printer.progress,4), "elapsed_s": printer.elapsed_s},
                "pending_physical_confirm": job["pending_confirm"]}
    def job_abort(self, session_id, job_hash):
        s = self._session(session_id); job = self.jobs.get(job_hash)
        if not job: raise err32602("job_hash", "JOB_NOT_FOUND")
        self._check_job_binding("job_abort", s, job)  # D5
        self.printers[job["printer_serial"]].cancel(); job["state"] = "ABORTED"
        self.receipt("job_abort", "ABORT_RECEIPTED", job_hash, s["mandate"].get("mandate_id"), job["printer_serial"])
        return {"job_hash": job_hash, "state": "ABORTED", "receipted": True}
    def telemetry_read(self, session_id, printer_serial):
        s = self._session(session_id)
        if printer_serial not in s["mandate"]["printer_serials"]: raise err32602("printer_serial", "PRINTER_NOT_IN_MANDATE")
        return self.printers[printer_serial].telemetry() or {"state": "UNKNOWN", "telemetry": None}
    def confirm_physical(self, session_id, job_hash, fact, human_principal):
        """Human at machine confirms readiness — recorded human-declared, never machine-attested."""
        s = self._session(session_id); job = self.jobs[job_hash]
        self._check_job_binding("confirm_physical", s, job)  # D5
        if fact in job["pending_confirm"]: job["pending_confirm"].remove(fact)
        job.setdefault("readiness_human", []).append({"fact": fact, "by": human_principal, "level": "human-declared", "at": self.now().isoformat()})
        if not job["pending_confirm"] and job["state"] == "PENDING_PHYSICAL_CONFIRM": job["state"] = "PREPARED"
        return job["state"]
    # ---- evidence pack (§12, 16 fields)
    def _signer_info(self):
        return {"type": "local", "fingerprint": self.signer.fingerprint, "public_key_hex": self.signer.pk.hex()}
    def _seal_pack(self, body):
        # pack_hash = unkeyed checksum (excl. hash + signature); pack_signature =
        # Ed25519 over the canonical body incl. pack_hash (D2: the keyed seal —
        # recomputing every unkeyed hash without the key still fails Proof).
        body["pack_hash"] = slicer.sha256_hex(slicer.canonical_json({k: v for k, v in body.items() if k not in ("pack_hash", "pack_signature")}))
        body["pack_signature"] = self.signer.sign({k: v for k, v in body.items() if k != "pack_signature"})
        return body
    def build_pack(self, session_id, job):
        s = self.sessions[session_id]; m = s["mandate"]; printer = self.printers[job["printer_serial"]]
        signed_record = s.get("mandate_signed_record") or m  # as-presented signed record (D2: signature must verify in Proof)
        d = self.designs[job["design_id"]]; p_rec = self.profiles[job["profile_id"]]
        trace_bytes = slicer.canonical_json(job["telemetry_trace"])
        body = {
         "pack_id": "pack-" + secrets.token_hex(6), "signer": self._signer_info(),
         "printer": {"serial": printer.serial, "model": printer.model, "firmware": printer.firmware,
                     "firmware_attestation_hash": s["attestations"].get(printer.serial), "target_class": "simulator"},
         "mandate": {"mandate_hash": slicer.sha256_hex(slicer.canonical_json(signed_record)), "record": signed_record},
         "design": {"pin": d["pin"], "activation": d["activation"], "source": d["source"], "params": d["params"]},
         "slicer": dict(self.slicer_build),
         "profile": {"profile_hash": p_rec["profile_hash"], "profile": p_rec["profile"]},
         "toolpath": {"raw_hash": job["raw_hash"], "canonical_hash": job["canonical_hash"], "stripped_header_lines": job["stripped_header_lines"]},
         "dispatch_record": job["dispatch_record"],
         "telemetry_trace_digest": slicer.sha256_hex(trace_bytes),
         "loadout": {"material_loaded": printer.material_loaded, "level": (job["dispatch_record"] or {}).get("loadout_level", "unchecked")},
         "readiness": {"facts": job.get("readiness_human", []), "pending": job["pending_confirm"]},
         "budgets": {"estimated_grams": job["estimates"]["grams"], "actual_grams_estimate": round(job["estimates"]["grams"]*printer.progress,4),
                     "estimated_duration_s": job["estimates"]["duration_s"], "actual_elapsed_s": printer.elapsed_s,
                     "limits": {"grams": m["max_filament_grams"], "duration_s": m["max_print_duration_s"]}, "overrun_events": []},
         "refusals": [r for r in self.refusal_log if r["mandate_id"] == m.get("mandate_id")],
         "gaps": job["gaps"], "events": job.get("events", []), "end_state": job["state"], "site_class": m["site_class"],
         "_telemetry_trace": job["telemetry_trace"],
         "meter_record": {"grams": job["estimates"]["grams"], "machine_minutes": round(printer.elapsed_s/60,3), "printer_serial": printer.serial},
         "friction_findings": [f for f in self.findings if f.get("serial") == printer.serial],
        }
        return self._seal_pack(body)
    def session_close(self, session_id):
        s = self._session(session_id); packs = []
        for jh in s["jobs"]:
            job = self.jobs[jh]
            if job["state"] == "PRINTING": job["state"] = "PAUSED_AT_CLOSE"
            pack = self.build_pack(session_id, job); self.packs[pack["pack_id"]] = pack; packs.append(pack)
            self.meter_records.append(pack["meter_record"])
            if self.pack_store_available:
                (self.pack_dir / f"{pack['pack_id']}.json").write_text(json.dumps(pack, indent=1, sort_keys=True))
        # refusal-only pack if no jobs
        if not packs:
            signed_record = s.get("mandate_signed_record") or s["mandate"]
            pack = {"pack_id": "pack-" + secrets.token_hex(6), "signer": self._signer_info(),
                    "refusals": [r for r in self.refusal_log if r["mandate_id"] == s["mandate"].get("mandate_id")],
                    "end_state": "PAUSED_AT_CLOSE", "site_class": s["mandate"]["site_class"], "mandate": {"mandate_hash": slicer.sha256_hex(slicer.canonical_json(signed_record)), "record": signed_record}}
            pack = self._seal_pack(pack)
            self.packs[pack["pack_id"]] = pack; packs.append(pack)
        s["closed"] = True
        return {"session_id": session_id, "packs": packs, "pack_ids": [p["pack_id"] for p in packs]}
# Eclipse Strata MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
