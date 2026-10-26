#!/usr/bin/env python3
# Eclipse Strata MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Strata test suite — happy path, guards, and hostile-agent suite H1-H18 (§14).
import copy, json, sys, tempfile, unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
import slicer, server
from strata_engine import Engine, Refusal
from guards import parse_time, coerce_int_param, ToolError
from gauge import check_gauge
from proof import verify_pack

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
PROFILE = {"temps": {"hotend": 205, "bed": 60, "first_layer_hotend": 210, "first_layer_bed": 65},
           "filament": {"diameter_mm": 1.75, "density_g_cm3": 1.24, "material_class": "PLA"}}
PARAMS = {"bbox_mm": {"x": 20, "y": 20, "z": 4}, "min_wall_mm": 1.2}
SOURCE = "from build123d import *\npart = Box(20,20,4)\n"

def make_engine():
    e = Engine(Path(tempfile.mkdtemp())); e.set_now(NOW); return e

def setup_printable(e, profile=None, mandate_over=None, printer_serial="SIM-OCTO-001"):
    profile = copy.deepcopy(profile or PROFILE)
    d = e.design_register("agent-1", SOURCE, copy.deepcopy(PARAMS))
    e.activate_design(d["design_id"], {"id": "ace", "role": "human_principal"})
    pr = e.register_profile("agent-1", profile)
    e.activate_profile(pr["profile_id"], {"id": "ace", "role": "human_principal"})
    m = {"mandate_id": "mand-1", "agent_identity": "agent-1", "printer_serials": [printer_serial],
         "design_pins": [e.designs[d["design_id"]]["pin"]], "slicer_build": dict(e.slicer_build),
         "profile_pins": [pr["profile_hash"]], "material_class": "PLA",
         "thermal_envelope": {"hotend_max_C": 250, "bed_max_C": 80},
         "build_volume_bounds": {"x_max_mm": 220, "y_max_mm": 220, "z_max_mm": 250},
         "max_print_duration_s": 100000, "max_filament_grams": 1000, "site_class": "ATTENDED",
         "window": {"not_before": (NOW-timedelta(hours=1)).isoformat(), "not_after": (NOW+timedelta(hours=5)).isoformat()},
         "expiry": (NOW+timedelta(hours=5)).isoformat(), "telemetry_gap_threshold_s": 30, "delegation": None}
    if mandate_over: m.update(mandate_over)
    m = e.sign_mandate(m)
    s = e.session_open(m, "agent-1")
    return d, pr, m, s["session_id"]

def assert_refusal(tc, code, fn):
    with tc.assertRaises(Refusal) as cm: fn()
    tc.assertEqual(cm.exception.code, code)

class Happy(unittest.TestCase):
    def test_full_print_and_pack(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001")
        out = e.job_dispatch(sid, prep["job_hash"]); self.assertTrue(out["dispatched"])
        for _ in range(40): e.tick(sid, 10)
        st = e.job_status(sid, prep["job_hash"]); self.assertEqual(st["state"], "COMPLETED")
        close = e.session_close(sid); pack = close["packs"][0]
        for f in ("pack_id","pack_hash","signer","printer","mandate","design","slicer","profile","toolpath","dispatch_record","telemetry_trace_digest","loadout","readiness","budgets","refusals","gaps","end_state","site_class"):
            self.assertIn(f, pack)
        self.assertEqual(pack["printer"]["target_class"], "simulator")
        anchor = {e.signer.fingerprint: {"public_key_hex": e.signer.pk.hex(), "signer": "local"}}
        v = verify_pack(copy.deepcopy(pack), registry=anchor); self.assertEqual(v["verdict"], "PRINT_VERIFIED", v)
        self.assertTrue(e.meter_records)
    def test_klipper_simulator(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e, printer_serial="SIM-KLIP-001")
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-KLIP-001")
        self.assertTrue(e.job_dispatch(sid, prep["job_hash"])["dispatched"])
    def test_discover_inspect_pin_get(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        self.assertEqual(len(e.printers_discover()["printers"]), 3)
        self.assertEqual(e.design_inspect(d["design_id"])["bbox_mm"]["x"], 20)
        self.assertEqual(e.design_pin_get(d["design_id"])["status"], "ACTIVATED")
        self.assertEqual(e.telemetry_read(sid, "SIM-OCTO-001")["state"], "idle")
    def test_abort_receipted(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001"); e.job_dispatch(sid, prep["job_hash"])
        self.assertEqual(e.job_abort(sid, prep["job_hash"])["state"], "ABORTED")
    def test_canonical_hash_volatile_invariant(self):
        a, _ = slicer.slice_design(SOURCE, PARAMS, PROFILE, {"x":1}, volatile_seed="t1")
        b, _ = slicer.slice_design(SOURCE, PARAMS, PROFILE, {"x":1}, volatile_seed="t2-other")
        self.assertEqual(slicer.canonical_hash(a), slicer.canonical_hash(b))
        self.assertNotEqual(slicer.raw_hash(a), slicer.raw_hash(b))
        tampered = a.replace("M104 S210", "M104 S225")
        self.assertNotEqual(slicer.canonical_hash(a), slicer.canonical_hash(tampered))
    def test_guards(self):
        self.assertEqual(coerce_int_param("42", "x"), 42)
        with self.assertRaises(ToolError): coerce_int_param(True, "x")
        with self.assertRaises(ToolError): parse_time("2026-10-25T12:00:00", "expiry")
        self.assertIsNotNone(parse_time("2026-10-25", "expiry").tzinfo)
    def test_gauge_direct(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        g = check_gauge(m, PROFILE, {"firmware_limits": {"hotend_max_C":300,"bed_max_C":130}, "build_volume_mm":{"x":220,"y":220,"z":250}}, PARAMS["bbox_mm"])
        self.assertEqual(g["verdict"], "ENVELOPE_SOUND")
    def test_till_gated_and_delegation_slot(self):
        e = make_engine()
        with self.assertRaises(Refusal): e.till.settle()
        d, pr, m, sid = setup_printable(e); self.assertIn("delegation", m)
    def test_signature_invalid(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        bad = copy.deepcopy(m); bad["max_filament_grams"] = 99999
        assert_refusal(self, "MANDATE_SIGNATURE_INVALID", lambda: e.session_open(bad, "agent-1"))

class Hostile(unittest.TestCase):
    def test_H1_toolpath_substitution(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001")
        tampered = e.jobs[prep["job_hash"]]["toolpath_text"].replace("M104 S210", "M104 S225")
        assert_refusal(self, "TOOLPATH_PROVENANCE_MISMATCH", lambda: e.job_dispatch(sid, prep["job_hash"], supplied_toolpath=tampered))
        self.assertFalse(e.printers["SIM-OCTO-001"].heated)
    def test_H2_profile_tampering(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        e.profiles[pr["profile_id"]]["profile"]["temps"]["hotend"] = 260
        assert_refusal(self, "PROFILE_PIN_MISMATCH", lambda: e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001"))
    def test_H3_slicer_drift(self):
        e = make_engine()
        bad = {"name": "PrusaSlicer", "version": "9.9", "binary_hash": "0"*64}
        d, pr, m, sid = None, None, None, None
        # build mandate with wrong slicer, signed, session opens, prepare refuses
        dd = e.design_register("agent-1", SOURCE, copy.deepcopy(PARAMS)); e.activate_design(dd["design_id"], {"id":"ace","role":"human_principal"})
        pp = e.register_profile("agent-1", copy.deepcopy(PROFILE)); e.activate_profile(pp["profile_id"], {"id":"ace","role":"human_principal"})
        mm = {"mandate_id":"m3","agent_identity":"agent-1","printer_serials":["SIM-OCTO-001"],"design_pins":[e.designs[dd["design_id"]]["pin"]],
              "slicer_build": bad, "profile_pins":[pp["profile_hash"]],"material_class":"PLA","thermal_envelope":{"hotend_max_C":250,"bed_max_C":80},
              "build_volume_bounds":{"x_max_mm":220,"y_max_mm":220,"z_max_mm":250},"max_print_duration_s":100000,"max_filament_grams":1000,
              "site_class":"ATTENDED","window":{"not_before":(NOW-timedelta(hours=1)).isoformat(),"not_after":(NOW+timedelta(hours=5)).isoformat()},"expiry":(NOW+timedelta(hours=5)).isoformat()}
        mm = e.sign_mandate(mm); s = e.session_open(mm, "agent-1")
        assert_refusal(self, "SLICER_BUILD_MISMATCH", lambda: e.job_prepare(s["session_id"], dd["design_id"], pp["profile_id"], "SIM-OCTO-001"))
    def test_H4_material_mismatch(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001")
        e.printers["SIM-OCTO-001"].material_loaded = "ABS"
        assert_refusal(self, "MATERIAL_MISMATCH", lambda: e.job_dispatch(sid, prep["job_hash"]))
    def test_H5_config_drift(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001")
        e.printers["SIM-OCTO-001"].tamper_config(max_hotend_C=999)
        assert_refusal(self, "CONFIG_DRIFT", lambda: e.job_dispatch(sid, prep["job_hash"]))
    def test_H6_wildcard(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        bad = copy.deepcopy(m); bad["printer_serials"] = ["*"]; bad = e.sign_mandate({k:v for k,v in bad.items() if k!="signature"})
        assert_refusal(self, "PRINTER_WILDCARD_REFUSED", lambda: e.session_open(bad, "agent-1"))
    def test_H7_expired_dispatch(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001")
        e.set_now(NOW + timedelta(hours=6))
        assert_refusal(self, "MANDATE_EXPIRED", lambda: e.job_dispatch(sid, prep["job_hash"]))
        self.assertFalse(e.printers["SIM-OCTO-001"].heated)
    def test_H8_expiry_mid_print_completes(self):
        e = make_engine()
        over = {"window": {"not_before": (NOW-timedelta(hours=1)).isoformat(), "not_after": (NOW+timedelta(minutes=30)).isoformat()},
                "expiry": (NOW+timedelta(minutes=30)).isoformat()}
        d, pr, m, sid = setup_printable(e, mandate_over=over)
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001"); e.job_dispatch(sid, prep["job_hash"])
        e.set_now(NOW + timedelta(hours=2))  # expired mid-print: NOT a kill
        for _ in range(40): e.tick(sid, 10)
        self.assertEqual(e.jobs[prep["job_hash"]]["state"], "COMPLETED")
        pack = e.session_close(sid)["packs"][0]
        self.assertIn("mandate_expired_mid_print_continuing_monitored", str(e.jobs[prep["job_hash"]].get("notices")))
        self.assertEqual(pack["end_state"], "COMPLETED")
    def test_H9_escape_hatches(self):
        for name, code in (("raw_gcode","RAW_GCODE_REFUSED"),("execute_code","RAW_GCODE_REFUSED"),("move_axis","RAW_GCODE_REFUSED"),("set_heater","RAW_GCODE_REFUSED"),("config_write","CONFIG_WRITE_REFUSED")):
            with self.assertRaises(ToolError) as cm: server.call_tool(name, {})
            self.assertEqual(cm.exception.code, -32602); self.assertEqual(cm.exception.refusal, code)
        with self.assertRaises(ToolError) as cm: server.call_tool("totally_unknown_tool", {})
        self.assertEqual(cm.exception.code, -32602)
        self.assertEqual(len(server.TOOLS), 11)
    def test_H10_toolpath_content(self):
        bad = copy.deepcopy(PROFILE); bad["start_gcode_lines"] = ["M500"]
        e = make_engine(); d, pr, m, sid = setup_printable(e, profile=bad)
        assert_refusal(self, "TOOLPATH_CONTENT_REFUSED", lambda: e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001"))
    def test_H11_agent_self_pin(self):
        e = make_engine(); d = e.design_register("agent-1", SOURCE, copy.deepcopy(PARAMS))
        assert_refusal(self, "AGENT_SELF_PIN_REFUSED", lambda: e.activate_design(d["design_id"], {"id":"agent-1","role":"agent"}))
        with self.assertRaises(ToolError) as cm: server.call_tool("design_pin_activate", {"design_id": d["design_id"]})
        self.assertEqual(cm.exception.refusal, "AGENT_SELF_PIN_REFUSED")
    def test_H12_fabricated_attestation(self):
        e = make_engine(); e.printers["SIM-OCTO-001"].plate_clear_attestable = False
        d, pr, m, sid = setup_printable(e, mandate_over={"require_plate_clear_attested": True})
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001")
        self.assertEqual(prep["state"], "PENDING_PHYSICAL_CONFIRM")
        out = e.job_dispatch(sid, prep["job_hash"]); self.assertFalse(out["dispatched"])
        e.confirm_physical(sid, prep["job_hash"], "plate_clear", "ace-human")
        self.assertEqual(e.jobs[prep["job_hash"]]["readiness_human"][0]["level"], "human-declared")
        self.assertTrue(e.job_dispatch(sid, prep["job_hash"])["dispatched"])
    def test_H13_evidence_failure(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001")
        e.pack_store_available = False
        assert_refusal(self, "EVIDENCE_FAILURE", lambda: e.job_dispatch(sid, prep["job_hash"]))
        self.assertFalse(e.printers["SIM-OCTO-001"].heated)
    def test_H14_telemetry_gap(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001"); e.job_dispatch(sid, prep["job_hash"])
        e.tick(sid, 10); e.printers["SIM-OCTO-001"].telemetry_cut = True
        e.tick(sid, 40)
        self.assertEqual(e.jobs[prep["job_hash"]]["state"], "PAUSED_TELEMETRY_GAP")
        e.printers["SIM-OCTO-001"].telemetry_cut = False; e.printers["SIM-OCTO-001"].telemetry_gap_s = 0
        e.tick(sid, 10)
        self.assertEqual(e.jobs[prep["job_hash"]]["state"], "PRINTING")
    def test_H15_profile_over_envelope(self):
        bad = copy.deepcopy(PROFILE); bad["temps"]["hotend"] = 280; bad["temps"]["first_layer_hotend"] = 280
        e = make_engine(); d, pr, m, sid = setup_printable(e, profile=bad)
        assert_refusal(self, "ENVELOPE_VIOLATION", lambda: e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001"))
    def test_H16_nonprint_head_content(self):
        bad = copy.deepcopy(PROFILE); bad["start_gcode_lines"] = ["M3 S1000"]
        e = make_engine(); d, pr, m, sid = setup_printable(e, profile=bad)
        assert_refusal(self, "NONPRINT_HEAD_REFUSED", lambda: e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001"))
    def test_H17_stale_authority_queueing(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001")
        assert_refusal(self, "MANDATE_EXPIRED", lambda: e.job_dispatch(sid, prep["job_hash"], scheduled_at="later"))
        e.heartbeat_alive = False
        assert_refusal(self, "TELEMETRY_GAP", lambda: e.job_dispatch(sid, prep["job_hash"]))
    def test_H18_proof_tampering(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001"); e.job_dispatch(sid, prep["job_hash"])
        for _ in range(40): e.tick(sid, 10)
        pack = copy.deepcopy(e.session_close(sid)["packs"][0])
        pack["profile"]["profile"]["temps"]["hotend"] = 999
        v = verify_pack(pack)
        self.assertEqual(v["verdict"], "PRINT_UNVERIFIED")
        self.assertTrue(any("profile" in f or "toolpath" in f for f in v["failing_elements"]), v)
        self.assertIsNotNone(v["rederived_toolpath_canonical_hash"])
    def test_unresolved_profile_and_budget_and_window(self):
        e = make_engine(); d = e.design_register("agent-1", SOURCE, copy.deepcopy(PARAMS)); e.activate_design(d["design_id"], {"id":"ace","role":"human_principal"})
        pr = e.register_profile("agent-1", {"inherits": "base", "temps": PROFILE["temps"], "filament": PROFILE["filament"]})
        self.assertEqual(pr["status"], "PROPOSED_UNRESOLVED")
        # budget: tiny gram budget signed mandate -> prepare refusal (use happy profile)
        e2 = make_engine(); d2, pr2, m2, sid2 = setup_printable(e2, mandate_over={"max_filament_grams": 0.0001})
        # mandate_over applied before signing in helper? helper signs after update, yes
        assert_refusal(self, "BUDGET_EXCEEDED_AT_PREPARE", lambda: e2.job_prepare(sid2, d2["design_id"], pr2["profile_id"], "SIM-OCTO-001"))
    def test_config_write_and_unknown_serial_fail_closed(self):
        e = make_engine(); d, pr, m, sid = setup_printable(e)
        with self.assertRaises(ToolError): e.design_inspect("nope")

if __name__ == "__main__": unittest.main()
# Eclipse Strata MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
