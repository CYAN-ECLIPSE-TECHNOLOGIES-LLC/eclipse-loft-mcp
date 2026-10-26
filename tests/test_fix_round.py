#!/usr/bin/env python3
# Eclipse Strata MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Fix-round regressions D1-D10 — Verity bench shapes replicated byte-for-byte
# (scorecard eclipse-strata-mcp-2026-10-25.json: H10 variants, H18 V3/V4/V5,
# F1/F2 container set, G1 site-class set, S2 cross-session, H8a, G6, P2, P3).
import copy, hashlib, json, subprocess, sys, tempfile, unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
import signing, slicer, server
from strata_engine import Engine, Refusal
from guards import ToolError
from proof import verify_pack

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
PROFILE = {"temps": {"hotend": 205, "bed": 60, "first_layer_hotend": 210, "first_layer_bed": 65},
           "filament": {"diameter_mm": 1.75, "density_g_cm3": 1.24, "material_class": "PLA"}}
PARAMS = {"bbox_mm": {"x": 20, "y": 20, "z": 4}, "min_wall_mm": 1.2}
SOURCE = "from build123d import *\npart = Box(20,20,4)\n"
HERE = Path(__file__).parent.parent

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
    return d, pr, m, s

def base_mandate(e, d, pr, **over):
    m = {"mandate_id": "mand-x", "agent_identity": "agent-1", "printer_serials": ["SIM-OCTO-001"],
         "design_pins": [e.designs[d["design_id"]]["pin"]], "slicer_build": dict(e.slicer_build),
         "profile_pins": [pr["profile_hash"]], "material_class": "PLA",
         "thermal_envelope": {"hotend_max_C": 250, "bed_max_C": 80},
         "build_volume_bounds": {"x_max_mm": 220, "y_max_mm": 220, "z_max_mm": 250},
         "max_print_duration_s": 100000, "max_filament_grams": 1000, "site_class": "ATTENDED",
         "window": {"not_before": (NOW-timedelta(hours=1)).isoformat(), "not_after": (NOW+timedelta(hours=5)).isoformat()},
         "expiry": (NOW+timedelta(hours=5)).isoformat(), "telemetry_gap_threshold_s": 30, "delegation": None}
    m.update(over); return e.sign_mandate(m)

def register_pair(e):
    d = e.design_register("agent-1", SOURCE, copy.deepcopy(PARAMS))
    e.activate_design(d["design_id"], {"id": "ace", "role": "human_principal"})
    pr = e.register_profile("agent-1", copy.deepcopy(PROFILE))
    e.activate_profile(pr["profile_id"], {"id": "ace", "role": "human_principal"})
    return d, pr

def assert_refusal(tc, code, fn):
    with tc.assertRaises(Refusal) as cm: fn()
    tc.assertEqual(cm.exception.code, code)

def completed_pack(e):
    d, pr, m, s = setup_printable(e); sid = s["session_id"]
    prep = e.job_prepare(sid, d["design_id"], pr["profile_id"], "SIM-OCTO-001")
    e.job_dispatch(sid, prep["job_hash"])
    for _ in range(40): e.tick(sid, 10)
    return copy.deepcopy(e.session_close(sid)["packs"][0])

def rehash_attacker(pack):
    """Strongest unkeyed attacker: recompute every unkeyed hash with full recipe knowledge."""
    pack["mandate"]["mandate_hash"] = slicer.sha256_hex(slicer.canonical_json(pack["mandate"]["record"]))
    if pack.get("_telemetry_trace") is not None:
        pack["telemetry_trace_digest"] = slicer.sha256_hex(slicer.canonical_json(pack["_telemetry_trace"]))
    body = {k: v for k, v in pack.items() if k not in ("pack_hash", "pack_signature")}
    pack["pack_hash"] = slicer.sha256_hex(slicer.canonical_json(body))
    return pack

class D1ContentScan(unittest.TestCase):
    # H10 variant set, byte-for-byte from the scorecard evidence
    VARIANTS = ["SAVE_CONFIG", "M301 P22.2 I1.08 D114", "M92 X80.00",
                "SET_HEATER_TEMPERATURE HEATER=extruder TARGET=280", "RESTART"]
    def test_h10_variants_refuse_at_prepare_via_pinned_profile_start_lines(self):
        for line in self.VARIANTS:
            with self.subTest(line=line):
                bad = copy.deepcopy(PROFILE); bad["start_gcode_lines"] = [line]
                e = make_engine(); d, pr, m, s = setup_printable(e, profile=bad)
                assert_refusal(self, "TOOLPATH_CONTENT_REFUSED",
                               lambda: e.job_prepare(s["session_id"], d["design_id"], pr["profile_id"], "SIM-OCTO-001"))
                self.assertFalse(e.printers["SIM-OCTO-001"].heated)
    def test_h10_variants_refuse_in_scan_of_final_toolpath(self):
        for line in self.VARIANTS:
            with self.subTest(line=line):
                canon, _ = slicer.canonicalize_toolpath("G21\n" + line + "\nG1 X1 Y1 E0.1\n")
                self.assertEqual(slicer.scan_toolpath(canon, PROFILE), "TOOLPATH_CONTENT_REFUSED")
    def test_h10_controls_still_refuse(self):
        for line in ("M500", "M112", "M502", "M997"):
            canon, _ = slicer.canonicalize_toolpath(line + "\n")
            self.assertEqual(slicer.scan_toolpath(canon, PROFILE), "TOOLPATH_CONTENT_REFUSED")

def genuine_anchor(e):
    """Trusted signer anchor for an engine's signer — built from the ENGINE's
    signer (never from the pack under test, which is the D2X hole)."""
    return {e.signer.fingerprint: {"public_key_hex": e.signer.pk.hex(), "signer": "local"}}

def key_substitution_attacker(pack):
    """D2X shape, byte-for-byte from scorecard r2: attacker-minted keypair,
    mandate tampered (material_class -> ABS, expiry +365d) + re-signed with
    the attacker's key, signer block replaced with attacker pk+fingerprint
    (self-consistent), mandate_hash + pack_hash recomputed, pack re-sealed
    with the attacker's pack_signature. No bridge key used."""
    pack = copy.deepcopy(pack)
    atk = signing.generate_keypair()
    rec = pack["mandate"]["record"]
    rec["material_class"] = "ABS"
    rec["expiry"] = (NOW + timedelta(days=365)).isoformat()
    mpayload = {k: v for k, v in rec.items() if k != "signature"}
    msig, atk_pk = signing.sign(atk, slicer.canonical_json(mpayload))
    rec["signature"] = msig.hex()
    pack["mandate"]["mandate_hash"] = slicer.sha256_hex(slicer.canonical_json(rec))
    pack["signer"] = {"type": "local", "fingerprint": signing.fingerprint(atk_pk),
                      "public_key_hex": atk_pk.hex()}
    body = {k: v for k, v in pack.items() if k not in ("pack_hash", "pack_signature")}
    pack["pack_hash"] = slicer.sha256_hex(slicer.canonical_json(body))
    ppayload = {k: v for k, v in pack.items() if k != "pack_signature"}
    psig, _ = signing.sign(atk, slicer.canonical_json(ppayload))
    pack["pack_signature"] = psig.hex()
    return pack

class D2Proof(unittest.TestCase):
    def test_genuine_pack_verifies(self):
        e = make_engine(); pack = completed_pack(e)
        v = verify_pack(pack, registry=genuine_anchor(e)); self.assertEqual(v["verdict"], "PRINT_VERIFIED", v)
    def test_h18_v3_mandate_tamper_rehashed(self):
        e = make_engine(); pack = completed_pack(e)
        pack["mandate"]["record"]["material_class"] = "ABS"
        pack["mandate"]["record"]["expiry"] = (NOW + timedelta(days=365)).isoformat()
        v = verify_pack(rehash_attacker(pack), registry=genuine_anchor(e))
        self.assertEqual(v["verdict"], "PRINT_UNVERIFIED"); self.assertTrue(v["failing_elements"])
        self.assertIn("pack_signature", v["failing_elements"])
    def test_h18_v4_telemetry_tamper_rehashed(self):
        e = make_engine(); pack = completed_pack(e)
        self.assertTrue(pack["_telemetry_trace"])
        pack["_telemetry_trace"][0]["hotend_C"] = 999
        v = verify_pack(rehash_attacker(pack), registry=genuine_anchor(e))
        self.assertEqual(v["verdict"], "PRINT_UNVERIFIED"); self.assertTrue(v["failing_elements"])
        self.assertIn("pack_signature", v["failing_elements"])
    def test_h18_v5_endstate_slicer_tamper_rehashed(self):
        e = make_engine(); pack = completed_pack(e)
        pack["end_state"] = "ABORTED"; pack["slicer"]["version"] = "9.9.9-tampered"
        v = verify_pack(rehash_attacker(pack), registry=genuine_anchor(e))
        self.assertEqual(v["verdict"], "PRINT_UNVERIFIED"); self.assertTrue(v["failing_elements"])
        self.assertIn("pack_signature", v["failing_elements"])
    def test_unsigned_pack_never_verifies(self):
        e = make_engine(); pack = completed_pack(e)
        del pack["pack_signature"]
        v = verify_pack(pack); self.assertEqual(v["verdict"], "PRINT_UNVERIFIED")
        self.assertIn("pack_signature", v["failing_elements"])

class D2Anchor(unittest.TestCase):
    # Fix round 2 (D2X): trusted signer anchor — §7.1 local registry only.
    def test_d2x_attacker_key_fabrication_refused_with_genuine_anchor(self):
        e = make_engine(); pack = key_substitution_attacker(completed_pack(e))
        v = verify_pack(pack, registry=genuine_anchor(e))
        self.assertEqual(v["verdict"], "PRINT_UNVERIFIED", v)
        self.assertIn("UNVERIFIED_SIGNER", v["failing_elements"])
        v2 = verify_pack(pack, expected_fingerprint=e.signer.fingerprint)
        self.assertEqual(v2["verdict"], "PRINT_UNVERIFIED", v2)
        self.assertIn("UNVERIFIED_SIGNER", v2["failing_elements"])
    def test_genuine_pack_with_registry_anchor_verifies(self):
        e = make_engine(); pack = completed_pack(e)
        v = verify_pack(pack, registry=genuine_anchor(e))
        self.assertEqual(v["verdict"], "PRINT_VERIFIED", v)
        self.assertNotIn("UNVERIFIED_SIGNER", v["failing_elements"])
    def test_genuine_pack_with_expected_fingerprint_verifies(self):
        e = make_engine(); pack = completed_pack(e)
        v = verify_pack(pack, expected_fingerprint=e.signer.fingerprint)
        self.assertEqual(v["verdict"], "PRINT_VERIFIED", v)
    def test_genuine_pack_without_anchor_is_unverified_signer(self):
        # §7.1 reading: no anchor supplied -> never a silent verify.
        e = make_engine(); pack = completed_pack(e)
        v = verify_pack(pack)
        self.assertEqual(v["verdict"], "PRINT_UNVERIFIED", v)
        self.assertIn("UNVERIFIED_SIGNER", v["failing_elements"])
    def test_genuine_pack_with_unknown_signer_registry_refused(self):
        e = make_engine(); pack = completed_pack(e)
        atk = signing.generate_keypair()
        foreign = {signing.fingerprint(atk[2]): {"public_key_hex": atk[2].hex(), "signer": "local"}}
        v = verify_pack(pack, registry=foreign)
        self.assertEqual(v["verdict"], "PRINT_UNVERIFIED", v)
        self.assertIn("UNVERIFIED_SIGNER", v["failing_elements"])
    def test_registry_key_mismatch_refused(self):
        # Registry holds the genuine fingerprint but a DIFFERENT public key.
        e = make_engine(); pack = completed_pack(e)
        atk = signing.generate_keypair()
        mismatched = {e.signer.fingerprint: {"public_key_hex": atk[2].hex(), "signer": "local"}}
        v = verify_pack(pack, registry=mismatched)
        self.assertEqual(v["verdict"], "PRINT_UNVERIFIED", v)
        self.assertIn("UNVERIFIED_SIGNER", v["failing_elements"])
    def test_proof_cli_anchor_surface(self):
        e = make_engine(); pack = completed_pack(e)
        tmp = Path(tempfile.mkdtemp())
        pack_f = tmp / "pack.json"; pack_f.write_text(json.dumps(pack))
        reg_f = tmp / "registry.json"; reg_f.write_text(json.dumps(genuine_anchor(e)))
        cli = str(HERE / "tools" / "strata_proof.py")
        def run(*args):
            out = subprocess.run([sys.executable, cli, *args], capture_output=True, text=True, timeout=120)
            self.assertEqual(out.returncode, 0, out.stderr)
            return json.loads(out.stdout)
        v = run(str(pack_f), "--registry", str(reg_f))
        self.assertEqual(v["verdict"], "PRINT_VERIFIED", v)
        v = run(str(pack_f), "--expected-fingerprint", e.signer.fingerprint)
        self.assertEqual(v["verdict"], "PRINT_VERIFIED", v)
        v = run(str(pack_f))  # no anchor -> UNVERIFIED_SIGNER, never silent-verify
        self.assertEqual(v["verdict"], "PRINT_UNVERIFIED", v)
        self.assertIn("UNVERIFIED_SIGNER", v["failing_elements"])
        atk_f = tmp / "atk.json"; atk_f.write_text(json.dumps(key_substitution_attacker(pack)))
        v = run(str(atk_f), "--registry", str(reg_f))
        self.assertEqual(v["verdict"], "PRINT_UNVERIFIED", v)
        self.assertIn("UNVERIFIED_SIGNER", v["failing_elements"])

class D3Malformed(unittest.TestCase):
    def test_f2_window_missing_not_after_named(self):
        e = make_engine(); d, pr = register_pair(e)
        m = base_mandate(e, d, pr, window={"not_before": (NOW-timedelta(hours=1)).isoformat()})
        with self.assertRaises(ToolError) as cm: e.session_open(m, "agent-1")
        self.assertEqual(cm.exception.code, -32602)
    def test_f2_window_is_string_named(self):
        e = make_engine(); d, pr = register_pair(e)
        m = base_mandate(e, d, pr, window="soon")
        with self.assertRaises(ToolError) as cm: e.session_open(m, "agent-1")
        self.assertEqual(cm.exception.code, -32602)
    def test_f2_partial_volume_bounds_prepare_named_not_keyerror(self):
        e = make_engine(); d, pr, m, s = setup_printable(e, mandate_over={"build_volume_bounds": {"x_max_mm": 220}})
        with self.assertRaises(Refusal): e.job_prepare(s["session_id"], d["design_id"], pr["profile_id"], "SIM-OCTO-001")
    def test_f2_grams_lots_named(self):
        e = make_engine(); d, pr = register_pair(e)
        m = base_mandate(e, d, pr, max_filament_grams="lots")
        with self.assertRaises(ToolError) as cm: e.session_open(m, "agent-1")
        self.assertEqual(cm.exception.code, -32602)
    def test_f2_templess_profile_prepare_named(self):
        e = make_engine(); d = e.design_register("agent-1", SOURCE, copy.deepcopy(PARAMS))
        e.activate_design(d["design_id"], {"id": "ace", "role": "human_principal"})
        pr = e.register_profile("agent-1", {"filament": {"diameter_mm": 1.75, "density_g_cm3": 1.24, "material_class": "PLA"}})
        e.activate_profile(pr["profile_id"], {"id": "ace", "role": "human_principal"})
        m = base_mandate(e, d, pr)
        s = e.session_open(m, "agent-1")
        with self.assertRaises(ToolError) as cm: e.job_prepare(s["session_id"], d["design_id"], pr["profile_id"], "SIM-OCTO-001")
        self.assertEqual(cm.exception.code, -32602)
    def test_f2_supplied_toolpath_int_named(self):
        e = make_engine(); d, pr, m, s = setup_printable(e)
        with self.assertRaises(ToolError) as cm:
            e.job_prepare(s["session_id"], d["design_id"], pr["profile_id"], "SIM-OCTO-001", supplied_toolpath=4242)
        self.assertEqual(cm.exception.code, -32602)
    def test_f1_wire_server_survives_malformed_containers(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "design_register", "arguments": {"agent_identity": "agent-1", "source": SOURCE, "parameter_set": {"bbox_mm": {"x": "evil", "y": 20, "z": 4}}}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "design_register", "arguments": {"agent_identity": "agent-1", "source": 4242, "parameter_set": {"bbox_mm": [1, 2]}}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "session_open", "arguments": {"mandate": "soon", "agent_identity": "agent-1"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "job_prepare", "arguments": {"session_id": 9, "design_id": None, "profile_id": [], "printer_serial": {}}}},
            {"jsonrpc": "2.0", "id": 900, "method": "tools/list"},
        ]
        inp = "\n".join(json.dumps(r) for r in reqs) + "\nnot json{{{\n"
        out = subprocess.run([sys.executable, str(HERE / "server.py")], input=inp, capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        lines = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
        by_id = {l.get("id"): l for l in lines}
        for rid in (1, 2, 3, 4):
            self.assertIn(rid, by_id, lines)
            self.assertNotEqual(by_id[rid].get("error", {}).get("code"), -32603)
        self.assertTrue(any(l.get("error", {}).get("code") == -32700 for l in lines), lines)
        self.assertEqual(len(by_id[900]["result"]["tools"]), 11)

class D4SiteClass(unittest.TestCase):
    # G1 set, byte-for-byte from the scorecard evidence
    GARBAGE = ["attended", "WHATEVER", "UNATTENDED_RATED ", "ATTENDED; rm -rf"]
    def test_g1_garbage_site_class_grants_t0_only(self):
        for sc in self.GARBAGE:
            with self.subTest(site_class=sc):
                e = make_engine(); d, pr, m, s = setup_printable(e, mandate_over={"site_class": sc})
                self.assertEqual(s["tier"], "T0")
                assert_refusal(self, "MANDATE_WINDOW_REFUSED",
                               lambda: e.job_prepare(s["session_id"], d["design_id"], pr["profile_id"], "SIM-OCTO-001"))
    def test_exact_enum_still_grants(self):
        e = make_engine(); d, pr, m, s = setup_printable(e, mandate_over={"site_class": "UNATTENDED_RATED"})
        self.assertEqual(s["tier"], "T1")
        e2 = make_engine(); d2, pr2, m2, s2 = setup_printable(e2, mandate_over={"site_class": "UNKNOWN"})
        self.assertEqual(s2["tier"], "T0")

class D5CrossSession(unittest.TestCase):
    def test_s2_job_of_mandate_a_refuses_under_session_b(self):
        e = make_engine(); d, pr, m, sA = setup_printable(e)
        prep = e.job_prepare(sA["session_id"], d["design_id"], pr["profile_id"], "SIM-OCTO-001")
        mb = {k: v for k, v in m.items() if k != "signature"}; mb["mandate_id"] = "mand-2"
        mb = e.sign_mandate(mb); sB = e.session_open(mb, "agent-1")
        assert_refusal(self, "JOB_SESSION_MISMATCH", lambda: e.job_dispatch(sB["session_id"], prep["job_hash"]))
        assert_refusal(self, "JOB_SESSION_MISMATCH", lambda: e.job_status(sB["session_id"], prep["job_hash"]))
        assert_refusal(self, "JOB_SESSION_MISMATCH", lambda: e.job_abort(sB["session_id"], prep["job_hash"]))
        self.assertFalse(e.printers["SIM-OCTO-001"].heated)
        self.assertTrue(e.job_dispatch(sA["session_id"], prep["job_hash"])["dispatched"])  # own session still works

class D6ExpiryEvent(unittest.TestCase):
    OVER = {"window": {"not_before": (NOW-timedelta(hours=1)).isoformat(), "not_after": (NOW+timedelta(minutes=30)).isoformat()},
            "expiry": (NOW+timedelta(minutes=30)).isoformat()}
    def test_h8a_pack_seals_expiry_event_and_completion(self):
        e = make_engine(); d, pr, m, s = setup_printable(e, mandate_over=dict(self.OVER))
        prep = e.job_prepare(s["session_id"], d["design_id"], pr["profile_id"], "SIM-OCTO-001")
        e.job_dispatch(s["session_id"], prep["job_hash"])
        e.set_now(NOW + timedelta(hours=2))
        for _ in range(40): e.tick(s["session_id"], 10)
        pack = e.session_close(s["session_id"])["packs"][0]
        self.assertEqual(pack["end_state"], "COMPLETED")
        ev = [x for x in pack["events"] if x["type"] == "mandate_expired_mid_print"]
        self.assertEqual(len(ev), 1, pack["events"]); self.assertEqual(ev[0]["action"], "continuing_monitored")
    def test_h8_hard_stop_pack_seals_expiry_event(self):
        over = dict(self.OVER); over["hard_stop_at_expiry"] = True
        e = make_engine(); d, pr, m, s = setup_printable(e, mandate_over=over)
        prep = e.job_prepare(s["session_id"], d["design_id"], pr["profile_id"], "SIM-OCTO-001")
        e.job_dispatch(s["session_id"], prep["job_hash"])
        e.set_now(NOW + timedelta(hours=2)); e.tick(s["session_id"], 10)
        pack = e.session_close(s["session_id"])["packs"][0]
        self.assertEqual(pack["end_state"], "ABORTED")
        ev = [x for x in pack["events"] if x["type"] == "mandate_expired_mid_print"]
        self.assertEqual(len(ev), 1, pack["events"]); self.assertEqual(ev[0]["action"], "hard_stop_cancel")

class D7GeometryHonesty(unittest.TestCase):
    def test_p3_declared_geometry_labeled_not_kernel(self):
        e = make_engine()
        d = e.design_register("agent-1", "Box(500,500,500)", {"bbox_mm": {"x": 35, "y": 25, "z": 6}, "min_wall_mm": 1.2})
        g = e.design_inspect(d["design_id"])
        self.assertEqual(g["bbox_mm"]["x"], 35)  # declared value, labeled as declared
        self.assertEqual(g["geometry_basis"], "declared_geometry_only")
        self.assertIsNone(g["manifold"]); self.assertIsNone(g["triangle_count"]); self.assertIsNone(g["face_count"])
    def test_spec_and_manifest_carry_no_kernel_claim(self):
        spec = (HERE.parent / "eclipse-strata-spec-20261025.md").read_text()
        self.assertNotIn("kernel-side tooling on the file", spec)
        self.assertIn("declared geometry", spec)
        manifest = (HERE / "bazaar-manifest.json").read_text()
        self.assertNotIn("kernel", manifest.lower())

class D8OpenWindow(unittest.TestCase):
    def test_g6_expired_mandate_refused_at_open(self):
        e = make_engine(); d, pr = register_pair(e)
        m = base_mandate(e, d, pr,
                         window={"not_before": (NOW-timedelta(hours=5)).isoformat(), "not_after": (NOW-timedelta(hours=4)).isoformat()},
                         expiry=(NOW-timedelta(hours=4)).isoformat())
        assert_refusal(self, "MANDATE_EXPIRED", lambda: e.session_open(m, "agent-1"))
    def test_future_window_refused_at_open(self):
        e = make_engine(); d, pr = register_pair(e)
        m = base_mandate(e, d, pr,
                         window={"not_before": (NOW+timedelta(hours=2)).isoformat(), "not_after": (NOW+timedelta(hours=5)).isoformat()},
                         expiry=(NOW+timedelta(hours=5)).isoformat())
        assert_refusal(self, "MANDATE_WINDOW_REFUSED", lambda: e.session_open(m, "agent-1"))

class D9LoadoutLabel(unittest.TestCase):
    def test_p2_unattestable_loadout_labeled_unchecked(self):
        e = make_engine(); d, pr, m, s = setup_printable(e, printer_serial="SIM-KLIP-001")
        e.printers["SIM-KLIP-001"].material_attestable = False
        prep = e.job_prepare(s["session_id"], d["design_id"], pr["profile_id"], "SIM-KLIP-001")
        out = e.job_dispatch(s["session_id"], prep["job_hash"])
        self.assertTrue(out["dispatched"])
        self.assertEqual(out["dispatch_record"]["loadout_level"], "unchecked")
        pack = e.session_close(s["session_id"])["packs"][0]
        self.assertEqual(pack["loadout"]["level"], "unchecked")

class D10Vocabulary(unittest.TestCase):
    def test_budget_shaped_gauge_defect_uses_budget_code(self):
        e = make_engine(); d, pr, m, s = setup_printable(e, mandate_over={"max_filament_grams": -5})
        assert_refusal(self, "BUDGET_EXCEEDED_AT_PREPARE",
                       lambda: e.job_prepare(s["session_id"], d["design_id"], pr["profile_id"], "SIM-OCTO-001"))
    def test_unknown_serial_at_open_is_named_32602_not_wildcard(self):
        e = make_engine()
        with self.assertRaises(ToolError) as cm: setup_printable(e, printer_serial="SIM-NOPE-999")
        self.assertEqual(cm.exception.code, -32602)
    def test_wildcard_serial_still_wildcard_refusal(self):
        e = make_engine(); d, pr = register_pair(e)
        m = base_mandate(e, d, pr, printer_serials=["SIM-*"])
        assert_refusal(self, "PRINTER_WILDCARD_REFUSED", lambda: e.session_open(m, "agent-1"))

if __name__ == "__main__": unittest.main()
# Eclipse Strata MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
