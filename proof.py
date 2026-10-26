#!/usr/bin/env python3
# Eclipse Strata MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Strata Proof — offline evidence-pack verifier (Strata §10.1).

"""Strata Proof: PRINT_VERIFIED | PRINT_UNVERIFIED, failing element named; re-derives chain.

Verification law (§10.1, D2 fix): an unkeyed hash is a checksum, never proof.
A pack verifies ONLY if its Ed25519 pack_signature verifies against the
signer public key embedded in the pack (fingerprint-checked) — an agent alone,
able to recompute every unkeyed hash, cannot fabricate a verified pack.

Trust-anchor law (§7.1, D2 fix round 2): embedded key <-> fingerprint
self-consistency is NEVER sufficient. Proof takes a TRUSTED SIGNER ANCHOR
supplied out-of-band by the verifier — a local registry of trusted signer
entries (fingerprint -> public key + signer class herald|local, §7.1) and/or
an expected signer fingerprint. The pack's signer fingerprint AND embedded
public key are cross-checked against that anchor: an unknown/unregistered
signer, a registry key mismatch, a signer-class mismatch, or NO anchor
supplied at all each refuse as the named failing element UNVERIFIED_SIGNER
(§11 carries no Proof signer-trust name; this is the UNVERIFIED-class name
for this surface) and the verdict is PRINT_UNVERIFIED — never a silent
verify. A locally-signed pack verifies against the local registry only.
On top of the signature: mandate signature + window/expiry semantics,
design/profile/slicer pins vs the mandate, telemetry digest vs trace +
trace vs envelope, loadout label sanity, end_state sanity, toolpath
re-derivation from the pack's pinned inputs.
"""
import json, os
from pathlib import Path
import signing, slicer
from gauge import check_gauge  # noqa: F401  (kept: Gauge is Proof's suite sibling)
from guards import parse_time, ToolError

END_STATES = {"COMPLETED","ABORTED","PAUSED_AT_CLOSE","FAILED","PENDING_PHYSICAL_CONFIRM"}
LOADOUT_LEVELS = {"machine-attested","human-declared","unchecked"}
UNVERIFIED_SIGNER = "UNVERIFIED_SIGNER"
SIGNER_CLASSES = {"herald", "local"}

# ---------------------------------------------------------------- trust anchor (§7.1)
def _pk_hex(value):
    """Normalize a public key given as bytes or hex str -> lowercase hex, else None."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex() if len(value) == 32 else None
    if isinstance(value, str):
        v = value.strip().lower()
        try:
            raw = bytes.fromhex(v)
        except Exception:
            return None
        return raw.hex() if len(raw) == 32 else None
    return None

def _signer_class(obj):
    if isinstance(obj, dict):
        for k in ("signer_class", "signer", "type", "class"):
            v = obj.get(k)
            if isinstance(v, str) and v.strip().lower() in SIGNER_CLASSES:
                return v.strip().lower()
    if isinstance(obj, str) and obj.strip().lower() in SIGNER_CLASSES:
        return obj.strip().lower()
    return None

def _is_fingerprint(value):
    if not isinstance(value, str): return False
    v = value.strip().lower()
    if len(v) != 64: return False
    try: bytes.fromhex(v)
    except Exception: return False
    return True

def _absorb_anchor(source, registry, expected_fps):
    """Absorb one anchor source into (registry, expected_fps). Returns True if it supplied anchor material.

    Accepted shapes: fingerprint str; registry dict {fp: pk_hex | entry-dict | None};
    entry dict {fingerprint, public_key_hex|public_key|pk_hex, signer|signer_class|type};
    local-signer file shape {pk_hex: ...}; list/tuple/set of any of these; a path
    (str/Path) to a JSON file in any of these shapes; inline JSON in a str.
    """
    if source is None: return False
    if isinstance(source, (bytes, bytearray)):
        pk = _pk_hex(source)
        if pk is None: return False
        registry[signing.fingerprint(bytes.fromhex(pk))] = {"public_key_hex": pk, "signer_class": None}
        return True
    if isinstance(source, Path):
        try: return _absorb_anchor(json.loads(source.read_text()), registry, expected_fps)
        except Exception: return False
    if isinstance(source, str):
        s = source.strip()
        if not s: return False
        if os.path.exists(s):
            try: return _absorb_anchor(json.loads(Path(s).read_text()), registry, expected_fps)
            except Exception: return False
        if s[:1] in ("{", "["):
            try: return _absorb_anchor(json.loads(s), registry, expected_fps)
            except Exception: return False
        if _is_fingerprint(s):
            expected_fps.add(s.lower()); return True
        # Any other string is a claimed fingerprint/path that resolved to
        # nothing trusted: record it as an expected fingerprint so the check
        # fails closed (UNVERIFIED_SIGNER) rather than silently passing.
        expected_fps.add(s.lower()); return True
    if isinstance(source, (list, tuple, set)):
        supplied = False
        for item in source: supplied = _absorb_anchor(item, registry, expected_fps) or supplied
        return supplied
    if isinstance(source, dict):
        for wrap in ("trusted_signers", "signers", "registry", "entries", "trusted_registry"):
            if wrap in source:
                return _absorb_anchor(source[wrap], registry, expected_fps)
        fp = None
        for k in ("fingerprint", "signer_fingerprint", "expected_fingerprint", "id"):
            if _is_fingerprint(source.get(k)): fp = source[k].strip().lower(); break
        pk = None
        for k in ("public_key_hex", "public_key", "pk_hex", "pk"):
            pk = _pk_hex(source.get(k))
            if pk: break
        if fp or pk:
            if pk and not fp: fp = signing.fingerprint(bytes.fromhex(pk))
            if fp and not pk: expected_fps.add(fp); return True
            registry[fp] = {"public_key_hex": pk, "signer_class": _signer_class(source)}
            return True
        # Plain mapping: fingerprint -> pk_hex / entry dict / None.
        supplied = False
        for k, v in source.items():
            if not _is_fingerprint(k): continue
            fp = k.strip().lower()
            if v is None: expected_fps.add(fp); supplied = True
            elif isinstance(v, dict):
                epk = None
                for pk_key in ("public_key_hex", "public_key", "pk_hex", "pk"):
                    epk = _pk_hex(v.get(pk_key))
                    if epk: break
                if epk: registry[fp] = {"public_key_hex": epk, "signer_class": _signer_class(v)}
                else: expected_fps.add(fp)
                supplied = True
            else:
                epk = _pk_hex(v)
                if epk: registry[fp] = {"public_key_hex": epk, "signer_class": None}; supplied = True
        return supplied
    return False

def normalize_trust_anchor(registry=None, expected_fingerprint=None, extra_sources=()):
    """Return (registry_dict, expected_fingerprint_set, anchor_supplied)."""
    reg, fps, supplied = {}, set(), False
    for src in (registry, expected_fingerprint, *extra_sources):
        supplied = _absorb_anchor(src, reg, fps) or supplied
    return reg, fps, supplied

def load_registry(path):
    """Load a local trusted-signer registry JSON file (§7.1) -> registry dict."""
    reg, fps, _ = normalize_trust_anchor(registry=path)
    for fp in fps: reg.setdefault(fp, {"public_key_hex": None, "signer_class": None})
    return reg

def registry_from_signer(signer_info):
    """Build a one-entry registry from a signer block {fingerprint, public_key_hex, type|signer}."""
    reg, _, _ = normalize_trust_anchor(registry=signer_info)
    return reg

def _is_slicer_build(value):
    return (isinstance(value, dict) and "name" in value
            and ("version" in value or "binary_hash" in value)
            and not any(k in value for k in ("fingerprint", "public_key_hex", "public_key", "pk_hex", "pk")))

def _pin_hashes(pins):
    out = []
    for p in pins or []:
        out.append(p.get("profile_hash") if isinstance(p, dict) else p)
    return out

_ANCHOR_KWARGS = ("registry", "trusted_registry", "signer_registry", "local_registry",
                  "trusted_signers", "trusted_signer", "trust_anchor", "anchor",
                  "registry_path", "registry_file", "signer_registry_path",
                  "expected_fingerprint", "expected_signer_fingerprint",
                  "trusted_fingerprint", "trusted_signer_fingerprint",
                  "trusted_fingerprints", "expected_fingerprints")

def verify_pack(pack, engine_slicer_build=None, registry=None, expected_fingerprint=None, **kwargs):
    fails = []
    def fail(name):
        if name not in fails: fails.append(name)
    if not isinstance(pack, dict):
        return {"verdict": "PRINT_UNVERIFIED", "failing_elements": ["pack_not_object"],
                "rederived_toolpath_canonical_hash": None}
    # --- trusted signer anchor (§7.1): an anchor may arrive as the registry /
    # expected-fingerprint arguments, under any common alias kwarg, or — for
    # callers that pass it positionally — in the second positional slot when
    # that value is not a slicer build.
    extra_sources = [kwargs.pop(k) for k in list(kwargs) if k in _ANCHOR_KWARGS]
    if engine_slicer_build is not None and not _is_slicer_build(engine_slicer_build):
        extra_sources.append(engine_slicer_build); engine_slicer_build = None
    trust_registry, expected_fps, anchor_supplied = normalize_trust_anchor(
        registry=registry, expected_fingerprint=expected_fingerprint, extra_sources=extra_sources)
    signer_trust = {"anchor_supplied": bool(anchor_supplied), "status": "unverified",
                    "reason": None, "fingerprint": None, "signer_class": None}
    # --- signer identity: embedded public key must match the claimed fingerprint
    signer_info = pack.get("signer") or {}
    if isinstance(signer_info, str): signer_info = {"signer": signer_info}
    if not isinstance(signer_info, dict): signer_info = {}
    pk_hex = None
    for _pk_key in ("public_key_hex", "public_key", "pk_hex", "pk"):
        pk_hex = _pk_hex(signer_info.get(_pk_key))
        if pk_hex: break
    claimed_fp = None
    for _fp_key in ("fingerprint", "signer_fingerprint"):
        if _is_fingerprint(signer_info.get(_fp_key)): claimed_fp = signer_info[_fp_key].strip().lower(); break
    pack_signer_class = _signer_class(signer_info)
    signer_trust["fingerprint"] = claimed_fp; signer_trust["signer_class"] = pack_signer_class
    pk = None
    if not pk_hex:
        fail("pack_signature")  # unsigned / legacy pack: unkeyed hashes alone never verify
    else:
        try:
            pk = bytes.fromhex(pk_hex)
            if signing.fingerprint(pk) != claimed_fp: fail("signer_fingerprint")
        except Exception:
            fail("signer_fingerprint"); pk = None
    # --- trust anchor cross-check: embedded key/fingerprint vs the registry /
    # expected fingerprint ONLY (§7.1). Self-consistency above is never enough.
    if not anchor_supplied:
        fail(UNVERIFIED_SIGNER); signer_trust["reason"] = "no_trusted_signer_anchor_supplied"
    else:
        embedded_fp = signing.fingerprint(pk) if pk is not None else None
        anchor_fps = set(trust_registry) | set(expected_fps)
        matched_fp = None
        for cand in (claimed_fp, embedded_fp):
            if cand and cand in anchor_fps: matched_fp = cand; break
        if matched_fp is None:
            fail(UNVERIFIED_SIGNER); signer_trust["reason"] = "signer_fingerprint_not_in_trusted_registry"
        else:
            entry = trust_registry.get(matched_fp)
            if entry is not None:
                entry_pk = entry.get("public_key_hex")
                if entry_pk and pk_hex and entry_pk != pk_hex:
                    fail(UNVERIFIED_SIGNER); signer_trust["reason"] = "registry_key_mismatch"
                elif entry_pk and signing.fingerprint(bytes.fromhex(entry_pk)) != matched_fp:
                    fail(UNVERIFIED_SIGNER); signer_trust["reason"] = "registry_entry_fingerprint_mismatch"
                entry_class = entry.get("signer_class")
                if entry_class and pack_signer_class and entry_class != pack_signer_class:
                    fail(UNVERIFIED_SIGNER); signer_trust["reason"] = "signer_class_mismatch"
            if expected_fps and embedded_fp is not None and embedded_fp not in expected_fps and not trust_registry:
                fail(UNVERIFIED_SIGNER); signer_trust["reason"] = "signer_fingerprint_not_expected"
    if UNVERIFIED_SIGNER not in fails:
        signer_trust["status"] = "trusted"; signer_trust["reason"] = None
    # --- pack hash (unkeyed checksum over body excl. hash + signature fields)
    body = {k: v for k, v in pack.items() if k not in ("pack_hash", "pack_signature")}
    if slicer.sha256_hex(slicer.canonical_json(body)) != pack.get("pack_hash"): fail("pack_hash")
    # --- pack signature (keyed; the anti-fabrication check)
    sig_hex = pack.get("pack_signature")
    if pk is not None:
        if not sig_hex: fail("pack_signature")
        else:
            try:
                payload = {k: v for k, v in pack.items() if k != "pack_signature"}
                if not signing.verify(pk, slicer.canonical_json(payload), bytes.fromhex(sig_hex)):
                    fail("pack_signature")
            except Exception:
                fail("pack_signature")
    # --- mandate: hash, signature, window/expiry semantics
    m = (pack.get("mandate") or {}).get("record")
    if not m:
        fail("mandate_record")
    else:
        if slicer.sha256_hex(slicer.canonical_json(m)) != pack["mandate"].get("mandate_hash"): fail("mandate_hash")
        msig = m.get("signature")
        if pk is not None:
            if not msig: fail("mandate_signature")
            else:
                try:
                    mpayload = {k: v for k, v in m.items() if k != "signature"}
                    if not signing.verify(pk, slicer.canonical_json(mpayload), bytes.fromhex(msig)):
                        fail("mandate_signature")
                except Exception:
                    fail("mandate_signature")
        try:
            win = m.get("window") or {}
            nb = parse_time(win.get("not_before"), "not_before"); na = parse_time(win.get("not_after"), "not_after")
            exp = parse_time(m.get("expiry"), "expiry")
            if na > exp or nb > na: fail("mandate_window_expiry")
            dr = pack.get("dispatch_record")
            if dr and dr.get("dispatch_time"):
                dt = parse_time(dr["dispatch_time"], "dispatch_time")
                if dt > exp or not (nb <= dt <= na): fail("mandate_window_expiry")
        except ToolError:
            fail("mandate_window_expiry")
        except Exception:
            fail("mandate_window_expiry")
    # --- profile pin vs mandate + profile hash
    if pack.get("profile"):
        prof = pack["profile"].get("profile")
        if not isinstance(prof, dict) or slicer.sha256_hex(slicer.canonical_json(prof)) != pack["profile"].get("profile_hash"):
            fail("profile_hash")
        if m and pack["profile"].get("profile_hash") not in _pin_hashes(m.get("profile_pins")):
            fail("profile_pin")
    # --- design pin: hashes recomputed from embedded source/params + pin in mandate
    design = pack.get("design") or {}
    if design:
        pin = design.get("pin") or {}
        src, params = design.get("source"), design.get("params")
        if src is not None and slicer.sha256_hex(str(src).encode()) != pin.get("design_source_hash"): fail("design_pin")
        if params is not None and slicer.sha256_hex(slicer.canonical_json(params)) != pin.get("parameter_set_hash"): fail("design_pin")
        if m and pin and pin not in (m.get("design_pins") or []): fail("design_pin")
    # --- slicer pin: pack slicer must equal the mandate's pinned build
    if m and pack.get("slicer") and pack["slicer"] != m.get("slicer_build"): fail("slicer_build_pin")
    if engine_slicer_build and pack.get("slicer") and pack["slicer"] != engine_slicer_build: fail("slicer_build_pin")
    # --- telemetry: digest vs verbatim trace, trace vs envelope
    trace = pack.get("_telemetry_trace"); digest = pack.get("telemetry_trace_digest")
    if digest is not None and trace is None: fail("telemetry_trace_digest")
    if trace is not None:
        if slicer.sha256_hex(slicer.canonical_json(trace)) != digest: fail("telemetry_trace_digest")
        env = (m or {}).get("thermal_envelope") or {}
        eh, eb = env.get("hotend_max_C"), env.get("bed_max_C")
        if isinstance(trace, list):
            for sample in trace:
                if not isinstance(sample, dict): continue
                if isinstance(eh, (int, float)) and isinstance(sample.get("hotend_C"), (int, float)) and sample["hotend_C"] > eh:
                    fail("telemetry_envelope")
                if isinstance(eb, (int, float)) and isinstance(sample.get("bed_C"), (int, float)) and sample["bed_C"] > eb:
                    fail("telemetry_envelope")
    # --- loadout label sanity (never upgraded beyond its source)
    loadout = pack.get("loadout") or {}
    if loadout and loadout.get("level") not in LOADOUT_LEVELS: fail("loadout_level")
    # --- end state sanity
    end_state = pack.get("end_state")
    if end_state is not None:
        if end_state not in END_STATES: fail("end_state")
        if end_state == "COMPLETED" and not pack.get("dispatch_record"): fail("end_state")
    # --- re-derive toolpath from pinned inputs (§10.1, §14 H18)
    rederived = None
    try:
        prof = (pack.get("profile") or {}).get("profile")
        src = (pack.get("design") or {}).get("source"); params = (pack.get("design") or {}).get("params")
        if src and params and prof and pack.get("slicer"):
            text, _ = slicer.slice_design(src, params, prof, pack["slicer"], volatile_seed="proof-rederive")
            rederived = slicer.canonical_hash(text)
            if rederived != (pack.get("toolpath") or {}).get("canonical_hash"): fail("toolpath_canonical_hash")
    except Exception:
        fail("toolpath_rederivation_error")
    return {"verdict": "PRINT_VERIFIED" if not fails else "PRINT_UNVERIFIED", "failing_elements": fails,
            "refusal": UNVERIFIED_SIGNER if UNVERIFIED_SIGNER in fails else None,
            "signer_trust": signer_trust,
            "rederived_toolpath_canonical_hash": rederived}
# Eclipse Strata MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
