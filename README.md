# Eclipse Strata

*governed design-to-print authority for agents — signed provenance from model to machine, safety envelopes at the bridge, evidence for every print.*

**Status: CERTIFIED(simulator) — Eclipse Bazaar Test Bench 2026-10-25, scoped re-bench r3 (standing card `../test-bench/results/eclipse-strata-mcp-2026-10-25-r3.json`, 12/12 scoped checks). Bench history, all cards retained append-only: bench 1 FAILED (35 of 45), scoped re-bench r2 FAILED (25 of 26 — D2 signer-anchor defect open), r3 CERTIFIED(simulator) with D2 closed. Simulator scope only — no live printer was exercised; no claim broader than CERTIFIED(simulator) is made.**

Spec: `../eclipse-strata-spec-20261025.md` (Silas Forge W-002, 2026-10-25). Name **CONDITIONAL** — Strata pending trademark screen (Stratasys); fallbacks Sinter, then Loft (D7).

## What it is

Fabrication authority exercised only inside a signed mandate pinning agent × printer serial × design pin × slicer build × profile hash × material × thermal/volume/duration/budget envelope × site class × window. The bridge **re-slices the pinned inputs at dispatch and canonical-hash-matches** (§4.3: comments + volatile header stripped, rest byte-exact) before any printer contact. Every print and every refusal seals into a Blackbox-form evidence pack (16+ fields, §12) verifiable offline by Strata Proof.

## Surfaces

- **MCP server** (`server.py`, stdio JSON-RPC, stdlib only) — exactly **11 tools**: `design_register, design_inspect, design_pin_get, printers_discover, session_open, job_prepare, job_dispatch, job_status, job_abort, telemetry_read, session_close`. No raw G-code, axis, heater, config-write, code-exec, or pin-activation tool exists on the surface; forbidden names refuse `-32602` with the named refusal (§11).
- **Bridge** (`strata_engine.py`) — simulators only at P0: OctoPrint virtual printer + virtual Klipper/Moonraker (+ a virtual multi-function unit for non-print-head refusal). Slicer is a deterministic simulated PrusaSlicer/Orca behind the production interface (real CLI adapters slot in at P1+); re-derivation is real: identical pinned inputs re-derive the identical canonical hash, any content edit changes it.
- **Bridge admin CLI** (`bridge_admin.py`) — operator-only, bridge host, never MCP-reachable: toolchain registry, printer declaration, human-principal pin activation, pack export; admin acts receipted to `data/bridge-admin.log`.
- **Strata Proof** (`proof.py`, `tools/strata_proof.py`) — offline pack verifier: `PRINT_VERIFIED | PRINT_UNVERIFIED`, failing element named, toolpath re-derived from the pack's pinned inputs. Verification requires a **trusted signer anchor** supplied to the verifier (`verify_pack(..., registry=… / expected_fingerprint=…)`; CLI `--registry FILE` / `--expected-fingerprint FP`): the pack's signer fingerprint + embedded key are cross-checked against that local registry (§7.1) — unknown signers, registry key mismatches, and no-anchor presentations refuse naming `UNVERIFIED_SIGNER`.
- **Strata Gauge** (`gauge.py`, `tools/strata_gauge.py`) — static mandate+profile conformance: `ENVELOPE_SOUND | ENVELOPE_UNSOUND`, violations named.

## Safety law (§5, enforced in code)

CONFIG_DRIFT refusal on firmware attestation change; config writes = permanent refusal (no T3 verb exists); T2 raw G-code refused; dead-man = telemetry loss (mandate gap threshold, default 30 s, 10–300) → state UNKNOWN + pause, resume only after re-attestation; mandate expiry mid-print ≠ kill (completes under monitoring unless `hard_stop_at_expiry` signed); `PENDING_PHYSICAL_CONFIRM` is honest waiting, never a bypass; readiness facts are labeled machine-attested / human-declared / unchecked, never upgraded. Registration split (§4.4/S6): `design_register` only PROPOSES; activation requires a human-principal signed pin record — agent self-pin refuses `AGENT_SELF_PIN_REFUSED`.

## Composition (§7, by port)

PinSigner port with local Ed25519 signer fallback (pure-stdlib; Herald upgrades verifiability, never behavior); Blackbox-form packs native; Tripwire-pattern ceilings native; Friction auto-file hook on adapter telemetry findings; Meter-shaped consumption records emitted read-side per print; **Till = P3-gated port only** (present, disabled, no active code paths); Span delegation slot present in the mandate grammar from P0 (inert); **Census rejected** (no port, no discovery targeting).

## Tests

`python3 -m unittest discover -s tests` — 64 tests: happy-path full governed print on both simulators + pack verification, guards (`coerce_int_param`, `parse_time`, ref guard), canonical-hash volatile-invariance, and the §14 hostile-agent suite **H1–H18** in bench shape (same fixtures, same expected refusal codes). Note: pure-Python Ed25519 makes the suite slow (~95 s); signing is the only non-trivial cost. `python3 smoke.py` — wire-level smoke (11 tools, discover, forbidden-name refusal).

## Honest limits (P0)

Simulators only — no real printer was touched, no heat, no network calls, no vendor clouds, no Bambu path (Developer-Mode gate is P2+). A mandate layer never substitutes for a site's own risk assessment, fire precautions, or insurer terms (§6.6). On an open desktop, bridge custody is a discipline, not physics (§3). **Geometry at P0 is declared geometry only** (fix round D7): `design_inspect` returns the caller-declared bounding box from the parameter set plus arithmetic over it — no kernel/mesh inspection of the artifact is performed, and manifold / wall-thickness / triangle facts are reported unchecked (`null`), never echoed as verified. **Packs are key-sealed** (fix round D2): every pack carries an Ed25519 `pack_signature`; Strata Proof requires it — recomputing the pack's unkeyed hashes without the signer key does not verify. **Proof is signer-anchored** (fix round 2, D2X): the embedded key's self-consistency never suffices — Proof cross-checks signer fingerprint + embedded key against a verifier-supplied local registry / expected fingerprint (§7.1), and an attacker-minted self-consistent pack refuses `UNVERIFIED_SIGNER`.

**Powered by Cyan Eclipse Technologies** — https://cetech.ai
