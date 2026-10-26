#!/usr/bin/env python3
# Eclipse Strata MCP
# Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
# Eclipse Strata Proof CLI — verify a pack file offline (§10.1).
"""Proof CLI (§10.1 + §7.1 trust anchor).

Usage:
  strata_proof.py PACK [--registry REGISTRY.json] [--expected-fingerprint FP]
  strata_proof.py PACK [REGISTRY.json | FP]        (positional anchor form)

The trusted signer anchor is REQUIRED for PRINT_VERIFIED: a pack checked
with no --registry / --expected-fingerprint reports PRINT_UNVERIFIED with
the named failing element UNVERIFIED_SIGNER — an embedded key alone never
verifies (§7.1: a locally-signed pack verifies against the local registry
only). Registry JSON shapes: {fingerprint: public_key_hex},
{fingerprint: {public_key_hex, signer: herald|local}}, a list of such
entries, or a local-signer public-key file ({pk_hex: ...}).
"""
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from proof import verify_pack

if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog="strata_proof", description="Verify a Strata print evidence pack against a trusted signer anchor (§7.1).")
    ap.add_argument("pack", help="evidence pack JSON file")
    ap.add_argument("anchor", nargs="?", default=None,
                    help="optional positional anchor: registry JSON file or expected signer fingerprint")
    ap.add_argument("--registry", "--signer-registry", "--trusted-registry", dest="registry",
                    action="append", default=None, help="local trusted-signer registry JSON file (repeatable)")
    ap.add_argument("--expected-fingerprint", "--trusted-fingerprint", "--expected-signer-fingerprint",
                    dest="expected_fingerprint", action="append", default=None,
                    help="expected trusted signer fingerprint (repeatable)")
    args = ap.parse_args()
    pack = json.loads(Path(args.pack).read_text())
    registry_sources = list(args.registry or [])
    if args.anchor:
        # A positional anchor that names an existing file is a registry;
        # anything else is taken as an expected fingerprint.
        if Path(args.anchor).exists(): registry_sources.append(args.anchor)
        elif args.expected_fingerprint is None and not registry_sources:
            args.expected_fingerprint = [args.anchor]
        else: registry_sources.append(args.anchor)
    result = verify_pack(pack,
                         registry=registry_sources or None,
                         expected_fingerprint=args.expected_fingerprint or None)
    print(json.dumps(result, indent=1))
# Eclipse Strata MCP · © 2026 Cyan Eclipse Technologies LLC · cetech.ai
