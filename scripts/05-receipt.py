#!/usr/bin/env python3
"""Phase 5 SS1 receipt: re-exports Phase 4 hash-chained receipt helpers.

SS1 does NOT introduce a new chain kind. Denials are recorded via
append_run_event(db, "vsock", "DENY ... errno=...").

This module exists only so 05-supervisor.py has a phase-scoped import
surface; all schema and chain logic lives in 04-receipt.py, unchanged.
"""
import importlib.util, os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "receipt4", os.path.join(_HERE, "04-receipt.py"))
_r = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_r)

CHAIN_GENESIS   = _r.CHAIN_GENESIS
SCHEMA          = _r.SCHEMA
chain_hash      = _r.chain_hash
open_db         = _r.open_db
append_run_event = _r.append_run_event
verify          = _r.verify

if __name__ == "__main__":
    sys.exit(_r.main())
