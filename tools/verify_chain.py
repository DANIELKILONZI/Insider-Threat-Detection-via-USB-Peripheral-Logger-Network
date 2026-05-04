"""tools/verify_chain.py – Standalone audit-chain integrity verifier.

Replays either:
  a) a local agent JSON-Lines log file, or
  b) the server-side chain fetched from the REST API

and reports any gaps or tampered records.

Usage
-----
Verify a local agent log::

    python -m tools.verify_chain --file /var/log/itdn/agent.log

Verify the server-side chain for a hostname::

    python -m tools.verify_chain --server https://siem.internal:8443 \\
        --hostname ws-laptop-01 \\
        [--ca /etc/itdn/siem-ca.crt]

Exit codes:
    0  – chain is intact
    1  – chain is broken (tamper or gap detected)
    2  – usage / connectivity error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import sys
import urllib.request
from typing import Any, Dict, List, Optional

_GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def _compute_hash(record: Dict[str, Any]) -> str:
    """Recompute the record_hash from the record contents (excluding record_hash itself)."""
    copy = {k: v for k, v in record.items() if k != "record_hash"}
    serialized = json.dumps(copy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Verification logic
# ---------------------------------------------------------------------------

def verify_chain(records: List[Dict[str, Any]]) -> List[str]:
    """
    Verify a list of chain records.

    Returns a list of error messages.  Empty list means the chain is intact.
    """
    errors: List[str] = []
    prev_hash = _GENESIS_HASH

    for idx, record in enumerate(records):
        record_id = record.get("id", idx)
        stored_prev = record.get("prev_hash", "")
        stored_hash = record.get("record_hash", "")

        # 1. Linkage check
        if stored_prev != prev_hash:
            errors.append(
                f"Record #{record_id}: prev_hash mismatch "
                f"(expected {prev_hash[:16]}…, got {stored_prev[:16]}…) "
                "– possible gap or deletion"
            )

        # 2. Hash integrity check
        computed = _compute_hash(record)
        if computed != stored_hash:
            errors.append(
                f"Record #{record_id}: record_hash mismatch "
                f"(stored {stored_hash[:16]}…, computed {computed[:16]}…) "
                "– record was tampered with"
            )

        prev_hash = stored_hash if stored_hash else prev_hash

    return errors


# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

def _load_from_file(path: str) -> List[Dict[str, Any]]:
    """Read a local JSON-Lines agent log, decrypting records if necessary."""
    from agent.crypto import decrypt_record

    records: List[Dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(decrypt_record(line))
                except (json.JSONDecodeError, ValueError) as exc:
                    print(f"  WARNING: line {lineno} could not be parsed/decrypted – {exc}", file=sys.stderr)
                except RuntimeError as exc:
                    print(f"  ERROR: line {lineno} is encrypted but no key provided – {exc}", file=sys.stderr)
                    sys.exit(2)
    except OSError as exc:
        print(f"ERROR: cannot open file {path!r}: {exc}", file=sys.stderr)
        sys.exit(2)
    return records


def _load_from_server(server_url: str, hostname: str, ca_cert: Optional[str], limit: int) -> List[Dict[str, Any]]:
    """Fetch the audit chain from the server REST API."""
    url = f"{server_url.rstrip('/')}/api/v1/audit?hostname={hostname}&limit={limit}"
    ctx = ssl.create_default_context()
    if ca_cert:
        ctx.load_verify_locations(ca_cert)

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            body = json.loads(resp.read())
    except Exception as exc:  # pylint: disable=broad-except
        print(f"ERROR: failed to fetch chain from server: {exc}", file=sys.stderr)
        sys.exit(2)

    records = body.get("records", [])
    print(f"  Fetched {len(records)} records for hostname '{hostname}' from {server_url}")
    return records


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify_chain",
        description="Verify the ITDN audit chain for tampering or gaps.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--file", metavar="PATH",
        help="Local JSON-Lines agent log file to verify.",
    )
    source.add_argument(
        "--server", metavar="URL",
        help="ITDN server base URL (e.g. https://siem.internal:8443).",
    )
    parser.add_argument(
        "--hostname", metavar="HOST",
        help="Hostname whose chain to fetch (required when --server is used).",
    )
    parser.add_argument(
        "--ca", metavar="PATH", dest="ca_cert",
        help="CA certificate file to verify the server TLS certificate.",
    )
    parser.add_argument(
        "--limit", metavar="N", type=int, default=10_000,
        help="Maximum number of records to fetch from the server (default: 10000).",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.server and not args.hostname:
        parser.error("--hostname is required when --server is used")

    print("ITDN Audit Chain Verifier")
    print("=" * 50)

    # Load records
    if args.file:
        print(f"  Source : local file  →  {args.file}")
        records = _load_from_file(args.file)
    else:
        print(f"  Source : server API  →  {args.server}")
        records = _load_from_server(args.server, args.hostname, args.ca_cert, args.limit)

    print(f"  Records: {len(records)}")

    if not records:
        print("\n  (no records – chain is trivially valid)")
        sys.exit(0)

    # Verify
    errors = verify_chain(records)

    print()
    if errors:
        print(f"  ✗ CHAIN INTEGRITY FAILURE – {len(errors)} error(s) detected:")
        for err in errors:
            print(f"    • {err}")
        sys.exit(1)
    else:
        print(f"  ✓ Chain is intact ({len(records)} records verified)")
        sys.exit(0)


if __name__ == "__main__":
    main()
