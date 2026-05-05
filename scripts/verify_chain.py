#!/usr/bin/env python3
"""
verify_chain.py — Validate local event chain and optionally check against server anchor.

Usage:
    python scripts/verify_chain.py --agent-id agent-001
    python scripts/verify_chain.py --agent-id agent-001 --server https://localhost:8443 --api-key changeme
"""
import argparse
import sys
from pathlib import Path

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.chain import EventChain


def main():
    parser = argparse.ArgumentParser(description="Verify event chain integrity")
    parser.add_argument("--agent-id", required=True, help="Agent ID")
    parser.add_argument(
        "--db", default="chain.db", help="Path to chain SQLite DB (default: chain.db)"
    )
    parser.add_argument("--server", default="", help="Server URL for anchor validation")
    parser.add_argument("--api-key", default="", help="Server API key")
    args = parser.parse_args()

    chain = EventChain(db_path=args.db)
    ok = chain.verify_chain()
    head = chain.get_chain_head()

    if ok:
        print(f"[OK] Chain is VALID. Head: {head}")
    else:
        print("[FAIL] Chain is TAMPERED or CORRUPT.")
        sys.exit(1)

    if args.server and head:
        import httpx

        headers = {}
        if args.api_key:
            headers["X-API-Key"] = args.api_key
        try:
            resp = httpx.get(
                f"{args.server}/api/v1/anchor/{args.agent_id}",
                headers=headers,
                verify=False,
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                server_head = data.get("chain_head_hash", "")
                if server_head == head:
                    print(f"[OK] Server anchor MATCHES local head: {head[:16]}...")
                else:
                    print(
                        f"[WARN] Server anchor MISMATCH: server={server_head[:16]}... local={head[:16]}..."
                    )
                    sys.exit(2)
            elif resp.status_code == 404:
                print("[INFO] No server anchor found yet.")
            else:
                print(f"[WARN] Server returned {resp.status_code}")
        except Exception as exc:
            print(f"[ERROR] Could not reach server: {exc}")
            sys.exit(3)


if __name__ == "__main__":
    main()
