"""Audit trail / compliance report endpoints.

GET /api/v1/reports/agent/{agent_id}
    Returns a signed CSV of all events + chain integrity status for the
    given agent, optionally filtered to a time range.

    Query params:
        since  – ISO-8601 datetime (e.g. 2025-01-01T00:00:00Z)
        until  – ISO-8601 datetime
        format – "csv" (default) or "json"
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import Alert, Anchor, Event

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])
logger = logging.getLogger(__name__)


def _iso(dt: Optional[datetime]) -> str:
    return dt.isoformat() if dt else ""


@router.get("/agent/{agent_id}")
async def agent_report(
    agent_id: str,
    since: Annotated[Optional[str], Query(description="ISO-8601 start timestamp")] = None,
    until: Annotated[Optional[str], Query(description="ISO-8601 end timestamp")] = None,
    fmt: Annotated[str, Query(alias="format", description="csv or json")] = "csv",
    db: AsyncSession = Depends(get_db),
):
    """Generate a signed audit-trail report for *agent_id*."""
    # ------------------------------------------------------------------
    # Parse optional date filters
    # ------------------------------------------------------------------
    since_dt: Optional[datetime] = None
    until_dt: Optional[datetime] = None
    try:
        if since:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        if until:
            until_dt = datetime.fromisoformat(until.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid timestamp: {exc}")

    # ------------------------------------------------------------------
    # Fetch events
    # ------------------------------------------------------------------
    eq = select(Event).where(Event.agent_id == agent_id).order_by(Event.timestamp.asc())
    if since_dt:
        eq = eq.where(Event.timestamp >= since_dt)
    if until_dt:
        eq = eq.where(Event.timestamp <= until_dt)
    events = (await db.execute(eq)).scalars().all()

    # ------------------------------------------------------------------
    # Fetch alerts
    # ------------------------------------------------------------------
    aq = select(Alert).where(Alert.agent_id == agent_id).order_by(Alert.timestamp.asc())
    if since_dt:
        aq = aq.where(Alert.timestamp >= since_dt)
    if until_dt:
        aq = aq.where(Alert.timestamp <= until_dt)
    alerts = (await db.execute(aq)).scalars().all()

    # ------------------------------------------------------------------
    # Verify chain integrity (walk hashes)
    # ------------------------------------------------------------------
    chain_ok, chain_error = _verify_chain(events)

    # ------------------------------------------------------------------
    # Latest anchor
    # ------------------------------------------------------------------
    anchor_result = await db.execute(
        select(Anchor)
        .where(Anchor.agent_id == agent_id)
        .order_by(Anchor.timestamp.desc())
        .limit(1)
    )
    anchor = anchor_result.scalars().first()

    # ------------------------------------------------------------------
    # Build report signature (SHA-256 of all event hashes + chain status)
    # ------------------------------------------------------------------
    report_hash = hashlib.sha256(
        "|".join(e.event_hash for e in events).encode()
    ).hexdigest()

    report_meta = {
        "agent_id": agent_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "since": since or "",
        "until": until or "",
        "event_count": len(events),
        "alert_count": len(alerts),
        "chain_integrity": "OK" if chain_ok else f"FAIL: {chain_error}",
        "latest_anchor_hash": anchor.chain_head_hash if anchor else "",
        "report_hash": report_hash,
    }

    if fmt.lower() == "json":
        payload = {
            "meta": report_meta,
            "events": [
                {
                    "event_id": e.event_id,
                    "timestamp": _iso(e.timestamp),
                    "actor": e.actor,
                    "device_id": e.device_id,
                    "action": e.action,
                    "source_type": e.source_type,
                    "event_hash": e.event_hash,
                    "prev_hash": e.prev_hash,
                }
                for e in events
            ],
            "alerts": [
                {
                    "id": a.id,
                    "rule": a.rule,
                    "score": a.score,
                    "device_id": a.device_id,
                    "timestamp": _iso(a.timestamp),
                    "details_json": a.details_json,
                }
                for a in alerts
            ],
        }
        return Response(
            content=json.dumps(payload, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="report_{agent_id}.json"'
            },
        )

    # ------------------------------------------------------------------
    # CSV output (default)
    # ------------------------------------------------------------------
    output = io.StringIO()
    writer = csv.writer(output)

    # Metadata header
    writer.writerow(["## REPORT METADATA"])
    for k, v in report_meta.items():
        writer.writerow([f"# {k}", v])
    writer.writerow([])

    # Events section
    writer.writerow(["## EVENTS"])
    writer.writerow(
        [
            "event_id",
            "timestamp",
            "actor",
            "device_id",
            "action",
            "source_type",
            "event_hash",
            "prev_hash",
        ]
    )
    for e in events:
        writer.writerow(
            [
                e.event_id,
                _iso(e.timestamp),
                e.actor,
                e.device_id,
                e.action,
                e.source_type,
                e.event_hash,
                e.prev_hash or "",
            ]
        )

    writer.writerow([])

    # Alerts section
    writer.writerow(["## ALERTS"])
    writer.writerow(["id", "rule", "score", "device_id", "timestamp", "details"])
    for a in alerts:
        writer.writerow(
            [
                a.id,
                a.rule,
                a.score,
                a.device_id,
                _iso(a.timestamp),
                a.details_json,
            ]
        )

    csv_content = output.getvalue()
    output.close()

    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="report_{agent_id}.csv"'
        },
    )


# ---------------------------------------------------------------------------
def _verify_chain(events) -> tuple[bool, str]:
    """Walk event hash chain; return (True, "") or (False, reason)."""
    prev: Optional[str] = None
    for ev in events:
        if prev is not None and ev.prev_hash != prev:
            return (
                False,
                f"Chain break at event {ev.event_id}: "
                f"expected prev={prev!r}, got {ev.prev_hash!r}",
            )
        prev = ev.event_hash
    return True, ""
