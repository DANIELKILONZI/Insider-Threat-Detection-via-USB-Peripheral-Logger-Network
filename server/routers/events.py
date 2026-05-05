"""POST /api/v1/events — receive and store NormalizedEvents."""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.honeypot.profiles import HoneypotManager
from server.models import Alert, Event
from server.notifications.bus import get_bus
from server.scoring.baseline import BaselineProfiler
from server.scoring.risk_engine import RiskEngine
from shared.schema import NormalizedEvent

router = APIRouter(prefix="/api/v1/events", tags=["events"])
logger = logging.getLogger(__name__)

risk_engine = RiskEngine()
baseline = BaselineProfiler()
honeypot = HoneypotManager()


@router.post("", status_code=201)
async def create_event(event: NormalizedEvent, db: AsyncSession = Depends(get_db)):
    """Store an event and run risk scoring."""
    # Check honeypot
    hp_alert = await honeypot.check(event.device_id, event.agent_id, db)

    # Record baseline
    await baseline.record_device(event.agent_id, event.device_id, event.timestamp, db)

    # Risk scoring
    score, rule_alert = await risk_engine.score_event(event, db)

    # Persist event
    db_event = Event(
        event_id=event.event_id,
        agent_id=event.agent_id,
        actor=event.actor,
        device_id=event.device_id,
        action=event.action,
        source_type=event.source_type,
        confidence=event.confidence,
        raw_json=json.dumps(event.raw),
        event_hash=event.event_hash,
        prev_hash=event.prev_hash,
        timestamp=event.timestamp,
    )
    db.add(db_event)

    alert_out = None
    for al in [hp_alert, rule_alert]:
        if al is not None:
            db.add(al)
            alert_out = {
                "id": al.id,
                "rule": al.rule,
                "score": al.score,
                "device_id": al.device_id,
            }

    await db.commit()

    # Dispatch alerts via notification bus (non-blocking; errors are logged)
    if alert_out is not None:
        import asyncio

        from server.routers.dashboard import manager as ws_manager

        alert_payload = {
            **alert_out,
            "agent_id": event.agent_id,
            "timestamp": event.timestamp.isoformat(),
            "details_json": "{}",
        }
        bus = get_bus()
        asyncio.create_task(bus.dispatch(alert_payload))
        asyncio.create_task(ws_manager.broadcast({"type": "alert", **alert_payload}))

    return {"event_id": event.event_id, "score": score, "alert": alert_out}


@router.get("/{agent_id}")
async def list_events(
    agent_id: str,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Event)
        .where(Event.agent_id == agent_id)
        .order_by(Event.timestamp.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = result.scalars().all()
    return [
        {
            "event_id": r.event_id,
            "device_id": r.device_id,
            "action": r.action,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "score": None,
        }
        for r in rows
    ]
