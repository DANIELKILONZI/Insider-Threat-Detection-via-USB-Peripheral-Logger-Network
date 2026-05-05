"""GET /api/v1/alerts — list and retrieve alerts."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import Alert

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("")
async def list_alerts(
    agent_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    q = select(Alert).order_by(Alert.timestamp.desc()).limit(limit).offset(offset)
    if agent_id:
        q = q.where(Alert.agent_id == agent_id)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "agent_id": r.agent_id,
            "rule": r.rule,
            "score": r.score,
            "device_id": r.device_id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in rows
    ]


@router.get("/{alert_id}")
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    row = result.scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "id": row.id,
        "agent_id": row.agent_id,
        "rule": row.rule,
        "score": row.score,
        "device_id": row.device_id,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "details_json": row.details_json,
    }
