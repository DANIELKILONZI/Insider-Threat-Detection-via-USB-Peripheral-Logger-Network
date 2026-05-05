"""Device allowlist / policy endpoints.

POST /api/v1/policy/allowlist          — add a device to the allowlist
GET  /api/v1/policy/allowlist          — list all entries (filter by agent_id)
DELETE /api/v1/policy/allowlist/{id}   — remove an entry
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import AllowlistedDevice

router = APIRouter(prefix="/api/v1/policy", tags=["policy"])


class AllowlistEntry(BaseModel):
    agent_id: str = "*"  # "*" = org-wide
    device_id: str
    note: str = ""


@router.post("/allowlist", status_code=201)
async def add_allowlist_entry(
    entry: AllowlistEntry,
    db: AsyncSession = Depends(get_db),
):
    """Add *device_id* to the allowlist (scoped to agent or org-wide)."""
    record = AllowlistedDevice(
        agent_id=entry.agent_id,
        device_id=entry.device_id,
        note=entry.note,
        created_at=datetime.now(timezone.utc),
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return {
        "id": record.id,
        "agent_id": record.agent_id,
        "device_id": record.device_id,
        "note": record.note,
        "created_at": record.created_at.isoformat(),
    }


@router.get("/allowlist")
async def list_allowlist(
    agent_id: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Return allowlist entries; optionally filtered by agent_id."""
    q = select(AllowlistedDevice).order_by(AllowlistedDevice.id)
    if agent_id:
        q = q.where(
            (AllowlistedDevice.agent_id == agent_id)
            | (AllowlistedDevice.agent_id == "*")
        )
    result = await db.execute(q)
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "agent_id": r.agent_id,
            "device_id": r.device_id,
            "note": r.note,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.delete("/allowlist/{entry_id}", status_code=204)
async def remove_allowlist_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Remove an allowlist entry by ID."""
    result = await db.execute(
        select(AllowlistedDevice).where(AllowlistedDevice.id == entry_id)
    )
    row = result.scalars().first()
    if not row:
        raise HTTPException(status_code=404, detail="Allowlist entry not found")
    await db.delete(row)
    await db.commit()
